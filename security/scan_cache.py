"""
Persistent scan-result cache and safe quarantine helpers.

The cache lets the background scanner skip unchanged files on subsequent
passes (``run_scheduled_scans()`` in quick_start.py), and it gives the
operator a record of which hashes have been seen and what their verdicts
were.  The safe-quarantine helper prevents the scanner from crashing or
spamming the log when it hits protected system files.
"""
import hashlib
import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger('scan_cache')

# Locations that should never be quarantined/deleted by an unelevated scan.
# The list is intentionally conservative: it protects the Windows install,
# Program Files, and other shared data areas.  Quarantine is still attempted
# in user-writable directories (Desktop, Downloads, etc.).
_PROTECTED_PREFIXES = [
    r'c:\windows',
    r'c:\program files',
    r'c:\program files (x86)',
    r'c:\programdata',
    r'c:\windows.old',
    r'c:\$',
]


def _normalize_path(path):
    """Return a lowercased, long-path normalized path for prefix checks."""
    try:
        return os.path.normpath(os.path.abspath(path)).lower()
    except Exception:
        return path.lower()


def _is_protected(path):
    """Return True if the path lives under a protected system location."""
    normalized = _normalize_path(path)
    for prefix in _PROTECTED_PREFIXES:
        if normalized.startswith(prefix):
            return True
    # Also block paths that are not on a local drive (UNC, etc.) for safety.
    if normalized.startswith('\\'):
        return True
    return False


def _file_fingerprint(path):
    """Return a stable, content-based fingerprint for a file.

    For files <= 50 MB a full SHA-256 is computed.  For larger files a
    header/tail/size fingerprint is used to avoid reading gigabytes every
    time the cache is consulted.  The fingerprint is meant for cache
    invalidation, not as a cryptographic guarantee.
    """
    try:
        stat = os.stat(path)
    except (OSError, IOError):
        return None

    size = stat.st_size
    mtime = stat.st_mtime
    # Full SHA-256 for reasonably sized files.
    if size <= 50 * 1024 * 1024:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        digest = h.hexdigest()
    else:
        # Large files: hash first and last 64 KB, size, and mtime.
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            h.update(f.read(64 * 1024))
            if size > 64 * 1024:
                f.seek(-64 * 1024, 2)
                h.update(f.read(64 * 1024))
        h.update(str(size).encode())
        h.update(str(mtime).encode())
        digest = h.hexdigest()

    return f"{digest}:{size}:{mtime}"


class FileScanCache:
    """Persistent JSON cache keyed by file content fingerprint."""

    def __init__(self, cache_path='data/scan_cache.json'):
        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache = self._load()

    def _load(self):
        if not self.cache_path.exists():
            return {}
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warning('Scan cache is not a JSON object, starting fresh')
                return {}
            return data
        except Exception as e:
            logger.warning(f'Failed to load scan cache, starting fresh: {e}')
            # Move the corrupt/truncated file aside so it won't keep breaking.
            try:
                backup = self.cache_path.with_suffix(
                    f'.json.bak.{int(time.time())}'
                )
                self.cache_path.rename(backup)
                logger.info(f'Backed up corrupt scan cache to {backup}')
            except Exception:
                pass
            return {}

    def _save(self):
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            # Write to a temp file first, then atomically replace the real one
            # so a crash mid-write never leaves a truncated scan_cache.json.
            tmp_path = self.cache_path.with_suffix('.json.tmp')
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(self._cache, f, indent=2)
            tmp_path.replace(self.cache_path)
        except Exception as e:
            logger.warning(f'Failed to save scan cache: {e}')

    def _prune(self, max_age_days=30, max_entries=50000):
        """Remove stale entries to keep the cache from growing unbounded."""
        now = time.time()
        cutoff = now - max_age_days * 24 * 3600
        fresh = {}
        for k, v in self._cache.items():
            if v.get('timestamp', 0) >= cutoff:
                fresh[k] = v
        # If still too large, drop oldest first.
        if len(fresh) > max_entries:
            sorted_items = sorted(fresh.items(), key=lambda x: x[1].get('timestamp', 0))
            fresh = dict(sorted_items[-max_entries:])
        self._cache = fresh

    def get(self, file_path):
        """Return the cached scan result for a file, or None if unknown/changed."""
        fp = _file_fingerprint(file_path)
        if fp is None:
            return None
        return self._cache.get(fp)

    def set(self, file_path, result):
        """Store a scan result, keyed by the file's content fingerprint."""
        fp = _file_fingerprint(file_path)
        if fp is None:
            return
        # Keep only serializable fields.
        result['path'] = str(file_path)
        result['timestamp'] = time.time()
        self._cache[fp] = result
        # Save and prune on every 100th insert to keep I/O reasonable.
        if len(self._cache) % 100 == 0:
            self._prune()
        self._save()

    def clear(self):
        """Clear the cache and delete the backing file."""
        self._cache = {}
        if self.cache_path.exists():
            try:
                self.cache_path.unlink()
            except Exception as e:
                logger.warning(f'Failed to delete cache file: {e}')


def safe_quarantine(file_path, quarantine_dir, encrypt_fn, max_size=100 * 1024 * 1024):
    """Safely encrypt and remove a suspicious file.

    Returns ``(success, message)``.  Protected system files, files too large
    to read into memory, and files that cannot be accessed are skipped with
    a descriptive message instead of raising an exception.
    """
    file_path = str(file_path)
    try:
        if not os.path.exists(file_path):
            return False, 'File does not exist'

        if _is_protected(file_path):
            return False, f'Skipped protected system location: {file_path}'

        size = os.path.getsize(file_path)
        if size > max_size:
            return False, (
                f'Skipped large file ({size / 1024 / 1024:.1f}MB > '
                f'{max_size / 1024 / 1024:.1f}MB limit): {file_path}'
            )

        # Verify we can read the file before allocating a quarantine name.
        try:
            with open(file_path, 'rb') as f:
                f.read(1)
        except (OSError, IOError) as e:
            return False, f'Cannot read file (permission/access): {e}'

        os.makedirs(quarantine_dir, exist_ok=True)
        base_name = os.path.basename(file_path)
        name, ext = os.path.splitext(base_name)
        encrypted_name = f"{name}{ext}.enc"
        quarantine_path = os.path.join(quarantine_dir, encrypted_name)

        if os.path.exists(quarantine_path):
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            quarantine_path = os.path.join(
                quarantine_dir, f"{name}_{timestamp}{ext}.enc"
            )

        if not encrypt_fn(file_path, quarantine_path):
            return False, f'Encryption failed for {file_path}'

        # Attempt to remove the original.  If this fails the encrypted copy
        # is still in quarantine, which is safer than leaving it in place.
        try:
            os.remove(file_path)
            return True, f'Quarantined and removed: {file_path} -> {quarantine_path}'
        except (OSError, IOError) as e:
            return False, (
                f'Encrypted copy saved, but failed to remove original '
                f'{file_path}: {e}'
            )

    except Exception as e:
        return False, f'Unexpected quarantine error for {file_path}: {e}'
