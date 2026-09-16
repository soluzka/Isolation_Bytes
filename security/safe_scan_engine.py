"""Safe, unbounded file enumeration and evidence correlation for malware scanning.

The engine deliberately separates discovery from containment. There is no global
file-count cap: every reachable regular file is considered. Per-file failures are
recorded and do not abort the scan. Symlinked directories are not followed to
avoid cycles and scanning outside the requested roots.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Optional


@dataclass
class ScanStats:
    discovered: int = 0
    scanned: int = 0
    suspicious: int = 0
    contained: int = 0
    errors: int = 0
    skipped: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


def iter_regular_files(roots: Iterable[str]) -> Iterator[str]:
    """Yield every regular file below *roots* without a file-count ceiling.

    Directory symlinks are not followed. Regular-file symlinks are skipped as
    well because their target can change between discovery and analysis.
    Duplicate roots and hard-linked files are de-duplicated by device/inode.
    """
    seen_dirs: set[tuple[int, int]] = set()
    seen_files: set[tuple[int, int]] = set()

    for raw_root in roots:
        if not raw_root:
            continue
        root = os.path.abspath(os.path.expanduser(os.fspath(raw_root)))
        try:
            st = os.stat(root, follow_symlinks=False)
        except OSError as exc:
            logging.warning("Cannot access scan root %s: %s", root, exc)
            continue
        if not os.path.isdir(root):
            if os.path.isfile(root) and not os.path.islink(root):
                key = (st.st_dev, st.st_ino)
                if key not in seen_files:
                    seen_files.add(key)
                    yield root
            continue

        stack = [root]
        while stack:
            current = stack.pop()
            try:
                cst = os.stat(current, follow_symlinks=False)
                dkey = (cst.st_dev, cst.st_ino)
                if dkey in seen_dirs:
                    continue
                seen_dirs.add(dkey)
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            est = entry.stat(follow_symlinks=False)
                            fkey = (est.st_dev, est.st_ino)
                            if fkey in seen_files:
                                continue
                            seen_files.add(fkey)
                            yield entry.path
                        except OSError as exc:
                            logging.debug("Cannot inspect %s: %s", entry.path, exc)
            except OSError as exc:
                logging.warning("Cannot enumerate %s: %s", current, exc)


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file incrementally so large files do not require full RAM."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_roots(
    roots: Iterable[str],
    *,
    timeout: int = 2,
    quarantine: bool = False,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> ScanStats:
    """Scan all discovered files with the existing correlated security stack.

    Containment is intentionally opt-in. When enabled, only the existing
    pipeline's containment policy can quarantine a file; this function never
    deletes or overwrites a source file itself.
    """
    from security.yara_ml_pipeline import analyze_file, quarantine_correlated

    stats = ScanStats()
    excluded = {
        os.path.abspath(os.path.expanduser(os.fspath(p)))
        for p in (exclude_dirs or ())
        if p
    }

    for path in iter_regular_files(roots):
        stats.discovered += 1
        normalized = os.path.abspath(path)
        if any(normalized == p or normalized.startswith(p + os.sep) for p in excluded):
            stats.skipped += 1
            continue

        try:
            result = analyze_file(normalized, timeout=timeout)
            stats.scanned += 1
            threat = result.get("threat") or {}
            yara_matches = result.get("yara_matches") or []
            if yara_matches or threat.get("level") in {"medium", "high", "critical"}:
                stats.suspicious += 1

            record = {
                "filepath": normalized,
                "sha256": sha256_file(normalized),
                "yara_severity": result.get("yara_severity", "low"),
                "yara_matches": [getattr(m, "rule", str(m)) for m in yara_matches],
                "threat": threat,
                "contained": False,
            }
            if quarantine and result.get("yara_severity") == "critical":
                record["contained"] = bool(
                    quarantine_correlated(normalized, reason="critical YARA detection")
                )
                if record["contained"]:
                    stats.contained += 1
            stats.results.append(record)
        except (OSError, PermissionError) as exc:
            stats.errors += 1
            stats.results.append({"filepath": normalized, "error": str(exc)})
        except Exception as exc:
            # A broken rule, model, or individual file must never terminate the
            # complete recursive scan.
            stats.errors += 1
            logging.exception("Scan failed for %s", normalized)
            stats.results.append({"filepath": normalized, "error": str(exc)})

    return stats
