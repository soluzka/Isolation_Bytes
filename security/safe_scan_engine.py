"""Safe, unbounded file enumeration and evidence correlation for malware scanning.

Discovery is separated from containment. Every reachable regular file is
considered without a global file-count or file-size ceiling. Per-file failures
are recorded and do not abort the scan. Directory symlinks are not followed.
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


def _normalise_root(raw_root: str) -> str | None:
    if not raw_root:
        return None
    return os.path.abspath(os.path.expanduser(os.fspath(raw_root)))


def _file_key(path: str) -> tuple[int, int] | None:
    try:
        stat = os.stat(path, follow_symlinks=False)
        return stat.st_dev, stat.st_ino
    except OSError as exc:
        logging.debug("Cannot stat %s: %s", path, exc)
        return None


def _yield_root_file(root: str, seen_files: set[tuple[int, int]]) -> Iterator[str]:
    if not os.path.isfile(root) or os.path.islink(root):
        return
    key = _file_key(root)
    if key is not None and key not in seen_files:
        seen_files.add(key)
        yield root


def _walk_directory(
    root: str,
    seen_dirs: set[tuple[int, int]],
    seen_files: set[tuple[int, int]],
) -> Iterator[str]:
    stack = [root]
    while stack:
        current = stack.pop()
        key = _file_key(current)
        if key is None or key in seen_dirs:
            continue
        seen_dirs.add(key)
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    yield from _process_entry(entry, stack, seen_files)
        except OSError as exc:
            logging.warning("Cannot enumerate %s: %s", current, exc)


def _process_entry(
    entry: os.DirEntry[str],
    stack: list[str],
    seen_files: set[tuple[int, int]],
) -> Iterator[str]:
    try:
        if entry.is_dir(follow_symlinks=False):
            stack.append(entry.path)
            return
        if not entry.is_file(follow_symlinks=False):
            return
        key = entry.stat(follow_symlinks=False)
    except OSError as exc:
        logging.debug("Cannot inspect %s: %s", entry.path, exc)
        return
    file_key = (key.st_dev, key.st_ino)
    if file_key in seen_files:
        return
    seen_files.add(file_key)
    yield entry.path


def iter_regular_files(roots: Iterable[str]) -> Iterator[str]:
    """Yield every regular file below *roots* without a file-count ceiling."""
    seen_dirs: set[tuple[int, int]] = set()
    seen_files: set[tuple[int, int]] = set()
    for raw_root in roots:
        root = _normalise_root(raw_root)
        if root is None:
            continue
        try:
            if os.path.isdir(root) and not os.path.islink(root):
                yield from _walk_directory(root, seen_dirs, seen_files)
            else:
                yield from _yield_root_file(root, seen_files)
        except OSError as exc:
            logging.warning("Cannot access scan root %s: %s", root, exc)


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file incrementally so large files do not require full RAM."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_excluded(path: str, excluded: set[str]) -> bool:
    return any(path == item or path.startswith(item + os.sep) for item in excluded)


def _record_scan_error(stats: ScanStats, path: str, exc: Exception) -> None:
    stats.errors += 1
    stats.results.append({"filepath": path, "error": str(exc)})


def _scan_one(path: str, timeout: int, quarantine: bool, quarantine_correlated) -> dict[str, Any]:
    from security.yara_ml_pipeline import analyze_file

    result = analyze_file(path, timeout=timeout)
    threat = result.get("threat") or {}
    yara_matches = result.get("yara_matches") or []
    record: dict[str, Any] = {
        "filepath": path,
        "sha256": sha256_file(path),
        "yara_severity": result.get("yara_severity", "low"),
        "yara_matches": [getattr(match, "rule", str(match)) for match in yara_matches],
        "threat": threat,
        "contained": False,
    }
    if yara_matches or threat.get("level") in {"medium", "high", "critical"}:
        record["_suspicious"] = True
    if quarantine and result.get("yara_severity") == "critical":
        record["contained"] = bool(
            quarantine_correlated(path, reason="critical YARA detection")
        )
    return record


def scan_roots(
    roots: Iterable[str],
    *,
    timeout: int = 2,
    quarantine: bool = False,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> ScanStats:
    """Scan all discovered files with the existing correlated security stack."""
    from security.yara_ml_pipeline import quarantine_correlated

    stats = ScanStats()
    excluded = {
        os.path.abspath(os.path.expanduser(os.fspath(path)))
        for path in (exclude_dirs or ())
        if path
    }
    for path in iter_regular_files(roots):
        stats.discovered += 1
        normalized = os.path.abspath(path)
        if _is_excluded(normalized, excluded):
            stats.skipped += 1
            continue
        try:
            record = _scan_one(normalized, timeout, quarantine, quarantine_correlated)
            stats.scanned += 1
            stats.suspicious += int(record.pop("_suspicious", False))
            if record["contained"]:
                stats.contained += 1
            stats.results.append(record)
        except (OSError, PermissionError) as exc:
            _record_scan_error(stats, normalized, exc)
        except Exception as exc:
            logging.exception("Scan failed for %s", normalized)
            _record_scan_error(stats, normalized, exc)
    return stats
