"""Filesystem monitoring backed by the unified hardened malware pipeline.

This module intentionally has one scanning/remediation path. It does not
maintain a second legacy YARA/ML/quarantine decision tree, and it never skips
files because of a fixed file-size or file-count limit.
"""
from __future__ import annotations

import logging
import os
import platform
import string
import time
from pathlib import Path
from typing import Dict, List

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from utils.paths import get_resource_path
from security.hardened_scan_pipeline import scan_file, scan_target


RUNTIME_DIR = os.environ.get("ANTIVIRUS_RUNTIME_DIR", os.path.dirname(os.path.abspath(__file__)))

# Virtual/system trees that cannot safely be recursively enumerated. These are
# traversal exclusions, not malware exclusions; files outside them are scanned.
SKIP_DIRS = {
    "/proc", "/sys", "/dev", "/run", "/snap", "/var/snap",
    "/var/lib/docker", "/var/lib/containers",
    "c:\\windows\\system32\\config", "c:\\windows\\system32\\winevt",
    "c:\\$recycle.bin\\s-1-5-18",
}


def _normal(path: str) -> str:
    return os.path.abspath(path).lower().replace("/", "\\")


def _should_skip(path: str) -> bool:
    value = _normal(path)
    return any(value == _normal(item) or value.startswith(_normal(item) + "\\") for item in SKIP_DIRS)


def ensure_file_exists(filename: str, default_content: str | None = None) -> None:
    path = get_resource_path(filename)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            if default_content is not None:
                fh.write(default_content)


def load_scan_directories(config_path: str = "scan_directories.txt", auto_discover: bool = True) -> List[str]:
    """Load configured directories and optionally discover mounted storage."""
    directories: List[str] = []
    if auto_discover:
        directories.extend(discover_all_drives_and_important_folders())

    config = get_resource_path(config_path)
    try:
        with open(config, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                path = os.path.expanduser(os.path.expandvars(line))
                if os.path.isdir(path) and path not in directories:
                    directories.append(path)
    except OSError as exc:
        logging.warning("Unable to read scan directory configuration: %s", exc)

    return list(dict.fromkeys(directories))


def discover_all_drives_and_important_folders() -> List[str]:
    """Discover storage roots and important user locations without a scan cap."""
    found: List[str] = []

    def add(path: str) -> None:
        if path and os.path.isdir(path) and not _should_skip(path) and path not in found:
            found.append(path)

    home = str(Path.home())
    for name in (
        "Downloads", "Documents", "Desktop", "Pictures", "Videos", "Music",
        "Movies", "AppData", "Library", ".config", ".local/share",
    ):
        add(os.path.join(home, name))

    system = platform.system()
    if system == "Windows":
        for drive in string.ascii_uppercase:
            root = f"{drive}:\\"
            if os.path.exists(root):
                add(root)
    elif system in {"Linux", "Darwin"}:
        add("/")
        for mount_root in ("/mnt", "/media", "/run/media", "/Volumes"):
            if os.path.isdir(mount_root):
                try:
                    for entry in os.scandir(mount_root):
                        if entry.is_dir(follow_symlinks=False):
                            add(entry.path)
                except OSError as exc:
                    logging.warning("Unable to enumerate %s: %s", mount_root, exc)

    return found


ensure_file_exists(
    "scan_directories.txt",
    "# Directories are scanned recursively with no file-count or file-size cap.\n",
)
MONITORED_FOLDERS = load_scan_directories()


def get_scan_allowed() -> bool:
    return True


def scan_and_quarantine(filepath: str, timeout: int = 600, max_file_size=None) -> Dict[str, object]:
    """Authoritative single-file scan.

    ``max_file_size`` is accepted only for backwards API compatibility and is
    deliberately ignored. Large files are streamed by the behavioral layer.
    Quarantine occurs only after corroborated evidence or explicit host-AV
    confirmation, and successful containment is verified before reporting it.
    """
    del timeout, max_file_size
    return scan_file(os.path.abspath(filepath), quarantine=True)


def scan_file_with_yara(filepath: str) -> bool:
    """Compatibility shim: use the unified pipeline rather than a second gate."""
    result = scan_file(os.path.abspath(filepath), quarantine=False)
    return result.get("yara_severity") in {"high", "critical"}


def scan_all_monitored_directories() -> Dict[str, object]:
    """Scan every discoverable file recursively with no artificial file cap."""
    if not get_scan_allowed():
        return {"results": [], "stats": {"status": "scan_not_allowed"}}

    results: List[Dict[str, object]] = []
    for folder in MONITORED_FOLDERS:
        if not os.path.isdir(folder):
            logging.warning("Target folder does not exist: %s", folder)
            continue
        results.extend(scan_target(folder, quarantine=True))

    stats = {
        "total_files_scanned": len(results),
        "total_quarantined": sum(1 for r in results if r.get("status") == "quarantined"),
        "total_suspicious": sum(1 for r in results if r.get("status") == "suspicious_review_or_corroboration"),
        "total_errors": sum(1 for r in results if r.get("status") == "scan_error"),
        "unlimited_file_count": True,
        "unlimited_file_size": True,
    }
    logging.info("Full hardened scan complete: %d files", len(results))
    return {"results": results, "stats": stats}


class CustomEventHandler(FileSystemEventHandler):
    """Watchdog handler using the same hardened scan path as full scans."""

    def _process_event(self, file_path: str, event_type: str) -> None:
        if _should_skip(file_path):
            return
        try:
            result = scan_file(os.path.abspath(file_path), quarantine=True)
            logging.info("%s event scan: %s -> %s", event_type, file_path, result.get("status"))
        except (OSError, PermissionError) as exc:
            logging.warning("Could not scan %s: %s", file_path, exc)
        except Exception:
            logging.exception("Hardened scan failed for %s", file_path)

    def on_created(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            self._process_event(event.dest_path, "moved")


def start_monitoring() -> None:
    """Start recursive monitoring with the hardened scanner."""
    handler = CustomEventHandler()
    observer = Observer()
    scheduled = 0
    for folder in MONITORED_FOLDERS:
        if os.path.isdir(folder):
            observer.schedule(handler, folder, recursive=True)
            scheduled += 1
    logging.info("Starting hardened monitoring for %d roots", scheduled)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_monitoring()
