import os
import logging
import threading
import time
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class FolderWatcher(FileSystemEventHandler):
    """Real-time filesystem watcher backed by the hardened scan pipeline."""

    def __init__(self, directories=None):
        super().__init__()
        self.running = False
        self.observer = None
        self.event_handler = self
        self.monitored_directories = directories or []
        self._scan_lock = threading.RLock()
        self._recent_scans = {}
        self._scan_debounce_seconds = 0.75
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('folder_watcher.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('folder_watcher')

    def start(self):
        """Start recursive real-time monitoring of all configured folders."""
        if self.running:
            return

        self.running = True
        self.event_handler = self
        self.observer = Observer()
        self.monitored_directories = self.load_scan_directories()

        scheduled = 0
        for directory in self.monitored_directories:
            try:
                self.observer.schedule(self, directory, recursive=True)
                scheduled += 1
                self.logger.info("Real-time monitoring enabled: %s", directory)
            except Exception as exc:
                self.logger.error(
                    "Error monitoring directory %s: %s", directory, exc
                )

        if scheduled == 0:
            self.running = False
            self.observer = None
            self.logger.warning("Real-time folder monitoring started with no valid directories")
            return

        self.observer.start()
        self.logger.info(
            "Real-time folder protection started for %d directory(s)",
            scheduled,
        )

    def is_running(self):
        """Check if folder monitoring is active."""
        return self.running

    def stop(self):
        """Stop real-time folder monitoring."""
        if self.running:
            self.running = False
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None
            self.logger.info("Real-time folder protection stopped")

    def load_scan_directories(self):
        """Load the user folders monitored by real-time protection."""
        directories = []
        try:
            home_dir = os.path.expanduser("~")
            common_dirs = [
                os.path.join(home_dir, "Downloads"),
                os.path.join(home_dir, "Desktop"),
                os.path.join(home_dir, "Documents"),
            ]

            for dir_path in common_dirs:
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    directories.append(dir_path)
                    self.logger.info("Added real-time monitoring directory: %s", dir_path)
        except Exception as exc:
            self.logger.error("Error loading directories: %s", exc)

        return directories

    def _is_system_path(self, path):
        """Skip core Windows system directories, unless the file is under 200MB."""
        from security.detector import _large_system_file
        return _large_system_file(path)

    def _should_scan(self, file_path):
        """Avoid rescanning the same file repeatedly during one write operation."""
        now = time.monotonic()
        try:
            stat = os.stat(file_path)
            fingerprint = (stat.st_size, stat.st_mtime_ns)
        except OSError:
            return False

        with self._scan_lock:
            previous = self._recent_scans.get(file_path)
            if previous:
                previous_fingerprint, previous_time = previous
                if (
                    previous_fingerprint == fingerprint
                    and now - previous_time < self._scan_debounce_seconds
                ):
                    return False
            self._recent_scans[file_path] = (fingerprint, now)

            # Prevent this dictionary from growing indefinitely.
            if len(self._recent_scans) > 4096:
                cutoff = now - 60.0
                self._recent_scans = {
                    path: value
                    for path, value in self._recent_scans.items()
                    if value[1] >= cutoff
                }
        return True

    def _scan_realtime_file(self, file_path, event_name):
        """Scan one filesystem event through the unified hardened pipeline."""
        try:
            if not os.path.isfile(file_path):
                return
            if os.path.getsize(file_path) == 0:
                return
            if self._is_system_path(file_path):
                return
            if not self._should_scan(file_path):
                return

            from security.hardened_scan_pipeline import scan_file

            self.logger.info("Real-time protection scanning (%s): %s", event_name, file_path)
            result = scan_file(file_path, quarantine=True)

            if result.get("quarantine_verified"):
                self.logger.warning(
                    "Real-time protection quarantined %s "
                    "(status=%s, threat=%s %.1f, yara=%s, ml=%.3f)",
                    file_path,
                    result.get("status"),
                    result.get("threat_level"),
                    float(result.get("threat_score", 0.0)),
                    result.get("yara_matches", 0),
                    float(result.get("ml_confidence", 0.0)),
                )
            elif result.get("status") in {
                "suspicious_review_or_corroboration",
                "containment_unverified",
                "security_research_asset_review",
            }:
                self.logger.warning(
                    "Real-time protection flagged file without deleting it: %s "
                    "(status=%s, threat=%s %.1f, yara=%s observed=%s, ml=%.3f)",
                    file_path,
                    result.get("status"),
                    result.get("threat_level"),
                    float(result.get("threat_score", 0.0)),
                    result.get("yara_matches", 0),
                    result.get("yara_matches_observed", 0),
                    float(result.get("ml_confidence", 0.0)),
                )
            else:
                self.logger.info(
                    "Real-time protection cleared file: %s "
                    "(status=%s, threat=%s %.1f)",
                    file_path,
                    result.get("status"),
                    result.get("threat_level"),
                    float(result.get("threat_score", 0.0)),
                )
        except Exception as exc:
            self.logger.error(
                "Real-time protection error processing %s: %s",
                file_path,
                exc,
            )

    def on_created(self, event):
        """Scan newly created files immediately."""
        if not event.is_directory:
            self._scan_realtime_file(event.src_path, "created")

    def on_modified(self, event):
        """Scan files again when their contents change."""
        if not event.is_directory:
            self._scan_realtime_file(event.src_path, "modified")

    def on_moved(self, event):
        """Scan files moved into a monitored directory."""
        if not event.is_directory:
            self._scan_realtime_file(event.dest_path, "moved")

    def on_deleted(self, event):
        """Record deletion events without attempting to scan a missing file."""
        if not event.is_directory:
            self.logger.info("File deleted from monitored folder: %s", event.src_path)
