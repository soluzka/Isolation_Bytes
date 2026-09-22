import os
import logging
import threading
import shutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class FolderWatcher:
    def __init__(self, directories=None):
        self.running = False
        self.observer = None
        self.event_handler = None
        self.monitored_directories = directories or []
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
        """Start monitoring folders."""
        if not self.running:
            self.running = True
            self.event_handler = FileSystemEventHandler()
            self.observer = Observer()

            self.monitored_directories = self.load_scan_directories()

            for directory in self.monitored_directories:
                try:
                    self.observer.schedule(self.event_handler, directory, recursive=True)
                    self.logger.info(f"Monitoring directory: {directory}")
                except Exception as e:
                    self.logger.error(f"Error monitoring directory {directory}: {str(e)}")

            self.observer.start()
            self.logger.info("Folder monitoring started")

    def is_running(self):
        """Check if folder monitoring is active."""
        return self.running

    def stop(self):
        """Stop monitoring folders."""
        if self.running:
            self.running = False
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.logger.info("Folder monitoring stopped")

    def load_scan_directories(self):
        """Load directories to monitor."""
        directories = []
        try:
            home_dir = os.path.expanduser("~")
            common_dirs = [
                os.path.join(home_dir, "Downloads"),
                os.path.join(home_dir, "Desktop"),
                os.path.join(home_dir, "Documents")
            ]

            for dir_path in common_dirs:
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    directories.append(dir_path)
                    self.logger.info(f"Added monitoring directory: {dir_path}")
        except Exception as e:
            self.logger.error(f"Error loading directories: {str(e)}")

        return directories

    def _is_system_path(self, path):
        """Skip core Windows system directories, unless the file is under 200MB."""
        from security.detector import _large_system_file
        return _large_system_file(path)

    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            file_path = event.src_path
            try:
                if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                    return
                if self._is_system_path(file_path):
                    return

                self.logger.info(f"New file detected: {file_path}")

                # Use the unified hardened scanner for both detection and
                # containment.  The legacy watcher used to quarantine on any
                # single YARA or ML hit, which made legitimate packed files
                # such as UPX executables vulnerable to false-positive deletion.
                from security.hardened_scan_pipeline import scan_file

                result = scan_file(file_path, quarantine=True)

                if result.get("quarantine_verified"):
                    self.logger.warning(
                        "File quarantined after corroborated detection: %s "
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
                        "File flagged for review/corroboration, not deleted: %s "
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
                        "File created and scanned without containment: %s "
                        "(status=%s, threat=%s %.1f)",
                        file_path,
                        result.get("status"),
                        result.get("threat_level"),
                        float(result.get("threat_score", 0.0)),
                    )

            except Exception as e:
                self.logger.error(f"Error processing new file {file_path}: {str(e)}")

    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            file_path = event.src_path
            try:
                if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                    return
                if self._is_system_path(file_path):
                    return
                self.logger.info(f"File modified: {file_path}")
                # TODO: Add file scanning logic here
            except Exception as e:
                self.logger.error(f"Error processing modified file {file_path}: {str(e)}")

    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            file_path = event.src_path
            self.logger.info(f"File deleted: {file_path}")
