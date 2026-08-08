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
            
            # Load directories to monitor
            self.monitored_directories = self.load_scan_directories()
            
            # Schedule monitoring for each directory
            for directory in self.monitored_directories:
                try:
                    self.observer.schedule(self.event_handler, directory, recursive=True)
                    self.logger.info(f"Monitoring directory: {directory}")
                except Exception as e:
                    self.logger.error(f"Error monitoring directory {directory}: {str(e)}")
            
            # Start the observer
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

    def is_running(self):
        """Check if folder monitoring is running."""
        return self.running

    def load_scan_directories(self):
        """Load directories to monitor."""
        directories = []
        try:
            # Get user's home directory
            home_dir = os.path.expanduser("~")
            
            # Add common directories
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

    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            file_path = event.src_path
            try:
                # Check if file exists and is not empty
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    self.logger.info(f"New file detected: {file_path}")
                    
                    # Perform YARA scan
                    from security.yara_scanner import scan_file_with_yara
                    from security.detector import detector
                    
                    # Check with YARA rules
                    is_suspicious = scan_file_with_yara(file_path)
                    if not is_suspicious:
                        return
                        
                    # Get file details
                    file_size = os.path.getsize(file_path)
                    
                    # Get ML prediction
                    prediction = detector.predict([file_path])
                    anomaly_score = detector.get_anomaly_score(file_path)
                    
                    if prediction[0] == -1:  # If ML predicts malicious
                        self.logger.warning(f"Suspicious file detected: {file_path}")
                        
                        # Create quarantine filename
                        quarantine_filename = os.path.basename(file_path) + '.enc'
                        quarantine_path = os.path.join('quarantine', quarantine_filename)
                        
                        # Encrypt and move file to quarantine
                        key = os.environ.get('FERNET_KEY')
                        if not key:
                            self.logger.error("Encryption key not found")
                            return
                            
                        # Read file content
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                            
                        # Encrypt content
                        from cryptography.fernet import Fernet
                        fernet = Fernet(key)
                        encrypted_content = fernet.encrypt(file_content)
                        
                        # Write to quarantine
                        os.makedirs('quarantine', exist_ok=True)
                        with open(quarantine_path, 'wb') as f:
                            f.write(encrypted_content)
                        
                        # Try to delete original file
                        try:
                            os.remove(file_path)
                        except Exception as e:
                            self.logger.error(f"Could not delete original file: {str(e)}")
                            
                        # Log the action
                        self.logger.info(f"File {file_path} quarantined as suspicious")
                        
            except Exception as e:
                self.logger.error(f"Error processing new file {file_path}: {str(e)}")

    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            file_path = event.src_path
            try:
                # Check if file exists and is not empty
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    self.logger.info(f"File modified: {file_path}")
                    # TODO: Add file scanning logic here
            except Exception as e:
                self.logger.error(f"Error processing modified file {file_path}: {str(e)}")

    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            file_path = event.src_path
            self.logger.info(f"File deleted: {file_path}")
