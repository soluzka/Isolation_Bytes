import os
import logging
import threading
import subprocess
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from utils.paths import get_resource_path
from scan_utils import scan_file_for_viruses
from quarantine_utils import quarantine_file
import tempfile
import shutil
import rarfile
from hash_verify import HashVerifier
from ml_security import SecurityMLModel
from network_monitor import BLACKLISTED_IPS, is_blacklisted, analyze_connection_pattern
from datetime import datetime

# Ensure scan_directories.txt exists at startup
def ensure_file_exists(filename, default_content=None):
    full_path = get_resource_path(filename)
    if not os.path.exists(full_path):
        with open(full_path, 'w') as f:
            if default_content is not None:
                f.write(default_content)

ensure_file_exists(
    'scan_directories.txt',
    '# List each directory to scan, one per line.\n# Example:\nC:\\Users\\USER\\Downloads\nC:\\Users\\USER\\Desktop\n'
)

def load_scan_directories(config_path="scan_directories.txt"):
    """
    Load directories to scan from config file and auto-discover important folders.
    Works with any format hard drive by discovering all mounted drives.
    """
    scan_dirs = []
    
    # First, discover all drives and important folders
    discovered_folders = discover_all_drives_and_important_folders()
    scan_dirs.extend(discovered_folders)
    
    # Then add custom directories from config file
    config_full_path = get_resource_path(config_path)
    if os.path.exists(config_full_path):
        with open(config_full_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Expand user paths and environment variables
                    expanded_path = os.path.expanduser(os.path.expandvars(line))
                    if os.path.exists(expanded_path) and os.path.isdir(expanded_path) and expanded_path not in scan_dirs:
                        scan_dirs.append(expanded_path)
                        logging.info(f"Added custom directory from config: {expanded_path}")
    
    # Remove duplicates while preserving order
    unique_scan_dirs = []
    for directory in scan_dirs:
        if directory not in unique_scan_dirs:
            unique_scan_dirs.append(directory)
    
    if not unique_scan_dirs:
        logging.warning("No directories found to monitor!")
    else:
        logging.info(f"Total directories to monitor: {len(unique_scan_dirs)}")
    
    return unique_scan_dirs

def discover_all_drives_and_important_folders():
    """
    Discover all mounted drives and their important folders to monitor.
    Works across different drive formats (NTFS, FAT32, exFAT, etc.)
    """
    import platform
    import string
    from pathlib import Path
    
    discovered_folders = []
    system = platform.system()
    
    # Get user home directory
    user_home = str(Path.home())
    
    # Add common user folders
    user_folders = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Documents"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Pictures"),
        os.path.join(user_home, "Videos")
    ]
    
    # Add existing user folders
    for folder in user_folders:
        if os.path.exists(folder) and os.path.isdir(folder):
            discovered_folders.append(folder)
            logging.info(f"Added user folder: {folder}")
    
    # Platform-specific drive discovery
    if system == "Windows":
        # Get all available drives on Windows
        available_drives = []
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\" 
            if os.path.exists(drive_path):
                available_drives.append(drive_path)
                
        # For each drive, add important folders
        for drive in available_drives:
            # Add root of each drive
            discovered_folders.append(drive)
            logging.info(f"Added drive root: {drive}")
            
            # Add Recycle Bin for each drive
            recycle_bin = os.path.join(drive, "$Recycle.Bin")
            if os.path.exists(recycle_bin):
                discovered_folders.append(recycle_bin)
                logging.info(f"Added Recycle Bin: {recycle_bin}")
            
            # Add Program Files if it exists on this drive
            program_files = os.path.join(drive, "Program Files")
            if os.path.exists(program_files):
                discovered_folders.append(program_files)
                logging.info(f"Added Program Files: {program_files}")
            
            # Add Program Files (x86) if it exists on this drive
            program_files_x86 = os.path.join(drive, "Program Files (x86)")
            if os.path.exists(program_files_x86):
                discovered_folders.append(program_files_x86)
                logging.info(f"Added Program Files (x86): {program_files_x86}")
            
            # Add Users folder if it exists on this drive
            users_folder = os.path.join(drive, "Users")
            if os.path.exists(users_folder):
                discovered_folders.append(users_folder)
                logging.info(f"Added Users folder: {users_folder}")
                
            # Add Downloads folder for external drives
            downloads_folder = os.path.join(drive, "Downloads")
            if os.path.exists(downloads_folder) and os.path.isdir(downloads_folder):
                discovered_folders.append(downloads_folder)
                logging.info(f"Added Downloads folder on external drive: {downloads_folder}")
    
    elif system == "Darwin":  # macOS
        # Add standard macOS locations
        mac_locations = [
            "/Applications",
            "/Users",
            "/Library",
            "/Volumes"  # This will include all mounted drives
        ]
        
        for location in mac_locations:
            if os.path.exists(location):
                discovered_folders.append(location)
                logging.info(f"Added macOS location: {location}")
                
        # Add all mounted volumes
        volumes_dir = "/Volumes"
        if os.path.exists(volumes_dir):
            for volume in os.listdir(volumes_dir):
                volume_path = os.path.join(volumes_dir, volume)
                if os.path.isdir(volume_path) and volume_path not in discovered_folders:
                    discovered_folders.append(volume_path)
                    logging.info(f"Added mounted volume: {volume_path}")
    
    elif system == "Linux":
        # Add standard Linux locations
        linux_locations = [
            "/home",
            "/opt",
            "/usr/local/bin",
            "/tmp",
            "/media",  # Mounted drives on many distros
            "/mnt"     # Manually mounted drives ]
        ]
        for location in linux_locations:
            if os.path.exists(location):
                discovered_folders.append(location)
                logging.info(f"Added Linux location: {location}")
                
        # Add all mounted media
        media_dir = "/media"
        if os.path.exists(media_dir):
            for user_dir in os.listdir(media_dir):
                user_media_path = os.path.join(media_dir, user_dir)
                if os.path.isdir(user_media_path):
                    for drive in os.listdir(user_media_path):
                        drive_path = os.path.join(user_media_path, drive)
                        if os.path.isdir(drive_path):
                            discovered_folders.append(drive_path)
                            logging.info(f"Added mounted media: {drive_path}")
                            
    return discovered_folders
    
def build_monitored_folders():
    scan_dirs = load_scan_directories()
    seen = set()
    monitored = []
    for folder in scan_dirs:
        if (
            isinstance(folder, str)
            and folder.strip() != ''
            and folder not in seen
            and os.path.isdir(folder)
        ):
            monitored.append(folder)
            seen.add(folder)
    return monitored

MONITORED_FOLDERS = build_monitored_folders()

def scan_and_quarantine(filepath, timeout=600, max_file_size=100 * 1024 * 1024):
    """
    Scan the given file for viruses and quarantine if necessary.
    Handles .rar files by extracting and scanning their contents with Windows Defender.
    Skips the scan if it times out or if the file size exceeds the max_file_size.

    Args:
        filepath (str): Path to the file to be scanned.
        timeout (int): Timeout for the Windows Defender scan in seconds.
        max_file_size (int): Maximum file size in bytes to scan. Default is 100 MB.
    """
    try:
        # Check if the file size exceeds the maximum allowed size
        if os.path.getsize(filepath) > max_file_size:
            # Use debug level logging to avoid filling logs with large file warnings
            logging.debug(f"File {filepath} is too large to scan. Silently skipping.")
            return

        # Check if the file is a .rar file
        if filepath.endswith('.rar'):
            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    with rarfile.RarFile(filepath) as rf:
                        rf.extractall(temp_dir)
                    # Scan extracted files
                    for root, _, files in os.walk(temp_dir):
                        for filename in files:
                            extracted_filepath = os.path.join(root, filename)
                            scan_and_quarantine(extracted_filepath, timeout, max_file_size)
                except rarfile.Error as e:
                    logging.error(f"Failed to extract .rar file {filepath}: {e}")
        else:
            # Scan the file for viruses using scan_file_for_viruses
            virus_found = scan_file_for_viruses(filepath)
            if virus_found:
                logging.warning(f"Virus found in file: {filepath}")
                # Quarantine the file
                quarantine_file(filepath)

            # Scan the file using Windows Defender
            try:
                subprocess.run(
                    ['powershell', '-Command', f"Start-MpScan -ScanPath '{filepath}' -ScanType CustomScan"],
                    timeout=timeout,
                    check=True
                )
            except subprocess.TimeoutExpired:
                logging.warning(f"Windows Defender scan timed out for {filepath}. Skipping scan.")
            except Exception as e:
                logging.error(f"Failed to scan file with Windows Defender {filepath}: {e}")

    except Exception as e:
        logging.error(f"Failed to scan and quarantine file {filepath}: {e}")

def scan_file_with_yara(filepath):
    """
    Scan the given file using YARA rules from the security module.
    Returns True if suspicious (has matches), False otherwise.
    """
    try:
        # Import the function from the security module
        from security.yara_scanner import scan_file_with_yara as security_scan_file_with_yara
        
        # Use the security module version to do the scan - it returns a list of matches
        yara_matches = security_scan_file_with_yara(filepath)
        
        # Check if any matches were found (non-empty list means suspicious)
        if yara_matches and len(yara_matches) > 0:
            # Logging is already done in the security module
            return True
        return False
    except Exception as e:
        logging.error(f"Error handling suspicious file {filepath}: {str(e)}")
        return False

def get_scan_allowed():
    """
    Determine whether scanning is allowed based on certain conditions or configurations.
    """
    # For example, you might check a configuration file, environment variable, or other condition
    # Here, we'll just return True to allow scanning for simplicity
    return True

def scan_all_monitored_directories():
    """
    Scan all files in all monitored directories using scan_for_viruses and YARA.
    For each monitored directory, scan all subfolders (recursively) first, then scan files in the root of the monitored directory.
    """
    if not get_scan_allowed():
        logging.error("Scan is not allowed. Aborting scan_all_monitored_directories.")
        return

    monitored_folders = MONITORED_FOLDERS
    import time
    for folder in monitored_folders:
        if os.path.isdir(folder):
            # Scan all subfolders first (recursively)
            for entry in os.scandir(folder):
                if entry.is_dir():
                    for root, _, files in os.walk(entry.path):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            try:
                                scan_and_quarantine(filepath)
                                if scan_file_with_yara(filepath):
                                    logging.warning(f"YARA match: {filepath}")
                            except Exception as e:
                                logging.error(f"Error scanning {filepath}: {e}")
                            time.sleep(0.05)  # Throttle
            # Then scan files in the root of the monitored directory
            for entry in os.scandir(folder):
                if entry.is_file():
                    try:
                        scan_and_quarantine(entry.path)
                        if scan_file_with_yara(entry.path):
                            logging.warning(f"YARA match: {entry.path}")
                    except Exception as e:
                        logging.error(f"Error scanning {entry.path}: {e}")
                    time.sleep(0.05)  # Throttle
        else:
            logging.warning(f"Target folder does not exist: {folder}")

class CustomEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.quarantine_dir = os.path.join(get_resource_path('quarantine'))
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.hash_verifier = HashVerifier()
        self.ml_model = SecurityMLModel()
        self.suspicious_files = set()
        self.trusted_hashes = self._load_trusted_hashes()
        self.signature_db = self._load_signature_database()
        self.last_signature_update = datetime.now()
        self.network_monitor = NetworkMonitor()
        self.last_network_analysis = datetime.now()
        self.network_risk_score = 0.0
        
    def _load_trusted_hashes(self):
        """Load trusted file hashes from configuration."""
        trusted_hashes = {}
        try:
            with open(get_resource_path('trusted_hashes.json'), 'r') as f:
                trusted_hashes = json.load(f)
        except Exception as e:
            logging.warning(f"No trusted hashes file found: {e}")
            return {}
        return trusted_hashes
        
    def _load_signature_database(self):
        """Load malware signatures database."""
        signatures = {}
        try:
            with open(get_resource_path('malware_signatures.json'), 'r') as f:
                signatures = json.load(f)
        except Exception as e:
            logging.warning(f"No malware signatures file found: {e}")
            return {}
        return signatures
        
    def _update_signatures(self):
        """Update malware signatures database."""
        try:
            # Get suspicious files from ML analysis
            suspicious_files = list(self.suspicious_files)
            
            # Extract features from suspicious files
            
            # Generate new signatures based on combined file and network patterns
            combined_context = {
                **network_context,
                **network_patterns
            }
            
            new_signatures = self._generate_signatures(combined_context)
            
            # Update signature database
            self.signature_db.update(new_signatures)
            self._save_signature_database()
            self.last_signature_update = datetime.now()
            
            logging.info("Successfully updated malware signatures with network context")
        except Exception as e:
            logging.error(f"Error updating signatures: {str(e)}")
            
    def _extract_features(self, data):
        """Extract features from file data for ML analysis."""
        features = {
            'entropy': self._calculate_entropy(data),
            'byte_frequency': self._calculate_byte_frequency(data),
            'hex_pattern': self._extract_hex_patterns(data),
            'file_size': len(data)
        }
        return features
        
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of the data."""
        if not data:
            return 0
            
        occurrences = np.bincount(np.frombuffer(data, dtype=np.uint8))
        probabilities = occurrences / len(data)
        probabilities = probabilities[probabilities != 0]
        return -np.sum(probabilities * np.log2(probabilities))
        
    def _calculate_byte_frequency(self, data):
        """Calculate frequency of each byte in the data."""
        if not data:
            return np.zeros(256)
            
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        return counts / len(data)
        
    def _extract_hex_patterns(self, data):
        """Extract hex patterns from the data."""
        hex_data = data.hex()
        patterns = {}
        
        # Extract 4-byte patterns
        for i in range(0, len(hex_data) - 7, 2):
            pattern = hex_data[i:i+8]
            patterns[pattern] = patterns.get(pattern, 0) + 1
            
        return patterns
        
    def _generate_signatures(self, features):
        """Generate new malware signatures from features."""
        signatures = {}
        for i, feature in enumerate(features):
            signature = {
                'entropy_threshold': feature['entropy'] * 0.9,
                'byte_patterns': self._extract_significant_patterns(feature['hex_pattern'])
            }
            signatures[f"sig_{datetime.now().timestamp()}_{i}"] = signature
        return signatures
        
    def _extract_significant_patterns(self, patterns):
        """Extract significant patterns from hex patterns."""
        # Keep patterns that appear more than 3 times
        return {k: v for k, v in patterns.items() if v > 3}
        
    def _save_signature_database(self):
        """Save updated signature database."""
        try:
            with open(get_resource_path('malware_signatures.json'), 'w') as f:
                json.dump(self.signature_db, f, indent=4)
            logging.info("Signature database updated successfully")
        except Exception as e:
            logging.error(f"Error saving signature database: {e}")
            
    def _verify_file_hash(self, file_path):
        """Verify file hash and check against trusted hashes."""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
            # Calculate hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Check against trusted hashes
            if file_path in self.trusted_hashes:
                expected_hash = self.trusted_hashes[file_path]
                if self.hash_verifier.verify_hash(file_data, expected_hash):
                    logging.info(f"File verified: {file_path}")
                    return True
            
            # Analyze with ML
            features = self._extract_features(file_data)
            prediction = self.ml_model.pipeline.predict([features])[0]
            
            if prediction == -1:  # -1 indicates anomaly
                # Check against malware signatures
                hex_data = file_data.hex()
                for sig_id, signature in self.signature_db.items():
                    if self._matches_signature(hex_data, signature):
                        logging.warning(f"File matches malware signature {sig_id}: {file_path}")
                        self.suspicious_files.add(file_path)
                        return False
                
                # If no signature match but ML detected anomaly
                logging.warning(f"Suspicious file detected (ML): {file_path}")
                self.suspicious_files.add(file_path)
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Error verifying file {file_path}: {e}")
            return False
            
    def _matches_signature(self, hex_data, signature):
        """Check if file matches a malware signature."""
        # Check entropy threshold
        if self._calculate_entropy(bytes.fromhex(hex_data)) > signature['entropy_threshold']:
            # Check byte patterns
            for pattern in signature['byte_patterns']:
                if pattern in hex_data:
                    return True
        return False
            
    def _check_network_context(self, file_path):
        """Check network context for potential threats."""
        try:
            # Check if file contains network-related data
            with open(file_path, 'rb') as f:
                data = f.read()
                hex_data = data.hex()
                
                # Check for suspicious network patterns
                if any(ip in hex_data for ip in BLACKLISTED_IPS):
                    logging.warning(f"File contains blacklisted IP addresses: {file_path}")
                    return True
                    
                # Check for DNS requests to suspicious domains
                if b'dns' in data.lower():
                    domains = self._extract_domains(data)
                    for domain in domains:
                        if is_blacklisted(domain):
                            logging.warning(f"File contains blacklisted domain: {domain}")
                            return True
                            
            # Update network risk score based on current network activity
            self._update_network_context()
            return False
        except Exception as e:
            logging.error(f"Error checking network context for {file_path}: {str(e)}")
            return False

    def _extract_domains(self, data):
        """Extract potential domain names from binary data."""
        try:
            # Look for sequences that could be domain names
            domains = []
            parts = data.split(b'.')
            for i in range(len(parts) - 2):
                # Check for common TLDs
                if any(parts[i+2].lower().startswith(tld) 
                      for tld in [b'com', b'net', b'org', b'info']):
                    domain = b'.'.join(parts[i:i+3])
                    domains.append(domain.decode('utf-8', errors='ignore'))
            return domains
        except Exception as e:
            logging.error(f"Error extracting domains: {str(e)}")
            return []

    def _update_network_context(self):
        """Update network context and risk score."""
        try:
            # Get current network connections
            connections = self.network_monitor.get_active_connections()
            
            # Analyze connection patterns
            risk_factors = analyze_connection_pattern(connections)
            
            # Update risk score based on network activity
            self.network_risk_score = self._calculate_risk_score(risk_factors)
            
            # Log high risk events
            if self.network_risk_score > 0.7:
                logging.warning(f"High network risk detected: {self.network_risk_score}")
                
            # Update last analysis time
            self.last_network_analysis = datetime.now()
            
        except Exception as e:
            logging.error(f"Error updating network context: {str(e)}")

    def _calculate_risk_score(self, risk_factors):
        """Calculate overall network risk score."""
        try:
            # Base score starts at 0.0 (no risk)
            score = 0.0
            
            # Weighted risk factors
            weights = {
                'suspicious_connections': 0.4,
                'anomalous_patterns': 0.3,
                'high_bandwidth': 0.2,
                'unusual_ports': 0.1
            }
            
            # Calculate weighted sum of risk factors
            for factor, weight in weights.items():
                if factor in risk_factors:
                    score += risk_factors[factor] * weight
            
            # Normalize score to 0-1 range
            return min(1.0, max(0.0, score))
            
        except Exception as e:
            logging.error(f"Error calculating risk score: {str(e)}")
            return 0.0
    
    def _quarantine_file(self, file_path):
        """Quarantine a suspicious file by moving it to the quarantine directory.
        Uses the quarantine_file function from quarantine_utils.py."""
        try:
            # Import at function level to avoid circular imports
            from quarantine_utils import quarantine_file
            
            # Log the quarantine attempt
            logging.warning(f"Quarantining suspicious file: {file_path}")
            
            # Call the quarantine_file function from quarantine_utils.py
            quarantine_file(file_path)
            
            # Log success
            logging.info(f"Successfully quarantined file: {file_path}")
            
        except Exception as e:
            logging.error(f"Error quarantining file: {str(e)}")
            try:
                # Fallback: try to delete the file if quarantine fails
                os.remove(file_path)
                logging.warning(f"Quarantine failed, but file was deleted: {file_path}")
            except Exception as del_e:
                logging.error(f"Failed to delete file after quarantine failure: {str(del_e)}")

    def _process_file(self, file_path):
        """Process a new or modified file with network context."""
        try:
            # Skip if file is too large
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB
                logging.info(f"Skipping scan of large file: {file_path}")
                return

            # Check network context first
            if self._check_network_context(file_path):
                logging.warning(f"Network context indicates potential threat in: {file_path}")
                self._quarantine_file(file_path)
                return

            # Verify file hash
            if not self._verify_file_hash(file_path):
                logging.warning(f"File hash verification failed for: {file_path}")
                self._quarantine_file(file_path)
                return

            # Scan with YARA
            if scan_file_with_yara(file_path):
                logging.warning(f"YARA scan detected potential malware in: {file_path}")
                self._quarantine_file(file_path)
                return

            # Perform ML-based analysis
            with open(file_path, 'rb') as f:
                file_data = f.read()
                features = self._extract_features(file_data)
                
                # Combine network risk score with file analysis
                combined_features = features + [self.network_risk_score]
                if self.ml_model.predict(combined_features) > 0.5:
                    logging.warning(f"ML model detected suspicious file: {file_path}")
                    self._quarantine_file(file_path)
                    return

            # Windows Defender scan
            try:
                subprocess.run(
                    ['powershell', '-Command', f"Start-MpScan -ScanPath '{file_path}' -ScanType CustomScan"],
                    timeout=60,
                    check=True
                )
            except subprocess.TimeoutExpired:
                logging.warning(f"Windows Defender scan timed out for {file_path}")
            except Exception as e:
                logging.error(f"Windows Defender scan failed for {file_path}: {e}")

            logging.info(f"File processed successfully: {file_path}")
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {str(e)}")
            return

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self._process_event(file_path, "created")
            
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self._process_event(file_path, "modified")

    def _process_event(self, file_path, event_type):
        """Process a file event with multiple scanning layers."""
        try:
            # Skip system files and directories
            if any(part in file_path.lower() for part in ['\\windows\\', '\\system32\\']):
                return

            # Verify file hash
            if not self._verify_file_hash(file_path):
                return

            # Read file data
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except (IOError, OSError) as e:
                logging.error(f"Error reading file {file_path}: {str(e)}")
                return

            # YARA scan first
            if scan_file_with_yara(file_path):
                logging.warning(f"YARA match detected in {file_path}")
                self._quarantine_file(file_path)
                return

            # ML analysis
            features = self._extract_features(file_data)
            if self.ml_model.predict(features):
                logging.warning(f"ML model flagged {file_path} as suspicious")
                self._quarantine_file(file_path)
                return

            # Signature check
            if self._matches_signature(file_data.hex(), self.signature_db):
                logging.warning(f"Signature match detected in {file_path}")
                self._quarantine_file(file_path)
                return

            # Windows Defender scan
            try:
                subprocess.run(
                    ['powershell', '-Command', f"Start-MpScan -ScanPath '{file_path}' -ScanType CustomScan"],
                    timeout=60,
                    check=True
                )
            except subprocess.TimeoutExpired:
                logging.warning(f"Windows Defender scan timed out for {file_path}")
            except Exception as e:
                logging.error(f"Windows Defender scan failed for {file_path}: {e}")

        except Exception as e:
            logging.error(f"Error processing {event_type} event for {file_path}: {str(e)}")

# Update the observer setup in start_monitoring
def start_monitoring():
    """Start monitoring the directories for file system events."""
    event_handler = CustomEventHandler()
    observer = Observer()
    for folder in MONITORED_FOLDERS:
        observer.schedule(event_handler, folder, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    if scan_file_with_yara(event.src_path):
        logging.warning(f"YARA match: {event.src_path}")

def start_monitoring():
    """
    Start monitoring the directories for file system events.
    """
    event_handler = CustomEventHandler()
    observer = Observer()
    for folder in MONITORED_FOLDERS:
        observer.schedule(event_handler, folder, recursive=True)
    observer.start()
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Example usage
if __name__ == "__main__":
    start_monitoring()
