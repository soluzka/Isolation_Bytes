import base64
import os
import json
import logging
import threading
import subprocess
import shutil
import platform
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

POWERSHELL_PATH = shutil.which('powershell') or 'powershell'

# --- Windows subprocess window suppression ---
import sys as _sys
if _sys.platform == 'win32':
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
else:
    DETACHED_PROCESS = 0
    CREATE_NO_WINDOW = 0

def windows_defender_scan(filepath, timeout=60):
    """Run Windows Defender scan on a file. Only works on Windows with Defender installed."""
    if platform.system() != "Windows":
        return  # No Windows Defender on macOS/Linux
    try:
        filepath = os.path.abspath(filepath)
        if not os.path.isfile(filepath):
            return
        # Escape single quotes inside a PowerShell single-quoted string and run
        # via -EncodedCommand so the variable never appears in the command line.
        safe_path = filepath.replace("'", "''")
        ps_script = f"Start-MpScan -ScanPath '{safe_path}' -ScanType CustomScan"
        encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
        subprocess.run(  # nosec B603
            [POWERSHELL_PATH, '-EncodedCommand', encoded],
            timeout=timeout,
            check=True,
            capture_output=True,
            creationflags=CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        logging.warning(f"Windows Defender scan timed out for {filepath}")
    except Exception as e:
        logging.error(f"Windows Defender scan failed for {filepath}: {e}")

def clamav_scan(filepath, timeout=60):
    """Run ClamAV scan on a file. Works on macOS, Linux, and ChromeOS."""
    if platform.system() == "Windows":
        return  # Use Windows Defender on Windows
    clamscan = shutil.which('clamscan') or shutil.which('clamdscan')
    if not clamscan:
        return  # ClamAV not installed — skip silently
    try:
        if clamscan.endswith('clamdscan'):
            subprocess.run([clamscan, filepath], timeout=timeout, check=False,
                          capture_output=True)
        else:
            subprocess.run([clamscan, '--no-summary', filepath], timeout=timeout,
                          check=False, capture_output=True)
        logging.info(f"ClamAV scan completed for: {filepath}")
    except subprocess.TimeoutExpired:
        logging.warning(f"ClamAV scan timed out for {filepath}")
    except Exception as e:
        logging.error(f"ClamAV scan failed for {filepath}: {e}")

def system_antivirus_scan(filepath, timeout=60):
    """Run the appropriate system antivirus scanner based on platform.
    Windows: Windows Defender (Start-MpScan)
    macOS: ClamAV (if installed) — macOS has XProtect built-in
    Linux/ChromeOS: ClamAV (if installed)
    All platforms: YARA + ML + signature scanning (handled separately)
    """
    import platform as pf
    system = pf.system()
    if system == "Windows":
        windows_defender_scan(filepath, timeout)
    else:
        clamav_scan(filepath, timeout)
from network_monitor import BLACKLISTED_IPS, is_blacklisted, analyze_connection_pattern, NetworkMonitor
from datetime import datetime

# Base directory for writable runtime state.
RUNTIME_DIR = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))

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

def load_scan_directories(config_path="scan_directories.txt", auto_discover=True):
    """
    Load directories to scan from config file and optionally auto-discover
    important folders. Works with any format hard drive by discovering all
    mounted drives when auto_discover is True.
    """
    scan_dirs = []

    if auto_discover:
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
    Discover ALL folders to monitor on every system universally.
    Watches every drive, every mount point, and every user folder.
    Works across Windows, macOS, Linux, and ChromeOS (Crostini).
    """
    import platform
    import string
    from pathlib import Path

    discovered_folders = []
    system = platform.system()

    # Directories to skip (virtual/special filesystems that would cause issues)
    SKIP_DIRS = {
        # Linux virtual filesystems
        '/proc', '/sys', '/dev', '/run', '/snap', '/var/snap',
        '/var/lib/docker', '/var/lib/containers',
        # Windows system directories that cause lock issues
        'c:\\windows\\system32\\config', 'c:\\windows\\system32\\winevt',
        'c:\\$recycle.bin\\s-1-5-18',  # System recycle bin
    }

    def should_skip(path):
        """Check if a path should be skipped."""
        path_lower = path.lower().replace('/', '\\')
        for skip in SKIP_DIRS:
            skip_lower = skip.lower().replace('/', '\\')
            if path_lower.startswith(skip_lower):
                return True
        return False

    def add_folder(path):
        """Add a folder if it exists, is a directory, and isn't skipped."""
        if path and os.path.exists(path) and os.path.isdir(path) and not should_skip(path):
            if path not in discovered_folders:
                discovered_folders.append(path)
                logging.info(f"Monitoring: {path}")

    # Get user home directory
    user_home = str(Path.home())

    # Add all common user folders
    user_folders = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Documents"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Pictures"),
        os.path.join(user_home, "Videos"),
        os.path.join(user_home, "Music"),
        os.path.join(user_home, "Movies"),
        os.path.join(user_home, "AppData"),
        os.path.join(user_home, "AppData", "Local"),
        os.path.join(user_home, "AppData", "Roaming"),
        os.path.join(user_home, "AppData", "Local", "Temp"),
        os.path.join(user_home, "Library"),
        os.path.join(user_home, "Library", "Application Support"),
        os.path.join(user_home, "Library", "Caches"),
        os.path.join(user_home, ".config"),
        os.path.join(user_home, ".cache"),
        os.path.join(user_home, ".local", "share"),
    ]
    for folder in user_folders:
        add_folder(folder)

    # Platform-specific universal discovery
    if system == "Windows":
        # Get ALL available drives on Windows (A-Z)
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                # Add the entire drive root — recursive=True watches everything
                add_folder(drive_path)

                # Also explicitly add key folders for logging clarity
                for subfolder in ["$Recycle.Bin", "Program Files", "Program Files (x86)",
                                  "ProgramData", "Users", "Windows", "Windows\\System32",
                                  "Windows\\Temp", "Temp", "Downloads", "Documents"]:
                    add_folder(os.path.join(drive_path, subfolder))

    elif system == "Darwin":  # macOS
        # Add root and all top-level directories
        add_folder("/")
        for entry in os.scandir("/"):
            if entry.is_dir() and not should_skip(entry.path):
                add_folder(entry.path)

        # Add all mounted volumes (external drives, USB, network mounts)
        volumes_dir = "/Volumes"
        if os.path.exists(volumes_dir):
            for volume in os.listdir(volumes_dir):
                volume_path = os.path.join(volumes_dir, volume)
                add_folder(volume_path)
                # Also scan subdirectories of each volume
                try:
                    for entry in os.scandir(volume_path):
                        if entry.is_dir() and not should_skip(entry.path):
                            add_folder(entry.path)
                except (PermissionError, OSError):
                    pass

        # Add all user home directories
        users_dir = "/Users"
        if os.path.exists(users_dir):
            for user_dir in os.listdir(users_dir):
                user_path = os.path.join(users_dir, user_dir)
                if os.path.isdir(user_path) and user_dir not in ('Shared', '.'):
                    add_folder(user_path)
                    # Add all subfolders of each user
                    for subfolder in ["Downloads", "Documents", "Desktop", "Pictures",
                                      "Videos", "Movies", "Music", "Library"]:
                        add_folder(os.path.join(user_path, subfolder))

    elif system == "Linux":
        # Add root — recursive=True will watch everything
        add_folder("/")

        # Add all top-level directories explicitly
        for entry in os.scandir("/"):
            if entry.is_dir() and not should_skip(entry.path):
                add_folder(entry.path)

        # Add all user home directories
        home_dir = "/home"
        if os.path.exists(home_dir):
            for user_dir in os.listdir(home_dir):
                user_path = os.path.join(home_dir, user_dir)
                if os.path.isdir(user_path):
                    add_folder(user_path)
                    for subfolder in ["Downloads", "Documents", "Desktop", "Pictures",
                                      "Videos", "Music", ".config", ".cache",
                                      ".local", ".local/share"]:
                        add_folder(os.path.join(user_path, subfolder))

        # Add all mounted media and drives
        for mount_dir in ["/media", "/mnt", "/run/media"]:
            if os.path.exists(mount_dir):
                try:
                    for user_dir in os.listdir(mount_dir):
                        user_media_path = os.path.join(mount_dir, user_dir)
                        if os.path.isdir(user_media_path):
                            add_folder(user_media_path)
                            # Scan subdirectories (actual mount points)
                            try:
                                for drive in os.listdir(user_media_path):
                                    drive_path = os.path.join(user_media_path, drive)
                                    if os.path.isdir(drive_path):
                                        add_folder(drive_path)
                            except (PermissionError, OSError):
                                pass
                except (PermissionError, OSError):
                    pass

        # Add all mount points from /proc/mounts
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        mount_point = parts[1]
                        if not should_skip(mount_point):
                            add_folder(mount_point)
        except Exception:
            pass

        # ChromeOS Crostini: also check /mnt/chromeos
        add_folder("/mnt/chromeos")

    # Also scan all other users' home directories (universal)
    if system == "Windows":
        users_folder = os.path.join(os.environ.get('SystemDrive', 'C:'), 'Users')
        if os.path.exists(users_folder):
            for user_dir in os.listdir(users_folder):
                user_path = os.path.join(users_folder, user_dir)
                if os.path.isdir(user_path) and user_dir.lower() not in ('public', 'default', 'all users'):
                    add_folder(user_path)
                    for subfolder in ["Downloads", "Documents", "Desktop", "Pictures",
                                      "Videos", "Music", "AppData", "AppData\\Local",
                                      "AppData\\Roaming", "AppData\\Local\\Temp"]:
                        add_folder(os.path.join(user_path, subfolder))

    logging.info(f"Total folders discovered for monitoring: {len(discovered_folders)}")
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
            _, virus_found, _ = scan_file_for_viruses(filepath)
            if virus_found:
                logging.warning(f"Virus found in file: {filepath}")
                # Quarantine the file
                quarantine_file(filepath)

            # System antivirus scan (Windows Defender on Windows, ClamAV on macOS/Linux)
            system_antivirus_scan(filepath, timeout=timeout)

    except Exception as e:
        logging.error(f"Failed to scan and quarantine file {filepath}: {e}")

def scan_file_with_yara(filepath):
    """
    Scan the given file using YARA rules from the security module.
    Returns True only if a high or critical severity match is found.
    Low/medium matches are logged but do NOT trigger quarantine, since
    treating every YARA match as a threat caused widespread false positives
    on legitimate files.
    """
    try:
        # Import the function from the security module
        from security.yara_scanner import (
            scan_file_with_yara as security_scan_file_with_yara,
            get_highest_severity,
            _rank_of,
        )

        # Use the security module version to do the scan - it returns a list of matches
        yara_matches = security_scan_file_with_yara(filepath)

        # Check if any matches were found (non-empty list means suspicious)
        if yara_matches and len(yara_matches) > 0:
            highest = get_highest_severity(yara_matches)
            # Only high/critical matches should trigger quarantine from the
            # folder watcher.  Medium/low matches are logged by the scanner
            # already and left for user review.
            if _rank_of(highest) >= _rank_of('high'):
                return True
            else:
                logging.info(f"YARA low/medium match in {filepath} (severity: {highest}) - not quarantining")
                return False
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
    Scan ALL files in ALL monitored directories recursively using scan_for_viruses and YARA.
    Walks every subdirectory of every monitored folder on every system.
    """
    if not get_scan_allowed():
        logging.error("Scan is not allowed. Aborting scan_all_monitored_directories.")
        return

    monitored_folders = MONITORED_FOLDERS
    import time

    # Directories to skip during recursive walk (virtual/special filesystems)
    SKIP_DIRS = {
        'proc', 'sys', 'dev', 'run', 'snap', 'docker',
        '$recycle.bin\\s-1-5-18', 'system32\\config', 'system32\\winevt',
        'windows\\assembly', 'windows\\winsxs', 'windows\\installer',
        'windows\\servicing', 'windows\\softwaredistribution',
    }

    def should_skip_dir(dirname):
        dirname_lower = dirname.lower()
        for skip in SKIP_DIRS:
            if skip in dirname_lower:
                return True
        return False

    total_scanned = 0
    for folder in monitored_folders:
        if not os.path.isdir(folder):
            logging.warning(f"Target folder does not exist: {folder}")
            continue

        logging.info(f"Starting full recursive scan of: {folder}")
        for root, dirs, files in os.walk(folder):
            # Skip virtual/special directories in-place
            dirs[:] = [d for d in dirs if not should_skip_dir(os.path.join(root, d))]

            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    scan_and_quarantine(filepath)
                    if scan_file_with_yara(filepath):
                        logging.warning(f"YARA match: {filepath}")
                    total_scanned += 1
                except Exception as e:
                    logging.error(f"Error scanning {filepath}: {e}")
                time.sleep(0.01)  # Throttle to avoid CPU overload

        logging.info(f"Completed scan of: {folder}")

    logging.info(f"Full scan complete. Total files scanned: {total_scanned}")

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
            sig_path = os.path.join(RUNTIME_DIR, 'malware_signatures.json')
            with open(sig_path, 'r') as f:
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
            os.makedirs(RUNTIME_DIR, exist_ok=True)
            sig_path = os.path.join(RUNTIME_DIR, 'malware_signatures.json')
            with open(sig_path, 'w') as f:
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

            # Check network context first -- log but do NOT auto-quarantine.
            # The network context check matches very broadly (e.g. any file
            # containing the bytes "dns"), so treating it as a confirmed
            # threat caused widespread false positives.  It is now a signal
            # that feeds into the YARA/ML/signature checks below rather than
            # an automatic quarantine trigger.
            if self._check_network_context(file_path):
                logging.warning(f"Network context indicates potential threat in: {file_path} (flagged for review, not auto-quarantined)")

            # Verify file hash -- log but do NOT auto-quarantine.
            # _verify_file_hash() returns False when the IsolationForest ML
            # model flags the file as anomalous, which is noisy on legitimate
            # files (compressed archives, installers, media, etc.).  Let the
            # YARA and signature checks below make the quarantine decision.
            if not self._verify_file_hash(file_path):
                logging.warning(f"File hash/ML verification flagged for: {file_path} (review only)")

            # Scan with YARA -- only high/critical severity matches trigger
            # quarantine (see scan_file_with_yara above).
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

            # System antivirus scan (Windows Defender on Windows, ClamAV on macOS/Linux)
            system_antivirus_scan(file_path, timeout=60)

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
            # Skip only critical locked system paths, not all of system32
            skip_patterns = [
                '\\windows\\system32\\config\\',
                '\\windows\\system32\\winevt\\',
                '\\windows\\assembly\\',
                '\\windows\\winsxs\\',
                '\\windows\\installer\\',
                '\\windows\\servicing\\',
                '\\windows\\softwaredistribution\\',
                '\\$recycle.bin\\s-1-5-18\\',
            ]
            if any(p in file_path.lower() for p in skip_patterns):
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

            # System antivirus scan (Windows Defender on Windows, ClamAV on macOS/Linux)
            system_antivirus_scan(file_path, timeout=60)

        except Exception as e:
            logging.error(f"Error processing {event_type} event for {file_path}: {str(e)}")

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
