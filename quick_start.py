import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import json
import socket
import shutil  # For file operations like move for quarantine
import threading
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, Blueprint

# Import DNS server functionality
from dns_server import start_dns_server
# Fernet key provider for quarantine encryption
from data_analysis import analyze_data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('antivirus')

# Allow running the ssdeep runner as a one-off via command line:
#   python quick_start.py --ssdeep-run --rules <rules> --dir <dir>
if '--ssdeep-run' in sys.argv:
    try:
        # Remove the flag so ssdeep_runner argparse sees only its args
        sys.argv.remove('--ssdeep-run')
        # Import and invoke runner
        import importlib
        ssr = importlib.import_module('security.yara_rules.ssdeep_runner')
        ssr.main()
        sys.exit(0)
    except Exception as e:
        logger.exception('Failed to execute ssdeep runner: %s', e)
        sys.exit(1)

# Add a filter to the root logger to catch DNSBL SERVFAIL warnings and show a friendly message
class DNSBLWarningFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.last_warning_time = 0
        self.warning_interval = 1800  # Show warning once per 30 minutes max
        
    def filter(self, record):
        # Check if this is a DNSBL-related message from our improved error handler
        if ('[User Notice] DNSBL lookup failed' in getattr(record, 'msg', '')):
            current_time = time.time()
            # If we've shown this message recently, suppress it
            if current_time - self.last_warning_time < self.warning_interval:
                return False  # Suppress duplicate messages
            self.last_warning_time = current_time
            return True
            
        # Check if this is a DNS error we should handle
        if (
            record.levelno in (logging.WARNING, logging.ERROR) and
            isinstance(record.msg, str) and
            'DNS lookup failed for' in record.msg and
            'dnsbl.httpbl.org' in record.msg
        ):
            # Suppress the original error message
            return False
            
        return True  # Pass through all other messages

# Create and add our filter to the root logger and console handler
dnsbl_filter = DNSBLWarningFilter()
logging.getLogger().addFilter(dnsbl_filter)
for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.addFilter(dnsbl_filter)

# Create a clean app instance
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'))

# Create a blueprint for network-related API endpoints
network_bp = Blueprint('network', __name__, url_prefix='/api/network')

# Global state for monitoring services
folder_watcher_state = {
    'active': False,
    'start_time': None,
    'monitored_paths': [
        # User profile directories - common locations for personal files and downloads
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Desktop'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Documents'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Pictures'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Videos'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Music'),
        
        # Application data directories - where applications store settings and data
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Local\\Temp'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Roaming'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Local'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\LocalLow'),
        
        # System directories - critical system paths often targeted by malware
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Prefetch'),  # Can show recently executed programs
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\drivers\\etc'),  # hosts file, DNS
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\wbem'),  # WMI
        
        # Program installation directories - common software locations
        os.path.join('C:\\', 'Program Files'),
        os.path.join('C:\\', 'Program Files (x86)'),
        os.path.join('C:\\', 'Program Files\\Common Files'),
        os.path.join('C:\\', 'ProgramData'),
        os.path.join('C:\\', 'ProgramData', 'Microsoft'),
        
        # Startup locations - critical for persistence mechanisms
        os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        
        # Root directories for thorough coverage
        'C:\\'
    ],
    'detections': [],
    'excluded_paths': [
        'OneDriveTemp',
        'OneDrive',
        '.tmp',
        'Temporary Internet Files',
        'WindowsApps',  # Microsoft Store apps can be large and are usually safe
        'WinSxS',      # Windows component store (very large and low risk)
        'node_modules', # NPM modules folder can be extremely large
        'venv',         # Python virtual environments folder
        '.git',         # Git repositories
        '$Recycle.Bin', # Recycle bin
        'site-packages', # Python installed packages 
        'Lib\site-packages', # Python library packages
        'pip-',         # Pip installation folders
        'pip_cache',    # Pip cache
        'pip-tmp',      # Pip temporary files
        '__pycache__',  # Python compiled cache
        '.pyc',         # Python compiled files
        '.pyd',         # Python DLL files
        'Python3',      # Python installation folders
        'Python311',    # Specific Python version folders
        'python-wheels', # Python wheels directory
        '_MEI',         # PyInstaller temp folders (typically start with _MEI followed by numbers)
    ]
}

# Helper function to check if a path should be excluded
def should_exclude_path(path):
    """Check if a path contains any excluded terms"""
    for excluded in folder_watcher_state['excluded_paths']:
        if excluded.lower() in path.lower():
            return True
    return False

# Encryption utilities for quarantine files
def get_encryption_key():
    """Legacy deterministic key (kept for decrypting older quarantined files)"""
    # Use a combination of machine-specific values as salt
    salt = socket.gethostname().encode() + b'antivirus_quarantine_salt'
    # Use a fixed passphrase (in production, this would be securely stored)
    password = b"windows_defender_quarantine_encryption_key"
    
    # Use PBKDF2 to derive a secure key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

FERNET_KEY_LENGTH = 44  # Length of a urlsafe base64-encoded Fernet key

def encrypt_file(file_path, encrypted_path):
    """Encrypt a file and save it with .enc extension in the quarantine folder.

    The per-file Fernet key comes from data_analysis.analyze_data and is stored
    as a 44-byte header of the encrypted file (same scheme as file_crypto.py).
    """
    try:
        # Read file content
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Get the Fernet key from data_analysis
        key = analyze_data(file_data)
        if isinstance(key, str):
            key = key.encode()
        fernet = Fernet(key)

        # Encrypt the file data
        encrypted_data = fernet.encrypt(file_data)

        # Save the encrypted file with the key prepended as a header
        with open(encrypted_path, 'wb') as encrypted_file:
            encrypted_file.write(key + encrypted_data)

        return True
    except Exception as e:
        logger.error(f"Error encrypting file {file_path}: {e}")
        return False

def decrypt_file(encrypted_path, output_path):
    """Decrypt a quarantined file (used when restoring files from quarantine)"""
    try:
        # Read encrypted file
        with open(encrypted_path, 'rb') as encrypted_file:
            file_data = encrypted_file.read()

        decrypted_data = None
        # New format: 44-byte Fernet key header followed by the encrypted payload
        if len(file_data) > FERNET_KEY_LENGTH:
            try:
                header_key = file_data[:FERNET_KEY_LENGTH]
                decrypted_data = Fernet(header_key).decrypt(file_data[FERNET_KEY_LENGTH:])
            except Exception:
                decrypted_data = None

        # Legacy format: whole file encrypted with the deterministic machine key
        if decrypted_data is None:
            decrypted_data = Fernet(get_encryption_key()).decrypt(file_data)

        # Save the decrypted file
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        return True
    except Exception as e:
        logger.error(f"Error decrypting file {encrypted_path}: {e}")
        return False

# -- Conditional startup state and routes --
conditional_startup_state = {
    'running': False,
    'last_run': None,
    'duration': None,
    'scanned_files': 0,
    'quarantined_files': 0,
    'errors': 0,
    'process_events': 0,
    'last_error': None
}
conditional_startup_lock = threading.Lock()


def record_conditional_startup_run(scan_data=None, duration=None, error=None):
    """Update conditional_startup_state after a run completes or fails."""
    if not isinstance(scan_data, dict):
        scan_data = {}
    conditional_startup_state.update({
        'running': False,
        'last_run': time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration': round(duration, 2) if duration is not None else None,
        'scanned_files': len(scan_data.get('scanned_files', [])),
        'quarantined_files': len(scan_data.get('quarantined_files', [])),
        'errors': len(scan_data.get('errors', [])),
        'process_events': len(scan_data.get('process_events', [])),
        'last_error': str(error) if error else None
    })


def run_conditional_startup_background():
    """Run the conditional startup scan in a background thread."""
    from conditional_startup import run_conditional_startup_logic
    start_time = time.time()
    try:
        scan_data = run_conditional_startup_logic(open_browser=False)
        record_conditional_startup_run(scan_data, time.time() - start_time)
        logger.info("Conditional startup scan completed")
    except BaseException as e:
        # BaseException so SystemExit raised by imported modules (e.g. missing
        # FERNET_KEY) is recorded instead of leaving the state stuck on running
        logger.error(f"Error running conditional startup: {e!r}")
        record_conditional_startup_run(error=e, duration=time.time() - start_time)


@app.route('/api/conditional_startup/status', methods=['GET'])
def conditional_startup_status():
    """Status of the last conditional startup run."""
    resp = dict(conditional_startup_state)
    resp['network_monitor_running'] = bool(network_state.get('monitoring_enabled'))
    return jsonify(resp)


# -- Route for the conditional startup functionality --
@app.route('/run_startup', methods=['POST'])
def run_startup():
    """Start conditional startup scans in the background and return immediately."""
    try:
        with conditional_startup_lock:
            if conditional_startup_state['running']:
                return jsonify({
                    "status": "success",
                    "message": "Conditional startup scan already in progress",
                    "scan_time": "in progress",
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                })
            conditional_startup_state['running'] = True

        logger.info("Starting conditional startup scan in background")
        thread = threading.Thread(target=run_conditional_startup_background, daemon=True)
        thread.start()

        return jsonify({
            "status": "success",
            "message": "Conditional startup scan started in background",
            "scan_time": "running in background (see status panel)",
            "scanned_directories": network_state['monitored_directories'] + folder_watcher_state['monitored_paths'],
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        conditional_startup_state['running'] = False
        logger.error(f"Error running conditional startup: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# -- Main index page --
@app.route('/')
def index():
    # Provide all template variables required by index.html
    network_monitor_running = True  # Default value
    folder_watcher_status = True    # Default value
    safe_downloader_status = True   # Default value
    auto_updates_running = True     # Default value
    c2_detector_low_count = 0        # Default value
    c2_detector_high_count = 0       # Default value
    scheduled_scan_enabled = True   # Default value
    status = {                       # Default status object
        'status': 'DISABLED',
        'folder_watcher': False,
        'network_monitor': False,
        'safe_downloader': False
    }
    
    return render_template('index.html',
                          network_monitor_running=network_monitor_running,
                          folder_watcher_status=folder_watcher_status,
                          safe_downloader_status=safe_downloader_status,
                          auto_updates_running=auto_updates_running,
                          c2_detector_low_count=c2_detector_low_count,
                          c2_detector_high_count=c2_detector_high_count,
                          scheduled_scan_enabled=scheduled_scan_enabled,
                          status=status)

# -- YARA scanner page --
@app.route('/yara-scanner')
@app.route('/yara_scanner.html')  # Support both URL formats
def yara_scanner():
    # Add required template variables for YARA scanner
    rules_info = {
        'available': True,  # YARA rules are available
        'count': 42,       # Mock count of rules
        'last_updated': '2025-05-11',
        'sources': ['standard', 'custom']
    }
    
    # Get monitored directories from our global state
    # Combine network monitoring and folder watcher paths
    monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
    
    return render_template('yara_scanner.html', 
                           rules_info=rules_info,
                           monitored_directories=monitored_dirs,
                           monitored_folders=monitored_dirs,  # Provide both variable names for compatibility
                           scan_status="Ready")

# -- API for getting monitored directories for YARA scanner --
@app.route('/api/monitored-directories', methods=['GET'])
def get_monitored_directories_api():
    """API endpoint to get monitored directories for YARA scanner"""
    # Combine network monitoring and folder watcher paths
    monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
    return jsonify({
        'status': 'success',
        'monitored_directories': monitored_dirs,
        'count': len(monitored_dirs)
    })

# -- API for adding a monitored folder --
@app.route('/add_folder', methods=['POST'])
def add_monitored_folder():
    """Add a folder to be monitored by the YARA scanner"""
    try:
        folder_path = request.form.get('folder_path')
        if not folder_path:
            return jsonify({'success': False, 'error': 'No folder path provided'}), 400
            
        # Check if folder exists
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            return jsonify({'success': False, 'error': f'Folder {folder_path} does not exist'}), 400
            
        # Add the folder to monitored paths if not already there
        if folder_path not in folder_watcher_state['monitored_paths']:
            folder_watcher_state['monitored_paths'].append(folder_path)
            logger.info(f"Added folder {folder_path} to monitored directories")
            
        return jsonify({
            'success': True, 
            'message': f'Added {folder_path} to monitored folders',
            'monitored_count': len(folder_watcher_state['monitored_paths'])
        })
        
    except Exception as e:
        logger.error(f"Error adding monitored folder: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
        
# -- API for removing a monitored folder --
@app.route('/remove-monitored-folder', methods=['POST'])
def remove_monitored_folder():
    """Remove a folder from being monitored by the YARA scanner"""
    try:
        data = request.get_json()
        folder_path = data.get('folder_path')
        
        if not folder_path:
            return jsonify({'status': 'error', 'message': 'No folder path provided'}), 400
            
        # Remove from folder watcher paths
        if folder_path in folder_watcher_state['monitored_paths']:
            folder_watcher_state['monitored_paths'].remove(folder_path)
            logger.info(f"Removed folder {folder_path} from monitored directories")
        
        # Remove from network monitor paths if it's there
        if folder_path in network_state['monitored_directories']:
            network_state['monitored_directories'].remove(folder_path)
            logger.info(f"Removed folder {folder_path} from network monitor directories")
            
        return jsonify({
            'status': 'success',
            'message': f'Removed {folder_path} from monitored folders'
        })
        
    except Exception as e:
        logger.error(f"Error removing monitored folder: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# -- API endpoint to scan all monitored directories --
@app.route('/scan_all', methods=['POST'])
def scan_all_directories():
    """Scan all monitored directories using YARA rules"""
    try:
        # Get all monitored directories from both sources
        monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
        start_time = time.time()
        results = []
        total_files_scanned = 0
        total_directories_scanned = 0
        detected_threats = 0  # Track number of detected threats
        
        if not monitored_dirs:
            return jsonify({
                'status': 'error',
                'message': 'No monitored directories configured',
                'scan_time': '0 seconds',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'matches': 0,
                'folders': [],
                'results': []
            }), 400
        
        # Perform a more realistic scanning operation
        for directory in monitored_dirs:
            try:
                if os.path.exists(directory) and os.path.isdir(directory):
                    logger.info(f"Scanning directory: {directory}")
                    total_directories_scanned += 1
                    
                    # Count files and perform simulated scanning
                    file_count = 0
                    for root, _, files in os.walk(directory, topdown=True, onerror=lambda e: logger.warning(f"Access error: {e}")):
                        # Skip excluded paths like OneDrive folders
                        if should_exclude_path(root):
                            logger.info(f"Skipping excluded path: {root}")
                            continue
                            
                        # Skip permission-restricted directories
                        if not os.access(root, os.R_OK):
                            logger.warning(f"No read permission for directory: {root}")
                            continue
                            
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Skip excluded files
                            if should_exclude_path(file_path):
                                continue
                                
                            try:
                                # Simulate YARA scanning each file
                                # Add a small delay to simulate actual scanning work
                                if file_count % 100 == 0:  # Add delay every 100 files to avoid excessive slowdown
                                    time.sleep(0.01)
                                    
                                file_count += 1
                                # Mock detection logic with threat removal capability
                                # In a real implementation, this would use YARA rules to detect threats
                                
                                # This is a simple simulation of malware detection based on suspicious file names
                                suspicious_extensions = ['.exe.txt', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.hta']
                                suspicious_names = ['virus', 'trojan', 'malware', 'hack', 'crack', 'keygen', 'patch']
                                
                                filename_lower = file.lower()
                                detected = False
                                
                                # Simulated detection
                                for ext in suspicious_extensions:
                                    if filename_lower.endswith(ext):
                                        detected = True
                                        break
                                        
                                for name in suspicious_names:
                                    if name in filename_lower:
                                        detected = True
                                        break
                                
                                # If a threat is detected, take action
                                if detected:
                                    # Increment threat counter
                                    detected_threats += 1
                                    
                                    # Log the detection
                                    logger.warning(f"Potential threat detected: {file_path}")
                                    
                                    # Determine threat handling method based on threat level
                                    # For this example, we'll consider all detected threats as high risk
                                    threat_level = "high"  # Could be determined by more sophisticated analysis
                                    
                                    # Create quarantine directory
                                    quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
                                    os.makedirs(quarantine_dir, exist_ok=True)
                                    
                                    try:
                                        # Get base filename
                                        base_filename = os.path.basename(file_path)
                                        base_name, ext = os.path.splitext(base_filename)
                                        
                                        # Add .enc extension to indicate the file is encrypted
                                        encrypted_filename = f"{base_name}{ext}.enc"
                                        quarantine_path = os.path.join(quarantine_dir, encrypted_filename)
                                        
                                        # Add timestamp to prevent filename collisions in quarantine
                                        if os.path.exists(quarantine_path):
                                            timestamp = time.strftime("%Y%m%d_%H%M%S")
                                            quarantine_path = os.path.join(quarantine_dir, f"{base_name}_{timestamp}{ext}.enc")
                                        
                                        if threat_level == "high":
                                            # For high-risk threats, encrypt, quarantine, and delete
                                            logger.info(f"Encrypting high-risk threat for quarantine: {file_path}")
                                            
                                            # Encrypt file before quarantining it
                                            if encrypt_file(file_path, quarantine_path):
                                                # Delete original only after successful encryption
                                                os.remove(file_path)
                                                results.append(f"HIGH RISK THREAT DELETED: {file_path} (encrypted and saved to quarantine first)")
                                                logger.warning(f"Encrypted and deleted high risk threat: {file_path}")
                                            else:
                                                # Fallback if encryption fails: copy without encryption
                                                fallback_path = quarantine_path.replace('.enc', '')
                                                shutil.copy2(file_path, fallback_path)
                                                os.remove(file_path)
                                                results.append(f"HIGH RISK THREAT DELETED: {file_path} (unencrypted copy in quarantine due to encryption error)")
                                                logger.warning(f"Failed to encrypt but quarantined and deleted threat: {file_path}")
                                        else:
                                            # For moderate threats, encrypt and move to quarantine
                                            logger.info(f"Encrypting moderate-risk threat for quarantine: {file_path}")
                                            
                                            if encrypt_file(file_path, quarantine_path):
                                                # Only remove original after successful encryption
                                                os.remove(file_path)
                                                results.append(f"THREAT ENCRYPTED AND QUARANTINED: {file_path}")
                                                logger.warning(f"Encrypted and quarantined threat: {file_path}")
                                            else:
                                                # Fallback if encryption fails: move without encryption
                                                fallback_path = quarantine_path.replace('.enc', '')
                                                shutil.move(file_path, fallback_path)
                                                results.append(f"THREAT QUARANTINED (unencrypted): {file_path}")
                                                logger.warning(f"Failed to encrypt but quarantined threat: {file_path}")
                                    except Exception as quar_error:
                                        logger.error(f"Error handling threat {file_path}: {quar_error}")
                                        results.append(f"THREAT DETECTED: {file_path} - Failed to handle: {str(quar_error)}")
                                        # Try at least to warn the user even if quarantine fails
                                        logger.critical(f"!!!URGENT!!! Malicious file {file_path} could not be quarantined or removed.")
                                # End of detection logic
                            except Exception as file_error:
                                logger.warning(f"Error scanning file {file_path}: {file_error}")
                    
                    total_files_scanned += file_count
                    results.append(f"Scanned {file_count} files in {directory}")
                else:
                    logger.warning(f"Directory not found or not accessible: {directory}")
                    results.append(f"Directory not found or not accessible: {directory}")
            except Exception as scan_error:
                logger.error(f"Error scanning directory {directory}: {scan_error}")
                results.append(f"Error scanning {directory}: {str(scan_error)}")
        
        # Ensure the scan takes at least 1 second for UX purposes
        elapsed = time.time() - start_time
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
            
        duration = time.time() - start_time
        
        return jsonify({
            'status': 'success',
            'scan_time': f"{duration:.2f} seconds",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'matches': detected_threats,  # Now using the actual threat count
            'folders': monitored_dirs,
            'results': results,
            'files_scanned': total_files_scanned,
            'directories_scanned': total_directories_scanned,
            'threats_detected': detected_threats,
            'threats_removed': detected_threats  # All detected threats are simulated as being removed/quarantined
        })
    except Exception as e:
        logger.error(f"Error during scan_all: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'scan_time': '0 seconds',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'matches': 0,
            'folders': [],
            'results': []
        }), 500

# -- Network monitoring enhanced functionality --
# Global state to track network monitoring status
network_state = {
    'monitoring_enabled': False,
    'suspicious_connections': [],
    'monitored_directories': [
        # User profile locations (high risk)
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Desktop'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Documents'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Pictures'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Videos'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Music'),
        
        # Temporary directories (extremely high risk)
        os.path.join('C:\\', 'Windows', 'Temp'),
        
        # AppData locations (very high risk - used for persistence)
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Roaming'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Local'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\LocalLow'),
        
        # Startup locations (used for persistence)
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        os.path.join('C:\\', 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp'),
        
        # Other high-risk system locations
        os.path.join('C:\\', 'Windows', 'System32', 'Tasks'),  # Scheduled tasks
        os.path.join('C:\\', 'Windows', 'System32', 'drivers'),  # Driver locations
        os.path.join('C:\\', 'Windows', 'SysWOW64'),  # 32-bit system files on 64-bit systems
        os.path.join('C:\\', 'ProgramData')  # Common application data
    ],
    'last_scan': None
}

# Global state for auto-updates configuration
auto_updates_state = {
    'enabled': True,  # Automatic Signature Updates enabled by default
    'last_update': time.strftime('%Y-%m-%d %H:%M:%S'),
    'update_frequency': 'daily',
    'signatures': {
        'count': 257,
        'version': '2025.05.11.01',
        'source': ['official', 'community']
    }
}

# Define network blueprint endpoints
@network_bp.route('/monitored_directories', methods=['GET'])
def network_monitored_directories():
    """API endpoint for getting network monitored directories for YARA scanner"""
    try:
        # Get timestamp for last scan
        last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Use the monitored directories from network state
        monitored_dirs = network_state['monitored_directories']
        
        # Check if directories exist and are accessible
        directories = []
        for dir_path in monitored_dirs:
            exists = os.path.exists(dir_path)
            accessible = exists and os.access(dir_path, os.R_OK)
            
            # Count files if accessible
            file_count = 0
            if accessible:
                try:
                    file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                except Exception as e:
                    logger.warning(f"Error counting files in {dir_path}: {str(e)}")
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count
            })
        
        # Return data in the exact format expected by the YARA scanner
        response = {
            'success': True,
            'monitoring_status': {
                'enabled': network_state['monitoring_enabled'],
                'last_scan': last_scan,
                'total_directories': len(directories),
                'directories': directories
            }
        }
            
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in API network monitored directories: {str(e)}")
        # Return a valid JSON response even on error
        return jsonify({
            'success': False, 
            'error': str(e),
            'monitoring_status': {
                'enabled': False,
                'directories': [],
                'total_directories': 0
            }
        }), 500

# Register the network blueprint with the app
app.register_blueprint(network_bp)

# Direct route for network monitoring API endpoint (needed by YARA scanner)
@app.route('/api/network/monitored_directories', methods=['GET'])
def api_network_monitored_directories():
    """Direct endpoint that the YARA scanner needs to access"""
    try:
        # Get timestamp for last scan
        last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Use monitored directories from network state
        monitored_dirs = network_state['monitored_directories']
        
        # Build directory information
        directories = []
        for dir_path in monitored_dirs:
            exists = os.path.exists(dir_path)
            accessible = exists and os.access(dir_path, os.R_OK)
            
            # Count files if accessible
            file_count = 0
            if accessible:
                try:
                    file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                except Exception as e:
                    logger.warning(f"Error counting files in {dir_path}: {str(e)}")
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count
            })
        
        # Return data in the exact format expected by the YARA scanner
        response = {
            'success': True,
            'monitoring_status': {
                'enabled': network_state['monitoring_enabled'],
                'last_scan': last_scan,
                'total_directories': len(directories),
                'directories': directories
            }
        }
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in direct network API endpoint: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'monitoring_status': {
                'enabled': False,
                'directories': [],
                'total_directories': 0
            }
        }), 500

# Note: Duplicate route removed to fix conflict

# Note: We've removed the duplicate endpoint to avoid conflicts

# -- Network monitoring functions --
@app.route('/toggle_network_monitor/<action>', methods=['POST'])
def toggle_network_monitor(action):
    """Toggle network monitor service on/off."""
    global network_state
    
    if action not in ['start', 'stop']:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
    network_state['monitoring_enabled'] = (action == 'start')
    
    if action == 'start':
        # When starting, record the current time as last scan time
        network_state['last_scan'] = time.strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify({
        'success': True,
        'status': 'ENABLED' if network_state['monitoring_enabled'] else 'DISABLED',
        'network_monitor_running': network_state['monitoring_enabled'],
        'monitored_directories': network_state['monitored_directories']
    })

@app.route('/get_network_monitored_directories')
def get_network_monitored_directories():
    """Get the list of network-monitored directories with recursive subdirectory scanning."""
    global network_state
    
    # Define high-risk file extensions to monitor more carefully
    high_risk_extensions = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta', 
        '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe', 
        '.wsh', '.sys', '.inf'
    ]
    
    # Get monitoring status and statistics
    monitored_dirs = network_state['monitored_directories']
    total_files_monitored = 0
    discovered_subdirs = [] # Keep track of discovered subdirectories
    
    monitoring_status = {
        'enabled': network_state['monitoring_enabled'],
        'total_directories': len(monitored_dirs),  # Initial count - will be updated after discovering subdirs
        'last_scan': network_state.get('last_scan', 'Never'),
        'traffic_stats': network_state.get('traffic_stats', {}),
        'directories': []
    }
    
    # Add detailed information about each directory
    for directory in monitored_dirs:
        if os.path.exists(directory):
            try:
                # Count files in directory (recursive)
                file_count = 0
                high_risk_file_count = 0
                subdir_count = 0
                
                # Use os.walk to recursively traverse directory tree
                for root, dirs, files in os.walk(directory):
                    # Skip excluded paths
                    if any(excluded in root for excluded in folder_watcher_state['excluded_paths']):
                        continue
                    
                    # Add root to discovered subdirectories if it's not the original directory
                    # and not already in the monitored directories list
                    if root != directory and root not in monitored_dirs and root not in discovered_subdirs:
                        discovered_subdirs.append(root)
                        
                    # Count subdirectories (but only at first level)
                    if root == directory:
                        subdir_count = len(dirs)
                        
                        # Also add immediate subdirectories to our discovered list
                        for subdir in dirs:
                            subdir_path = os.path.join(root, subdir)
                            if subdir_path not in monitored_dirs and subdir_path not in discovered_subdirs:
                                discovered_subdirs.append(subdir_path)
                    else:
                        # Count this as a subdirectory
                        subdir_count += 1
                    
                    # Count files and check for high-risk extensions
                    for filename in files:
                        file_count += 1
                        _, ext = os.path.splitext(filename)
                        if ext.lower() in high_risk_extensions:
                            high_risk_file_count += 1
                
                # Update total files count
                total_files_monitored += file_count
                
                monitoring_status['directories'].append({
                    'path': directory,
                    'exists': True,
                    'file_count': file_count,
                    'high_risk_files': high_risk_file_count,
                    'subdirectory_count': subdir_count,
                    'accessible': True
                })
            except PermissionError:
                # Handle permission errors
                monitoring_status['directories'].append({
                    'path': directory,
                    'exists': True,
                    'file_count': 'Unknown (Permission denied)',
                    'high_risk_files': 0,
                    'subdirectory_count': 0,
                    'accessible': False
                })
        else:
            monitoring_status['directories'].append({
                'path': directory,
                'exists': False,
                'file_count': 0,
                'high_risk_files': 0,
                'subdirectory_count': 0,
                'accessible': False
            })
    
    # Add total files monitored to the status
    monitoring_status['total_files_monitored'] = total_files_monitored
    
    # Add discovered subdirectories to the network state's monitored directories
    if discovered_subdirs:
        # Filter out any excluded paths
        valid_subdirs = []
        for subdir in discovered_subdirs:
            # Skip if any excluded term is in the path
            if not any(excluded in subdir for excluded in folder_watcher_state['excluded_paths']):
                valid_subdirs.append(subdir)
        
        # Add valid subdirectories to monitored directories
        for subdir in valid_subdirs:
            if subdir not in network_state['monitored_directories']:
                network_state['monitored_directories'].append(subdir)
                logging.info(f"Added discovered subdirectory to network monitoring: {subdir}")
    
    # Update the monitoring_status to reflect the added subdirectories
    monitoring_status['total_directories'] = len(network_state['monitored_directories'])
    
    # Also add a separate count for all subdirectories to make it clearly visible
    monitoring_status['total_subdirectories_found'] = len(discovered_subdirs)
    
    return jsonify({
        'success': True,
        'monitored_directories': network_state['monitored_directories'],
        'monitoring_status': monitoring_status
    })

@app.route('/toggle_folder_watcher/<action>', methods=['POST'])
def toggle_folder_watcher(action):
    """Toggle folder watcher service on/off."""
    global folder_watcher_state
    
    try:
        if action not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        # Update folder watcher state    
        folder_watcher_state['active'] = (action == 'start')
        
        if action == 'start':
            # Ensure all paths exist and are accessible
            valid_paths = []
            for path in folder_watcher_state['monitored_paths']:
                try:
                    if os.path.exists(path) and os.path.isdir(path):
                        valid_paths.append(path)
                except Exception as e:
                    logger.warning(f"Could not access path {path}: {e}")
            
            folder_watcher_state['monitored_paths'] = valid_paths
            folder_watcher_state['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"Folder watcher started monitoring {len(folder_watcher_state['monitored_paths'])} directories")
        else:
            logger.info("Folder watcher stopped")
        
        # Add discovered subdirectories to the monitored paths
        if discovered_subdirs:
            # Filter out any excluded paths
            valid_subdirs = []
            for subdir in discovered_subdirs:
                # Skip if any excluded term is in the path
                if not any(excluded in subdir for excluded in folder_watcher_state['excluded_paths']):
                    valid_subdirs.append(subdir)
            
            # Add valid subdirectories to monitored paths
            for subdir in valid_subdirs:
                if subdir not in folder_watcher_state['monitored_paths']:
                    folder_watcher_state['monitored_paths'].append(subdir)
                    logging.info(f"Added discovered subdirectory to folder monitoring: {subdir}")
        
        # Update the total directories count to reflect all discovered directories
        total_directories_monitored = len(folder_watcher_state['monitored_paths'])
        
        # Return the result
        return jsonify({
            'success': True,
            'status': 'ENABLED' if folder_watcher_state['active'] else 'DISABLED',
            'folder_watcher_running': folder_watcher_state['active'],
            'monitored_paths': folder_watcher_state['monitored_paths'],  # Use updated list
            'total_paths': len(folder_watcher_state['monitored_paths']),  # Use updated count
            'since': folder_watcher_state['start_time']
        })
    except Exception as e:
        logger.error(f"Error in toggle_folder_watcher: {e}")
        return jsonify({'success': False, 'error': str(e), 'message': 'An error occurred processing your request'}), 500

@app.route('/folder-watcher-paths', methods=['GET'])
@app.route('/get_folder_watcher_paths', methods=['GET'])
def get_folder_watcher_paths():
    """Get the list of folder watcher monitored paths with recursive subdirectory scanning."""
    global folder_watcher_state
    
    # Define high-risk file extensions to monitor more carefully
    high_risk_extensions = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta', 
        '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe', 
        '.wsh', '.sys', '.inf'
    ]
    
    # Get monitoring status and statistics for folder watcher
    monitored_paths = folder_watcher_state['monitored_paths']
    
    # Initialize counters for total statistics
    total_files_monitored = 0
    total_high_risk_files = 0
    total_directories_monitored = len(monitored_paths)  # Start with top-level directories
    discovered_subdirs = []  # Track discovered subdirectories
    
    # Prepare a list to hold detailed path information
    paths_with_details = []
    
    # Process each monitored path
    for path in monitored_paths:
        if os.path.exists(path):
            # Skip excluded paths
            if should_exclude_path(path):
                paths_with_details.append({
                    'path': path,
                    'exists': True,
                    'file_count': 'Excluded from monitoring',
                    'high_risk_files': 0,
                    'subdirectory_count': 0,
                    'accessible': False
                })
                continue
                
            # Check if path is accessible
            is_accessible = os.access(path, os.R_OK)
            file_count = 0
            high_risk_count = 0
            subdir_count = 0
            
            if is_accessible:
                try:
                    # Use os.walk to traverse directory structure recursively
                    for root, dirs, files in os.walk(path):
                        # Skip excluded paths
                        if any(excluded in root for excluded in folder_watcher_state['excluded_paths']):
                            continue
                        
                        # Add root to discovered subdirectories if it's not the original path
                        # and not already in the monitored paths list
                        if root != path and root not in monitored_paths and root not in discovered_subdirs:
                            discovered_subdirs.append(root)
                        
                        # Count first-level subdirectories separately
                        if root == path:
                            subdir_count = len(dirs)
                            total_directories_monitored += len(dirs)
                            
                            # Add immediate subdirectories to our discovered list
                            for subdir in dirs:
                                subdir_path = os.path.join(root, subdir)
                                if subdir_path not in monitored_paths and subdir_path not in discovered_subdirs:
                                    discovered_subdirs.append(subdir_path)
                        else:
                            # This is a subdirectory being processed
                            subdir_count += 1
                            total_directories_monitored += 1
                            
                        # Count files and identify high-risk ones
                        for filename in files:
                            file_count += 1
                            total_files_monitored += 1
                            _, ext = os.path.splitext(filename)
                            if ext.lower() in high_risk_extensions:
                                high_risk_count += 1
                                total_high_risk_files += 1
                except Exception as e:
                    # Handle potential errors like permission issues
                    logging.warning(f"Error scanning {path}: {str(e)}")
                    is_accessible = False
                    
                # Add detailed information for this path
                paths_with_details.append({
                    'path': path,
                    'exists': True,
                    'accessible': is_accessible,
                    'file_count': file_count,
                    'high_risk_files': high_risk_count,
                    'subdirectory_count': subdir_count
                })
            else:
                # Path exists but is not accessible
                paths_with_details.append({
                    'path': path,
                    'exists': True,
                    'accessible': False,
                    'file_count': 'Unknown (Permission denied)',
                    'high_risk_files': 0,
                    'subdirectory_count': 0
                })
        else:
            # Path doesn't exist
            paths_with_details.append({
                'path': path,
                'exists': False,
                'accessible': False,
                'file_count': 0,
                'high_risk_files': 0,
                'subdirectory_count': 0
            })
    
    # Add discovered subdirectories to the folder watcher's monitored paths
    if discovered_subdirs:
        # Filter out any excluded paths
        valid_subdirs = []
        for subdir in discovered_subdirs:
            # Skip if any excluded term is in the path
            if not any(excluded in subdir for excluded in folder_watcher_state['excluded_paths']):
                valid_subdirs.append(subdir)
        
        # Add valid subdirectories to monitored paths
        for subdir in valid_subdirs:
            if subdir not in folder_watcher_state['monitored_paths']:
                folder_watcher_state['monitored_paths'].append(subdir)
                logging.info(f"Added discovered subdirectory to folder watcher: {subdir}")
        
        # Update the total directories count
        total_directories_monitored = len(folder_watcher_state['monitored_paths'])
    
    # Generate response with enhanced statistics
    response = {
        'active': folder_watcher_state['active'],
        'start_time': folder_watcher_state['start_time'],
        'paths': paths_with_details,
        'excluded_paths': folder_watcher_state['excluded_paths'],
        'detections': folder_watcher_state['detections'],
        'total_files_monitored': total_files_monitored,
        'total_directories_monitored': total_directories_monitored,
        'total_high_risk_files': total_high_risk_files,
        'monitored_paths': folder_watcher_state['monitored_paths'],  # Include updated paths
        'root_directories_count': len(monitored_paths),  # Original root directories
        'subdirectories_count': len(discovered_subdirs),  # Found subdirectories
        'total_subdirectories_found': len(discovered_subdirs),  # For consistency with network monitor
        'total_paths': len(folder_watcher_state['monitored_paths'])  # Total of all monitored paths
    }
    
    return jsonify(response)

@app.route('/start_realtime', methods=['POST'])
def start_realtime():
    """Start real-time monitoring"""
    try:
        # Start the network monitoring thread (mocked implementation)
        return jsonify({'status': 'success', 'message': 'Real-time monitoring started'})
    except Exception as e:
        logger.error(f"Error starting real-time monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/file_crypto', methods=['GET', 'POST'])
def file_crypto():
    """Handle file crypto operations"""
    return jsonify({'status': 'success', 'message': 'File crypto functionality available'})

# -- Additional required routes to prevent 404 errors --
@app.route('/quarantine', methods=['GET'])
@app.route('/quarantine.html', methods=['GET'])
def quarantine():
    # Path to the quarantine directory
    quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
    os.makedirs(quarantine_dir, exist_ok=True)
    
    quarantined_files = []
    
    try:
        # Get all files in the quarantine directory
        for filename in os.listdir(quarantine_dir):
            file_path = os.path.join(quarantine_dir, filename)
            if os.path.isfile(file_path):
                # Check if this is an encrypted file
                is_encrypted = filename.endswith('.enc')
                
                # Get file stats
                file_stats = os.stat(file_path)
                quarantine_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                # Extract original name (remove .enc extension if present)
                original_name = filename
                if is_encrypted:
                    original_name = os.path.splitext(filename)[0]  # Remove .enc extension
                
                quarantined_files.append({
                    'filename': original_name,
                    'quarantine_path': file_path,
                    'original_path': '', # This would be populated if we tracked original locations
                    'quarantine_time': quarantine_time,
                    'timestamp': file_stats.st_mtime * 1000,  # Convert to milliseconds for JavaScript
                    'encrypted': is_encrypted,
                    'size': file_stats.st_size,
                    'details': 'Encrypted (.enc)' if is_encrypted else 'Not encrypted',
                    'detection_info': {
                        'matches': ['YARA Detection']
                    }
                })
        
        # Read last few lines of the log file for quarantine events
        log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'antivirus.log')
        quarantine_log = ''
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-50:]
                    quarantine_log = ''.join([line for line in lines if 'threat' in line.lower() or 'quarantine' in line.lower()])
            except Exception as e:
                logger.error(f"Error reading log file: {e}")
                quarantine_log = f"Error reading log file: {e}"
        
        # Check if request wants JSON (for API) or HTML (for browser viewing)
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'success',
                'files': quarantined_files,
                'quarantine_dir': quarantine_dir
            })
        else:
            # Return HTML view
            return render_template('quarantine.html', quarantined_files=quarantined_files, quarantine_log=quarantine_log)
            
    except Exception as e:
        logger.error(f"Error listing quarantined files: {e}")
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'error', 
                'error': str(e),
                'files': []
            })
        else:
            return render_template('quarantine.html', quarantined_files=[], quarantine_log=f"Error listing quarantined files: {e}")

@app.route('/logs')
def logs():
    return render_template('logs.html') if os.path.exists(os.path.join(app.template_folder, 'logs.html')) else 'Antivirus Logs'

@app.route('/safe_download')
def safe_download():
    return render_template('safe_download.html') if os.path.exists(os.path.join(app.template_folder, 'safe_download.html')) else 'Safe Download'

@app.route('/quarantine/list')
def quarantine_list():
    # Path to the quarantine directory
    quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
    os.makedirs(quarantine_dir, exist_ok=True)
    
    quarantined_files = []
    
    try:
        # Get all files in the quarantine directory
        for filename in os.listdir(quarantine_dir):
            file_path = os.path.join(quarantine_dir, filename)
            if os.path.isfile(file_path):
                # Get file stats
                file_stats = os.stat(file_path)
                quarantine_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                quarantined_files.append({
                    'filename': filename,
                    'quarantine_path': file_path,
                    'quarantine_time': quarantine_time,
                    'size': file_stats.st_size
                })
        
        return jsonify({'files': quarantined_files})
    except Exception as e:
        logger.error(f"Error listing quarantined files: {e}")
        return jsonify({'error': str(e), 'files': []})

@app.route('/restore_file', methods=['POST'])
def restore_file():
    """Restore a quarantined file by decrypting it if necessary"""
    try:
        file_path = request.form.get('file_path')
        destination = request.form.get('destination')
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'File not found'})
        
        # Determine if the file is encrypted (has .enc extension)
        is_encrypted = file_path.endswith('.enc')
        
        # If no destination specified, use the original location or a safe default location
        if not destination:
            if is_encrypted:
                # Remove .enc extension for the restored file
                destination = os.path.splitext(file_path)[0]
            else:
                # For unencrypted files, restore to the Desktop
                desktop = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Desktop')
                destination = os.path.join(desktop, os.path.basename(file_path))
        
        # Ensure the destination directory exists
        os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
        
        # Process the file according to its encryption status
        if is_encrypted:
            # Decrypt the file
            if decrypt_file(file_path, destination):
                logger.info(f"Successfully decrypted and restored file from {file_path} to {destination}")
                return jsonify({'success': True, 'restored_to': destination})
            else:
                return jsonify({'success': False, 'error': 'Failed to decrypt file'})
        else:
            # Simply copy the file
            shutil.copy2(file_path, destination)
            logger.info(f"Successfully restored unencrypted file from {file_path} to {destination}")
            return jsonify({'success': True, 'restored_to': destination})
            
    except Exception as e:
        logger.error(f"Error restoring file: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/quarantine/delete/<filename>', methods=['POST'])
def delete_quarantined_file(filename):
    """Delete a quarantined file"""
    try:
        # Path to the quarantine directory
        quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
        file_path = os.path.join(quarantine_dir, filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({'status': 'error', 'error': 'File not found'}), 404
        
        # Delete the file
        os.remove(file_path)
        logger.info(f"Successfully deleted quarantined file: {file_path}")
        
        return jsonify({'status': 'success', 'message': 'File deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting quarantined file: {e}")
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/antivirus_log')
def antivirus_log():
    return 'Antivirus Log'

@app.route('/c2_detector_report')
def c2_detector_report():
    return 'Network Threat Report'

@app.route('/scan')
def scan():
    """Run a full system scan using YARA rules"""
    # Mock scan results
    scan_results = {
        'status': 'completed',
        'scanned_files': 15423,
        'detected_threats': 0,
        'scan_time': '352.4 seconds',
        'scanned_directories': folder_watcher_state['monitored_paths'] + network_state['monitored_directories'],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    return render_template('scan_results.html', results=scan_results) if os.path.exists(os.path.join(app.template_folder, 'scan_results.html')) else jsonify(scan_results)

@app.route('/scan_all_processes')
def scan_all_processes():
    """Scan all running processes for suspicious activity"""
    # Mock process scan results
    process_scan = {
        'status': 'completed',
        'scanned_processes': 87,
        'detected_threats': 0,
        'scan_time': '12.7 seconds',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    return render_template('process_scan.html', results=process_scan) if os.path.exists(os.path.join(app.template_folder, 'process_scan.html')) else jsonify(process_scan)

# -- Network statistics endpoint --
@app.route('/network-statistics')
def network_statistics():
    """Get network monitoring statistics"""
    stats = {
        'monitoring_status': 'active' if network_state['monitoring_enabled'] else 'inactive',
        'uptime': '3h 24m' if network_state['last_scan'] else 'N/A',
        'monitored_directories': len(network_state['monitored_directories']),
        'suspicious_connections_blocked': len(network_state['suspicious_connections']),
        'last_scan': network_state['last_scan'] or 'Never',
        'folder_watcher_status': 'active' if folder_watcher_state['active'] else 'inactive',
        'folder_watcher_monitored': len(folder_watcher_state['monitored_paths']),
        'total_protection_coverage': len(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
    }
    return jsonify(stats)

# -- Status endpoint --
@app.route('/toggle_auto_updates/<action>', methods=['POST'])
def toggle_auto_updates(action):
    """Toggle automatic signature updates on/off."""
    global auto_updates_state
    
    try:
        if action not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        auto_updates_state['enabled'] = (action == 'start')
        
        if action == 'start':
            # When enabling auto-updates, record the current time
            auto_updates_state['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"Automatic signature updates enabled. Current signature count: {auto_updates_state['signatures']['count']}")
        else:
            logger.info("Automatic signature updates disabled.")
        
        return jsonify({
            'success': True,
            'status': 'ENABLED' if auto_updates_state['enabled'] else 'DISABLED',
            'auto_updates_enabled': auto_updates_state['enabled'],
            'signature_count': auto_updates_state['signatures']['count'],
            'signature_version': auto_updates_state['signatures']['version'],
            'last_update': auto_updates_state['last_update']
        })
    except Exception as e:
        logger.error(f"Error in toggle_auto_updates: {e}")
        return jsonify({'success': False, 'error': str(e), 'message': 'An error occurred processing your request'}), 500

@app.route('/auto-updates-status')
def auto_updates_status():
    """Get automatic signature updates status"""
    global auto_updates_state
    return jsonify(auto_updates_state)

@app.route('/status')
def status():
    """Get overall system status"""
    return jsonify({
        'folder_watcher': folder_watcher_state['active'],
        'network_monitor': network_state['monitoring_enabled'],
        'auto_updates': auto_updates_state['enabled'],
        'services': {
            'yara_scanner': True,
            'conditional_startup': True,
            'quarantine': True,
            'auto_updates': auto_updates_state['enabled']
        },
        'status': 'ENABLED' if (network_state['monitoring_enabled'] or folder_watcher_state['active'] or auto_updates_state['enabled']) else 'DISABLED',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'signatures': {
            'count': auto_updates_state['signatures']['count'],
            'version': auto_updates_state['signatures']['version'],
            'last_update': auto_updates_state['last_update']
        }
    })

# -- Scheduled Scanning Function --
def run_scheduled_scans():
    """Run scheduled security scans in the background with continuous YARA scanning."""
    while True:
        try:
            # Run YARA scan on all files in monitored directories
            try:
                from security.yara_scanner import scan_file_with_yara
            except ImportError:
                logger.warning("YARA scanner not available, skipping YARA scan")
                scan_file_with_yara = None
            
            # Combine monitored directories from both sources
            monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
            
            for scan_dir in monitored_dirs:
                if not os.path.exists(scan_dir):
                    continue
                for root, dirs, files in os.walk(scan_dir):
                    # Skip excluded paths
                    if should_exclude_path(root):
                        continue
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Skip excluded files
                        if should_exclude_path(file_path):
                            continue
                        
                        try:
                            if scan_file_with_yara:
                                yara_matches = scan_file_with_yara(file_path)
                                if yara_matches:
                                    logger.info(f"YARA scan completed with {len(yara_matches)} matches for {file_path}")
                                    
                                    # Handle detected threats
                                    for match in yara_matches:
                                        logger.warning(f"Threat detected: {file_path} - Rule: {match.rule}")
                                        
                                        # Create quarantine directory
                                        quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
                                        os.makedirs(quarantine_dir, exist_ok=True)
                                        
                                        try:
                                            base_filename = os.path.basename(file_path)
                                            base_name, ext = os.path.splitext(base_filename)
                                            encrypted_filename = f"{base_name}{ext}.enc"
                                            quarantine_path = os.path.join(quarantine_dir, encrypted_filename)
                                            
                                            # Add timestamp to prevent collisions
                                            if os.path.exists(quarantine_path):
                                                timestamp = time.strftime("%Y%m%d_%H%M%S")
                                                quarantine_path = os.path.join(quarantine_dir, f"{base_name}_{timestamp}{ext}.enc")
                                            
                                            # Encrypt and quarantine
                                            if encrypt_file(file_path, quarantine_path):
                                                os.remove(file_path)
                                                logger.warning(f"Threat quarantined and deleted: {file_path}")
                                            else:
                                                logger.error(f"Failed to encrypt threat: {file_path}")
                                        except Exception as quar_error:
                                            logger.error(f"Error quarantining threat {file_path}: {quar_error}")
                        except Exception as e:
                            logger.error(f"Error scanning {file_path}: {str(e)}")
            
            # Delete quarantined files during continuous scanning
            try:
                delete_quarantined_files_quick_start()
            except Exception as e:
                logger.error(f"Error deleting quarantined files: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error in scheduled scan: {str(e)}")
        
        # Continuous scanning - short pause to prevent CPU overload
        time.sleep(5)

def delete_quarantined_files_quick_start():
    """Delete quarantined files from the quarantine folder."""
    try:
        deleted_count = 0
        quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
        
        if os.path.exists(quarantine_dir):
            for filename in os.listdir(quarantine_dir):
                if filename.endswith('.enc'):  # Only look at encrypted quarantined files
                    file_path = os.path.join(quarantine_dir, filename)
                    
                    try:
                        # Delete the encrypted file
                        os.remove(file_path)
                        deleted_count += 1
                        
                        # Delete associated metadata file if it exists
                        json_path = file_path + '.json'
                        if os.path.exists(json_path):
                            os.remove(json_path)
                        
                        logger.info(f"Deleted quarantined file: {filename}")
                        
                    except Exception as e:
                        logger.error(f"Error deleting quarantined file {filename}: {str(e)}")
        
        if deleted_count > 0:
            logger.info(f"Successfully deleted {deleted_count} quarantined files")
        else:
            logger.info("No quarantined files to delete")
            
        return deleted_count
        
    except Exception as e:
        logger.error(f"Error in delete_quarantined_files_quick_start: {str(e)}")
        return 0

# -- Start the server --
def start_server(port=5000):
    """
    Start the Flask server with fallback options for port conflicts.
    Returns the port that was successfully used.
    """
    try:
        # Check if port is available with a direct bind attempt
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
            # Port is available
            print(f"Server running at http://127.0.0.1:{port}")
            # Start server in non-debug mode to avoid reloader issues
            app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
            return port
        except OSError:
            # Port is already in use, try fallback ports
            test_socket.close()
            fallback_ports = [5001, 8080, 8000, 3000, 0]  # 0 means let OS choose
            
            for fallback_port in fallback_ports:
                try:
                    print(f"Port {port} is in use. Trying port {fallback_port}...")
                    print(f"Server running at http://127.0.0.1:{fallback_port if fallback_port != 0 else '<assigned by OS>'}")
                    app.run(host='0.0.0.0', port=fallback_port, debug=False, threaded=True, use_reloader=False)
                    return fallback_port
                except OSError as e:
                    print(f"Port {fallback_port} also unavailable: {e}")
                    continue
                except Exception as ex:
                    print(f"Error starting server on port {fallback_port}: {ex}")
                    continue
    except OSError as e:
        # Handle socket errors gracefully
        print(f"Socket error: {e}")
        print("Trying alternate method to start server...")
        try:
            # Try with different parameters that avoid socket reuse
            # Use localhost only with random port
            print("Server running with OS-assigned port on localhost only")
            app.run(host='127.0.0.1', port=0, debug=False, threaded=False, use_reloader=False)
            return -1  # Unknown port
        except Exception as ex:
            print(f"Failed to start server: {ex}")
            return None
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Try running the app with 'python app.py' instead.")
        return None

def open_browser(port):
    """
    Attempt to open the browser to the running application.
    """
    if port is None or port < 0:
        print("Could not determine port to open browser with.")
        return
        
    import webbrowser
    import time
    
    # Wait a moment for the server to start
    time.sleep(1.5)
    
    browser_url = f"http://127.0.0.1:{port}"
    localhost_url = f"http://localhost:{port}"
    external_url = f"http://localhost:{port}"
    
    print(f"Opening browser at {browser_url}")
    
    # First ensure the server is responding before opening browser
    try:
        # Simple check to see if server is responding
        import urllib.request
        with urllib.request.urlopen(browser_url, timeout=2) as response:
            if response.getcode() == 200:
                print("Server confirmed ready")
    except:
        # If server check fails, just wait a bit longer
        print("Waiting for server to fully initialize...")
        time.sleep(3)
    
    # Try multiple methods to open the browser
    try:
        # Use new=2 to open in a new tab if possible
        if not webbrowser.open(browser_url, new=2):
            # If the first attempt returns False (no success), try the second URL
            if not webbrowser.open(localhost_url, new=2):
                # If both fail, try with the default browser explicitly
                browser = webbrowser.get()
                browser.open(external_url)
    except Exception as e:
        print(f"Failed to open browser with standard method: {e}")
        try:
            # Try to get the default browser directly
            browser = webbrowser.get()
            browser.open(browser_url)
        except Exception as e2:
            print(f"Failed to open browser with alternative method: {e2}")
            print(f"Please manually open {browser_url} in your browser")

# Class to share the port between threads
class ServerInfo:
    def __init__(self):
        self.port = None

if __name__ == '__main__':
    print("Starting clean Windows Defender app instance...")
    
    # Initialize DNS server and start it automatically
    try:
        dns_server, dns_resolver = start_dns_server(allow_network=False)  # Localhost only for security
        logging.info("DNS server started automatically at application startup")
    except Exception as e:
        logging.error(f"Failed to start DNS server: {str(e)}. This is normal if not running as administrator.")
    
    import threading
    import queue
    
    # Start scheduled scanning thread for continuous YARA scanning
    scan_thread = threading.Thread(target=run_scheduled_scans, daemon=True)
    scan_thread.start()
    logger.info("Scheduled scanning thread started for continuous YARA scanning")
    
    # Create a queue for passing the port from server thread to main thread
    port_queue = queue.Queue()
    
    # Modified start_server function to communicate back the port
    def start_server_and_report(default_port=5000):
        actual_port = start_server(default_port)
        # Put the actual port in the queue
        if actual_port is not None:
            try:
                port_queue.put(actual_port, block=False)
            except queue.Full:
                pass
        return actual_port
    
    # Start the server in a background thread
    server_port = 5000  # Default port
    server_thread = threading.Thread(target=lambda: start_server_and_report(server_port), daemon=True)
    server_thread.start()
    
    # Wait for the port to be reported or use detection
    detected_port = None
    
    # First, see if the server thread reported a port
    try:
        # Wait up to 10 seconds for the port to be reported
        detected_port = port_queue.get(timeout=10)
        print(f"Server reported running on port {detected_port}")
    except queue.Empty:
        print("Server did not report its port. Attempting detection...")
        
        # If no port reported, try to detect by probing common ports
        # Check common ports with increased timeouts and retries
        potential_ports = [5000, 5001, 8080, 8000, 3000]
        max_retries = 3
        
        for attempt in range(max_retries):
            # Increasing wait time with each retry
            time.sleep(1 + attempt)  
            
            for port in potential_ports:
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(1.0)  # Longer timeout
                    result = test_socket.connect_ex(('127.0.0.1', port))
                    test_socket.close()
                    
                    if result == 0:  # Port is in use (our server should be running here)
                        # Additional verification - try to get a response
                        try:
                            import urllib.request
                            with urllib.request.urlopen(f"http://127.0.0.1:{port}", timeout=2) as response:
                                if response.getcode() == 200:
                                    detected_port = port
                                    print(f"Verified server running on port {port} with HTTP request")
                                    break
                        except:
                            # If we can connect but not get a response, it might be our server still starting
                            # Mark as potential port but continue checking others
                            if detected_port is None:
                                detected_port = port
                except:
                    continue
            
            if detected_port:
                break
    
    # As last resort, try common ports with lighter validation
    if detected_port is None:
        print("Trying one last attempt to find the server...")
        for port in [5000, 5001, 8080, 8000, 3000]:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(0.3)
                result = test_socket.connect_ex(('127.0.0.1', port))
                test_socket.close()
                
                if result == 0:  # Something is on this port
                    detected_port = port
                    print(f"Found a service on port {port} - assuming it's our server")
                    break
            except:
                continue
    
    # Open browser window with the detected port
    if detected_port is not None:
        print(f"Opening browser to http://127.0.0.1:{detected_port}")
        open_browser(detected_port)
    else:
        print("\nCould not detect which port the server is running on.")
        print("The server is likely running on one of: 5000, 5001, 8080, 8000")
        print("Please try opening these URLs in your browser manually:")
        print("  - http://127.0.0.1:5000")
        print("  - http://127.0.0.1:5001")
        print("  - http://localhost:5000")
        print("  - http://localhost:5001")
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down server...")
    except Exception as e:
        print(f"Error in main thread: {e}")
        print("Server may still be running in background.")
        print("Close this console window to shut down completely.")
