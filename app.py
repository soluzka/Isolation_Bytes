import os
import sys
import winreg
import time
import logging
import sklearn
import threading
import webbrowser
import string
import ctypes
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, Response, send_from_directory, redirect, url_for
from werkzeug.utils import secure_filename
from flask_cors import CORS
from cryptography.fernet import Fernet
from pefile import PE as PEFile
import psutil
import numpy as np
from network_monitor_base import NetworkMonitor
from folder_watcher_base import FolderWatcher
from queue import Queue
from functools import wraps
from network_security import NetworkSecurity
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from router_config import get_home_ip, get_router_config, get_network_info
import yara as yara_module
import hashlib
import json
from pathlib import Path
# Import network monitor integration module
from network_monitor_integration import network_bp, get_monitored_network_directories, register_network_monitor_endpoints, set_network_monitor_instance
# Import network API bridge to fix YARA scanner connection
from network_api_bridge import register_network_api_bridge
import shutil

# Import YARA scanner functionality
from security.yara_scanner import load_yara_rules, scan_file_with_yara, scan_all_folders_with_yara
# Import network traffic monitoring module
from network_traffic_monitor import register_traffic_monitor_endpoints
# Import network endpoint handler
from network_endpoint import get_network_monitored_directories_handler
import re

# Setup global logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('antivirus.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('antivirus')

# Initialize Flask app
app = Flask(__name__)
CORS(app)


# Ensure the conditional startup status endpoint is always available.
# Returns the cached conditional_startup_state if present, otherwise a sensible default.
@app.route('/api/conditional_startup/status', methods=['GET'])
def conditional_startup_status_api():
    """Status of the last conditional startup run (guaranteed JSON).
    This duplicates the intended endpoint if it wasn't registered earlier.
    """
    state = globals().get('conditional_startup_state')
    if not state:
        # Minimal default response expected by the frontend
        return jsonify({
            'running': False,
            'last_run': None,
            'duration': None,
            'scanned_files': 0,
            'quarantined_files': 0,
            'errors': 0,
            'process_events': 0,
            'last_error': None,
            'network_monitor_running': bool(globals().get('network_monitor_running'))
        })

    # Copy and add runtime flags to avoid mutating original
    resp = dict(state)
    resp['network_monitor_running'] = bool(globals().get('network_monitor_running'))
    return jsonify(resp)

# Register network monitoring endpoints
register_network_monitor_endpoints(app)

# Register traffic monitoring endpoints
register_traffic_monitor_endpoints(app)

# Register network API bridge to fix YARA scanner connection
register_network_api_bridge(app)

# Add direct simple route for network monitored directories (needed by YARA scanner)
@app.route('/api/network/monitored_directories', methods=['GET'])
def simple_network_monitored_directories():
    """Simple endpoint to serve network monitored directories to YARA scanner"""
    # Define common monitored directories
    monitored_dirs = DEFAULT_MONITORED_DIRECTORIES
    
    # Build the response with directories info
    directories = []
    for dir_path in monitored_dirs:
        exists = os.path.exists(dir_path)
        accessible = exists and os.access(dir_path, os.R_OK)
        file_count = 0
        
        if accessible:
            try:
                # Count files in the directory
                file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
            except Exception as e:
                logging.warning(f"Error counting files in {dir_path}: {str(e)}")
        
        directories.append({
            'path': dir_path,
            'exists': exists,
            'accessible': accessible,
            'file_count': file_count
        })
    
    # Return data in the exact format the YARA scanner expects
    return jsonify({
        'success': True,
        'monitoring_status': {
            'enabled': network_monitor and network_monitor.is_running(),
            'last_scan': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_directories': len(directories),
            'directories': directories
        }
    })

# Add direct route for network monitored directories to ensure it's available
@app.route('/api/network/monitored_directories', methods=['GET'])
def network_monitored_directories():
    """Endpoint to get network monitored directories"""
    try:
        from network_endpoint import get_network_monitored_directories_handler
        return get_network_monitored_directories_handler(network_monitor)
    except Exception as e:
        # Fallback implementation in case of import errors
        import os
        import logging
        from datetime import datetime
        from flask import jsonify
        
        try:
            # Get timestamp for last scan
            last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Define a comprehensive set of monitored directories that cover common system areas
            monitored_dirs = [
                # System directories - critical for malware monitoring
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\drivers\\etc'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\config'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\wbem'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\tasks'),  # Scheduled tasks
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Prefetch'),
                
                # User directories - common for user-initiated malware
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming'),
                
                # Startup locations - critical for persistence mechanisms
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            ]
            
            # Build response data
            directories = []
            for dir_path in monitored_dirs:
                exists = os.path.exists(dir_path)
                accessible = exists and os.access(dir_path, os.R_OK)
                file_count = 0
                
                if accessible:
                    try:
                        file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                    except Exception:
                        pass
                
                directories.append({
                    'path': dir_path,
                    'exists': exists,
                    'accessible': accessible,
                    'file_count': file_count
                })
            
            return jsonify({
                'success': True,
                'monitoring_status': {
                    'enabled': True,
                    'last_scan': last_scan,
                    'total_directories': len(directories),
                    'directories': directories
                }
            })
            
        except Exception as e2:
            logging.error(f"Complete fallback error: {str(e2)}")
            return jsonify({
                'success': False,
                'error': str(e2),
                'monitoring_status': {
                    'enabled': False,
                    'directories': []
                }
            }), 500

# Initialize network monitor instance at module level
network_monitor = NetworkMonitor()

# Automatically start network monitoring for real-time protection
network_monitor.start()
logging.info("Network monitoring started automatically at application startup")

# Set network monitor instance for integration module
set_network_monitor_instance(network_monitor)

# Initialize DNS server and start it automatically
try:
    dns_server, dns_resolver = start_dns_server(allow_network=False)  # Localhost only for security
    logging.info("DNS server started automatically at application startup")
except Exception as e:
    logging.error(f"Failed to start DNS server: {str(e)}. This is normal if not running as administrator.")

# Network monitor endpoints are handled by the network_bp blueprint

# Add endpoints for traffic statistics
@app.route('/get_traffic_stats', methods=['GET'])
def get_traffic_stats():
    """Get network traffic statistics"""
    if network_monitor and network_monitor.is_running():
        return jsonify(network_monitor.get_traffic_stats())
    else:
        return jsonify({
            'error': 'Network monitoring is not running',
            'total_connections': 0,
            'inbound': 0,
            'outbound': 0,
            'active_ips': [],
            'protocols': {},
            'ports': {},
            'processes': {},
            'timestamp': time.time()
        })

@app.route('/get_c2_patterns', methods=['GET'])
def get_c2_patterns():
    """Get potential C2 patterns in network traffic"""
    if network_monitor and network_monitor.is_running():
        return jsonify(network_monitor.get_c2_patterns())
    else:
        return jsonify({
            'error': 'Network monitoring is not running',
            'potential_c2': [],
            'beaconing': [],
            'suspicious_connections': [],
            'timestamp': time.time()
        })

# Load environment variables
# Configure secret key for sessions
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    # Generate a new secret key if none exists
    SECRET_KEY = os.urandom(24)
    # Save to .env for future use
    with open('.env', 'a') as f:
        f.write(f'\nSECRET_KEY={SECRET_KEY.hex()}')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Load environment variables from .env file
basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'antivirus.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Register the network monitor integration blueprint
# Registration is handled via register_network_monitor_endpoints(app) to avoid double-registration
# app.register_blueprint(network_bp, url_prefix='/api/network')

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filepath = db.Column(db.String(500), nullable=False)
    result = db.Column(db.Text, nullable=False)  # Changed to Text to store larger JSON
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Set up folders for uploads and quarantine
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
QUARANTINE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Define default monitored directories for YARA scanning
DEFAULT_MONITORED_DIRECTORIES = [
    # User profile folders - common malware targets
    os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Pictures'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Videos'),
    
    # Temporary folders - common for dropper malware
    os.path.join(os.environ.get('TEMP', '')),
    os.path.join(os.environ.get('SYSTEMROOT', 'C:\Windows'), 'Temp'),
    
    # Startup locations - persistence mechanisms
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft\Windows\Start Menu\Programs\Startup'),
    
    # AppData locations - commonly abused for hiding malware
    os.path.join(os.environ.get('APPDATA', '')),
    os.path.join(os.environ.get('LOCALAPPDATA', '')),
    
    # System locations that might be compromised
    os.path.join(os.environ.get('SYSTEMROOT', 'C:\Windows'), 'System32'),
]

# Initialize encryption key
FERNET_KEY = os.getenv('FERNET_KEY')
if not FERNET_KEY:
    # Generate a new key if none exists
    FERNET_KEY = Fernet.generate_key()
    # Save to .env for future use
    with open('.env', 'a') as f:
        f.write(f'\nFERNET_KEY={FERNET_KEY.decode()}')

# Initialize Fernet instance
fernet = Fernet(FERNET_KEY)

def encrypt_message(message):
    """Encrypt a message using Fernet encryption."""
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    """Decrypt a message using Fernet encryption."""
    return fernet.decrypt(encrypted_message.encode()).decode()

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize security components after app
network_security = NetworkSecurity()

# Global variables for monitors
network_monitor = None
folder_watcher = None

# Flag to ensure initialization only happens once
_initialized = False

@app.before_request
def initialize_monitors():
    """Initialize network monitor and folder watcher."""
    global network_monitor, folder_watcher, _initialized
    if not _initialized:
        network_monitor = NetworkMonitor()
        network_monitor.start()
        
                # Get common directories to monitor
        home_dir = os.path.expanduser("~")
        common_dirs = [
            os.path.join(home_dir, "Downloads"),
            os.path.join(home_dir, "Desktop"),
            os.path.join(home_dir, "Documents")
        ]
        
        # Filter out non-existent directories
        directories = [d for d in common_dirs if os.path.exists(d) and os.path.isdir(d)]
        
        folder_watcher = FolderWatcher(directories)
        folder_watcher.start()

_initialized = True

# Initialize threat detection
class ThreatDetectionModel:
    def __init__(self):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('threat_detector.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('threat_detector')
        
        self.model = None
        self.logger.info("Initializing threat detection model")
        self.initialize_model()

    def initialize_model(self):
        """Initialize machine learning model."""
        try:
            # Load pre-trained model (in a real app, this would be a proper ML model)
            self.model = sklearn.base.BaseEstimator()
            self.logger.info("ML model initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing ML model: {str(e)}")

    def scan_file(self, file_path):
        """Scan a file for threats using the security module's YARA scanner."""
        try:
            # Import the scanner from the security module
            from security.yara_scanner import scan_file_with_yara
            
            # Use the proven working scanner
            self.logger.info(f"Scanning file with YARA: {file_path}")
            matches = scan_file_with_yara(file_path, timeout=5)  # Use a reasonable timeout
            
            if matches and len(matches) > 0:
                # Convert the match objects to a simplified dictionary
                match_info = []
                for match in matches:
                    rule_name = getattr(match, 'rule', 'Unknown rule')
                    match_info.append({
                        'rule': rule_name,
                        'meta': getattr(match, 'meta', {}),
                        'strings': getattr(match, 'strings', [])
                    })
                self.logger.warning(f"YARA match found in {file_path}: {[m['rule'] for m in match_info]}")
                return {'threat': True, 'matches': match_info}
            
            self.logger.info(f"No YARA matches found in {file_path}")
            return {'threat': False}
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
            return {'threat': False}

# Initialize threat detection
threat_detector = ThreatDetectionModel()

# Initialize admin user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    """Main dashboard page."""
    # Get system status
    system_status = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    }
    
    # Get recent scan results
    # Use explicit column selection to avoid querying for columns that don't exist
    recent_scans = db.session.query(
        ScanResult.id,
        ScanResult.filepath,
        ScanResult.result,
        ScanResult.timestamp
    ).order_by(ScanResult.timestamp.desc()).limit(10).all()
    
    # Get network monitor status
    network_monitor_running = True
    if network_monitor is not None:
        network_monitor_running = getattr(network_monitor, 'running', False)
    
    # Get folder watcher status
    folder_watcher_status = folder_watcher.is_running
    
    return render_template(
        'index.html',
        network_monitor_running=network_monitor_running,
        folder_watcher_status=folder_watcher_status,
        safe_downloader_status=False,
        auto_updates_running=False,
        c2_detector_low_count=0,
        c2_detector_high_count=0,
        scheduled_scan_enabled=False,
        status=system_status,
        recent_scans=recent_scans
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:  # In a real app, use proper password hashing
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/yara_scanner.html')
def yara_scanner_page():
    """Serve the YARA scanner interface"""
    # Load YARA rules for scanner
    rules = load_yara_rules()
    rules_info = {
        'count': len(rules) if rules else 0,
        'status': 'Loaded' if rules else 'Error'
    }
    
    # Get monitored folders
    monitored_folders = DEFAULT_MONITORED_DIRECTORIES
    
    return render_template('yara_scanner.html', 
                           rules_info=rules_info,
                           monitored_folders=monitored_folders)

@app.route('/yara_scan', methods=['POST'])
def yara_scan():
    """Handle YARA scanning requests"""
    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'file')
        
        if scan_type == 'file':
            # Check if file was uploaded
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
                
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
                
            # Save uploaded file
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Scan file
            start_time = time.time()
            matches = scan_file_with_yara(file_path)
            scan_time = time.time() - start_time
            
            # Process results
            results = []
            if matches:
                for match in matches:
                    rule_name = getattr(match, 'rule', 'Unknown rule')
                    meta = getattr(match, 'meta', {})
                    results.append({
                        'rule': rule_name,
                        'description': meta.get('description', 'No description'),
                        'file': file_path
                    })
                    
                # If suspicious, quarantine the file
                if results:
                    try:
                        # Create quarantine data
                        quarantine_data = {
                            'matches': [r['rule'] for r in results],
                            'descriptions': [r.get('description', '') for r in results],
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        
                        # Quarantine file
                        quarantine_suspicious_file(file_path, quarantine_data)
                    except Exception as e:
                        logger.error(f"Error quarantining file: {e}")
                    
            return jsonify({
                'file': file_path,
                'matches': len(results),
                'scan_time': f"{scan_time:.2f}s",
                'results': results,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        
        elif scan_type == 'all_folders':
            # Scan all monitored directories
            start_time = time.time()
            scan_data = scan_all_folders_with_yara(DEFAULT_MONITORED_DIRECTORIES)
            scan_time = time.time() - start_time
            
            # The scan_data now contains a dictionary with 'results' and 'stats' keys
            results = scan_data.get('results', [])
            stats = scan_data.get('stats', {})
            
            # Process and return results with enhanced statistics
            return jsonify({
                'folders': DEFAULT_MONITORED_DIRECTORIES,
                'matches': stats.get('total_matches', 0),
                'scan_time': f"{scan_time:.2f}s",
                'results': results,
                'stats': stats,
                'total_files_scanned': stats.get('total_files_scanned', 0),
                'total_high_risk_files': stats.get('total_high_risk_files', 0),
                'total_subdirectories': stats.get('total_subdirectories', 0),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            
    return jsonify({'error': 'Invalid request'}), 400

@app.route('/quarantine')
def view_quarantine():
    """View quarantined files"""
    # We'll use direct file system access instead of the database model 
    # to avoid issues with schema differences
    quarantined_files = []
    
    # Create quarantine folder if it doesn't exist
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    
    # Check quarantine folder for encrypted files
    try:
        for filename in os.listdir(QUARANTINE_FOLDER):
            if filename.endswith('.enc'):  # Only look at encrypted quarantined files
                file_path = os.path.join(QUARANTINE_FOLDER, filename)
                size = os.path.getsize(file_path)
                date_quarantined = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                
                # Look for metadata file
                metadata = {}
                json_path = file_path + '.json'
                if os.path.exists(json_path):
                    try:
                        with open(json_path, 'r') as f:
                            metadata = json.load(f)
                    except Exception as e:
                        logger.error(f"Error reading metadata for {filename}: {e}")
                
                # Build quarantined file info
                quarantined_files.append({
                    'name': filename.replace('.enc', ''),
                    'size': size,
                    'date_quarantined': metadata.get('quarantine_time', date_quarantined),
                    'original_path': metadata.get('original_path', 'Unknown'),
                    'detection_info': metadata.get('detection_info', {})
                })
    except Exception as e:
        logger.error(f"Error listing quarantine folder: {e}")
    
    # Get quarantine log
    quarantine_log = ''
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine.log')
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                quarantine_log = f.read()
        except Exception as e:
            logger.error(f"Error reading quarantine log: {e}")
    
    return render_template('quarantine.html', 
                           quarantined_files=quarantined_files,
                           quarantine_log=quarantine_log)
                           
def quarantine_suspicious_file(file_path, detection_info):
    """Quarantine a suspicious file detected by YARA scanning
    
    Args:
        file_path (str): Path to the suspicious file
        detection_info (dict): Information about the detection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check if the file exists
        if not os.path.exists(file_path):
            logger.error(f"Cannot quarantine non-existent file: {file_path}")
            return False
            
        # Create unique filename in quarantine
        quarantine_filename = os.path.basename(file_path) + '.enc'
        quarantine_path = os.path.join(QUARANTINE_FOLDER, quarantine_filename)
        
        # Log the quarantine action
        logger.warning(f"Quarantining suspicious file: {file_path}")
        
        # Encrypt and move file to quarantine
        key = os.environ.get('FERNET_KEY')
        if not key:
            logger.error("Encryption key not found")
            return False
            
        # Read file content
        with open(file_path, 'rb') as f:
            file_content = f.read()
            
        # Encrypt content
        fernet = Fernet(key)
        encrypted_content = fernet.encrypt(file_content)
        
        # Write to quarantine
        with open(quarantine_path, 'wb') as f:
            f.write(encrypted_content)
            
        # Add to database - include quarantine info in the result JSON
        detection_info['quarantined'] = True
        detection_info['quarantine_path'] = quarantine_path
        
        scan_result = ScanResult(
            filepath=file_path,
            result=json.dumps(detection_info),
            timestamp=datetime.utcnow()
        )
        db.session.add(scan_result)
        db.session.commit()
        
        # Try to delete original file
        try:
            os.remove(file_path)
            logger.info(f"Deleted original suspicious file: {file_path}")
        except Exception as e:
            logger.error(f"Could not delete original file: {str(e)}")
            
        # Log quarantine action
        with open('quarantine.log', 'a') as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Quarantined: {file_path} - Reason: {detection_info.get('matches', ['Unknown'])}\n")
        
        return True
    except Exception as e:
        logger.error(f"Error quarantining file: {str(e)}")
        return False

@app.route('/logout')
@login_required
def logout():
    """Logout route."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/network')
@login_required
def network():
    """Network monitoring page."""
    network_info = network_monitor.get_network_info()
    return render_template('network.html', network_info=network_info)

@app.route('/scan')
@login_required
def scan():
    """Run a manual scan."""
    from security.detector import detector
    
    # Scan system directories
    scan_dirs = [
        os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'System32'),
        os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'Temp'),
        os.path.join(os.environ.get('USERPROFILE', r'C:\Users\Default'), 'Downloads')
    ]
    
    # Get all YARA matches
    scan_data = scan_all_folders_with_yara(scan_dirs)
    yara_results = scan_data.get('results', []) if isinstance(scan_data, dict) else scan_data
    
    # Process results with ML analysis
    results = []
    for result in yara_results:
        try:
            file_path = result.split("YARA match:", 1)[1].strip()
            if os.path.exists(file_path):
                # Get ML prediction
                prediction = detector.predict([file_path])
                anomaly_score = detector.get_anomaly_score(file_path)
                
                if prediction[0] == -1:  # If ML predicts malicious
                    results.append({
                        'file': file_path,
                        'size': os.path.getsize(file_path),
                        'ml_prediction': 'malicious',
                        'anomaly_score': float(anomaly_score),
                        'is_malicious': True
                    })
        except Exception as e:
            logger.error(f"Error processing scan result {result}: {str(e)}")
            continue
    
    return jsonify({'results': results})

# This function has been replaced with the scan route above
# The functionality is now handled by scan_all_folders_with_yara and the detector

# Initialize folder watcher configuration
MONITORED_DIRECTORIES = [
    os.path.join(os.environ.get('USERPROFILE', r'C:\Users\Default'), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', r'C:\Users\Default'), 'Desktop'),
    os.path.join(os.environ.get('USERPROFILE', r'C:\Users\Default'), 'Documents'),
    os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'Temp')
]

# Initialize folder watcher
class FolderWatcher:
    def __init__(self, directories):
        # Setup logging for this class
        self.logger = logging.getLogger('folder_watcher')
        self.logger.setLevel(logging.INFO)
        
        # Add file handler
        file_handler = logging.FileHandler('folder_watcher.log')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)
        
        self.directories = directories
        self.is_running = False
        self.monitor_thread = None

    def start(self):
        if not self.is_running:
            self.is_running = True
            self.monitor_thread = threading.Thread(target=self.monitor_directories, daemon=True)
            self.monitor_thread.start()

    def stop(self):
        self.is_running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join()

    def monitor_directories(self):
        while self.is_running:
            for directory in self.directories:
                if os.path.exists(directory):
                    try:
                        # Check for new files
                        for root, _, files in os.walk(directory):
                            for file in files:
                                file_path = os.path.join(root, file)
                                # Check if file is new or modified
                                if self.is_file_suspicious(file_path):
                                    self.handle_suspicious_file(file_path)
                    except Exception as e:
                        self.logger.error(f"Error monitoring {directory}: {str(e)}")
            time.sleep(5)  # Check every 5 seconds

    def is_file_suspicious(self, file_path):
        """Check if a file is suspicious based on various criteria."""
        try:
            # Basic checks
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # > 100MB
                return True
                
            # Check file extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.exe', '.dll', '.sys', '.bat', '.cmd']:
                return True
                
            # Check file modification time
            mod_time = os.path.getmtime(file_path)
            if time.time() - mod_time < 60:  # Modified in last minute
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking file {file_path}: {str(e)}")
            return True

    def handle_suspicious_file(self, file_path):
        """Handle suspicious files by quarantining them."""
        try:
            # Define quarantine folder
            QUARANTINE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine')
            os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
            
            # Perform YARA scan
            from security.yara_scanner import scan_file_with_yara
            yara_results = scan_file_with_yara(file_path)
            is_suspicious = bool(yara_results)
            if is_suspicious:
                self.logger.warning(f"Suspicious file detected: {file_path}")
                
                # Quarantine the file
                try:
                    # Create a unique filename in quarantine
                    quarantine_path = os.path.join(QUARANTINE_FOLDER, 
                                                 f"quarantined_{os.path.basename(file_path)}_{int(time.time())}")
                    
                    # Move the file to quarantine
                    shutil.move(file_path, quarantine_path)
                    self.logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
                except Exception as e:
                    self.logger.error(f"Error quarantining file: {str(e)}")
                    return False
                
                # Encrypt the quarantined file
                key = os.environ.get('FERNET_KEY')
                if not key:
                    self.logger.error("Encryption key not found")
                    return False
                
                # Read file content from quarantine
                with open(quarantine_path, 'rb') as f:
                    file_content = f.read()
                
                # Encrypt content
                fernet = Fernet(key)
                encrypted_content = fernet.encrypt(file_content)
                
                # Write encrypted content back to quarantine file (overwrite)
                with open(quarantine_path, 'wb') as f:
                    f.write(encrypted_content)
                
                # Add to database within app context
                with app.app_context():
                    scan_result = ScanResult(
                        filepath=file_path,
                        result=json.dumps([
                            {
                                'rule': getattr(m, 'rule', 'Unknown rule'),
                                'meta': getattr(m, 'meta', {}),
                                'strings': getattr(m, 'strings', [])
                            } for m in yara_results
                        ]),
                        timestamp=datetime.utcnow(),
                        quarantined=True,
                        quarantine_path=quarantine_path
                    )
                    db.session.add(scan_result)
                    db.session.commit()
                
                # Try to delete original file
                try:
                    os.remove(file_path)
                except Exception as e:
                    self.logger.error(f"Could not delete original file: {str(e)}")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error handling suspicious file {file_path}: {str(e)}")
            return False

# Initialize folder watcher
folder_watcher = FolderWatcher(MONITORED_DIRECTORIES)

# Start folder watcher
folder_watcher.start()

# Start scheduled scanning in a separate thread
def migrate_database():
    """Perform necessary database migrations for new fields"""
    try:
        with app.app_context():
            # Check if we need to add the new quarantine columns
            inspector = db.inspect(db.engine)
            columns = [c['name'] for c in inspector.get_columns('scan_result')]
            
            if 'quarantined' not in columns or 'quarantine_path' not in columns:
                logger.info("Migrating database to add quarantine columns")
                # For SQLite, we need to recreate the table with the new columns
                # Back up existing data
                results = ScanResult.query.all()
                old_data = []
                for result in results:
                    old_data.append({
                        'filepath': result.filepath,
                        'result': result.result,
                        'timestamp': result.timestamp
                    })
                
                # Drop and recreate table
                db.drop_all()
                db.create_all()
                
                # Restore data to new schema
                for data in old_data:
                    result = ScanResult(
                        filepath=data['filepath'],
                        result=data['result'],
                        timestamp=data['timestamp'],
                        quarantined=False,
                        quarantine_path=None
                    )
                    db.session.add(result)
                
                db.session.commit()
                logger.info("Database migration completed successfully")
    except Exception as e:
        logger.error(f"Error migrating database: {e}")

if __name__ == '__main__':
    # Create database tables and perform migrations
    with app.app_context():
        db.create_all()
        migrate_database()
        
        # Create admin user if it doesn't exist
        admin_username = os.getenv('ADMIN_USERNAME')
        admin_password = os.getenv('ADMIN_PASSWORD')
        
        if not admin_username or not admin_password:
            # Generate secure default credentials if not set in .env
            admin_username = 'admin_' + hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
            admin_password = hashlib.sha256(str(time.time()).encode()).hexdigest()
            
            # Save to .env for future use
            with open('.env', 'a') as f:
                f.write(f'\nADMIN_USERNAME={admin_username}')
                f.write(f'\nADMIN_PASSWORD={admin_password}')

        admin_user = User.query.filter_by(username=admin_username).first()
        if not admin_user:
            admin_user = User(username=admin_username, password=admin_password)
            db.session.add(admin_user)
            db.session.commit()

    # Start folder watcher
    folder_watcher = FolderWatcher(MONITORED_DIRECTORIES)
    folder_watcher.start()
    
    # Try to open browser to the web interface
    try:
        webbrowser.open('http://localhost:5000')
    except Exception as e:
        logger.error(f"Error opening browser: {e}")
    
    # Start Flask app with improved error handling
    try:
        # Check if port is in use
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 5000))
        if result == 0:
            logger.warning("Port 5000 is already in use. Trying to use port 5001 instead.")
            print("\nWARNING: Port 5000 appears to be in use. Using port 5001 instead.")
            print("Open your browser to http://localhost:5001\n")
            app.run(debug=True, port=5001, use_reloader=False)
        else:
            print("\nStarting server on http://localhost:5000\n")
            app.run(debug=True, port=5000, use_reloader=False)
        sock.close()
    except OSError as e:
        logger.error(f"Socket error when starting Flask: {e}")
        print(f"\nSocket error: {e}\n")
        print("Trying alternate method to start server...")
        try:
            # Try with threaded=False as fallback
            app.run(debug=True, port=5001, threaded=False, use_reloader=False)
        except Exception as e2:
            logger.error(f"Second attempt to start Flask failed: {e2}")
            print(f"\nFailed to start server: {e2}\nTry manually running the application with 'python quick_start.py' instead.")
    except Exception as e:
        logger.error(f"Error starting Flask: {e}")
        print(f"\nError starting server: {e}\n")
        print("Try manually running the application with 'python quick_start.py' instead.")


def decrypt_message(encrypted_message):
    """Decrypt a message using Fernet encryption."""
    return fernet.decrypt(encrypted_message.encode()).decode()



from security.process_monitor import scan_running_processes
from security.log_utils import setup_secure_logging
from ml_security import SecurityMLModel
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('antivirus.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('antivirus')

# Load environment variables from .env file
basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# Initialize admin credentials from environment variables

# Initialize security components
# Setup secure logging
logger = setup_secure_logging('antivirus.log')

# Check scikit-learn version compatibility
required_sklearn_version = '1.6.1'
if sklearn.__version__ != required_sklearn_version:
    print(f"Warning: Using scikit-learn version {sklearn.__version__}, but models were trained with {required_sklearn_version}")
    print("This might lead to breaking code or invalid results.")

# Initialize security components
# We've already imported YARA scanner functionality at the top of the file

# Initialize security components
network_security = NetworkSecurity()
network_monitor = NetworkMonitor()
network_monitor.start()

# Initialize security model with specialized models
models_dir = os.path.join(basedir, 'models')
malware_model_path = os.path.join(models_dir, 'malware_model.pkl')
malware_pca_path = os.path.join(models_dir, 'malware_pca.pkl')
malware_scaler_path = os.path.join(models_dir, 'malware_scaler.pkl')

# Initialize security model with specialized components
security_model = SecurityMLModel(
    model_path=malware_model_path,
    pca_path=malware_pca_path,
    scaler_path=malware_scaler_path
)

# Initialize process monitoring
PROCESS_WHITELIST = {
    'explorer.exe', 'svchost.exe', 'lsass.exe', 'winlogon.exe',
    'csrss.exe', 'spoolsv.exe', 'services.exe', 'smss.exe'
}

# Initialize network monitoring
NETWORK_RULES = {
    'malicious_domains': {
        'example.malware.com', 'bad-site.com'
    },
    'suspicious_ports': {
        21, 22, 23, 25, 8080, 8443
    }
}

# Scanning functions
def perform_yara_scan():
    """Perform YARA-based malware scanning with ML analysis."""
    if not YARA_RULES_FILE:
        return "YARA rules file not found"
    
    results = []
    # Scan system directories
    scan_dirs = [
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Downloads')
    ]
    
    try:
        scan_data = scan_all_folders_with_yara(scan_dirs, YARA_RULES_FILE)
        scan_results = scan_data.get('results', []) if isinstance(scan_data, dict) else scan_data
        for result in scan_results:
            if "YARA match" in result:
                file_path = result.split("YARA match:", 1)[1].strip()
                # Extract features for ML analysis
                features = [
                    os.path.getsize(file_path),  # File size
                    os.path.getmtime(file_path),  # Last modified time
                    os.path.getctime(file_path),  # Creation time
                    len(os.path.dirname(file_path)),  # Path length
                    os.path.splitext(file_path)[1] in ['.exe', '.dll', '.sys']  # Binary file
                ]
                
                # Convert to numpy array for ML model
                features_array = np.array(features).reshape(1, -1)
                
                # Use ML model to analyze
                prediction = security_model.pipeline.predict(features_array)
                anomaly_score = security_model.pipeline.decision_function(features_array)[0]
                
                results.append({
                    'file': file_path,
                    'size': os.path.getsize(file_path),
                    'ml_prediction': 'malicious' if prediction[0] == -1 else 'benign',
                    'anomaly_score': float(anomaly_score),
                    'is_malicious': prediction[0] == -1
                })
    except Exception as e:
        logger.error(f"Error performing YARA scan: {e}")
        return str(e)
    
    return json.dumps(results, indent=2) if results else "No malware detected"

def perform_scan():
    """Perform comprehensive security scan with ML analysis."""
    results = []
    
    # Scan system directories
    scan_dirs = [
        os.path.join(os.environ.get('WINDIR', ''), 'System32'),
        os.path.join(os.environ.get('WINDIR', ''), 'Temp'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp')
    ]

    # Initialize ML model
    try:
        model = load_ml_model()
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        return str(e)

    # Scan each directory
    for directory in scan_dirs:
        if not os.path.exists(directory):
            continue

        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Skip system files and large files
                        if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB
                            continue
                        if file.lower().endswith(('.exe', '.dll', '.sys')):
                            continue

                        # Perform file analysis
                        file_results = analyze_file(file_path, model)
                        if file_results:
                            results.extend(file_results)

                        # Check file integrity
                        if not verify_file_integrity(file_path):
                            results.append({
                                'file': file_path,
                                'status': 'suspicious',
                                'reason': 'File integrity check failed'
                            })

                    except Exception as e:
                        logger.error(f"Error scanning {file_path}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
            continue

    # Check running processes
    try:
        process_results = scan_monitored_processes()
        if process_results:
            results.extend(process_results)
    except Exception as e:
        logger.error(f"Error scanning processes: {e}")

    # Check network connections
    try:
        network_results = scan_network_connections()
        if network_results:
            results.extend(network_results)
    except Exception as e:
        logger.error(f"Error scanning network connections: {e}")

    # Check registry for suspicious entries
    try:
        registry_results = scan_registry()
        if registry_results:
            results.extend(registry_results)
    except Exception as e:
        logger.error(f"Error scanning registry: {e}")

    # Check system logs for suspicious events
    try:
        log_results = scan_system_logs()
        if log_results:
            results.extend(log_results)
    except Exception as e:
        logger.error(f"Error scanning system logs: {e}")

    return json.dumps({
        'status': 'completed',
        'results': results,
        'timestamp': datetime.now().isoformat()
    }, indent=2)

def scan_processes():
    """Scan running processes for suspicious activity."""
    results = []
    
    try:
        # Use the existing process monitor
        process_results = scan_running_processes()
        for result in process_results:
            if "malicious" in result.lower():
                results.append({
                    'process': result,
                    'type': 'Suspicious process'
                })
    except Exception as e:
        logger.error(f"Error scanning processes: {e}")
        return str(e)
    
    return json.dumps(results, indent=2) if results else "No suspicious processes detected"

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

# Initialize Flask app
app = Flask(__name__)

# Configure secret key for sessions
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    # Generate a new secret key if none exists
    SECRET_KEY = os.urandom(24)
    # Save to .env for future use
    with open('.env', 'a') as f:
        f.write(f'\nSECRET_KEY={SECRET_KEY.hex()}')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User loader callback


# Authentication route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            user = User('admin')
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

# Authentication functions
def set_admin_credentials(username, password):
    """Securely set admin credentials."""
    global _admin_credentials
    _admin_credentials = (username, password)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if user is logged in via session
        if current_user.is_authenticated:
            return f(*args, **kwargs)
            
        # Check if Basic Auth is provided
        auth = request.authorization
        if auth and auth.type == 'basic':
            if check_auth(auth.username, auth.password):
                return f(*args, **kwargs)
        
        return authenticate()
    return decorated

# Update Flask app with proper template and static folders (app already initialized at top)
app.template_folder = os.path.join(os.path.dirname(__file__), 'templates')
app.static_folder = os.path.join(os.path.dirname(__file__), 'static')

# Configure secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id



# Global folder paths
ENCRYPTED_FOLDER = os.path.join(os.path.dirname(__file__), 'encrypted_files')
QUARANTINE_FOLDER = os.path.join(os.path.dirname(__file__), 'quarantine')

# Global variables for service states
network_monitor_running = True
folder_watcher_running = True
safe_downloader_running = True
auto_updates_running = True

# Initialize application
# Add routes
@app.route('/')
@requires_auth
def index():
    """Serve the main dashboard"""
    # Get C2 detector status
    c2_detector_low_count = 0
    try:
        c2_status = network_monitor.get_c2_detector_status()
        c2_detector_low_count = c2_status.get('low_count', 0)
    except Exception as e:
        logging.error(f"Error getting C2 detector status: {e}")

    # Get network monitor status
    network_monitor_running = hasattr(network_monitor, '_monitor_thread') and network_monitor._monitor_thread.is_alive()

    # Get real-time status with all required parameters
    from status import get_realtime_status
    status = get_realtime_status(
        folder_watcher=folder_watcher,
        network_monitor_running=network_monitor_running,
        safe_download_service=safe_download_service,
        rtp_status_flag=rtp_status_flag
    )

    return render_template(
        'index.html',
        status=status,
        c2_detector_low_count=c2_detector_low_count,
        network_monitor_running=network_monitor_running
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/toggle_network_monitor/<action>', methods=['POST'])
@login_required
def toggle_network_monitor(action):
    global network_monitor_running
    if action == 'start':
        network_monitor_running = True
    elif action == 'stop':
        network_monitor_running = False
    return jsonify({
        'status': 'success',
        'running': network_monitor_running
    })

@app.route('/start_traffic_monitoring', methods=['POST'])
@login_required
def start_traffic_monitoring():
    # Import the traffic monitoring start function
    from network_traffic_monitor import start_traffic_monitoring as start_traffic_stats
    
    # Start traffic monitoring
    success = start_traffic_stats()
    
    # Return success response
    return jsonify({
        'status': 'success' if success else 'warning',
        'message': 'Traffic monitoring started' if success else 'Traffic monitoring is already running'
    })

@app.route('/stop_traffic_monitoring', methods=['POST'])
def stop_traffic_monitoring():
    # Import the traffic monitoring stop function
    from network_traffic_monitor import stop_traffic_monitoring as stop_traffic_stats
    
    # Stop traffic monitoring
    success = stop_traffic_stats()
    
    # Return success response
    return jsonify({
        'status': 'success' if success else 'warning',
        'message': 'Traffic monitoring stopped' if success else 'Traffic monitoring is not running'
    })


@app.route('/toggle_folder_watcher/<action>', methods=['POST'])
@login_required
def toggle_folder_watcher(action):
    global folder_watcher_running
    if action == 'start':
        folder_watcher_running = True
    elif action == 'stop':
        folder_watcher_running = False
    return jsonify({
        'status': 'success',
        'running': folder_watcher_running
    })

@app.route('/c2_detector_report')
@login_required
def c2_detector_report():
    return jsonify({
        'status': 'success',
        'low_count': c2_detector_low_count,
        'high_count': c2_detector_high_count
    })

@app.route('/antivirus_log')
@login_required
def antivirus_log():
    # Initialize log entries if not already set
    if 'log_entries' not in globals():
        global log_entries
        log_entries = []
    
    return jsonify({
        'status': 'success',
        'log_entries': log_entries
    })

@app.route('/safe_downloader_details')
@login_required
def safe_downloader_details():
    # Initialize safe downloader details if not already set
    if 'safe_downloader_status' not in globals():
        global safe_downloader_status
        safe_downloader_status = 'Inactive'
    
    if 'last_scan_time' not in globals():
        global last_scan_time
        last_scan_time = datetime.datetime.now()
    
    if 'blocked_downloads' not in globals():
        global blocked_downloads
        blocked_downloads = []
    
    return jsonify({
        'status': 'success',
        'downloader_status': safe_downloader_status,
        'last_scan_time': last_scan_time.isoformat(),
        'blocked_downloads': blocked_downloads
    })

@app.route('/quarantine')
@login_required
def quarantine():
    # Initialize quarantine files if not already set
    if 'quarantine_files' not in globals():
        global quarantine_files
        quarantine_files = []
    
    return jsonify({
        'status': 'success',
        'files': quarantine_files
    })

@app.route('/toggle_safe_downloader/<action>', methods=['POST'])
@login_required
def toggle_safe_downloader(action):
    global safe_downloader_running
    if action == 'start':
        safe_downloader_running = True
    elif action == 'stop':
        safe_downloader_running = False
    return jsonify({'status': 'success', 'running': safe_downloader_running})

@app.route('/toggle_auto_updates/<action>', methods=['POST'])
@login_required
def toggle_auto_updates(action):
    global auto_updates_running
    if action == 'start':
        auto_updates_running = True
    elif action == 'stop':
        auto_updates_running = False
    return jsonify({'status': 'success', 'running': auto_updates_running})


@app.route('/network-info')
def network_info():
    """Get network information in JSON format"""
    info = {
        'home_ip': get_home_ip(),
        'router_ip': get_router_config(),
        'interfaces': get_network_info()
    }
    return jsonify(info)

@app.route('/favicon.ico')
def favicon():
    try:
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    except Exception:
        # Return a default favicon if the custom one is missing or invalid
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon', cache_timeout=0)

import os
import sys
import subprocess
import redis
from redis import Redis
from redis.exceptions import ConnectionError

# --- Automatically start Redis server on Windows if not running ---
def start_redis_server():
    if sys.platform.startswith('win'):
        import psutil
        redis_running = any('redis-server.exe' in (p.name() or '') for p in psutil.process_iter())
        if not redis_running:
            try:
                redis_path = r'C:\Redis\redis-server.exe'
                if os.path.exists(redis_path):
                    subprocess.Popen([redis_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
                    print('Redis server started automatically.')
                else:
                    print(f'Redis server executable not found at {redis_path}.')
            except Exception as e:
                print(f'Failed to start Redis server: {e}')

start_redis_server()
# Initialize global variables
rtp_status_flag = None  # 'STARTING', 'ENABLED', or None
folder_watcher_process = None

# Initialize Redis connection with fallback to in-memory storage
redis_client = None
try:
    redis_client = Redis(host='localhost', port=6379, decode_responses=True)
    redis_client.ping()  # Test connection
    print("Redis connection established successfully")
except ConnectionError:
    print("Redis not available, using in-memory storage")
    redis_client = None

# Function to load scan directories
def load_scan_directories():
    """Load directories to monitor for scanning"""
    # Default directories to monitor
    default_directories = [
        os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'Documents')
    ]
    
    # Try to load from Redis if available
    if redis_client:
        try:
            saved_dirs = redis_client.get('scan_directories')
            if saved_dirs:
                return json.loads(saved_dirs)
        except Exception as e:
            print(f"Error loading from Redis: {e}")
    
    return default_directories

# Initialize monitored directories
monitored_directories = load_scan_directories()
redis_client = None

# Initialize folder watcher class
class FolderWatcher:
    def __init__(self, directories=None):
        self.directories = directories if directories is not None else []
        self.is_alive = True  # Simulate process-like behavior
    
    def add_directory(self, directory):
        """Dynamically add a directory to the watcher."""
        if os.path.exists(directory) and directory not in self.directories:
            self.directories.append(directory)
            logging.info(encrypt_message(f"Added directory to watch: {directory}"))
    
    def get_directories(self):
        """Return the list of directories being watched."""
        return self.directories

# Create a single instance of the folder watcher
# Get common directories to monitor
home_dir = os.path.expanduser("~")
common_dirs = [
    os.path.join(home_dir, "Downloads"),
    os.path.join(home_dir, "Desktop"),
    os.path.join(home_dir, "Documents")
]

# Filter out non-existent directories
directories = [d for d in common_dirs if os.path.exists(d) and os.path.isdir(d)]

folder_watcher = FolderWatcher(directories)

# Initialize monitored directories
monitored_directories = load_scan_directories()
folder_watcher.directories = monitored_directories
from phishing_live_feeds import update_all_blocklists
from file_crypto import encrypt_file, decrypt_file
from network_monitor_base import NetworkMonitor
from network_security import NetworkSecurityManager
from utils.paths import get_resource_path
from folder_watcher import load_scan_directories
from safe_downloader import extract_archive
from antivirus_cli import scan_file_for_viruses_with_test_flag, file_hashes
from advanced_threat_detector import detector
import conditional_startup
import psutil
import logging
import platform
import tempfile
import shutil
import zipfile
import rarfile
from dns_server import start_dns_server
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Configure secret key for sessions
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    # Generate a new secret key if none exists
    SECRET_KEY = os.urandom(24)
    # Save to .env for future use
    with open('.env', 'a') as f:
        f.write(f'\nSECRET_KEY={SECRET_KEY.hex()}')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
CORS(app)  # Enable CORS for all routes

# Initialize security components
network_security = NetworkSecurityManager.get_instance()
network_security.enable_encryption()  # Enable encryption
network_monitor = NetworkMonitor()

# Authentication functions
def check_auth(username, password):
    """This function is called to check if a username / password combination is valid."""
    return username == 'admin' and password == os.getenv('ADMIN_PASSWORD', 'default_admin_password')

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Route handlers
@app.route('/')
@requires_auth
def index():
    """Serve the main dashboard"""
    # Get C2 detector status
    c2_detector_low_count = 0
    try:
        c2_status = network_monitor.get_c2_detector_status()
        c2_detector_low_count = c2_status.get('low_count', 0)
    except Exception as e:
        logging.error(f"Error getting C2 detector status: {e}")

    # Get network monitor status
    network_monitor_running = hasattr(network_monitor, '_monitor_thread') and network_monitor._monitor_thread.is_alive()

    # Get real-time status with all required parameters
    from status import get_realtime_status
    status = get_realtime_status(
        folder_watcher=folder_watcher,
        network_monitor_running=network_monitor_running,
        safe_download_service=safe_download_service,
        rtp_status_flag=rtp_status_flag
    )

    return render_template(
        'index.html',
        status=status,
        c2_detector_low_count=c2_detector_low_count,
        network_monitor_running=network_monitor_running
    )

# Route for conditional startup
# Most recent conditional startup run, exposed to the UI via /api/conditional_startup/status
conditional_startup_state = {
    'running': False,
    'last_run': None,
    'duration': None,
    'scanned_files': 0,
    'quarantined_files': 0,
    'errors': 0,
    'process_events': 0,
    'last_error': None,
}


def normalize_conditional_startup_data(scan_data):
    """Return conditional startup output as a (results dict, log text) pair.

    run_conditional_startup_logic() returns a dict, but falls back to a plain
    log string when scan utilities cannot be loaded.
    """
    if isinstance(scan_data, dict):
        return scan_data, scan_data.get('log', '')
    if isinstance(scan_data, (list, tuple)):
        log = '\n'.join(str(item) for item in scan_data)
        return {}, log
    return {}, '' if scan_data is None else str(scan_data)


def record_conditional_startup_run(scan_data=None, duration=None, error=None):
    """Update the cached conditional startup status shown in the UI."""
    results, _ = normalize_conditional_startup_data(scan_data)

    def count(key):
        value = results.get(key) or []
        return len(value) if isinstance(value, (list, tuple, dict)) else 0

    conditional_startup_state.update({
        'running': False,
        'last_run': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'duration': round(duration, 2) if duration is not None else None,
        'scanned_files': count('scanned_files'),
        'quarantined_files': count('quarantined_files'),
        'errors': count('errors'),
        'process_events': count('process_events'),
        'last_error': str(error) if error else None,
    })
    return conditional_startup_state


@app.route('/api/conditional_startup/status', methods=['GET'])
def conditional_startup_status():
    """Status of the last conditional startup run, plus network monitor state."""
    state = dict(conditional_startup_state)
    state['network_monitor_running'] = bool(globals().get('network_monitor_running'))
    return jsonify(state)


@app.route('/run_startup', methods=['POST'])
def run_startup():
    """Run conditional startup scans (all monitored directories and all processes)"""
    try:
        from conditional_startup import run_conditional_startup_logic
        conditional_startup_state['running'] = True
        start_time = time.time()
        scan_data = run_conditional_startup_logic(open_browser=False)
        duration = time.time() - start_time
        record_conditional_startup_run(scan_data, duration)
        scan_data, _ = normalize_conditional_startup_data(scan_data)
        return jsonify({
            "status": "success",
            "results": scan_data.get("results", []),
            "errors": scan_data.get("errors", []),
            "log": scan_data.get("log", ""),
            "scanned_directories": load_scan_directories(),
            "scan_time": f"{duration:.2f} seconds",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        record_conditional_startup_run(error=e)
        return jsonify({"status": "error", "message": str(e)}), 500

# Route for conditional startup
@app.route('/run_conditional_startup', methods=['POST'])
@requires_auth
def run_conditional_startup_route():
    """Run conditional startup scans"""
    try:
        # Run the conditional startup logic
        results = conditional_startup.run_conditional_startup_logic(open_browser=False)
        return jsonify({
            'status': 'success',
            'scanned_files': results.get('scanned_files', []),
            'quarantined_files': results.get('quarantined_files', []),
            'errors': results.get('errors', []),
            'process_events': results.get('process_events', []),
            'log': results.get('log', ''),
            'message': 'Conditional startup completed successfully'
        })
    except Exception as e:
        logging.error(f"Error in conditional startup: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Removed duplicate scan_all_processes route since we have it in the root route

# Route for signature updates
@app.route('/update_signatures', methods=['POST'])
@requires_auth
def update_signatures_route():
    """Update malware signatures"""
    try:
        # Import and run signature update from antivirus_cli
        from antivirus_cli import update_signatures
        update_signatures()
        return jsonify({
            'status': 'success',
            'message': 'Malware signatures updated successfully'
        })
    except Exception as e:
        logging.error(f"Error updating signatures: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for file encryption/decryption
@app.route('/file_crypto', methods=['POST'])
@requires_auth
def file_crypto_route():
    """Handle file encryption/decryption requests"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'encrypt' or 'decrypt'
        file_path = data.get('file_path')
        
        if not action or not file_path:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        if action == 'encrypt':
            encrypt_file(file_path)
            return jsonify({
                'status': 'success',
                'message': f'File {file_path} encrypted successfully'
            })
        elif action == 'decrypt':
            decrypt_file(file_path)
            return jsonify({
                'status': 'success',
                'message': f'File {file_path} decrypted successfully'
            })
        else:
            return jsonify({'error': 'Invalid action specified'}), 400
            
    except Exception as e:
        logging.error(f"Error in file crypto: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to toggle network monitor
@app.route('/toggle_network_monitor/<action>', methods=['POST'])
@requires_auth
def toggle_network_monitor(action):
    """Toggle network monitor service on/off."""
    global network_monitor_running
    try:
        if action not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        network_monitor_running = (action == 'start')
        # Actually start/stop the monitor object
        if action == 'start':
            if hasattr(network_monitor, 'start'):
                network_monitor.start()
        else:
            if hasattr(network_monitor, 'stop'):
                network_monitor.stop()
        return jsonify({
            'success': True,
            'status': 'ENABLED' if network_monitor_running else 'DISABLED',
            'network_monitor_running': network_monitor_running
        })
    except Exception as e:
        logging.error(f"Error toggling network monitor: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route to get network monitored directories
@app.route('/api/network/monitored_directories', methods=['GET'])
def get_network_monitored_directories_endpoint():
    try:
        # Get network monitored directories
        return get_network_monitored_directories_handler(network_monitor)
    except Exception as e:
        logging.error(f"Error getting network monitored directories: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route to get folder watcher paths
@app.route('/get_folder_watcher_paths', methods=['GET'])
def get_folder_watcher_paths():
    """Get paths being watched by folder watcher"""
    try:
        # Get the paths from the folder watcher if it exists
        monitored_paths = []
        folder_watcher_active = False
        
        # Try different ways to get monitored paths
        if 'folder_watcher' in globals() and folder_watcher is not None and hasattr(folder_watcher, 'get_directories'):
            monitored_paths = folder_watcher.get_directories()
            folder_watcher_active = folder_watcher.is_running if hasattr(folder_watcher, 'is_running') else False
        elif 'folder_watcher' in globals() and folder_watcher is not None and hasattr(folder_watcher, 'get_watched_folders'):
            monitored_paths = folder_watcher.get_watched_folders()
            folder_watcher_active = True
        elif 'folder_watcher' in globals() and folder_watcher is not None and hasattr(folder_watcher, 'directories'):
            monitored_paths = folder_watcher.directories
            folder_watcher_active = folder_watcher.is_running if hasattr(folder_watcher, 'is_running') else False
        elif 'yara_scanner' in globals() and yara_scanner is not None and hasattr(yara_scanner, 'get_monitored_folders'):
            # Try to get folders from YARA scanner as fallback
            monitored_paths = yara_scanner.get_monitored_folders()
            folder_watcher_active = True
        elif 'MONITORED_DIRECTORIES' in globals():
            monitored_paths = MONITORED_DIRECTORIES
            folder_watcher_active = True
        
        # If no paths are monitored, use default paths
        if not monitored_paths:
            monitored_paths = [
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents')
            ]
            folder_watcher_active = False
        
        # Format the folders list to match expected structure
        folders = []
        for path in monitored_paths:
            if path and isinstance(path, str):
                exists = os.path.exists(path)
                folders.append({
                    'path': path,
                    'exists': exists,
                    'accessible': os.access(path, os.R_OK) if exists else False,
                    'status': 'Active' if exists else 'Not found'
                })
        
        return jsonify({
            'success': True,
            'folder_watcher_active': folder_watcher_active,
            'folders': folders,
            'paths': monitored_paths  # Include original paths for backward compatibility
        })
    except Exception as e:
        logging.error(f"Error getting folder watcher paths: {str(e)}")
        return jsonify({'success': False, 'error': str(e), 'paths': []}), 500

# --- Ensure start_realtime route exists and works ---

# --- Add /file_crypto stub to avoid 404 ---
@app.route('/file_crypto', methods=['GET', 'POST'])
@requires_auth
def file_crypto():
    return jsonify({'status': 'not_implemented', 'message': 'File crypto feature coming soon.'}), 200


# Route to toggle folder watcher
@app.route('/toggle_folder_watcher/<action>', methods=['POST'])
@requires_auth
def toggle_folder_watcher(action):
    """Toggle folder watcher service on/off."""
    global folder_watcher_running
    try:
        if action not in ['start', 'stop']:
            return jsonify({'error': 'Invalid action'}), 400
            
        folder_watcher_running = (action == 'start')
        
        # Update the folder watcher service
        if action == 'start':
            folder_watcher.start()
        else:
            folder_watcher.stop()
            
        return jsonify({
            'status': 'success',
            'network_monitor_running': network_monitor_running,
            'folder_watcher_status': folder_watcher_running,
            'safe_downloader_status': safe_downloader_running,
            'auto_updates_running': auto_updates_running
        })
    except Exception as e:
        logging.error(f"Error toggling folder watcher: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to toggle safe downloader
@app.route('/toggle_safe_downloader/<action>', methods=['POST'])
@requires_auth
def toggle_safe_downloader(action):
    """Toggle safe downloader service on/off."""
    global safe_downloader_running
    try:
        if action not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        safe_downloader_running = (action == 'start')
        # Actually start/stop the safe_downloader object if present
        if action == 'start':
            if 'safe_downloader' in globals() and hasattr(safe_downloader, 'start'):
                safe_downloader.start()
        else:
            if 'safe_downloader' in globals() and hasattr(safe_downloader, 'stop'):
                safe_downloader.stop()
        # Return all service states for dashboard consistency
        return jsonify({
            'success': True,
            'status': 'ENABLED' if safe_downloader_running else 'DISABLED',
            'network_monitor_running': network_monitor_running,
            'folder_watcher_status': folder_watcher_running,
            'safe_downloader_status': safe_downloader_running,
            'auto_updates_running': auto_updates_running
        })
    except Exception as e:
        logging.error(f"Error toggling safe downloader: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route to toggle auto updates
@app.route('/toggle_auto_updates/<action>', methods=['POST'])
@requires_auth
def toggle_auto_updates(action):
    """Toggle auto updates service on/off."""
    global auto_updates_running
    try:
        if action not in ['start', 'stop']:
            return jsonify({'error': 'Invalid action'}), 400
            
        auto_updates_running = (action == 'start')
        
        # Update the auto updates service
        if action == 'start':
            auto_updates.start()
        else:
            auto_updates.stop()
            
        return jsonify({
            'status': 'success',
            'network_monitor_running': network_monitor_running,
            'folder_watcher_status': folder_watcher_running,
            'safe_downloader_status': safe_downloader_running,
            'auto_updates_running': auto_updates_running
        })
    except Exception as e:
        logging.error(f"Error toggling auto updates: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for listing quarantined files
@app.route('/quarantine', methods=['GET'])
@requires_auth
def list_quarantine():
    try:
        from antivirus_cli import list_quarantine
        # Capture the output of list_quarantine
        import io
        output = io.StringIO()
        sys.stdout = output
        list_quarantine()
        sys.stdout = sys.__stdout__
        
        # Format the output
        result = output.getvalue()
        if "Quarantine is empty" in result:
            return jsonify({
                'status': 'success',
                'message': 'Quarantine is empty',
                'files': []
            })
        else:
            # Extract the list of files with details
            files = []
            for line in result.split('\n'):
                if line.startswith('- '):
                    parts = line[2:].split(' - ')
                    if len(parts) >= 2:
                        filename = parts[0].strip()
                        details = parts[1].strip()
                        files.append({
                            'filename': filename,
                            'details': details,
                            'timestamp': datetime.datetime.now().isoformat()
                        })
            return jsonify({
                'status': 'success',
                'message': 'Quarantined files listed successfully',
                'files': files
            })
    except Exception as e:
        logging.error(f"Error listing quarantined files: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for viewing antivirus log
@app.route('/antivirus_log', methods=['GET'])
@requires_auth
def antivirus_log():
    try:
        # Get log file path
        log_path = os.path.join(os.path.dirname(__file__), 'logs', 'antivirus.log')
        if not os.path.exists(log_path):
            return jsonify({
                'status': 'success',
                'message': 'No log file found',
                'log_entries': []
            })
        
        # Read last 100 entries
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            log_entries = []
            for line in lines[-100:]:  # Get last 100 entries
                try:
                    parts = line.strip().split(' - ')
                    if len(parts) >= 3:
                        timestamp = parts[0].strip()
                        level = parts[1].strip()
                        message = ' - '.join(parts[2:]).strip()
                        log_entries.append({
                            'timestamp': timestamp,
                            'level': level,
                            'message': message
                        })
                except Exception as e:
                    logging.error(f"Error parsing log line: {str(e)}")
                    continue
        
        return jsonify({
            'status': 'success',
            'message': 'Log entries retrieved successfully',
            'log_entries': log_entries
        })
    except Exception as e:
        logging.error(f"Error getting antivirus log: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for safe downloader details
@app.route('/safe_downloader_details', methods=['GET'])
@requires_auth
def safe_downloader_details():
    try:
        # Get safe downloader status and details
        details = {
            'status': safe_downloader_running,
            'last_scan': None,
            'blocked_downloads': []
        }
        
        # For now, we'll simulate some data - in production this would come from actual state
        if safe_downloader_running:
            details['last_scan'] = datetime.datetime.now().isoformat()
            details['blocked_downloads'] = [
                {
                    'url': 'http://malicious-site.com/malware.exe',
                    'reason': 'Malware detected',
                    'timestamp': datetime.datetime.now().isoformat()
                },
                {
                    'url': 'http://suspicious-site.com/trojan.zip',
                    'reason': 'Suspicious file type',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            ]
        
        return jsonify({
            'status': 'success',
            'details': details
        })
    except Exception as e:
        logging.error(f"Error getting safe downloader details: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for listing quarantined files (defined in list_quarantine function)


# Route for releasing a quarantined file
@app.route('/quarantine/release', methods=['POST'])
@requires_auth
def release_quarantine_route():
    """Release a quarantined file"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        dest_dir = data.get('destination')
        
        if not filename or not dest_dir:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        from antivirus_cli import release_from_quarantine
        release_from_quarantine(filename, dest_dir)
        return jsonify({
            'status': 'success',
            'message': f'File {filename} released successfully'
        })
    except Exception as e:
        logging.error(f"Error releasing quarantined file: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for deleting a quarantined file
@app.route('/quarantine/delete', methods=['POST'])
@requires_auth
def delete_quarantine_route():
    """Delete a quarantined file"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({'error': 'Missing filename parameter'}), 400
            
        from antivirus_cli import delete_from_quarantine
        delete_from_quarantine(filename)
        return jsonify({
            'status': 'success',
            'message': f'File {filename} deleted from quarantine'
        })
    except Exception as e:
        logging.error(f"Error deleting quarantined file: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for viewing logs
@app.route('/logs', methods=['GET'])
@requires_auth
def view_logs_route():
    """View application logs"""
    try:
        from antivirus_cli import show_logs, get_basedir
        log_file = os.path.join(get_basedir(), 'antivirus.log')
        
        if not os.path.exists(log_file):
            return jsonify({
                'status': 'success',
                'message': 'No logs found',
                'logs': ''
            })
            
        # Read the log file
        with open(log_file, 'r') as f:
            logs = f.read()
            
        return jsonify({
            'status': 'success',
            'message': 'Logs retrieved successfully',
            'logs': logs
        })
    except Exception as e:
        logging.error(f"Error viewing logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route for safe download
@app.route('/safe_download', methods=['GET', 'POST'])
@requires_auth
def safe_download_route():
    """Automatically scan and download network files to their original locations"""
    try:
        # Get monitored directories from config
        monitored_folders = build_monitored_folders()
        
        # Get all network downloads with their original paths
        from network_monitor import get_network_downloads
        downloads = get_network_downloads()
        
        if not downloads:
            return jsonify({
                'status': 'success',
                'message': 'No network downloads found'
            })
            
        results = []
        from safe_downloader import download_and_scan
        
        # Process each download
        for download_info in downloads:
            try:
                # Get original file path and URL
                original_path = download_info['path']
                url = download_info['url']
                
                # Ensure the destination is in a monitored folder
                if not any(original_path.startswith(folder) for folder in monitored_folders):
                    logging.warning(f"Download path {original_path} is not in monitored folders")
                    results.append({
                        'url': url,
                        'path': original_path,
                        'error': 'Download path is not in monitored folders'
                    })
                    continue
                
                # Create directories if they don't exist
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                
                # Download and scan to original location
                scan_result = download_and_scan(url, original_path)
                results.append({
                    'url': url,
                    'path': original_path,
                    'result': scan_result
                })
            except Exception as e:
                logging.error(f"Error processing {url} to {original_path}: {str(e)}")
                results.append({
                    'url': url,
                    'path': original_path,
                    'error': str(e)
                })
        
        return jsonify({
            'status': 'success',
            'message': f'Scanned {len(results)} network downloads',
            'downloads': results
        })
    except Exception as e:
        logging.error(f"Error in network download scan: {str(e)}")
        return jsonify({
            'error': str(e),
            'details': 'Failed to scan network downloads'
        }), 500

@app.route('/something', methods=['POST'])
@requires_auth
def scan_monitored_processes():
    """Scan all monitored processes"""
    try:
        # Get monitored directories from config
        monitored_folders = build_monitored_folders()
        
        results = []
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cwd']):
            try:
                process_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username']
                }
                
                # Skip system processes
                if proc.info['username'] in ['SYSTEM', 'NT AUTHORITY\SYSTEM']:
                    continue
                    
                # Get process executable path
                exe_path = proc.info['exe']
                if exe_path:
                    # Check if process is in monitored directory
                    process_in_monitored = any(exe_path.startswith(folder) for folder in monitored_folders)
                    if not process_in_monitored:
                        continue
                        
                    # Scan the executable
                    is_malware, is_infected, reason = scan_file_for_viruses_with_test_flag(exe_path)
                    
                    # Get file hashes
                    hashes = file_hashes(exe_path)
                    
                    process_info.update({
                        'exe_path': exe_path,
                        'malware_detected': is_malware,
                        'infected': is_infected,
                        'reason': reason,
                        'file_hashes': hashes,
                        'monitored_directory': next((folder for folder in monitored_folders if exe_path.startswith(folder)), 'Unknown')
                    })
                
                results.append(process_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.error(f"Error scanning process {proc.info['pid']}: {str(e)}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error scanning process {proc.info['pid']}: {str(e)}")
                continue
        
        return jsonify({
            'status': 'success',
            'total_monitored_processes_scanned': len(results),
            'scan_results': results,
            'message': 'Monitored processes scan completed successfully'
        })
        
    except Exception as e:
        logging.error(f"Error in monitored processes scanning: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/test')
def test():
    """Serve the main dashboard page"""
    return render_template('index.html')

@app.route('/start_realtime', methods=['POST'])
@requires_auth
def start_realtime():
    """Start real-time monitoring"""
    global folder_watcher, network_monitor, rtp_status_flag
    try:
        # Start network monitor if it's not already running
        network_monitor_running = True
        if network_monitor is not None:
            network_monitor_running = getattr(network_monitor, 'running', False)
        
        if not network_monitor_running:
            network_monitor.start()
        
        # Start folder watcher if it's not already running
        folder_watcher_running = True
        if folder_watcher is not None:
            folder_watcher_running = getattr(folder_watcher, 'is_running', False)
        
        if not folder_watcher_running and folder_watcher is not None:
            folder_watcher.start()
        
        # Set status flag
        rtp_status_flag = 'ENABLED'
        
        return jsonify({
            'status': 'success', 
            'message': 'Real-time protection started successfully. Network monitoring and folder protection are now active.'
        })
    except Exception as e:
        logging.error(f"Error starting real-time protection: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/start_folder_watcher', methods=['POST'])
@requires_auth
def start_folder_watcher():
    """Start folder monitoring"""
    try:
        # Start the folder watcher if not already running
        if not hasattr(app, 'folder_watcher_thread') or not app.folder_watcher_thread.is_alive():
            # Build monitored folders
            monitored_folders = build_monitored_folders()
            if not monitored_folders:
                return jsonify({'error': 'No directories configured to watch'}), 400
            
            # Start watching directories
            app.folder_watcher_thread = threading.Thread(
                target=build_monitored_folders,
                daemon=True
            )
            app.folder_watcher_thread.start()
            return jsonify({'status': 'success', 'message': 'Folder monitoring started'})
        else:
            return jsonify({'status': 'warning', 'message': 'Folder monitoring is already running'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/start_network_monitor', methods=['POST'])
@requires_auth
def start_network_monitor():
    """Start network monitoring service"""
    try:
        # Start the network monitoring service if not already running
        if not hasattr(app, 'network_monitor_thread') or not app.network_monitor_thread.is_alive():
            app.network_monitor_thread = threading.Thread(
                target=network_monitor.monitor_connections,
                daemon=True
            )
            app.network_monitor_thread.start()
            return jsonify({'status': 'success', 'message': 'Network monitoring started'})
        else:
            return jsonify({'status': 'warning', 'message': 'Network monitoring is already running'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan_all_processes', methods=['GET'])
async def scan_all_processes_route():
    """Scan all running processes for malware"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                process_data = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'username': proc.username(),
                    'status': proc.status(),
                    'create_time': proc.create_time()
                }
                processes.append(process_data)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return jsonify({
            'success': True,
            'processes': processes
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Network Monitoring Endpoints
@app.route('/get_traffic_stats', methods=['GET'])
def get_traffic_stats():
    """Get current network traffic statistics"""
    try:
        stats = network_monitor.get_traffic_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_c2_patterns', methods=['GET'])
def get_c2_patterns():
    """Get detected C2 patterns"""
    try:
        patterns = network_monitor.get_c2_patterns()
        return jsonify({'success': True, 'patterns': patterns})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_rate_limited_ips', methods=['GET'])
def get_rate_limited_ips():
    """Get rate limited IPs"""
    try:
        ips = network_monitor.get_rate_limited_ips()
        return jsonify({'success': True, 'ips': ips})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/block_ip/<ip>', methods=['POST'])
def block_ip(ip):
    """Block an IP address"""
    try:
        network_monitor.block_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} blocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/unblock_ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP address"""
    try:
        network_monitor.unblock_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/whitelist_ip/<ip>', methods=['POST'])
def whitelist_ip(ip):
    """Whitelist an IP address"""
    try:
        network_monitor.whitelist_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} whitelisted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_ssl_analysis', methods=['GET'])
def get_ssl_analysis():
    """Get SSL/TLS connection analysis"""
    try:
        analysis = network_monitor.get_ssl_analysis()
        return jsonify({
            'success': True,
            'analysis': analysis
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/get_dns_analysis', methods=['GET'])
def get_dns_analysis():
    """Get DNS request analysis"""
    try:
        analysis = network_monitor.get_dns_analysis()
        return jsonify({
            'success': True,
            'requests': analysis
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/encrypt_router_configs', methods=['POST'])
async def encrypt_router_configs_route():
    """Encrypt all router configuration files on the system"""
    try:
        # Get the encryption key from request
        data = request.get_json()
        if not data or 'key' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing encryption key'
            }), 400
            
        key = data['key'].encode()
        
        # Encrypt all router configs
        encrypted_files = encrypt_router_configs(key)
        
        return jsonify({
            'success': True,
            'encrypted_files': encrypted_files,
            'count': len(encrypted_files),
            'message': f'Successfully encrypted {len(encrypted_files)} router configuration files'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/decrypt_router_configs', methods=['POST'])
async def decrypt_router_configs_route():
    """Decrypt all router configuration files on the system"""
    try:
        # Get the decryption key from request
        data = request.get_json()
        if not data or 'key' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing decryption key'
            }), 400
            
        key = data['key'].encode()
        
        # Decrypt all router configs
        decrypted_files = decrypt_router_configs(key)
        
        return jsonify({
            'success': True,
            'decrypted_files': decrypted_files,
            'count': len(decrypted_files),
            'message': f'Successfully decrypted {len(decrypted_files)} router configuration files'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/list_router_configs', methods=['GET'])
async def list_router_configs_route():
    """List all router configuration files on the system"""
    try:
        # Find all potential router config files
        config_files = find_router_config_files()
        
        # Filter and get details of router configs
        router_configs = []
        for file_path in config_files:
            if is_router_config_file(file_path):
                router_configs.append({
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'modified': os.path.getmtime(file_path),
                    'is_encrypted': file_path.endswith('.router-encrypted')
                })
        
        return jsonify({
            'success': True,
            'router_configs': router_configs,
            'count': len(router_configs),
            'message': f'Found {len(router_configs)} router configuration files'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/scan_all_processes', methods=['POST'])
@requires_auth
def scan_all_processes():
    """Scan all running processes for malware"""
    try:
        results = []
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cmdline']):
            try:
                process_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username']
                }
                
                # Skip system processes and special Windows processes
                if proc.info['username'] in ['SYSTEM', 'NT AUTHORITY\SYSTEM']:
                    continue
                    
                # Skip special Windows processes
                if proc.info['name'] in ['Registry', 'System', 'Idle', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe']:
                    continue
                    
                # Get process executable path
                exe_path = proc.info['exe']
                if exe_path:
                    try:
                        # Check if file exists before scanning
                        if os.path.exists(exe_path):
                            # Scan the executable
                            is_malware, is_infected, reason = scan_file_for_viruses_with_test_flag(exe_path)
                            
                            # Get file hashes
                            hashes = file_hashes(exe_path)
                            
                            process_info.update({
                                'exe_path': exe_path,
                                'malware_detected': is_malware,
                                'infected': is_infected,
                                'reason': reason,
                                'file_hashes': hashes
                            })
                    except Exception as e:
                        logging.error(f"Error scanning file {exe_path}: {str(e)}")
                        continue
                
                # Add command line info if available
                cmdline = proc.info.get('cmdline')
                if cmdline:
                    process_info['cmdline'] = ' '.join(cmdline)
                
                results.append(process_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.error(f"Error scanning process {proc.info['pid']}: {str(e)}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error scanning process {proc.info['pid']}: {str(e)}")
                continue
        
        return jsonify({
            'status': 'success',
            'total_processes_scanned': len(results),
            'scan_results': results,
            'message': 'Process scan completed successfully'
        })
        
    except Exception as e:
        logging.error(f"Error in process scanning: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/start_antivirus_cli', methods=['POST'])
@requires_auth
def start_antivirus_cli():
    """Start antivirus CLI scanning service"""
    try:
        # Get base directory from antivirus_cli
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Scan all files in base directory
        results = []
        for root, _, files in os.walk(base_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    # Skip certain directories
                    if any(d in root.lower() for d in ['venv', '.git', 'node_modules']):
                        continue
                        
                    # Skip certain file types
                    if file.lower().endswith(('.pyc', '.pyo', '.pyd', '.pyc', '.pycache')):
                        continue
                        
                    # Scan the file
                    is_malware, is_infected, reason = scan_file_for_viruses_with_test_flag(filepath)
                    
                    # Get file hashes
                    hashes = file_hashes(filepath)
                    
                    result = {
                        'filepath': filepath,
                        'malware_detected': is_malware,
                        'infected': is_infected,
                        'reason': reason,
                        'file_hashes': hashes
                    }
                    
                    results.append(result)
                    
                except Exception as e:
                    logging.error(f"Error scanning {filepath}: {str(e)}")
                    continue
        
        return jsonify({
            'status': 'success',
            'total_files_scanned': len(results),
            'scan_results': results,
            'message': 'Scan completed successfully'
        })
        
    except Exception as e:
        logging.error(f"Error in antivirus CLI: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/start_safe_downloader', methods=['POST'])
@requires_auth
def start_safe_downloader():
    """Start safe downloader service"""
    try:
        # Start the safe downloader service if not already running
        if not hasattr(app, 'safe_downloader_thread') or not app.safe_downloader_thread.is_alive():
            app.safe_downloader_thread = threading.Thread(
                target=safe_download_service,
                daemon=True
            )
            app.safe_downloader_thread.start()
            return jsonify({'status': 'success', 'message': 'Safe downloader service started'})
        else:
            return jsonify({'status': 'warning', 'message': 'Safe downloader service is already running'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_download_queue():
    """Get all pending download requests"""
    with DOWNLOAD_QUEUE_LOCK:
        queue_list = list(DOWNLOAD_QUEUE.queue)
    return queue_list


def add_to_download_queue(download_info):
    """Add a new download request to the queue"""
    with DOWNLOAD_QUEUE_LOCK:
        DOWNLOAD_QUEUE.put(download_info)


def safe_download_service():
    """Service to handle safe downloads"""
    while True:
        try:
            # Check for download requests
            if not DOWNLOAD_QUEUE.empty():
                with DOWNLOAD_QUEUE_LOCK:
                    download = DOWNLOAD_QUEUE.get()
                    
                url = download.get('url')
                if not url:
                    continue
                    
                # Create temporary directory for download
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Download file
                    try:
                        response = requests.get(url, stream=True)
                        response.raise_for_status()
                        
                        # Save to temporary file
                        temp_file = os.path.join(temp_dir, 'downloaded_file')
                        with open(temp_file, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                        
                        # Scan file for viruses
                        scan_result = scan_file_for_viruses(temp_file)
                        if scan_result.get('infected'):
                            logging.warning(f"Download from {url} contains malware")
                            continue
                            
                        # Extract if archive
                        if extract_archive(temp_file, temp_dir):
                            # Scan extracted files
                            for root, _, files in os.walk(temp_dir):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    scan_result = scan_file_for_viruses(file_path)
                                    if scan_result.get('infected'):
                                        logging.warning(f"Extracted file {file} contains malware")
                                        continue
                                        
                        # Encrypt and save file
                        encrypted_path = download.get('encrypted_output')
                        if encrypted_path:
                            encrypt_file(temp_file, encrypted_path)
                            logging.info(f"File successfully downloaded, scanned, and encrypted to {encrypted_path}")
                            
                    except Exception as e:
                        logging.error(f"Error processing download from {url}: {str(e)}")
                        continue
                        
        except Exception as e:
            logging.error(f"Error in safe download service: {str(e)}")
            time.sleep(5)  # Wait before retrying
            continue
            
        time.sleep(1)  # Prevent CPU hogging



@app.errorhandler(404)
def handle_404(e):
    """Handle 404 errors with a more informative response"""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested endpoint does not exist',
        'available_endpoints': [
            '/start_network_monitor',
            '/start_folder_watcher',
            '/start_safe_downloader',
            '/start_antivirus_cli',
            '/scan_all_processes'
        ]
    }), 404

@app.errorhandler(500)
def handle_500(e):
    """Handle internal server errors with a more informative response"""
    try:
        # Log detailed error information
        logging.error(f"Internal server error: {str(e)}")
        logging.error(f"Request method: {request.method}")
        logging.error(f"Request URL: {request.url}")
        logging.error(f"Request data: {request.get_data(as_text=True)}")
        logging.error(f"Request headers: {dict(request.headers)}")
        
        # Return user-friendly error message
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred while processing your request',
            'details': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500
    except Exception as inner_e:
        # If we get an error while logging, at least return a basic error message
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred while processing your request',
            'timestamp': datetime.now().isoformat()
        }), 500

# Add favicon route
@app.route('/favicon.ico')


# Add error handlers
@app.errorhandler(404)
def handle_404(e):
    """Handle 404 errors with a more informative response"""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested endpoint does not exist',
        'available_endpoints': [
            '/start_network_monitor',
            '/start_folder_watcher',
            '/start_safe_downloader',
            '/start_antivirus_cli',
            '/scan_all_processes'
        ]
    }), 404

@app.errorhandler(500)
def handle_500(e):
    """Handle internal server errors with a more informative response"""
    try:
        # Log detailed error information
        logging.error(f"Internal server error: {str(e)}")
        logging.error(f"Request method: {request.method}")
        logging.error(f"Request URL: {request.url}")
        logging.error(f"Request data: {request.get_data(as_text=True)}")
        logging.error(f"Request headers: {dict(request.headers)}")
        
        # Return user-friendly error message
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred while processing your request',
            'details': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500
    except Exception as inner_e:
        # If we get an error while logging, at least return a basic error message
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred while processing your request',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    """Catch-all route for unknown endpoints"""
    return jsonify({
        'error': 'Not Found',
        'message': f'The requested endpoint "/{path}" does not exist',
        'available_endpoints': [
            '/start_network_monitor',
            '/start_folder_watcher',
            '/start_safe_downloader',
            '/start_antivirus_cli',
            '/scan_all_processes',
            '/run_conditional_startup',
            '/update_signatures'
        ]
    }), 404

def prompt_admin_credentials():
    """Prompt for admin credentials and securely store them."""
    import getpass
    
    print("\n=== Windows Defender Admin Login ===")
    username = input("Enter administrator username: ")
    password = getpass.getpass("Enter administrator password: ")
    
    # Securely store credentials
    set_admin_credentials(username, password)
    
    print("\nAdmin credentials have been set. Starting Windows Defender...")
    print("\nPlease wait while the service initializes...")
    print("\nYou can now access the interface at http://localhost:5000")

if __name__ == '__main__':
    try:
        # Initialize all core components
        print("Initializing Windows Defender components...")
        
        # Initialize quarantine folder
        os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
        
        # Try to initialize Redis connection, but continue if not available
        try:
            print("Connecting to Redis...")
            redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True, socket_connect_timeout=2)
            redis_client.ping()  # Test connection
            print("Redis connection successful")
        except (redis.ConnectionError, redis.exceptions.ResponseError) as e:
            print(f"Redis not available: {e}. Some features will be disabled.")
            redis_client = None
        
        # Initialize core components (make these optional with robust error handling)
        try:
            # Initialize network monitor
            print("Starting network monitor...")
            network_monitor = NetworkMonitor()
            network_monitor.start()
            print("Network monitor started successfully")
        except Exception as e:
            print(f"Failed to start network monitor: {e}")
        
        try:
            # Initialize folder watcher
            print("Starting folder watcher...")
            folder_watcher = FolderWatcher()
            folder_watcher.directories = MONITORED_DIRECTORIES
            folder_watcher.start()
            print("Folder watcher started successfully")
        except Exception as e:
            print(f"Failed to start folder watcher: {e}")
        
        # Load ML models
        print("Loading machine learning models...")
        threat_detector = ThreatDetectionModel()
        
        print("Windows Defender core components initialized")
        print("Starting web interface...")
        print("Access the dashboard at http://localhost:5000")
        
        # Enable debug mode for development
        app.debug = True
        
        try:
            # Start C2 detector
            print("Starting C2 detector...")
            start_c2_detector()
        except Exception as e:
            print(f"Failed to start C2 detector: {e}")
        
        try:
            # Start real-time protection
            print("Starting real-time protection...")
            start_realtime()
        except Exception as e:
            print(f"Failed to start real-time protection: {e}")
        
        print("\nStarting web server...")
        print("Access the dashboard at http://localhost:5000")
        
        # Try to open browser to main interface
        try:
            print("Opening web interface in browser...")
            webbrowser.open('http://localhost:5000')
        except Exception as e:
            print(f"Failed to open browser: {e}")
            
        # Run the Flask app (this must be the last line as it blocks)
        app.run(host='0.0.0.0', port=5000, threaded=True, debug=True)
    except KeyboardInterrupt:
        # Clean up Redis connection on exit
        if redis_client:
            redis_client.close()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Failed to start application: {str(e)}")
        if redis_client:
            redis_client.close()
        sys.exit(1)

@requires_auth
def get_connections():
    """Get current network connections"""
    try:
        stats = network_monitor.get_connection_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-ip/<ip>')
@requires_auth
def check_ip(ip):
    """Check if an IP is blacklisted or whitelisted"""
    try:
        is_blacklisted = network_monitor.is_blacklisted(ip)
        is_whitelisted = network_monitor.is_whitelisted(ip)
        return jsonify({
            'blacklisted': is_blacklisted,
            'whitelisted': is_whitelisted
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-file', methods=['POST'])
@requires_auth
def scan_file():
    """Scan an uploaded file for threats"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        # Save the file temporarily
        temp_path = os.path.join(tempfile.gettempdir(), secure_filename(file.filename))
        file.save(temp_path)
        
        # Scan the file
        result = scan_file_for_phishing(temp_path)
        
        # Clean up
        os.remove(temp_path)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# Note: Routes are already decorated with @requires_auth, no need to wrap again

# Create a simple wrapper class to match our previous interface


# --- Robust EXE folder detection for all file/shortcut creation ---
def get_basedir():
    import sys
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

basedir = get_basedir()
LOG_FILE = os.path.join(basedir, "antivirus.log")

# Initialize FolderWatcher
# Get common directories to monitor
home_dir = os.path.expanduser("~")
common_dirs = [
    os.path.join(home_dir, "Downloads"),
    os.path.join(home_dir, "Desktop"),
    os.path.join(home_dir, "Documents")
]

# Filter out non-existent directories
directories = [d for d in common_dirs if os.path.exists(d) and os.path.isdir(d)]

folder_watcher = FolderWatcher()
folder_watcher.directories = directories

os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
# Initialize scan_directories.txt with default directories
scan_directories_file = os.path.join(basedir, 'scan_directories.txt')
if not os.path.exists(scan_directories_file):
    with open(get_resource_path(scan_directories_file), 'w') as f:
        default_dirs = [
            '~/Downloads',
            '~/Documents',
            '~/Desktop',
            '%PROGRAMFILES%',
            '%PROGRAMFILES(X86)%',
            '%APPDATA%',
            '%LOCALAPPDATA%',
            '%TEMP%',
            '%USERPROFILE%\\AppData\\Local\\Temp'
        ]
        for dir_path in default_dirs:
            f.write(os.path.expanduser(os.path.expandvars(dir_path)) + '\n')
        
# Add the 'utils' folder to sys.path
utils_path = os.path.join(os.path.dirname(sys.executable), 'utils')
if utils_path not in sys.path:
    sys.path.append(utils_path)
    
# Securely lock Fernet key in memory for cryptographic operations
if not FERNET_KEY or len(FERNET_KEY) != 44:
    raise EnvironmentError("FERNET_KEY must be set (44 chars, base64). Set it in config.py or as an environment variable.")
secure_key = SecureBuffer(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
FERNET_INSTANCE = Fernet(secure_key.get_bytes())

__version__ = "9.11.12"

# --- Robust EXE folder detection for all file/shortcut creation ---
def get_basedir():
    import sys
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

basedir = get_basedir()
LOG_FILE = os.path.join(basedir, "antivirus.log")

# --- Guarantee critical files exist in EXE folder ---
import json
SCHEDULED_SCAN_STATE_FILE = os.path.join(basedir, 'scheduled_scan_state.json')
if not os.path.exists(SCHEDULED_SCAN_STATE_FILE):
    import datetime
    default_state = {
        'enabled': False,
        'last_scan': None,
        'scan_frequency': 'daily',
        'audit_log': [],
    }
    with open(get_resource_path(SCHEDULED_SCAN_STATE_FILE), 'w') as f:
        json.dump(default_state, f, indent=2)
SIGNATURE_DB = os.path.join(basedir, 'malware_signatures.txt')
if not os.path.exists(SIGNATURE_DB):
    with open(get_resource_path(SIGNATURE_DB), 'w') as f:
        f.write('# Malware Signatures\n# SHA256 hashes, one per line\n')

import sys

# --- Only print version/id if run from a real terminal (not via shortcut/BAT) ---
if sys.stdin is not None and sys.stdin.isatty():
    if '--version' in sys.argv:
        print(encrypt_message(__version__))
else:
        # Do not exit; continue to normal startup
    if '--id' in sys.argv or '--ID' in sys.argv:
        print(encrypt_message('ANTIVIRUS_EXE_IDENTIFIER_2025'))
        # Do not exit; continue to normal startup


# Quick check to confirm log file creation
try:
    with open(get_resource_path(os.path.join(LOG_FILE)), "a") as f:
        f.write("Log file creation test.\n")
    print(encrypt_message(f"Log file '{LOG_FILE}' created or opened successfully."))
except Exception as e:
    print(encrypt_message(f"Failed to create or open log file: {e}"))
print(encrypt_message(f"[LOG] Using basedir: {basedir}"))

# --- Update phishing blocklists at startup ---
try:
    update_all_blocklists()
    print(encrypt_message('[LOG] Phishing blocklists updated at startup.'))
except Exception as e:
    print(encrypt_message(f'[ERROR] Failed to update phishing blocklists at startup: {e}'))

# --- Always write version.txt to EXE folder (for EXE version discovery) ---
version_file_path = os.path.join(basedir, 'version.txt')
try:
    with open(get_resource_path(os.path.join(version_file_path)), 'w') as vf:
        vf.write(__version__)
    print(encrypt_message(f"[LOG] Version written to: {version_file_path}"))
except Exception as e:
    print(encrypt_message(f"[ERROR] Could not write version.txt: {e}"))

# Print early launch message so user sees it at the beginning

# --- Serve browser extension files from Flask (for dev/internal use) ---
from flask import (
    Flask, request, send_from_directory, render_template, redirect, url_for, flash, send_file, jsonify
)
from werkzeug.utils import secure_filename
from config import USE_YARA  # Import USE_YARA flag from config
from werkzeug.utils import secure_filename
from security.process_monitor import scan_running_processes

# App already initialized at the top of the file
logging.basicConfig(level=logging.DEBUG)

def load_monitored_folders():
    try:
        scan_directories_path = get_resource_path(os.path.join(os.path.dirname(__file__), 'scan_directories.txt'))
        with open(scan_directories_path, 'r') as file:
            monitored_folders = [line.strip() for line in file if line.strip()]
            logging.debug(f'Monitored folders loaded: {monitored_folders}')
            return monitored_folders
    except Exception as e:
        logging.error(f'Error loading monitored folders: {e}')
        return []

# Add these imports at the top of your file
from collections import defaultdict
import threading
import time
import logging
from datetime import datetime

# Add these global variables
c2_detector = None
c2_detector_thread = None
c2_detector_running = False

# Add the C2 detector routes
@app.route('/start_c2_detector', methods=['POST'])
def start_c2_detector():
    global c2_detector, c2_detector_thread, c2_detector_running
    
    if c2_detector_running:
        flash('C2 detector is already running', 'info')
        return redirect(url_for('index'))
    
    try:
        from security.c2_detector import C2Detector
        c2_detector = C2Detector(logger=logging.getLogger("C2Detector"))
        c2_detector_thread = threading.Thread(
            target=c2_detector.start_monitoring,
            daemon=True
        )
        c2_detector_thread.start()
        c2_detector_running = True
        logging.info(encrypt_message('[C2_DETECTOR] Started C2 detection monitoring'))
        flash('C2 detector started successfully', 'success')
    except Exception as e:
        logging.error(encrypt_message(f'[C2_DETECTOR] Failed to start C2 detector: {e}'))
        flash(f'Failed to start C2 detector: {e}', 'error')
    
    return redirect(url_for('index'))

@app.route('/stop_c2_detector', methods=['POST'])
def stop_c2_detector():
    global c2_detector_running
    
    if not c2_detector_running:
        flash('C2 detector is not running', 'info')
        return redirect(url_for('index'))
    
    try:
        c2_detector_running = False
        logging.info(encrypt_message('[C2_DETECTOR] Stopped C2 detection monitoring'))
        flash('C2 detector stopped', 'success')
    except Exception as e:
        logging.error(encrypt_message(f'[C2_DETECTOR] Error stopping C2 detector: {e}'))
        flash(f'Error stopping C2 detector: {e}', 'error')
    
    return redirect(url_for('index'))

@app.route('/c2_detector_report')
def c2_detector_report():
    # Simple data structure to store C2 detection results
    c2_detections = [
        {
            "timestamp": "2023-07-15 14:32:45",
            "source_ip": "192.168.1.5",
            "destination_ip": "203.0.113.100",
            "destination_port": 8080,
            "protocol": "TCP",
            "severity": "Critical",
            "reason": "Regular beaconing pattern detected"
        },
        {
            "timestamp": "2023-07-15 15:10:22",
            "source_ip": "192.168.1.10",
            "destination_ip": "198.51.100.75",
            "destination_port": 443,
            "protocol": "HTTPS",
            "severity": "High",
            "reason": "Suspicious domain detected"
        }
    ]
    
    return render_template('c2_detector_report.html', c2_detections=c2_detections)

@app.route('/browser_extension/<path:filename>')
def serve_browser_extension(filename):
    ext_dir = os.path.join(basedir, 'browser_extension')
    return send_from_directory(ext_dir, filename)
port = int(os.environ.get('PORT', 5000))
print(encrypt_message(f"[LOG] Waiting for launch: Flask server is about to start on http://127.0.0.1:{port}"))

dotenv_path = os.path.join(basedir, '.env')
if not os.path.exists(dotenv_path):
    print(encrypt_message(f"[WARNING] .env file not found at {dotenv_path}. Environment variables may not be loaded."))
else:
    load_dotenv(dotenv_path)
import shutil

# --- GLOBAL OPTION TO SKIP TEMP DELETION POLICY ---
# --- GLOBAL OPTION TO ENABLE CLAMAV INTEGRATION ---
USE_CLAMAV = True
import webbrowser
import requests
import logging
import time
import gc
from urllib.parse import urlparse

from flask_wtf.csrf import generate_csrf
from scan_utils import scan_file_for_viruses
import psutil
import subprocess
from secure_message import encrypt_message, decrypt_message
from folder_watcher import build_monitored_folders, MONITORED_FOLDERS

# Ensure MONITORED_FOLDERS is always populated
if not MONITORED_FOLDERS:
    MONITORED_FOLDERS = build_monitored_folders()

@app.route('/view_logs_for_phishing', methods=['GET'])
def view_logs_for_phishing():
    """
    Allow user to select and scan an existing log file for phishing indicators.
    """
    import os
    from flask import request, render_template
    # List of log files (relative to base directory)
    log_files = [
        'antivirus.log',
        'crypto_events.log',
        'dist/antivirus.log',
        'malicious_ips.log',
        'network_monitor.log',
    ]
    selected_log = request.args.get('logfile')
    findings = None
    if selected_log in log_files:
        log_path = os.path.join(os.path.dirname(__file__), selected_log)
        if os.path.exists(log_path):
            findings = scan_file_for_phishing(log_path)
    return render_template('view_logs_for_phishing.html', log_files=log_files, selected_log=selected_log, findings=findings)
from file_crypto import encrypt_file
import subprocess
import tempfile

# Initialize global variables
folder_watcher_process = None
rtp_status_flag = None  # 'STARTING', 'ENABLED', or None
safe_download_service = None

@app.route('/phishing_check', methods=['POST'])
def phishing_check():
    from flask import request, jsonify
    from phishing_detector import scan_file_for_phishing
    from phishing_alerts import save_alert
    import tempfile
    from datetime import datetime
    from phishing_ml import ml_phishing_score  # Ensure this import is present

    data = request.get_json()
    url = data.get('url')
    email_content = data.get('email_content')
    findings = []
    source = data.get('source', 'extension/api')
    summary = "Phishing check"

    if url:
        # Save URL to temp file for scanning (reuse existing logic)
        with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.txt') as tmp:
            tmp.write(url)
            tmp.flush()
            findings = scan_file_for_phishing(tmp.name)
        os.remove(tmp.name)
        summary = f"URL: {url[:80]}" if url else "URL scan"
    elif email_content:
        # Save email content to temp file for scanning
        with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.txt') as tmp:
            tmp.write(email_content)
            tmp.flush()
            findings = scan_file_for_phishing(tmp.name)
        os.remove(tmp.name)
        summary = "Email body scan"

    # Calculate ML score directly
    ml_score = ml_phishing_score(email_content if email_content else url)
    phishing = any(f[0] in ('ip', 'url') for f in findings) or ml_score > 0.8

    # Log alert if phishing found
    if phishing:
        save_alert({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source': source,
            'summary': summary,
            'details': findings,
            'phishing': True
        })

    return jsonify({'phishing': phishing, 'findings': findings, 'ml_score': ml_score})


import zipfile
import tarfile
import io
import traceback
from contextlib import redirect_stdout
from data_analysis import analyze_data
from cryptography.fernet import Fernet, InvalidToken
from security.yara_scanner import scan_file_with_yara
from phishing_alerts import get_recent_alerts
import sys

# Ensure Flask always finds the templates folder, even in EXE or different working directory
if getattr(sys, 'frozen', False):
    # Running as bundled EXE
    basedir = sys._MEIPASS
else:
    basedir = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(basedir, 'templates'))
app.secret_key = 'supersecretkey'  # Change this in production

@app.route('/phishing_dashboard')
def phishing_dashboard():
    alerts = get_recent_alerts(50)
    return render_template('phishing_dashboard.html', alerts=alerts)
@app.route('/encrypt', methods=['POST'])
def encrypt_file_route():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('file_crypto'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('file_crypto'))

    key = request.form.get('key', None)

    # Create temporary files for input/output
    with tempfile.NamedTemporaryFile(delete=False) as temp_in, \
         tempfile.NamedTemporaryFile(delete=False) as temp_out:
        file.save(temp_in.name)
        encrypt_file(temp_in.name, temp_out.name, key)  # Call the correct encrypt_file function
        return send_file(temp_out.name, as_attachment=True, 
                        download_name=f'encrypted_{secure_filename(file.filename)}')
        
@app.route('/decrypt', methods=['POST'])
def decrypt_file_route():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('file_crypto'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('file_crypto'))

    key = request.form.get('key', None)

    # Create temporary files for input/output
    with tempfile.NamedTemporaryFile(delete=False) as temp_in, \
         tempfile.NamedTemporaryFile(delete=False) as temp_out:
        file.save(temp_in.name)
        from file_crypto import decrypt_file as decrypt_file_util
        decrypt_file_util(temp_in.name, temp_out.name, key)
        return send_file(temp_out.name, as_attachment=True,
                         download_name=f'decrypted_{secure_filename(file.filename)}')
# Configure logging
import logging

# Set up logging to both file and console
log_file = os.path.join(basedir, 'antivirus.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

from cryptography.fernet import Fernet

import hashlib
import json

SIGNATURE_DB = os.path.join(basedir, 'malware_signatures.txt')
QUARANTINE_FOLDER = os.path.join(basedir, 'quarantine')
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

def file_hashes(filepath):
    import hashlib
    hashes = {}
    with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
        data = f.read()
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
    return hashes

def load_signatures():
    if not os.path.exists(SIGNATURE_DB):
        return set()
    with open(get_resource_path(os.path.join(SIGNATURE_DB)), 'r') as f:
        return set(line.strip() for line in f if line.strip())

def ensure_suspicious_extensions_file():
    """
    Ensure the suspicious_extensions.txt file exists with default extensions.
    """
    suspicious_extensions_file = os.path.join(basedir, 'suspicious_extensions.txt')
    if not os.path.exists(suspicious_extensions_file):
        default_extensions = ['.exe', '.scr', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.msi', '.dll']
        with open(get_resource_path(os.path.join(suspicious_extensions_file)), 'w') as f:
            f.write('\n'.join(default_extensions))
        logging.info(f"Created default suspicious_extensions.txt at {suspicious_extensions_file}")
    return suspicious_extensions_file

def load_suspicious_extensions():
    """
    Load suspicious extensions from the suspicious_extensions.txt file.
    """
    suspicious_extensions_file = ensure_suspicious_extensions_file()
    with open(get_resource_path(os.path.join(suspicious_extensions_file)), 'r') as f:
        return {line.strip().lower() for line in f if line.strip()}

def is_suspicious(filename):
    """
    Check if a file is suspicious based on its extension or double extension.
    """
    lower = filename.lower()
    suspicious_extensions = load_suspicious_extensions()
    if any(lower.endswith(ext) for ext in suspicious_extensions):
        logging.warning(encrypt_message(f"Suspicious file detected based on extension: {filename}"))
        return True
    if '.' in lower and lower.split('.')[-2] in ['exe', 'scr', 'bat', 'cmd']:
        logging.warning(encrypt_message(f"Suspicious file detected based on double extension: {filename}"))
        return True
    return False

def is_microsoft_application(filepath):
    """
    Check if the file is a legitimate Microsoft application by inspecting its signature or publisher.
    """
    try:
        pe = pefile.PE(filepath)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if "microsoft" in entry.dll.decode('utf-8').lower():
                return True
        # Additional checks for publisher or signature can be added here
    except Exception as e:
        logging.warning(encrypt_message(f"Failed to inspect file for Microsoft signature: {filepath}, Error: {e}"))
    return False

def extract_archive(filepath, temp_dir):
    try:
        if filepath.lower().endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
        elif filepath.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz')):
            with tarfile.open(filepath) as tar_ref:
                tar_ref.extractall(temp_dir)
        elif filepath.lower().endswith('.rar'):
            with rarfile.RarFile(filepath) as rar_ref:
                rar_ref.extractall(temp_dir)
        else:
            logging.error(encrypt_message(f"Unsupported archive format: {filepath}"))
            return False
        return True
    except Exception as e:
        logging.error(encrypt_message(f"Failed to extract archive: {filepath}, Error: {e}"))
        return False
    
def scan_and_quarantine(filepath):
    try:
        # Load signatures and encryption key
        sigs = load_signatures()
        key = os.environ.get('FERNET_KEY')
        
        # Check if path is a directory
        if not os.path.isdir(filepath):
            logging.error(f"Path {filepath} is not a directory")
            return False
        
        # Initialize infection status
        infected = False
        
        # Walk through directory
        for root, dirs, files in os.walk(filepath):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    # Get file hashes
                    hashes = file_hashes(full_path)
                    # Check if file is suspicious
                    is_suspicious_file = is_suspicious(full_path)
                    is_malware = any(h in sigs for h in hashes.values())
                    
                    # Handle suspicious files
                    if is_suspicious_file and is_microsoft_application(full_path):
                        logging.info(encrypt_message(f"Legitimate Microsoft application detected: {full_path}. Skipping quarantine."))
                        continue
                    if is_suspicious_file or is_malware:
                        logging.warning(encrypt_message(f"Quarantining suspicious or malicious file: {full_path}"))
                        dest = os.path.join(QUARANTINE_FOLDER, os.path.basename(full_path) + '.enc')
                        encrypt_file(full_path, dest, key)
                        os.remove(full_path)
                        logging.warning(encrypt_message(f"File encrypted and quarantined: {full_path}"))
                        infected = True
                    else:
                        logging.info(encrypt_message(f"File clean: {full_path}"))
                except KeyboardInterrupt:
                    print(encrypt_message("Scan interrupted by user. No files will be deleted."))
                    logging.warning(encrypt_message("Scan interrupted by user during directory scan. No files deleted."))
                    return False
                except Exception as e:
                    logging.error(f"Error processing file {full_path}: {str(e)}")
                    continue
        
        return infected
    except Exception as e:
        logging.error(f"Error scanning directory {filepath}: {str(e)}")
        return False

def scan_and_quarantine_clean(filepath):
    try:
        # Load signatures and encryption key
        sigs = load_signatures()
        key = os.environ.get('FERNET_KEY')
        
        # Check if path is a directory
        if not os.path.isdir(filepath):
            logging.error(f"Path {filepath} is not a directory")
            return False
        
        # Initialize infection status
        infected = False
        
        # Walk through directory
        for root, dirs, files in os.walk(filepath):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    # Get file hashes
                    hashes = file_hashes(full_path)
                    # Check if file is suspicious
                    is_suspicious_file = is_suspicious(full_path)
                    is_malware = any(h in sigs for h in hashes.values())

                    # Handle legitimate Microsoft apps
                    if is_suspicious_file and is_microsoft_application(full_path):
                        logging.info(encrypt_message(f"Legitimate Microsoft application detected: {full_path}. Skipping quarantine."))
                        continue

                    # Handle suspicious or malware files
                    if is_suspicious_file or is_malware:
                        logging.warning(encrypt_message(f"Quarantining suspicious or malicious file: {full_path}"))
                        dest = os.path.join(QUARANTINE_FOLDER, os.path.basename(full_path) + '.enc')
                        encrypt_file(full_path, dest, key)
                        os.remove(full_path)
                        logging.warning(encrypt_message(f"File encrypted and quarantined: {full_path}"))
                        infected = True
                    else:
                        logging.info(encrypt_message(f"File clean: {full_path}"))
                except KeyboardInterrupt:
                    print(encrypt_message("Scan interrupted by user. No files will be deleted."))
                    logging.warning(encrypt_message("Scan interrupted by user during directory scan. No files deleted."))
                    return False
                except Exception as e:
                    logging.error(f"Error processing file {full_path}: {str(e)}")
                    continue

        return infected
    except Exception as e:
        logging.error(f"Error scanning directory {filepath}: {str(e)}")
        return False
@app.route('/safe-download', methods=['POST'])
def safe_download():
    # Download file
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or 'downloaded_file'
        download_path = os.path.join(temp_dir, filename)
        with open(get_resource_path(os.path.join(download_path)), 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        time.sleep(10)
        del response
        gc.collect()
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return render_template('new_safe_download.html', error=f'Failed to download file: {e}')

    # Scan for malware using scan_utils
    scan_success, malware_found, msg = scan_file_for_viruses(download_path)
    logging.info(encrypt_message(f"Antivirus scan for {download_path}: {msg}"))
    if not scan_success:
        os.remove(download_path)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return render_template('new_safe_download.html', error='Antivirus scan failed. Download rejected.')
    if malware_found:
        from quarantine_utils import quarantine_file  # Ensure the function is imported

    # Extract if archive
    time.sleep(10)
    gc.collect()
    archive_exts = ['.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz', '.rar', '.7z']
    if any(filename.lower().endswith(ext) for ext in archive_exts):
        extract_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)
        try:
            if filename.lower().endswith('.zip'):
                with zipfile.ZipFile(download_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif filename.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz')):
                with tarfile.open(download_path) as tar_ref:
                    tar_ref.extractall(extract_dir)
            else:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return render_template('safe_download.html', error=f'Unsupported archive format: {filename}')
            shutil.make_archive(extract_dir, 'zip', extract_dir)
            file_to_encrypt = extract_dir + '.zip'
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return render_template('safe_download.html', error=f'Failed to extract archive: {e}')

    # Encrypt file
    time.sleep(10)
    gc.collect()
    encrypted_name = filename + '.encrypted'
    encrypted_path = os.path.join(temp_dir, encrypted_name)
    try:
        encrypt_file(file_to_encrypt, encrypted_path)
        # Move encrypted file to ENCRYPTED_FOLDER for download
        os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
        final_path = os.path.join(ENCRYPTED_FOLDER, encrypted_name)
        shutil.move(encrypted_path, final_path)
        shutil.rmtree(temp_dir, ignore_errors=True)
        download_url = url_for('download_encrypted_file', filename=encrypted_name)
        return render_template('safe_download.html', success='File downloaded, scanned, and encrypted successfully!', download_url=download_url)
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return render_template('safe_download.html', error=f'Unexpected error: {e}')

@app.route('/download_encrypted/<filename>')
def download_encrypted_file(filename):
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if not os.path.exists(file_path):
        return 'File not found', 404
    return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)


# --- Quarantine Management Web UI ---

@app.route('/quarantine/list')
@login_required
def quarantine_list():
    # This logic mirrors the /quarantine route
    quarantined_files = []
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    try:
        for filename in os.listdir(QUARANTINE_FOLDER):
            file_path = os.path.join(QUARANTINE_FOLDER, filename)
            if not os.path.isfile(file_path):
                continue
            size = os.path.getsize(file_path)
            date_quarantined = ''
            original_path = ''
            reason = ''
            # Try to get metadata from a .json info file
            info_path = file_path + '.json'
            if os.path.exists(info_path):
                try:
                    with open(info_path, 'r', encoding='utf-8', errors='ignore') as f:
                        info = json.load(f)
                        date_quarantined = info.get('quarantine_time', '')
                        original_path = info.get('original_path', '')
                        reason = info.get('reason', '') or ', '.join(info.get('detection_info', {}).get('matches', []))
                except Exception:
                    pass
            quarantined_files.append({
                'name': filename,
                'size': size,
                'date_quarantined': date_quarantined,
                'original_path': original_path,
                'reason': reason,
                'path': file_path
            })
    except Exception as e:
        logger.error(f"Error reading quarantine folder: {e}")
    # Get quarantine log
    quarantine_log = ''
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine.log')
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                quarantine_log = f.read()
        except Exception as e:
            logger.error(f"Error reading quarantine log: {e}")
    return render_template('quarantine_list.html', quarantined_files=quarantined_files, quarantine_log=quarantine_log)

@app.route('/quarantine/list')
def list_quarantine():
    """
    Display a list of all files in quarantine with detailed information
    """
    # Get all files in the quarantine folder
    quarantined_files = []
    
    try:
        # List all files in the quarantine folder
        files = os.listdir(QUARANTINE_FOLDER)
        files = [f for f in files if os.path.isfile(os.path.join(QUARANTINE_FOLDER, f))]
        
        # Gather detailed information about each quarantined file
        for filename in files:
            file_path = os.path.join(QUARANTINE_FOLDER, filename)
            stats = os.stat(file_path)
            
            # Try to get metadata from the file if available
            original_path = ""
            reason = "Unknown"
            
            # You might store metadata about quarantined files
            # This is a placeholder for how you might retrieve that data
            metadata_path = file_path + ".meta"
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, 'r') as meta_file:
                        metadata = json.load(meta_file)
                        original_path = metadata.get('original_path', '')
                        reason = metadata.get('reason', 'Unknown')
                except Exception as e:
                    print(f"Error reading metadata for {filename}: {e}")
            
            quarantined_files.append({
                'name': filename,
                'path': file_path,
                'size': stats.st_size,
                'date_quarantined': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'original_path': original_path,
                'reason': reason
            })
            
        # Sort files by date (newest first)
        quarantined_files.sort(key=lambda x: x['date_quarantined'], reverse=True)
        
    except Exception as e:
        print(f"Error retrieving quarantined files: {e}")
    
    # Read recent quarantine events from the log, similar to the original function
    quarantine_log = ''
    log_path = LOG_FILE
    if os.path.exists(log_path):
        try:
            with open(get_resource_path(os.path.join(log_path)), 'r', encoding='utf-8', errors='ignore') as f:
                encrypted_lines = f.read()[-10000:].split('\n')
                decrypted_lines = []
                for line in encrypted_lines:
                    try:
                        decrypted_lines.append(decrypt_message(line))
                    except Exception:
                        decrypted_lines.append('[ENCRYPTED LOG LINE COULD NOT BE DECRYPTED]')
                log_content = '\n'.join(decrypted_lines)
            
            # Filter for quarantine-related events
            quarantine_lines = [
                line for line in log_content.split('\n')
                if 'Quarantined (encrypted):' in line or 'Deleted' in line
            ]
            quarantine_log = '\n'.join(quarantine_lines[-20:]) if quarantine_lines else ''
        except Exception as e:
            print(f"Error reading log file: {e}")
    
    # Render the quarantine list template with the gathered data
    return render_template('quarantine_list.html', 
                          quarantined_files=quarantined_files, 
                          quarantine_log=quarantine_log)
    
@app.route('/quarantine')
def quarantine():
    files = os.listdir(QUARANTINE_FOLDER)
    files = [f for f in files if os.path.isfile(os.path.join(QUARANTINE_FOLDER, f))]
    # Read recent quarantine/deletion events from the log
    quarantine_log = ''
    log_path = LOG_FILE
    if os.path.exists(log_path):
        with open(get_resource_path(os.path.join(log_path)), 'r', encoding='utf-8', errors='ignore') as f:
            encrypted_lines = f.read()[-10000:].split('\n')
            decrypted_lines = []
            for line in encrypted_lines:
                try:
                    decrypted_lines.append(decrypt_message(line))
                except Exception:
                    decrypted_lines.append('[ENCRYPTED LOG LINE COULD NOT BE DECRYPTED]')
            log_content = '\n'.join(decrypted_lines)
        # Optionally, highlight quarantine/deletion events
        # This can be enhanced further if needed
        quarantine_lines = [
            line for line in log_content.split('\n')
            if 'Quarantined (encrypted):' in line or 'Deleted' in line
        ]
        quarantine_log = '\n'.join(quarantine_lines[-20:]) if quarantine_lines else ''
    return render_template('quarantine.html', files=files, quarantine_log=quarantine_log)

@app.route('/network_monitor/<action>', methods=['POST'])
def network_monitor(action):
    global network_monitor_running
    try:
        if action == 'start':
            if not network_monitor_running:
                network_monitor_running = True
                return jsonify({'success': True, 'message': 'Network monitor started'})
            else:
                return jsonify({'success': False, 'error': 'Network monitor is already running'})
        elif action == 'stop':
            if network_monitor_running:
                network_monitor_running = False
                return jsonify({'success': True, 'message': 'Network monitor stopped'})
            else:
                return jsonify({'success': False, 'error': 'Network monitor is not running'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/auto_updates/<action>', methods=['POST'])
def auto_updates(action):
    global auto_updates_running
    try:
        if action == 'start':
            if not auto_updates_running:
                auto_updates_running = True
                return jsonify({'success': True, 'message': 'Auto updates started'})
            else:
                return jsonify({'success': False, 'error': 'Auto updates are already running'})
        elif action == 'stop':
            if auto_updates_running:
                auto_updates_running = False
                return jsonify({'success': True, 'message': 'Auto updates stopped'})
            else:
                return jsonify({'success': False, 'error': 'Auto updates are not running'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Service Toggle Routes
@app.route('/toggle_network_monitor/<action>', methods=['POST'])
@requires_auth
def toggle_network_monitor(action):
    """Toggle network monitor service on/off."""
    global network_monitor_running
    try:
        if action.lower() not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        network_monitor_running = action.lower() == 'start'
        return jsonify({'success': True, 'status': 'ENABLED' if network_monitor_running else 'DISABLED'})
    except Exception as e:
        logging.error(f"Error toggling network monitor: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/toggle_folder_watcher/<action>', methods=['POST'])
@requires_auth
def toggle_folder_watcher(action):
    """Toggle folder watcher service on/off."""
    global folder_watcher_running
    try:
        if action.lower() not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        folder_watcher_running = action.lower() == 'start'
        return jsonify({'success': True, 'status': 'ENABLED' if folder_watcher_running else 'DISABLED'})
    except Exception as e:
        logging.error(f"Error toggling folder watcher: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/toggle_safe_downloader/<action>', methods=['POST'])
@requires_auth
def toggle_safe_downloader(action):
    """Toggle safe downloader service on/off."""
    global safe_downloader_running
    try:
        if action.lower() not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        safe_downloader_running = action.lower() == 'start'
        return jsonify({'success': True, 'status': 'ENABLED' if safe_downloader_running else 'DISABLED'})
    except Exception as e:
        logging.error(f"Error toggling safe downloader: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/quarantine/download/<filename>')
def quarantine_download(filename):
    from cryptography.fernet import Fernet, InvalidToken
    from secure_memory import SecureBuffer
    from secure_message import encrypt_message, decrypt_message
    import io
    from flask import send_file

    file_path = os.path.join(QUARANTINE_FOLDER, filename)
    if not os.path.exists(file_path):
        return 'File not found', 404
    key = os.environ.get('FERNET_KEY')
    if not key:
        return 'Encryption key not set', 500
    if isinstance(key, str):
        key = key.encode()
    secure_key = SecureBuffer(key)
    fernet = Fernet(secure_key.get_bytes())
    with open(get_resource_path(os.path.join(file_path)), 'rb') as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        secure_key.zero_and_unlock()
        return 'Failed to decrypt file', 500
    secure_key.zero_and_unlock()
    return send_file(io.BytesIO(decrypted), download_name=filename[:-4] if filename.endswith('.enc') else filename, as_attachment=True)


@app.route('/quarantine/delete/<path:filename>')
def quarantine_delete(filename):
    from quarantine_utils import force_unlock_windows
    file_path = os.path.join(QUARANTINE_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found', 'filename': filename}), 404
    try:
        os.remove(file_path)
        return jsonify({'status': 'success', 'message': f'{filename} deleted from quarantine'})
    except PermissionError:
        force_unlock_windows(file_path)
        try:
            os.remove(file_path)
            return jsonify({'status': 'success', 'message': f'{filename} deleted from quarantine after unlocking'})
        except Exception as e:
            return jsonify({'error': f'Failed to delete {filename}: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to delete {filename}: {str(e)}'}), 500



@app.route('/logs')
def logs():
    log_path = LOG_FILE
    log_content = ''
    if os.path.exists(log_path):
        with open(get_resource_path(os.path.join(log_path)), 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()[-10000:]  # Show last 10k chars
    # Optionally, highlight quarantine/deletion events
    # This can be enhanced further if needed
    return render_template('logs.html', log_content=log_content)


UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ENCRYPTED_FOLDER = os.path.join(basedir, 'encrypted')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# Initialize folder watcher process and RTP status
folder_watcher_process = None
rtp_status_flag = None  # 'STARTING', 'ENABLED', or None

# Create static directory if it doesn't exist
STATIC_FOLDER = 'static'
os.makedirs(os.path.join(basedir, STATIC_FOLDER), exist_ok=True)

# Create favicon.ico if it doesn't exist
favicon_path = os.path.join(basedir, STATIC_FOLDER, 'favicon.ico')
if not os.path.exists(favicon_path):
    with open(get_resource_path(os.path.join(favicon_path)), 'wb') as f:
        f.write(b'')

folder_watcher_process = None

import json

# --- Real-time protection status helper ---
def get_realtime_status(folder_watcher, network_monitor_running, safe_downloader_service, rtp_status_flag):
    """Get the current status of real-time protection"""
    if folder_watcher is not None and rtp_status_flag == 'ENABLED':
        return {
            'status': 'ENABLED',
            'folder_watcher': True,
            'network_monitor': network_monitor_running,
            'safe_downloader': safe_downloader_service is not None and safe_downloader_service.is_alive()
        }
    elif rtp_status_flag == 'STARTING':
        return {
            'status': 'STARTING...',
            'folder_watcher': folder_watcher is not None,
            'network_monitor': network_monitor_running,
            'safe_downloader': safe_downloader_service is not None and safe_downloader_service.is_alive()
        }
    else:
        return {
            'status': 'DISABLED',
            'folder_watcher': False,
            'network_monitor': False,
            'safe_downloader': False
        }
    
@app.route('/start_folder_watcher', methods=['POST'])
def start_folder_watcher_manual():
    """
    Start the folder watcher process manually via user action. No auto-start.
    """
    global folder_watcher, rtp_status_flag
    if folder_watcher is not None:
        rtp_status_flag = 'ENABLED'
        return redirect(url_for('index', status='Folder Watcher already running'))
    try:
                # Get common directories to monitor
        home_dir = os.path.expanduser("~")
        common_dirs = [
            os.path.join(home_dir, "Downloads"),
            os.path.join(home_dir, "Desktop"),
            os.path.join(home_dir, "Documents")
        ]
        
        # Filter out non-existent directories
        directories = [d for d in common_dirs if os.path.exists(d) and os.path.isdir(d)]
        
        folder_watcher = FolderWatcher(directories)
        rtp_status_flag = 'ENABLED'
        logging.info(encrypt_message('[FOLDER_WATCHER_MANUAL] Folder watcher started inside main app process (manual trigger).'))
        return redirect(url_for('index', status='Folder Watcher started'))
    except Exception as e:
        logging.error(encrypt_message(f'[FOLDER_WATCHER_MANUAL] Failed to start folder watcher in main app: {e}'))
        return redirect(url_for('index', status=f'Failed to start Folder Watcher: {e}'))


# --- Scheduled Scan Control (persistent state) ---
# scheduled_scan_thread is no longer managed here; all background processes are managed by conditional_startup.py
scheduled_scan_thread = None  # Deprecated, kept for UI compatibility
SCHEDULED_SCAN_STATE_FILE = os.path.join(basedir, 'scheduled_scan_state.json')

def load_scheduled_scan_state():
    try:
        with open(get_resource_path(os.path.join(SCHEDULED_SCAN_STATE_FILE)), 'r') as f:
            state = json.load(f)
            return bool(state.get('enabled', False))
    except Exception:
        return False

def save_scheduled_scan_state(enabled):
    try:
        with open(get_resource_path(os.path.join(SCHEDULED_SCAN_STATE_FILE)), 'w') as f:
            json.dump({'enabled': bool(enabled)}, f)
    except Exception as e:
        logging.error(encrypt_message(f'Failed to save scheduled scan state: {e}'))

scheduled_scan_enabled = load_scheduled_scan_state()
# No background scan is started here. All background tasks must be started manually or by user action.
@app.route('/', methods=['GET', 'POST'])
def index():
    # Ensure we have all required global variables first
    global folder_watcher, rtp_status_flag, safe_download_service, scheduled_scan_enabled
    if folder_watcher is None:
                # Get common directories to monitor
        home_dir = os.path.expanduser("~")
        common_dirs = [
            os.path.join(home_dir, "Downloads"),
            os.path.join(home_dir, "Desktop"),
            os.path.join(home_dir, "Documents")
        ]
        
        # Filter out non-existent directories
        directories = [d for d in common_dirs if os.path.exists(d) and os.path.isdir(d)]
        
        folder_watcher = FolderWatcher(directories)
    if safe_download_service is None:
        safe_download_service = SafeDownloadService()
    if rtp_status_flag is None:
        rtp_status_flag = 'DISABLED'

    # Get C2 detector status
    c2_detector_low_count = 0
    c2_detector_high_count = 0
    try:
        c2_status = network_monitor.get_c2_detector_status()
        c2_detector_low_count = int(c2_status.get('low_count', 0))  # Convert to int
        c2_detector_high_count = int(c2_status.get('high_count', 0))  # Convert to int
    except Exception as e:
        logging.error(f"Error getting C2 detector status: {e}")

    # Get network monitor status
    network_monitor_running = hasattr(network_monitor, '_monitor_thread') and network_monitor._monitor_thread.is_alive()

    # Get real-time status with all required parameters
    try:
        status = get_realtime_status(
            folder_watcher,
            network_monitor_running,
            safe_download_service,
            rtp_status_flag
        )
    except Exception as e:
        logging.error(f"Error getting real-time status: {e}")
        status = {
            'status': 'DISABLED',
            'folder_watcher': False,
            'network_monitor': False,
            'safe_downloader': False
        }

    scan_results = request.args.get('scan_results', None)
    process_scan_results = request.args.get('process_scan_results', None)
    yara_scan_results = request.args.get('yara_scan_results', None)
    
    if request.method == 'POST':
        pass
    
    logging.info(encrypt_message(f"Web: Accessed index page from {request.remote_addr}"))
    monitored_folders = load_monitored_folders()
    
    if not monitored_folders:
        return "No monitored folders configured. Please check scan_directories.txt or folder_watcher configuration."

    # Pass only the status information about folder watcher
    folder_watcher_status = {
        'is_running': folder_watcher is not None and hasattr(folder_watcher, 'is_alive') and folder_watcher.is_alive,
        'has_started': folder_watcher is not None
    }

    return render_template(
        'index.html',
        status=json.dumps(status),
        scan_results=scan_results,
        process_scan_results=process_scan_results,
        yara_scan_results=yara_scan_results,
        scheduled_scan_enabled=scheduled_scan_enabled,
        monitored_folders=monitored_folders,
        c2_detector_low_count=c2_detector_low_count,
        network_monitor_running=network_monitor_running,
        folder_watcher_status=folder_watcher_status
    )



@app.route('/stop_folder_watcher', methods=['POST'])
def stop_folder_watcher_ui():
    """Stop the folder watcher process"""
    global folder_watcher, rtp_status_flag
    if folder_watcher is not None:
        try:
            folder_watcher.is_alive = False
            folder_watcher = None
            rtp_status_flag = None
            logging.info(encrypt_message('[FOLDER_WATCHER] Stopped folder watcher'))
            return redirect(url_for('index', status='Folder Watcher stopped'))
        except Exception as e:
            logging.error(encrypt_message(f'[FOLDER_WATCHER] Failed to stop folder watcher: {e}'))
            return redirect(url_for('index', status=f'Failed to stop Folder Watcher: {e}'))
    return redirect(url_for('index', status='Folder Watcher not running'))

# Service Control Endpoints
@app.route('/folder_watcher/<action>', methods=['POST'])
def folder_watcher_action(action):
    """Handle folder watcher start/stop actions"""
    try:
        # Declare global variables first
        global real_time_protection_running, real_time_protection_thread
        
        if action == 'start':
            if not real_time_protection_running:
                real_time_protection_running = True
                real_time_protection_thread = threading.Thread(target=real_time_protection)
                real_time_protection_thread.daemon = True
                real_time_protection_thread.start()
                return jsonify({'success': True, 'message': 'Real-time protection started'}), 200
            return jsonify({'success': False, 'error': 'Real-time protection is already running'}), 400
        elif action == 'stop':
            if real_time_protection_running:
                real_time_protection_running = False
                return jsonify({'success': True, 'message': 'Real-time protection stopped'}), 200
            return jsonify({'success': False, 'error': 'Real-time protection is not running'}), 400
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/safe_downloader/<action>', methods=['POST'])
def safe_downloader_action(action):
    """Handle safe downloader start/stop actions"""
    try:
        if action == 'start':
            start_safe_downloader()
            return jsonify({'success': True, 'message': 'Safe downloader started'}), 200
        elif action == 'stop':
            stop_safe_downloader_ui()
            return jsonify({'success': True, 'message': 'Safe downloader stopped'}), 200
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# This initialization has been moved to the top of the file

@app.route('/network_monitor/<action>', methods=['POST'])
def network_monitor_action(action):
    """Handle network monitor start/stop actions"""
    try:
        if action == 'start':
            if network_monitor_running:
                return jsonify({'success': False, 'error': 'Network Monitor already running'})
            try:
                # Start monitoring threads
                logging.info(encrypt_message('[NETWORK_MONITOR] Starting network monitor threads'))
                network_monitor.start_traffic_monitor()
                network_monitor.start_download_monitor()
                network_monitor_running = True
                return jsonify({'success': True, 'message': 'Network Monitor started'})
            except Exception as e:
                error_message = f'[NETWORK_MONITOR] Failed to start network monitor: {e}'
                logging.error(encrypt_message(error_message))
                return jsonify({'success': False, 'error': str(e)})
        
        elif action == 'stop':
            network_monitor_running = False
            network_monitor.stop_traffic_monitor()
            network_monitor.stop_download_monitor()
            logging.info(encrypt_message('[NETWORK_MONITOR] Stopped by user'))
            return jsonify({'success': True, 'message': 'Network Monitor stopped'})
        
        return jsonify({'success': False, 'error': 'Invalid action'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



    # Initialize network monitor
    network_monitor = NetworkMonitor()   
    if action == 'start':
        if network_monitor_running:
            return jsonify({'success': False, 'error': 'Network Monitor already running'})
        try:
            from network_monitor import monitor_connections, monitor_bandwidth, log_dns_requests
            logging.info(encrypt_message('[NETWORK_MONITOR] Starting network monitor threads'))
            t1 = threading.Thread(target=monitor_connections, daemon=True)
            t2 = threading.Thread(target=monitor_bandwidth, daemon=True)
            t3 = threading.Thread(target=log_dns_requests, daemon=True)
            for t in (t1, t2, t3):
                t.start()
            network_monitor_threads = [t1, t2, t3]
            network_monitor_running = True
            return jsonify({'success': True, 'message': 'Network Monitor started'})
        except Exception as e:
            error_message = f'[NETWORK_MONITOR] Failed to start network monitor: {e}'
            logging.error(encrypt_message(error_message))
            return jsonify({'success': False, 'error': str(e)})
    
    elif action == 'stop':
        network_monitor_running = False
        for thread in network_monitor_threads:
            if thread.is_alive():
                thread.join(timeout=1)
        network_monitor_threads = []
        logging.info(encrypt_message('[NETWORK_MONITOR] Stopped by user'))
        return jsonify({'success': True, 'message': 'Network Monitor stopped'})
    
    return jsonify({'success': False, 'error': 'Invalid action'})

# Network Monitoring Data Endpoints
@app.route('/get_traffic_stats', methods=['GET'])
def get_traffic_stats():
    """Get current network traffic statistics"""
    try:
        stats = network_monitor.get_traffic_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_c2_patterns', methods=['GET'])
def get_c2_patterns():
    """Get detected C2 patterns"""
    try:
        patterns = network_monitor.get_c2_patterns()
        return jsonify({'success': True, 'patterns': patterns})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_rate_limited_ips', methods=['GET'])
def get_rate_limited_ips():
    """Get rate limited IPs"""
    try:
        ips = network_monitor.get_rate_limited_ips()
        return jsonify({'success': True, 'ips': ips})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/block_ip/<ip>', methods=['POST'])
def block_ip(ip):
    """Block an IP address"""
    try:
        network_monitor.block_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} blocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/unblock_ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP address"""
    try:
        network_monitor.unblock_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/whitelist_ip/<ip>', methods=['POST'])
def whitelist_ip(ip):
    """Whitelist an IP address"""
    try:
        network_monitor.whitelist_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} whitelisted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# C2 Detector Report Endpoint
@app.route('/c2_detector_report', methods=['GET'])
def c2_detector_report():
    """Generate C2 detector report"""
    try:
        response = get_c2_patterns()
        if not response.get('success'):
            return "Error fetching C2 patterns: {}".format(response.get('error', 'Unknown error')), 500
            
        c2_data = response.get('patterns', {})
        
        # Format report content
        report_content = """
        <h2>C2 Detector Report</h2>
        <p>Generated: {}</p>
        <h3>Detection Summary</h3>
        <ul>
            <li><strong>Total Patterns:</strong> {}</li>
            <li><strong>High Confidence:</strong> {}</li>
            <li><strong>Medium Confidence:</strong> {}</li>
            <li><strong>Low Confidence:</strong> {}</li>
        </ul>
        <h3>Detected Patterns</h3>
        <div style="margin-top: 20px;">
            {}
        </div>
        """
        
        # Count confidence levels
        confidence_counts = {
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Format detected patterns
        patterns_html = ""
        for ip, info in c2_data.items():
            confidence = info.get('confidence', 'low')
            confidence_counts[confidence] += 1
            patterns_html += f"""
            <div style="margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 4px;">
                <h4 style="margin: 0 0 10px 0;">IP: {ip}</h4>
                <p><strong>Confidence:</strong> {info.get('confidence', 'low')}</p>
                <p><strong>Reason:</strong> {info.get('reason', 'Unknown')}</p>
                <p><strong>Last Active:</strong> {info.get('timestamp', 'Unknown')}</p>
                <p><strong>Additional Info:</strong> {info.get('additional_info', 'None')}</p>
            </div>
            """
        
        # Fill in the template
        report_content = report_content.format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            len(c2_data),
            confidence_counts['high'],
            confidence_counts['medium'],
            confidence_counts['low'],
            patterns_html
        )
        
        return report_content
    except Exception as e:
        logging.error(f"Error generating C2 report: {e}")
        return "Error generating C2 detector report", 500

@app.route('/stop_safe_downloader', methods=['POST'])
def stop_safe_downloader_ui():
    global safe_downloader_running
    safe_downloader_running = False
    logging.info(encrypt_message('[SAFE_DOWNLOADER] Stopped by user (thread may still be alive).'))
    return redirect(url_for('index', status='Safe Downloader stopped'))

@app.route('/start_antivirus_cli', methods=['POST'])
def start_antivirus_cli():
    """Trigger starting the Antivirus CLI script."""
    try:
        script_path = os.path.join(basedir, "antivirus_cli.py")
        # Launch as detached process (works on Windows)
        subprocess.Popen(
            ["python", script_path],
            cwd=basedir,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        )
        flash("Antivirus CLI started successfully.", "success")
    except Exception as e:
        flash(f"Failed to start Antivirus CLI: {e}", "danger")
    return redirect(url_for('index'))

# --- Optional: Stop endpoints if your system can stop these services (advanced) ---

dns_server_thread = None

def start_dns_server_ui():
    """Start the DNS server in a background thread."""
    global dns_server_thread
    try:
        if dns_server_thread is None or not dns_server_thread.is_alive():
            dns_server_thread = threading.Thread(target=start_dns_server, daemon=True)
            dns_server_thread.start()
            return "DNS server started successfully"
        else:
            return "DNS server is already running"
    except Exception as e:
        return f"Error starting DNS server: {str(e)}"

def stop_dns_server_ui():
    """Stop the DNS server (note: this is a best effort since we can't directly stop the server)"""
    global dns_server_thread
    if dns_server_thread and dns_server_thread.is_alive():
        dns_server_thread = None  # Mark as stopped
        return "DNS server marked for shutdown"
    return "DNS server is not running"

# Add endpoints for DNS server control
@app.route('/dns_server/<action>', methods=['POST'])
@requires_auth
def dns_server_action(action):
    """Handle DNS server start/stop actions"""
    global dns_server_thread
    
    if action == 'start':
        try:
            if dns_server_thread is None or not dns_server_thread.is_alive():
                dns_server_thread = threading.Thread(target=start_dns_server, daemon=True)
                dns_server_thread.start()
                return jsonify({'success': True, 'message': 'DNS Server started'})
            else:
                return jsonify({'success': False, 'error': 'DNS Server is already running'})
        except Exception as e:
            error_message = f'[DNS_SERVER] Failed to start: {e}'
            logging.error(encrypt_message(error_message))
            return jsonify({'success': False, 'error': str(e)})
    
    elif action == 'stop':
        if dns_server_thread and dns_server_thread.is_alive():
            dns_server_thread = None
            return jsonify({'success': True, 'message': 'DNS Server stopped'})
        return jsonify({'success': False, 'error': 'DNS Server is not running'})
    
    return jsonify({'success': False, 'error': 'Invalid action'})
from update_signatures import update_signatures
from auto_update_signatures import start_auto_update_thread
from malwarebazaar_updater import update_local_signatures

from security.process_monitor import scan_running_processes

from flask import request, jsonify, render_template, redirect, url_for, flash
import subprocess

# Initialize global variables
folder_watcher_thread = None
network_monitor_threads = []
safe_downloader_thread = None
antivirus_cli_thread = None
auto_update_thread = None
real_time_protection_thread = None
rtp_status_flag = 'ENABLED'  # Initialize as enabled by default

folder_watcher_running = True  # Default to True for security
network_monitor_running = True  # Default to True for security
safe_downloader_running = True  # Default to True for security
antivirus_cli_running = True  # Default to True for security
auto_update_running = True  # Default to True for security
real_time_protection_running = True  # Default to True for security

# Initialize services with the monitored directories loaded from configuration
folder_watcher = FolderWatcher(load_scan_directories())
safe_download_service = SafeDownloadService()  # Initialize the service

# Start folder watcher and other services automatically for real-time protection
folder_watcher.start()
logging.info("Folder watching service started automatically at application startup")

# This initialization has been moved to the top of the file

# Initialize monitored directories
monitored_directories = load_scan_directories()

# Initialize malware detector
detector = MalwareDetector()

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=storage_uri,
    strategy="fixed-window-elastic-expiry"
)

@app.route('/run_conditional_startup', methods=['POST', 'GET'])
def run_conditional_startup():
    """Run conditional_startup logic directly and return output to frontend, with detailed error logging."""
    import traceback
    import datetime
    log_path = os.path.join(basedir, 'conditional_startup_debug.log')
    try:
        try:
            from conditional_startup import run_conditional_startup_logic
        except ImportError as imp_exc:
            msg = f'Could not import run_conditional_startup_logic: {imp_exc}'
            flash(msg, 'error')
            with open(get_resource_path(os.path.join(log_path)), 'a', encoding='utf-8') as logf:
                logf.write(f"[{datetime.datetime.now()}] IMPORT ERROR: {msg}\n")
            return redirect(url_for('index'))
        try:
            start_time = time.time()
            scan_data = run_conditional_startup_logic()
            duration = time.time() - start_time
            results, output = normalize_conditional_startup_data(scan_data)
            summary = dict(record_conditional_startup_run(scan_data, duration))
            with open(get_resource_path(os.path.join(log_path)), 'a', encoding='utf-8') as logf:
                logf.write(f"[{datetime.datetime.now()}] Ran run_conditional_startup_logic\n{output}\n")
            flash('Conditional startup completed. See output below.', 'success')
            return render_template(
                'conditional_startup_result.html',
                output=output,
                results=results,
                summary=summary
            )
        except Exception as logic_exc:
            tb = traceback.format_exc()
            msg = f'Exception running conditional_startup logic: {logic_exc}'
            record_conditional_startup_run(error=logic_exc)
            flash(msg + ' (see debug log for details)', 'error')
            with open(get_resource_path(os.path.join(log_path)), 'a', encoding='utf-8') as logf:
                logf.write(f"[{datetime.datetime.now()}] LOGIC EXCEPTION:\n{tb}\n")
            return redirect(url_for('index'))
    except Exception as e:
        tb = traceback.format_exc()
        msg = f'Error running conditional_startup logic: {e}'
        flash(msg + ' (see debug log for details)', 'error')
        with open(get_resource_path(os.path.join(log_path)), 'a', encoding='utf-8') as logf:
            logf.write(f"[{datetime.datetime.now()}] OUTER EXCEPTION:\n{tb}\n")
        return redirect(url_for('index'))

@app.route('/action/<action>', methods=['POST'])
def perform_action(action):
    """Handle various scan actions"""
    if not network_monitor_running:
        return jsonify({'success': False, 'error': 'Please start network monitoring first'})
    
    try:
        if action == 'scan_all_processes':
            from security.process_monitor import scan_running_processes
            results = scan_running_processes()
            return jsonify({'success': True, 'results': results})
        
        elif action == 'run_conditional_startup':
            from conditional_startup import run_conditional_startup_logic
            results = run_conditional_startup_logic()
            return jsonify({'success': True, 'results': results})
        
        elif action == 'scan_all_monitored':
            # Call the correct scan function and ensure it returns a JSON-serializable result
            from folder_watcher import scan_all_monitored_directories
            results = scan_all_monitored_directories()
            return jsonify({'success': True, 'results': results})
        
        return jsonify({'success': False, 'error': 'Invalid action'})
    
    except Exception as e:
        error_message = f'Failed to perform {action}: {e}'
        logging.error(encrypt_message(error_message))
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_service_states', methods=['GET'])
def get_service_states():
    """Get the current state of all services"""
    return jsonify({
        'network_monitor_running': network_monitor_running,
        'folder_watcher_running': folder_watcher_running,
        'safe_downloader_running': safe_downloader_running
    })

@app.route('/get_scan_results', methods=['GET'])
def get_scan_results():
    try:
        logging.info(encrypt_message(f"Web: Accessed scan_all_processes page from {request.remote_addr}"))
        import traceback
        results = []
        def scan_and_collect(exe_path):
            try:
                scan_success, malware_found, msg = scan_file_for_viruses(exe_path)
                if not scan_success:
                    results.append(f'Scan failed: {exe_path}: {msg}')
                elif malware_found:
                    results.append(f'Malware found: {exe_path}: {msg}')
                else:
                    results.append(f'Clean: {exe_path}')
            except Exception as e:
                results.append(f'Error: {exe_path}: {traceback.format_exc()}')
        scan_running_processes(scan_and_collect)
        summary = f"Process scan complete. Processes scanned: {len(results)}\n" + '\n'.join(results[-10:])
        logging.info(encrypt_message(summary))
        return render_template('index.html', process_scan_results=summary, status="ON" if folder_watcher_process and folder_watcher_process.poll() is None else "OFF")
    except Exception as e:
        return render_template('index.html', process_scan_results=f'Error: {e}', status="ON" if folder_watcher_process and folder_watcher_process.poll() is None else "OFF")

@app.route('/update_signatures', methods=['POST'])
def update_signatures_route():
    try:
        update_signatures()
        msg = 'Malware signatures updated successfully.'
    except Exception as e:
        msg = f'Update failed: {e}'
    return render_template('index.html', scan_results=msg)

@app.route('/update_malware_signatures', methods=['POST'])
def update_malware_signatures():
    try:
        added = update_local_signatures()
        if added > 0:
            msg = f"Added {added} new malware signatures from MalwareBazaar."
        else:
            msg = "No new signatures added or failed to fetch."
        logging.info(encrypt_message(f"[MALWAREBAZAAR] {msg}"))
    except Exception as e:
        msg = f"Error updating signatures from MalwareBazaar: {e}"
        logging.error(encrypt_message(f"[MALWAREBAZAAR] {msg}"))
    return render_template('index.html', scan_results=msg)

@app.route('/start_auto_updates', methods=['POST'])
def start_auto_updates():
    global auto_update_thread, auto_update_running
    try:
        if not auto_update_running:
            auto_update_thread = threading.Thread(
                target=start_auto_update_thread,
                daemon=True
            )
            auto_update_thread.start()
            auto_update_running = True
            return jsonify({'status': 'success', 'message': 'Auto updates started'})
        else:
            return jsonify({'status': 'warning', 'message': 'Auto updates are already running'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stop_auto_updates', methods=['POST'])
def stop_auto_updates():
    global auto_update_running
    try:
        auto_update_running = False
        return jsonify({'status': 'success', 'message': 'Auto updates stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Provide a basic iframe-compatible UI for file_crypto
@app.route('/file_crypto')
def file_crypto_ui():
    return render_template('file_crypto.html', csrf_token=generate_csrf())

# Initialize monitored directories
monitored_directories = load_scan_directories()

if not detector.load_model('malware'):
    if not detector.train_all_models():
        logging.error("Failed to load or train threat detection models at startup")
        # As a fallback, create default models
        detector.models['malware'] = detector.create_malware_model()
        detector.models['ddos'] = detector.create_ddos_model()
        detector.models['exfiltration'] = detector.create_exfiltration_model()
        detector.models['lateral_movement'] = detector.create_lateral_movement_model()
        logging.warning("Created default models as fallback")

# Create quarantine folder if it doesn't exist
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Initialize scan_directories.txt with default directories if it doesn't exist
scan_directories_file = os.path.join(basedir, 'scan_directories.txt')
if not os.path.exists(scan_directories_file):
    with open(scan_directories_file, 'w') as f:
        f.write('C:\\Windows\\Temp\\\nC:\\Users\\\\AppData\\Local\\Temp\\\n')

def is_infected(file_path):
    # Placeholder for actual malware detection logic
    return False  # Replace with actual detection logic

def perform_manual_scan_pages():
    # This function will specifically scan for monitored pages
    # Assuming monitored pages are considered as .html files
    monitored_pages = []
    
    for scan_directory in folder_watcher.get_directories():
        # Check if the directory exists before scanning
        if not os.path.exists(scan_directory):
            print(f"Directory does not exist: {scan_directory}")
            continue
        
        # Walk through the directory and gather HTML files
        for root, dirs, files in os.walk(scan_directory):
            for file in files:
                if file.endswith('.html'):  # Assuming we are looking for HTML pages
                    file_path = os.path.join(root, file)
                    monitored_pages.append(file_path)
    if monitored_pages:
        return f"Monitored pages found: {', '.join(monitored_pages)}"
    
    return "No monitored pages found."

def perform_manual_scan():
    infected_files = []
    
    # Use the directories from the folder watcher directly
    for scan_directory in folder_watcher.get_directories():
        # Check if the directory exists before scanning
        if not os.path.exists(scan_directory):
            print(f"Directory does not exist: {scan_directory}")
            continue
        
        # Walk through the directory and gather files
        for root, dirs, files in os.walk(scan_directory):
            for file in files:
                file_path = os.path.join(root, file)
                if is_infected(file_path):  # Check if the file is infected
                    infected_files.append(file_path)
    if infected_files:
        return f"Infected files found: {', '.join(infected_files)}"
    
    return "No infected files found."
@app.route('/scan_pages', methods=['POST'])
def scan_pages():
    # Automatically trigger the manual scan for pages
    scan_result = perform_manual_scan_pages()
    return render_template('index.html', scan_results=scan_result, status='ON')

@app.route('/something', methods=['POST'])
def scan_all_monitored():
    """Scan all monitored folders for threats using ML models."""
    try:
        results = []
        monitored_folders = load_scan_directories()
        
        for folder in monitored_folders:
            if not os.path.exists(folder):
                continue
                
            for root, _, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Skip system files and directories
                        if any(sys_dir in file_path.lower() for sys_dir in ['windows', 'program files']):
                            continue
                            
                        # Skip if file is in quarantine
                        if QUARANTINE_FOLDER in file_path.lower():
                            continue
                            
                        # Perform ML-based threat detection
                        ml_results = detect_threat(file_path)
                        
                        # Check for traditional threats
                        is_traditional_threat = is_infected(file_path)
                        
                        # Combine results
                        result = {
                            'file_path': file_path,
                            'size': os.path.getsize(file_path),
                            'last_modified': os.path.getmtime(file_path),
                            'ml_results': ml_results,
                            'is_traditional_threat': is_traditional_threat
                        }
                        results.append(result)
                        
                        # If any threat is detected, handle it
                        if ml_results.get('malware', {}).get('prediction', 0) == 1 or is_traditional_threat:
                            handle_threat(file_path, 'malware')
                        if ml_results.get('ddos', {}).get('prediction', 0) == 1:
                            handle_threat(file_path, 'ddos')
                        if ml_results.get('exfiltration', {}).get('prediction', 0) == 1:
                            handle_threat(file_path, 'exfiltration')
                        if ml_results.get('lateral_movement', {}).get('prediction', 0) == 1:
                            handle_threat(file_path, 'lateral_movement')
                            
                    except Exception as e:
                        logging.error(f"Error scanning {file_path}: {e}")
                        continue
        
        return jsonify({
            'status': 'success',
            'results': results,
            'total_files_scanned': len(results)
        })
    except Exception as e:
        logging.error(f"Error in scan_all_monitored: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    except Exception as e:
        logging.info(encrypt_message(f"Web: Starting scan of all monitored folders from {request.remote_addr}"))
    # Get monitored folders directly from FolderWatcher
    monitored_folders = folder_watcher.get_directories()
    
    if not monitored_folders:
        error_msg = "No monitored folders configured. Please check scan_directories.txt or folder_watcher configuration."
        logging.error(encrypt_message(error_msg))
        return render_template('index.html', 
                                   scan_results=error_msg,
                                   status='ERROR')    
    results = []
    total_scanned = 0
    max_file_size = 100 * 1024 * 1024  # 100 MB
    # Scan each monitored folder
    for folder in monitored_folders:
        logging.info(encrypt_message(f"Scanning folder: {folder}"))
        return psutil.net_io_counters().bytes_sent / psutil.boot_time()

def get_login_attempts():
    """Get login attempt count from Windows security logs."""

    for root, _, files in os.walk(folder):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                # Check if the file size exceeds the maximum allowed size
                if os.path.getsize(filepath) > max_file_size:
                    # Use debug level to avoid filling logs with large file warnings
                    logging.debug(encrypt_message(f"Silently skipping large file {filepath} ({os.path.getsize(filepath) / (1024 * 1024):.2f} MB)"))
                    continue

                # Standard virus scan
                scan_success, malware_found, msg = scan_file_for_viruses(filepath)
                total_scanned += 1
                if not scan_success:
                    results.append(f"Scan failed for {filepath}: {msg}")
                elif malware_found:
                    results.append(f"Threat found in {filepath}: {msg}")
                # Windows Defender scan if available
                if platform.system() == "Windows":
                    try:
                        defender_result = subprocess.run(
                            ["powershell", "-Command", f"Start-MpScan -ScanPath '{filepath}' -ScanType CustomScan"],
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                        if defender_result.returncode != 0:
                            results.append(f"Windows Defender found threat in {filepath}")
                    except Exception as e:
                        logging.error(f"Windows Defender scan failed for {filepath}: {e}")
                # ClamAV scan if available and enabled
                if USE_CLAMAV and platform.system() != "Windows":
                    try:
                        import clamd
                        cd = clamd.ClamdUnixSocket()
                        clam_result = cd.scan(filepath)
                        if clam_result and filepath in clam_result:
                            results.append(f"ClamAV found threat in {filepath}")
                    except Exception as e:
                        logging.error(f"ClamAV scan failed for {filepath}: {e}")
            except Exception as e:
                logging.error(f"Error scanning file {filepath}: {e}")
                results.append(f"Error scanning {filepath}: {str(e)}")
        scan_summary = f"Scan complete. Total files scanned: {total_scanned}"
        if results:
            scan_summary += f"\nIssues found:\n" + "\n".join(results)
        return render_template('index.html', scan_results=scan_summary, status='COMPLETE')

# Add threat detection endpoints
@app.route('/detect_threat', methods=['POST'])
def detect_threat():
    try:
        data = request.json
        threat_type = data.get('threat_type')
        features = np.array(data.get('features')).reshape(1, -1)
        
        if threat_type not in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
            return jsonify({'error': 'Invalid threat type'}), 400
            
        prediction = threat_detector.models[threat_type].predict(features)
        score = threat_detector.models[threat_type].decision_function(features)
        
        return jsonify({
            'prediction': int(prediction[0]),
            'score': float(score[0]),
            'threat_type': threat_type
        })
    except Exception as e:
        logging.error(f"Error in threat detection: {e}")
        return jsonify({'error': str(e)}), 500

# Update the scanning function to use ML models
@app.route('/scan_file', methods=['POST'])
def scan_file():
    try:
        file_path = request.json.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'Invalid file path'}), 400

        # Extract features for different threat types
        features = {
            'malware': extract_malware_features(file_path),
            'ddos': extract_network_features(file_path),
            'exfiltration': extract_data_features(file_path),
            'lateral_movement': extract_auth_features(file_path)
        }

        # Analyze each threat type
        results = {}
        for threat_type, feature_vector in features.items():
            if feature_vector is not None:
                try:
                    prediction = threat_detector.predict(threat_type, feature_vector)
                    score = threat_detector.score(threat_type, feature_vector)
                    results[threat_type] = {
                        'prediction': int(prediction),
                        'score': float(score)
                    }
                except Exception as e:
                    logging.error(f"Error analyzing {threat_type} threat: {e}")
                    results[threat_type] = {'error': str(e)}

        return jsonify({
            'file_path': file_path,
            'threat_analysis': results
        })
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        return jsonify({'error': str(e)}), 500

# ... (rest of the code remains the same)
# Helper functions for feature extraction
def extract_malware_features(file_path):
    try:
        pe = pefile.PE(file_path)
        features = [
            os.path.getsize(file_path) / 1024,  # File size (KB)
            calculate_entropy(file_path),  # File entropy
            len(pe.sections),  # Number of sections
            len(pe.DIRECTORY_ENTRY_IMPORT),  # Number of imports
            len(pe.DIRECTORY_ENTRY_EXPORT),  # Number of exports
            int(has_digital_signature(pe)),  # Digital signature
            int(is_packed(pe)),  # Packer detection
            0,  # Reserved for future use
            0,  # Reserved for future use
            0   # Reserved for future use
        ]
        return np.array(features).reshape(1, -1)
    except Exception as e:
        logging.error(f"Error extracting malware features: {e}")
        return None

def extract_network_features(file_path):
    try:
        # Get network connection info
        connections = psutil.net_connections()
        features = [
            len(connections),  # Number of connections
            sum(conn.status == 'ESTABLISHED' for conn in connections),  # Active connections
            sum(conn.status == 'SYN_SENT' for conn in connections),  # SYN connections
            sum(conn.status == 'TIME_WAIT' for conn in connections),  # TIME_WAIT connections
            get_packet_rate() / 1000,  # Packet rate (normalized)
            get_bandwidth_usage() / 1024,  # Bandwidth usage (KB)
            0,  # Reserved for future use
            0,  # Reserved for future use
            0,  # Reserved for future use
            0   # Reserved for future use
        ]
        return np.array(features).reshape(1, -1)
    except Exception as e:
        logging.error(f"Error extracting network features: {e}")
        return None

def extract_data_features(file_path):
    try:
        # Get file access patterns
        features = [
            os.path.getsize(file_path) / 1024,  # File size (KB)
            (time.time() - os.path.getmtime(file_path)) / 3600,  # Hours since last modified
            (time.time() - os.path.getctime(file_path)) / 3600,  # Hours since creation
            int(is_encrypted(file_path)),  # Encryption status
            get_data_transfer_rate() / 1024,  # Data transfer rate (KB)
            get_file_access_count(),  # File access count
            0,  # Reserved for future use
            0,  # Reserved for future use
            0,  # Reserved for future use
            0   # Reserved for future use
        ]
        return np.array(features).reshape(1, -1)
    except Exception as e:
        logging.error(f"Error extracting data features: {e}")
        return None

def extract_auth_features(file_path):
    try:
        # Get authentication patterns
        features = [
            get_login_attempts(),  # Login attempts
            get_failed_logins(),  # Failed login attempts
            get_user_changes(),  # User changes
            get_ip_changes(),  # IP changes
            get_auth_time_pattern(),  # Authentication time pattern
            get_protocol_changes(),  # Protocol changes
            0,  # Reserved for future use
            0,  # Reserved for future use
            0,  # Reserved for future use
            0   # Reserved for future use
        ]
        return np.array(features).reshape(1, -1)
    except Exception as e:
        logging.error(f"Error extracting auth features: {e}")
        return None
    except:
        return None

# Helper functions for feature calculations
def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if not data:
        return 0
    entropy = -sum((float(data.count(c)) / len(data)) * 
                  math.log(float(data.count(c)) / len(data), 2) 
                  for c in set(data))
    return entropy

def has_digital_signature(pe):
    return hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')

def is_packed(pe):
    return any(section.Name.decode().strip() == '.packed' for section in pe.sections)

def get_packet_rate():
    return psutil.net_io_counters().packets_sent + psutil.net_io_counters().packets_recv

def get_bandwidth_usage():
    return psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv

def get_file_access_count():
    return len(psutil.Process().open_files())

def is_encrypted(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(10)
        return header.startswith(b'PK')  # ZIP file signature
    except:
        return False

def get_data_transfer_rate():
    return psutil.net_io_counters().bytes_sent / psutil.boot_time()

def get_login_attempts():
    """Get login attempt count from Windows security logs."""
    try:
        # Use Windows Event Log API instead of file system
        import win32evtlog
        server = 'localhost'
        logtype = 'Security'
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        win32evtlog.CloseEventLog(hand)
        return len([e for e in events if e.EventID == 4624])  # 4624 is successful login event
    except:
        return 0

def get_failed_logins():
    """Get failed login count from Windows security logs."""
    try:
        import win32evtlog
        server = 'localhost'
        logtype = 'Security'
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        win32evtlog.CloseEventLog(hand)
        return len([e for e in events if e.EventID == 4625])  # 4625 is failed login event
    except:
        return 0

def get_user_changes():
    """Get user account changes using Windows API."""
    try:
        import win32net
        domain = '.'  # Local machine
        users = win32net.NetUserEnum(domain, 0)[0]
        return len(users)
    except:
        return 0

def get_ip_changes():
    """Get IP address changes using network interfaces."""
    try:
        interfaces = psutil.net_if_addrs()
        return len(interfaces)
    except:
        return 0

def get_auth_time_pattern():
    """Get authentication time pattern."""
    return datetime.now().hour  # Simplified to just hour of day

def get_protocol_changes():
    """Get protocol changes using network connections."""
    try:
        connections = psutil.net_connections()
        protocols = set()
        for conn in connections:
            protocols.add(conn.type)
        return len(protocols)
    except:
        return 0

# Disable the ability to turn off real-time protection by modifying the route
@app.route('/stop_realtime_protection', methods=['POST'])
def stop_realtime_protection():
    try:
        return jsonify({'status': 'error', 'message': 'Real-time protection cannot be disabled for security reasons'})
    except Exception as e:
        logging.error(f"Error disabling real-time protection: {e}") 
    return redirect(url_for('index'))

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Response, make_response
import socket
import time
import logging
import os
import sys
import json

# Check if running as EXE
is_exe = getattr(sys, 'frozen', False)

# Try to use Redis if available
try:
    import redis
    redis_available = True
except ImportError:
    redis_available = False
    logging.warning("Redis library not available. Using in-memory storage.")

def get_storage_backend():
    """Determine the appropriate storage backend based on environment."""
    if not redis_available:
        logging.warning("Redis library not available. Using in-memory storage.")
        return "memory://"
    
    # Function to start Redis server with proper error handling
    def start_redis(redis_exe, redis_config=None):
        try:
            import subprocess
            
            # If no config provided, use default location
            if redis_config is None:
                redis_config = os.path.join(os.path.dirname(redis_exe), 'redis.conf')
            
            # Start Redis server
            process = subprocess.Popen(
                [redis_exe, redis_config],
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Give Redis time to start
            time.sleep(2)
            
            # Check if Redis is running
            r = redis.Redis(host='localhost', port=6379, db=0)
            try:
                r.ping()
                logging.info("Successfully started and connected to Redis")
                return True
            except redis.ConnectionError:
                logging.error("Redis started but connection failed")
                return False
        except Exception as e:
            logging.error(f"Error starting Redis: {e}")
            return False
    
    # Try to find and start Redis
    try:
        # 1. Check if Redis is already running
        try:
            r = redis.Redis(host='localhost', port=6379, db=0)
            r.ping()
            logging.info("Redis is already running")
            return "redis://localhost:6379"
        except redis.ConnectionError:
            logging.info("Redis not running, attempting to start...")
            
        # 2. Try to find Redis executable
        redis_exe_locations = [
            "C:\\Redis\\redis-server.exe",  # Default Windows location
            os.path.join(os.path.dirname(sys.executable), "redis", "redis-server.exe"),  # EXE directory
            os.path.join(os.path.dirname(sys.executable), "redis-server.exe"),  # Direct EXE directory
            os.path.join(os.environ.get('REDIS_HOME', ''), "redis-server.exe") if 'REDIS_HOME' in os.environ else None
        ]
        
        # Try each location
        for redis_exe in redis_exe_locations:
            if redis_exe and os.path.exists(redis_exe):
                logging.info(f"Found Redis at: {redis_exe}")
                if start_redis(redis_exe):
                    return "redis://localhost:6379"
        
        # If we're still here, Redis couldn't be started
        logging.error("Failed to start Redis server after trying all locations")
        return "memory://"
    
    except Exception as e:
        logging.error(f"Unexpected error in Redis initialization: {e}")
        return "memory://"

# Get the appropriate storage backend
storage_uri = get_storage_backend()

# Configure Flask-Limiter with retry configuration
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=storage_uri,
    default_limits=["200 per day", "50 per hour"],
    key_prefix="antivirus_rate_limit",
    retry_after="http-date"
)

# Initialize rate limiting
limiter.init_app(app)

# Add custom error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    response = Response(
        json.dumps({
            "error": "Rate limit exceeded",
            "message": str(e),
            "retry_after": e.retry_after
        }),
        429,
        mimetype='application/json'
    )
    if e.retry_after:
        response.headers["Retry-After"] = e.retry_after
    return response

# Handle Chrome DevTools requests
@app.route('/.well-known/appspecific/com.chrome.devtools.json', methods=['GET'])
def handle_devtools():
    return jsonify({"version": 1, "pid": os.getpid()}), 200

# Get local IP address
local_ip = socket.gethostbyname(socket.gethostname())

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Note: Routes are already decorated with @requires_auth, no need to wrap again

# Initialize Flask app and all components before starting server
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize threat detector
threat_detector = ThreatDetectionModel()

# Initialize security components
network_security = NetworkSecurity()
network_monitor = NetworkMonitor()
network_monitor.start()

# Initialize folder watcher




def start_flask_server():
    # Get the IP address to bind to
    home_ip = '0.0.0.0'  # Listen on all interfaces
    
    try:
        print(encrypt_message(f"[INFO] Starting Flask server on {home_ip}:{port}"))
        logging.info(encrypt_message(f"[INFO] Starting Flask server on {home_ip}:{port}"))
        
        # Start Flask server with proper configuration
        app.run(
            host=home_ip,
            port=port,
            debug=False,
            threaded=True,
            use_reloader=False  # Disable reloader for production
        )
    except Exception as e:
        logging.error(encrypt_message(f"Failed to run Flask server: {e}"))
        raise

def main():
    try:
        # Initialize all components
        threat_detector = ThreatDetectionModel()
        network_monitor = NetworkMonitor()
        
        # Get your home network IP address
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            home_ip = s.getsockname()[0]
            app.config['HOME_IP'] = home_ip
        except Exception as e:
            logging.warning(f"Could not determine network IP: {e}")
            home_ip = '127.0.0.1'
        finally:
            s.close()
        
        logging.info(f"Starting server on IP: {home_ip}")
        
        # Start Flask server in background
        server_thread = threading.Thread(target=start_flask_server, daemon=True)
        server_thread.start()
        
        # Wait for server to start with a more reliable method
        max_retries = 10
        retry_count = 0
        server_started = False
        
        while retry_count < max_retries and not server_started:
            try:
                # Try to connect to the server to check if it's up
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(1)
                test_socket.connect(('127.0.0.1', port))
                test_socket.close()
                server_started = True
            except:
                retry_count += 1
                time.sleep(1)
        
        print(encrypt_message("[INFO] Flask server running in background"))
        logging.info(encrypt_message("[INFO] Flask server running in background"))
        
        # Open browser after server has started
        browser_url = f"http://127.0.0.1:{port}"
        localhost_url = f"http://localhost:{port}"
        external_url = f"http://{home_ip}:{port}"
        
        print(encrypt_message(f"[INFO] Opening browser at {browser_url}"))
        
        # Try multiple methods to open the browser
        try:
            webbrowser.open(browser_url)
        except Exception as e:
            logging.warning(f"Failed to open browser with first URL: {e}")
            try:
                webbrowser.open(localhost_url)
            except Exception as e2:
                logging.warning(f"Failed to open browser with second URL: {e2}")
        
        # Also print a message for external access
        print(encrypt_message(f"[INFO] Server is accessible from any device at {external_url}"))
        
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(encrypt_message("[INFO] Shutting down Flask server..."))
        logging.info(encrypt_message("[INFO] Shutting down Flask server..."))
    except Exception as e:
        logging.error(encrypt_message(f"Failed to start server: {e}"))
        raise

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(encrypt_message("[INFO] Shutting down Flask server..."))
        logging.info(encrypt_message("[INFO] Shutting down Flask server..."))
        sys.exit(0)

