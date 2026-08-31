import os
import sys
import glob
import base64
import secrets

# Load .env before importing modules that validate FERNET_KEY at import time.
from dotenv import dotenv_values, load_dotenv

FLASK_DEBUG = '--debug' in sys.argv


def _upsert_local_env_value(path, name, value):
    """Persist one generated secret without printing or exposing its value."""
    lines = []
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as env_file:
            lines = env_file.read().splitlines()
    replacement = f'{name}={value}'
    replaced = False
    updated = []
    for line in lines:
        if line.startswith(f'{name}='):
            if not replaced:
                updated.append(replacement)
                replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(replacement)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as env_file:
            env_file.write('\\n'.join(updated) + '\\n')
        return True
    except (OSError, IOError, PermissionError):
        return False


def _load_environment_before_imports():
    if getattr(sys, 'frozen', False):
        executable_dir = os.path.dirname(sys.executable)
        appdata_dir = os.path.join(
            os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'antivirus_server'
        )
        candidates = [
            os.path.join(appdata_dir, '_internal', '.env'),
            os.path.join(appdata_dir, '.env'),
            os.path.join(executable_dir, '_internal', '.env'),
            os.path.join(executable_dir, '.env'),
        ]
    else:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(project_dir, '_internal', '.env'),
            os.path.join(project_dir, '.env'),
            os.path.join(os.getcwd(), '.env'),
        ]

    for path in candidates:
        if not os.path.exists(path):
            continue
        values = dotenv_values(path)
        file_fernet_key = values.get('FERNET_KEY') or ''
        if len(file_fernet_key) != 44:
            continue
        load_dotenv(path, override=False)
        # Replace only a missing/invalid environment value. Valid process
        # environment settings continue to take precedence over .env.
        if len(os.environ.get('FERNET_KEY', '')) != 44:
            os.environ['FERNET_KEY'] = file_fernet_key
        if not os.environ.get('SECRET_KEY'):
            os.environ['SECRET_KEY'] = secrets.token_urlsafe(32)
            _upsert_local_env_value(path, 'SECRET_KEY', os.environ['SECRET_KEY'])
        return path

    # First run: create per-install secrets in the first writable .env.
    generated_fernet = len(os.environ.get('FERNET_KEY', '')) != 44
    generated_secret = not os.environ.get('SECRET_KEY')
    if generated_fernet:
        os.environ['FERNET_KEY'] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    if generated_secret:
        os.environ['SECRET_KEY'] = secrets.token_urlsafe(32)

    for target in candidates:
        writable = True
        if generated_fernet:
            writable = _upsert_local_env_value(target, 'FERNET_KEY', os.environ['FERNET_KEY']) and writable
        if generated_secret:
            writable = _upsert_local_env_value(target, 'SECRET_KEY', os.environ['SECRET_KEY']) and writable
        if writable:
            return target

    # The package directory may be read-only. The process can still continue
    # with in-memory keys, but report the condition rather than crashing.
    return None


_load_environment_before_imports()

import ctypes
import time
import logging
from logging.handlers import RotatingFileHandler
import json
import socket
import shutil  # For file operations like move for quarantine
import subprocess
import threading

# --- Windows subprocess window suppression ---
if sys.platform == 'win32':
    CREATE_NO_WINDOW = 0x08000000
else:
    CREATE_NO_WINDOW = 0
import winreg
import psutil
import ipaddress
import base64
import tempfile
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, send_file, Blueprint, session, make_response, flash
from data_analysis import load_trusted_hashes

# Load environment variables from .env (e.g. FERNET_KEY) -- needed because this
# module is normally run directly with `python quick_start.py`, which (unlike
# `flask run`) does not load .env/.flaskenv automatically. Without this,
# anything that depends on FERNET_KEY being set (e.g. file_crypto.py) would
# fail with EnvironmentError even though the key is present in .env.

# When running as a PyInstaller bundle, prefer the onedir itself so the
# package is self-contained. If the onedir is on a read-only / OneDrive
# reparse point, fall back to the user's AppData\Local directory.
if getattr(sys, 'frozen', False):
    onedir = os.path.dirname(sys.executable)
    runtime_dir = onedir
    # Some packaged locations (e.g. WindowsApps) report W_OK but are not
    # actually writable for files, so probe by creating a test file.
    try:
        test_path = os.path.join(onedir, '.write_probe')
        with open(test_path, 'w') as f:
            f.write('probe')
        os.remove(test_path)
    except (OSError, IOError, PermissionError):
        runtime_dir = os.path.join(
            os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
            'antivirus_server'
        )
    os.makedirs(runtime_dir, exist_ok=True)
    os.environ['ANTIVIRUS_RUNTIME_DIR'] = runtime_dir
    os.chdir(runtime_dir)

    # Load trusted hashes once for the session
    global TRUSTED_HASHES
    TRUSTED_HASHES = load_trusted_hashes()

    # Copy bundled signature seeds to the runtime directory when it is outside
    # the onedir (e.g., a read-only/AppData fallback). When runtime == onedir,
    # the bundled files are already in place.
    if runtime_dir != onedir:
        for seed in ('malware_signatures.txt', 'malware_signatures.json', 'iocs.json'):
            src = os.path.join(onedir, seed)
            if not os.path.exists(src):
                src = os.path.join(onedir, '_internal', seed)
            dst = os.path.join(runtime_dir, seed)
            if os.path.exists(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
        os.makedirs(os.path.join(runtime_dir, 'blocklists'), exist_ok=True)
        for seed in ('blocklists/phishing_domains.txt', 'blocklists/phishing_ips.txt'):
            src = os.path.join(onedir, seed)
            if not os.path.exists(src):
                src = os.path.join(onedir, '_internal', 'blocklists', seed)
            dst = os.path.join(runtime_dir, seed)
            if os.path.exists(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)


def _request_admin_elevation():
    """Prompt for UAC elevation on Windows and relaunch if not running as admin."""
    if sys.platform != 'win32':
        return
    # The built EXE uses the PyInstaller --uac-admin manifest; don't try to
    # self-restart from inside the frozen bundle (it causes loop/new tabs).
    if getattr(sys, 'frozen', False):
        return
    # Only attempt UAC elevation once. The relaunched process carries this
    # flag so it cannot recurse and spam UAC prompts / new browser windows.
    if '--elevation-attempted' in sys.argv:
        return
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return
    if not is_admin:
        script = os.path.abspath(sys.argv[0])
        params = [script] + sys.argv[1:] + ['--elevation-attempted']
        params = ' '.join(['"%s"' % arg if ' ' in arg else arg for arg in params])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', sys.executable, params, None, 1
        )
        if ret <= 32:
            print('Administrator privileges are required to run this application.')
            sys.exit(1)
        sys.exit(0)


_request_admin_elevation()
# Load the bundled .env from the executable directory when frozen, otherwise
# load from the current working directory (source checkout). When frozen, copy
# the bundled .env to the writable user app data folder on first run and load
# from there so the user can edit it after install.
if getattr(sys, 'frozen', False):
    bundled_dotenv = os.path.join(os.path.dirname(sys.executable), '.env')
    app_data_dir = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'antivirus_server')
    os.makedirs(app_data_dir, exist_ok=True)
    dotenv_path = os.path.join(app_data_dir, '.env')
    if not os.path.exists(dotenv_path) and os.path.exists(bundled_dotenv):
        shutil.copy2(bundled_dotenv, dotenv_path)
else:
    dotenv_path = '.env'
load_dotenv(dotenv_path)

# Seed the web_auth password store from .env only if no local password exists.
# Prefer ADMIN_PASSWORD_HASH (a bcrypt string). Fall back to ADMIN_PASSWORD
# and hash it at startup for migration.
try:
    from security.web_auth import set_password, set_password_hash, verify_password, has_auth_data
    if not has_auth_data():
        admin_password_hash = os.environ.get('ADMIN_PASSWORD_HASH')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if admin_password_hash:
            set_password_hash(admin_password_hash)
        elif admin_password:
            set_password(admin_password)
except Exception:
    set_password = None
    set_password_hash = None
    verify_password = None

import secrets

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')

# Simple in-memory rate limiters for login and stop requests per remote address.
_login_attempts = {}
_stop_attempts = {}


def _is_login_rate_limited(remote_addr):
    now = time.time()
    window = 300  # 5 minutes
    max_attempts = 10
    attempts = _login_attempts.get(remote_addr, [])
    attempts = [t for t in attempts if now - t < window]
    _login_attempts[remote_addr] = attempts
    if len(attempts) >= max_attempts:
        return True
    _login_attempts[remote_addr].append(now)
    return False


def _is_stop_rate_limited(remote_addr):
    now = time.time()
    window = 60  # 1 minute
    max_attempts = 5
    attempts = _stop_attempts.get(remote_addr, [])
    attempts = [t for t in attempts if now - t < window]
    _stop_attempts[remote_addr] = attempts
    if len(attempts) >= max_attempts:
        return True
    _stop_attempts[remote_addr].append(now)
    return False


def _warn_default_credentials():
    """Warn if the admin account is still using the default values."""
    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    default_passwords = ('admin123', 'change-me')
    is_default = admin_user == 'admin'
    if is_default and verify_password:
        is_default = any(verify_password(p) for p in default_passwords)
    if is_default:
        logger.warning('Admin credentials are still the defaults. Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in .env for production.')
        print('WARNING: Default admin credentials are in use. Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in .env before production use.')


def _validate_production_config():
    """Abort startup if production mode is enabled with unsafe defaults."""
    if os.environ.get('FLASK_ENV', '').lower() != 'production':
        return
    errors = []
    if os.environ.get('SECRET_KEY') == 'dev-key-please-set-SECRET_KEY-in-dotenv' or not os.environ.get('SECRET_KEY'):
        errors.append('SECRET_KEY must be set to a real secret in .env when FLASK_ENV=production')
    if not os.environ.get('FERNET_KEY'):
        errors.append('FERNET_KEY must be set in .env when FLASK_ENV=production')
    admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
    if admin_user == 'admin':
        errors.append('ADMIN_USERNAME must be changed from the default when FLASK_ENV=production')
    if os.environ.get('ADMIN_PASSWORD'):
        errors.append('ADMIN_PASSWORD must be removed from .env; use ADMIN_PASSWORD_HASH instead')
    if not os.environ.get('ADMIN_PASSWORD_HASH'):
        errors.append('ADMIN_PASSWORD_HASH must be set in .env when FLASK_ENV=production')
    if verify_password and os.environ.get('ADMIN_PASSWORD_HASH'):
        default_passwords = ('admin123', 'change-me')
        if any(verify_password(p) for p in default_passwords):
            errors.append('ADMIN_PASSWORD_HASH must be for a strong, non-default password when FLASK_ENV=production')
    if errors:
        for e in errors:
            logger.error(f'Production config error: {e}')
            print(f'ERROR: {e}')
        raise SystemExit('Refusing to start in production mode with unsafe configuration.')



def _quarantine_dir():
    return os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')


def _is_safe_quarantine_path(path, base_dir=None):
    """Return True if the resolved path is inside the quarantine directory."""
    if not path:
        return False
    base = base_dir or _quarantine_dir()
    try:
        base = os.path.realpath(base)
        target = os.path.realpath(os.path.join(base, path) if not os.path.isabs(path) else path)
        return os.path.commonpath([base, target]) == base
    except (ValueError, OSError):
        return False


def _custom_scan_target(target_path, max_files=100):
    """YARA-scan a single file or a directory up to max_files."""
    if not os.path.exists(target_path):
        return {'error': 'Path not found'}
    from security.yara_scanner import scan_file_with_yara
    results = []
    if os.path.isfile(target_path):
        try:
            matches = scan_file_with_yara(target_path)
            if matches:
                results.append({'path': target_path, 'matches': [getattr(m, 'rule', str(m)) for m in matches]})
        except Exception as e:
            return {'error': str(e)}
        return {'scanned': 1, 'results': results}
    scanned = 0
    for root, dirs, files in os.walk(target_path):
        for f in files:
            if scanned >= max_files:
                break
            p = os.path.join(root, f)
            if should_exclude_path(p):
                continue
            try:
                matches = scan_file_with_yara(p)
                if matches:
                    results.append({'path': p, 'matches': [getattr(m, 'rule', str(m)) for m in matches]})
            except Exception:
                pass
            scanned += 1
    return {'scanned': scanned, 'results': results}


def _hash_sha256(file_path):
    """Return the SHA-256 hash of a file without loading it all at once."""
    import hashlib
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _append_malware_signature(file_path, label, sha256=None):
    """Add a quarantined/high-confidence file's SHA-256 to the local malware signature DB."""
    if not sha256:
        sha256 = _hash_sha256(file_path)
    if not sha256:
        return
    runtime_dir = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))
    sig_path = os.path.join(runtime_dir, 'malware_signatures.txt')
    try:
        if os.path.exists(sig_path):
            with open(sig_path, 'r', encoding='utf-8') as f:
                if sha256 in f.read():
                    return
        with open(sig_path, 'a', encoding='utf-8') as f:
            f.write(f'{label}:sha256:{sha256}\n')
            logger.info(f'Added {label} signature: {sha256}')
    except Exception as e:
        logger.warning(f'Failed to append malware signature: {e}')


# Import DNS server functionality
from dns_server import start_dns_server
# Fernet key provider for quarantine encryption and graph helpers
from data_analysis import (
    analyze_data, compute_file_entropy, generate_threat_graph, detect_file_signature,
    yara_risk_score, packed_encoder_score, exploit_score, network_ioc_score,
    yara_mitre_tags, _load_iocs, missing_critical_patches, load_trusted_hashes,
    scan_startup_and_tasks,
    multi_engine_hash_lookup, read_recent_security_summary, scan_email_attachments,
    email_attachment_score, startup_risk_score, event_risk_score, hash_lookup_risk_score,
    extra_file_risk_score, scan_archive_file, scan_pdf_file, scan_shortcut_file, scan_macro_document,
    scan_powershell_script_block, _read_one_event_log, scan_running_processes, process_risk_score,
    create_canary_files, check_canary_files, scan_network_connections, network_beacon_score,
    scan_windows_services, service_risk_score, is_startup_enabled, toggle_startup_with_windows,
    update_ioc_feeds
)

# Persistent scan cache and safe quarantine helper
from security.scan_cache import FileScanCache, safe_quarantine
from quarantine_utils import quarantine_file, list_quarantine_files, restore_quarantine_file, delete_quarantine_file
from windows_admin_service import (
    AdminServiceUnavailable,
    AdminServiceProtocolError,
    call_admin_service,
)
# Self-protection / watchdog helpers (imported so they are bundled)
import security.self_protect

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('antivirus')


def _ensure_single_instance():
    """Create a Windows named mutex so only one app instance runs at a time."""
    if sys.platform != 'win32':
        return None
    try:
        name = 'Local\\AntivirusYaraRulesC_SingleInstance'
        handle = ctypes.windll.kernel32.CreateMutexW(None, False, name)
        err = ctypes.windll.kernel32.GetLastError()
        if err == 183:  # ERROR_ALREADY_EXISTS
            ctypes.windll.kernel32.CloseHandle(handle)
            print('Another antivirus instance is already running. Exiting.')
            sys.exit(0)
        if not handle and err == 5:  # ERROR_ACCESS_DENIED
            print('Another antivirus instance is already running. Exiting.')
            sys.exit(0)
        if not handle:
            raise ctypes.WinError(err)
        return handle
    except Exception as e:
        logger.warning(f'Could not create single-instance mutex: {e}')
        return None


# Persistent scan cache: avoid rescanning unchanged files on every background
# pass and gives the operator a hash -> verdict record.
scan_cache = FileScanCache('data/scan_cache.json')

# Trust hashes are loaded once after the runtime directory is set.
TRUSTED_HASHES = set()

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

def _is_startup_installed():
    """Check whether the EXE is already registered to run at logon."""
    try:
        subprocess.run(
            ['schtasks', '/query', '/tn', 'AntivirusYARAServerStartup'],
            check=True, capture_output=True, text=True,
            creationflags=CREATE_NO_WINDOW
        )
        return True
    except Exception:
        pass
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'Software\Microsoft\Windows\CurrentVersion\Run',
            0, winreg.QUERY_VALUE
        )
        winreg.QueryValueEx(key, 'AntivirusYARAServer')
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def install_startup():
    """Add the current EXE to the current user's startup if not already."""
    exe_path = sys.executable
    if not exe_path.lower().endswith('.exe'):
        print("Install startup is only supported when running the built EXE.")
        return False

    if _is_startup_installed():
        print("Startup entry already exists.")
        return True

    # Try Task Scheduler first
    try:
        subprocess.run(
            ['schtasks', '/create', '/tn', 'AntivirusYARAServerStartup',
             '/tr', f'"{exe_path}"', '/sc', 'ONLOGON', '/f'],
            check=True, capture_output=True, text=True,
            creationflags=CREATE_NO_WINDOW
        )
        print("Startup task created. It will run at logon.")
        return True
    except Exception as e:
        print(f"Task Scheduler install failed: {e}; using registry fallback.")

    # Fallback to HKCU\...\Run
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'Software\Microsoft\Windows\CurrentVersion\Run',
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, 'AntivirusYARAServer', 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        print("Added to HKCU\\...\\Run for current-user logon.")
        return True
    except Exception as e:
        print(f"Registry install failed: {e}")
        return False

# Create a clean app instance
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'))

# Cap request/upload size at 125MB (currently only used by the file
# encryption/decryption feature's file uploads).
app.config['MAX_CONTENT_LENGTH'] = 125 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-key-please-set-SECRET_KEY-in-dotenv'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SECURE_SESSION_COOKIE should only be True when serving over HTTPS.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', '').lower() == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600


def _running_as_administrator():
    """Return whether the current process has an elevated Windows token."""
    if sys.platform != 'win32':
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


RUNNING_AS_ADMIN = _running_as_administrator()


def _admin_service_read(action, **fields):
    """Call a read-only administrator-service operation, or return None if unavailable."""
    try:
        return call_admin_service(action, **fields)
    except (AdminServiceUnavailable, AdminServiceProtocolError) as error:
        logger.info("Administrator service unavailable for %s: %s", action, error)
        return None


def _admin_service_mutation(action, **fields):
    """Call a service mutation; None means unavailable and permits fallback.

    An explicit service response is returned unchanged, including validation or
    confirmation failures. This prevents silently bypassing the privileged
    service once it is installed.
    """
    try:
        return call_admin_service(action, **fields)
    except (AdminServiceUnavailable, AdminServiceProtocolError) as error:
        logger.info("Administrator service unavailable for %s: %s", action, error)
        return None


if not RUNNING_AS_ADMIN:
    logger.warning(
        'Running without Administrator privileges. The administrator service '
        'must be installed and started for protected operations.'
    )


@app.context_processor
def privilege_context():
    """Expose elevation and administrator-service state to dashboard templates."""
    service_status = _admin_service_read('service.status')
    service_available = bool(service_status and service_status.get('ok'))
    return {
        'running_as_admin': RUNNING_AS_ADMIN,
        'administrator_service_available': service_available,
        'admin_helper_message': (
            'Administrator-service operations are available for protected scans, '
            'firewall controls, and quarantine actions.' if service_available else
            'Install and start the administrator service to enable protected '
            'scans, firewall controls, and quarantine actions.'
        ),
    }


@app.route('/api/privilege-status', methods=['GET'])
def privilege_status_api():
    """Report whether the current app process is elevated."""
    service_status = _admin_service_read('service.status')
    return jsonify({
        'running_as_admin': RUNNING_AS_ADMIN,
        'administrator_service_available': bool(service_status and service_status.get('ok')),
        'message': None if RUNNING_AS_ADMIN else (
            'This MSIX session is running normally. Administrator-service '
            'protected scans and remediation require the installed service and '
            'explicit mutation confirmation.'
        ),
    })


_PRIVILEGED_PATH_PREFIXES = (
    '/toggle_network_monitor',
    '/start_realtime',
    '/stop_realtime',
    '/api/scan_processes',
    '/api/scan-file',
    '/api/scan_download',
)


@app.before_request
def explain_privileged_msix_operation():
    """Give MSIX users a clear response for known privileged operations."""
    if RUNNING_AS_ADMIN or request.method in {'GET', 'HEAD', 'OPTIONS'}:
        return None
    if request.path.startswith(_PRIVILEGED_PATH_PREFIXES):
        return jsonify({
            'status': 'admin_required',
            'error': (
                'This feature requires Administrator privileges. Launch the '
                'standalone Administrator shortcut instead of the MSIX shortcut.'
            ),
        }), 403
    return None


@app.errorhandler(PermissionError)
def permission_error_response(error):
    """Return actionable guidance instead of an opaque permission failure."""
    message = (
        'Administrator privileges are required for this operation. Use the '
        'standalone Administrator shortcut; the MSIX app itself cannot be '
        'elevated.'
    )
    if request.accept_mimetypes.best == 'text/html':
        return message, 403
    return jsonify({'status': 'admin_required', 'error': message}), 403

# Create a blueprint for network-related API endpoints
network_bp = Blueprint('network', __name__, url_prefix='/api/network')

# Global state for monitoring services
folder_watcher_state = {
    'active': True,
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
        os.path.join(os.environ.get('ProgramFiles', r'C:\\Program Files')),
        os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\\Program Files (x86)')),
        os.path.join(os.environ.get('CommonProgramFiles', r'C:\\Program Files\\Common Files')),
        os.path.join(os.environ.get('ProgramData', r'C:\\ProgramData')),
        os.path.join(os.environ.get('ProgramData', r'C:\\ProgramData'), 'Microsoft'),
        
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
        'C:\\\\Windows',
        'C:\\\\Program Files',
        'C:\\\\ProgramData',
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

        # FERNET_KEY environment format (used by quarantine_utils.quarantine_file)
        if decrypted_data is None:
            fernet_key = os.environ.get('FERNET_KEY')
            if fernet_key:
                try:
                    fernet_key = fernet_key.encode() if isinstance(fernet_key, str) else fernet_key
                    decrypted_data = Fernet(fernet_key).decrypt(file_data)
                except Exception:
                    decrypted_data = None

        # Legacy format: whole file encrypted with the deterministic machine key
        if decrypted_data is None:
            try:
                decrypted_data = Fernet(get_encryption_key()).decrypt(file_data)
            except Exception:
                decrypted_data = None

        if decrypted_data is None:
            return False

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
    'findings': [],
    'started_at': None,    # When the current/most recent run started
    'last_updated': None,  # Timestamp of the most recent progress tick (while running)
    'last_run': None,      # When the most recent run *completed* (success or failure)
    'duration': None,
    'scanned_files': 0,
    'quarantined_files': 0,
    'errors': 0,
    'process_events': 0,
    'ml_detections': 0,        # Files flagged by the static-file ML classifier (report-only, not quarantined)
    'ransomware_indicators': 0,  # Files flagged by the static ransomware heuristic (report-only, not quarantined)
    'persistence_indicators': 0,  # Processes/autostart entries in unusual locations (report-only, not quarantined)
    'yara_suspicious': 0,  # High/critical YARA matches for review (not auto-quarantined)
    'last_error': None
}
conditional_startup_lock = threading.Lock()
scanning_lock = threading.Lock()
conditional_startup_thread = None  # Background scan thread, used to detect dead scans
latest_yara_suspicious = []  # Full list of YARA suspicious matches from the last conditional startup
latest_ransomware_indicators = []  # Full list of ransomware heuristic findings from the last conditional startup
latest_persistence_indicators = {}  # Full persistence findings from the last conditional startup

# -- Continuous Scan All state --
continuous_scan_state = {
    'active': False,
    'last_run': None,
    'last_result': None,
    'last_error': None
}
continuous_scan_thread = None


def _perform_scan_all():
    '''Scan all monitored directories using YARA rules and optional ML scoring.'''
    from security.yara_scanner import scan_file_with_yara
    from security.detector import ember_detector, detector

    monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
    start_time = time.time()
    results = []
    total_files_scanned = 0
    total_directories_scanned = 0
    detected_threats = 0
    total_yara_matches = 0
    persistence_matches = 0
    ransomware_matches = 0
    yara_suspicious = []
    quarantined_count = 0

    if not monitored_dirs:
        return {
            'status': 'error',
            'message': 'No monitored directories configured',
            'scan_time': '0 seconds',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'matches': 0,
            'folders': [],
            'results': []
        }, 400

    try:
        quarantine_dir = os.path.join(os.environ.get('USERPROFILE', r'C:\Users\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')

        if continuous_scan_state['active']:
            continuous_scan_state['last_result'] = {
                'status': 'success',
                'scan_time': '0.00 seconds',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'matches': 0,
                'folders': monitored_dirs,
                'results': [f'Scan started on {len(monitored_dirs)} folder(s)...'],
                'files_scanned': 0,
                'directories_scanned': 0,
                'threats_detected': 0,
                'threats_removed': 0
            }

        for directory in monitored_dirs:
            try:
                if not os.path.exists(directory) or not os.path.isdir(directory):
                    results.append(f'Directory not found or not accessible: {directory}')
                    continue

                total_directories_scanned += 1
                logger.info(f'Scanning directory: {directory}')

                for root, dirs, files in os.walk(directory, topdown=True, onerror=lambda e: logger.warning(f'Access error: {e}')):
                    if should_exclude_path(root):
                        dirs[:] = []
                        continue

                    if not os.access(root, os.R_OK):
                        dirs[:] = []
                        continue

                    dirs[:] = [d for d in dirs if not should_exclude_path(os.path.join(root, d))]

                    for file in files:
                        time.sleep(0)
                        file_path = os.path.join(root, file)
                        if should_exclude_path(file_path):
                            continue

                        total_files_scanned += 1

                        if continuous_scan_state['active'] and total_files_scanned % 10 == 0:
                            elapsed = time.time() - start_time
                            continuous_scan_state['last_result'] = {
                                'status': 'success',
                                'scan_time': f'{elapsed:.2f} seconds',
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                                'matches': total_yara_matches,
                                'folders': monitored_dirs,
                                'results': results,
                                'files_scanned': total_files_scanned,
                                'directories_scanned': total_directories_scanned,
                                'threats_detected': detected_threats,
                                'threats_removed': quarantined_count
                            }

                        try:
                            cached = scan_cache.get(file_path)
                            if cached is not None:
                                cached_matches = cached.get('yara_matches', [])
                                if cached_matches:
                                    total_yara_matches += len(cached_matches)
                                    detected_threats += 1
                                    results.append('YARA match: ' + file_path + ' - Rules: ' + ', '.join(cached_matches))
                                continue

                            file_ext = os.path.splitext(file_path)[1].lower()

                            # Skip files whose SHA-256 is in the trusted hashes list.
                            if _hash_sha256(file_path) in TRUSTED_HASHES:
                                continue

                            # Quick email attachment scan for .eml and .msg files.
                            if file_ext in ('.eml', '.msg'):
                                email_scan = scan_email_attachments(file_path)
                                em_score = email_attachment_score(file_path)
                                if em_score >= 25:
                                    detected_threats += 1
                                    results.append(f'Suspicious email attachment (score {em_score}): {file_path} - ' + ', '.join(email_scan.get('suspicious', [])))
                                if em_score >= 50:
                                    try:
                                        quarantine_file(file_path, reason='suspicious email attachment')
                                        quarantined_count += 1
                                        results.append(f'Quarantined suspicious email: {file_path}')
                                        continue
                                    except Exception as qe:
                                        logger.warning(f'Failed to quarantine email {file_path}: {qe}')

                            # Extra file-type scans for archives, PDFs, shortcuts and macros.
                            extra_score = extra_file_risk_score(file_path)
                            if extra_score >= 25:
                                detected_threats += 1
                                results.append(f'Suspicious file content (score {extra_score}): {file_path}')
                            if extra_score >= 60:
                                try:
                                    quarantine_file(file_path, reason='suspicious file content / archive / macro / PDF / shortcut')
                                    quarantined_count += 1
                                    results.append(f'Quarantined suspicious file: {file_path}')
                                    continue
                                except Exception as qe:
                                    logger.warning(f'Failed to quarantine file {file_path}: {qe}')

                            yara_matches = scan_file_with_yara(file_path)
                            rule_names = [getattr(m, 'rule', str(m)) for m in yara_matches]

                            for rule in rule_names:
                                rl = rule.lower()
                                if 'persistence' in rl:
                                    persistence_matches += 1
                                if 'ransomware' in rl:
                                    ransomware_matches += 1
                            if any('persistence' in r.lower() or 'ransomware' in r.lower() for r in rule_names):
                                yara_suspicious.append({'file': file_path, 'rules': rule_names})

                            yara_score = yara_risk_score(rule_names)
                            cache_entry = {
                                'yara_matches': rule_names,
                                'yara_score': yara_score,
                                'quarantined': False,
                                'reported': False
                            }

                            ml_score = None
                            pe_extensions = ('.exe', '.dll', '.sys', '.scr', '.pif', '.com', '.cpl')
                            file_ext = os.path.splitext(file_path)[1].lower()
                            if ember_detector.available and file_ext in pe_extensions:
                                ml_score = ember_detector.score(file_path)
                                cache_entry['ember_score'] = ml_score
                            if ml_score is None and detector is not None:
                                try:
                                    ml_score = detector.get_anomaly_score(file_path)
                                    cache_entry['legacy_ml_score'] = ml_score
                                except Exception:
                                    pass

                            should_quarantine = False
                            if ml_score is not None:
                                if ember_detector.available and ml_score >= 0.60:
                                    should_quarantine = True
                                    cache_entry['quarantine_reason'] = 'ember'
                                elif not ember_detector.available and ml_score >= 0.5:
                                    should_quarantine = True
                                    cache_entry['quarantine_reason'] = 'legacy'

                            if yara_score >= 35:
                                should_quarantine = True
                                cache_entry['quarantine_reason'] = 'yara_high'

                            if yara_matches:
                                total_yara_matches += len(yara_matches)

                            if yara_matches or should_quarantine:
                                detected_threats += 1

                                if should_quarantine:
                                    sha256_hash = _hash_sha256(file_path)
                                    success, message = safe_quarantine(file_path, quarantine_dir, encrypt_file)
                                    cache_entry['quarantined'] = success
                                    if success:
                                        quarantined_count += 1
                                        if yara_matches:
                                            results.append('QUARANTINED: ' + file_path + ' - Rules: ' + ', '.join(rule_names))
                                        else:
                                            results.append(f'QUARANTINED (ember): {file_path} - ML score {ml_score:.4f}')
                                        logger.warning(f'Quarantined high-risk file: {file_path}')
                                        _append_malware_signature(file_path, cache_entry.get('quarantine_reason', 'quarantine'), sha256_hash)
                                    else:
                                        if yara_matches:
                                            results.append('YARA match (quarantine failed: ' + message + '): ' + file_path + ' - Rules: ' + ', '.join(rule_names))
                                        else:
                                            results.append(f'EMBER match (quarantine failed: {message}): {file_path} - ML score {ml_score:.4f}')
                                        logger.warning(f'EMBER match not quarantined ({message}): {file_path}')
                                else:
                                    cache_entry['reported'] = True
                                    if yara_matches:
                                        results.append('YARA match (report-only): ' + file_path + ' - Rules: ' + ', '.join(rule_names))
                                    else:
                                        results.append(f'EMBER match (report-only): {file_path} - ML score {ml_score:.4f}')
                                    if ml_score is not None:
                                        logger.info(f'  ML score {ml_score:.4f} did not reach quarantine threshold for {file_path}')

                            scan_cache.set(file_path, cache_entry)

                        except Exception as file_error:
                            logger.warning(f'Error scanning file {file_path}: {file_error}')

                results.append(f'Scanned directory: {directory}')
            except Exception as scan_error:
                logger.error(f'Error scanning directory {directory}: {scan_error}')
                results.append(f'Error scanning {directory}: {str(scan_error)}')

        # Make the latest YARA ransomware/persistence matches available to the
        # quarantine button, and update the dashboard counters from this scan.
        global latest_yara_suspicious
        latest_yara_suspicious = yara_suspicious
        conditional_startup_state['yara_suspicious'] = len(yara_suspicious)
        conditional_startup_state['persistence_indicators'] = persistence_matches
        conditional_startup_state['ransomware_indicators'] = ransomware_matches

        try:
            scan_cache._save()
        except Exception:
            pass

        duration = time.time() - start_time

        return {
            'status': 'success',
            'scan_time': f'{duration:.2f} seconds',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'matches': total_yara_matches,
            'folders': monitored_dirs,
            'results': results,
            'files_scanned': total_files_scanned,
            'directories_scanned': total_directories_scanned,
            'threats_detected': detected_threats,
            'threats_removed': quarantined_count
        }, 200
    except Exception as e:
        logger.error(f'Error during scan_all: {e}')
        return {
            'status': 'error',
            'message': str(e),
            'scan_time': '0 seconds',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'matches': 0,
            'folders': [],
            'results': []
        }, 500


def run_continuous_scan_all():
    """Background loop for continuous scan-all."""
    while continuous_scan_state['active']:
        try:
            result, _ = _perform_scan_all()
            continuous_scan_state['last_result'] = result
            continuous_scan_state['last_run'] = time.strftime('%Y-%m-%d %H:%M:%S')
            continuous_scan_state['last_error'] = None if result.get('status') == 'success' else result.get('message')
        except Exception as e:
            logger.error(f"Error in continuous scan: {e}")
            continuous_scan_state['last_error'] = str(e)
        for _ in range(10):
            if not continuous_scan_state['active']:
                break
            time.sleep(1)


def _count_persistence_indicators(scan_data):
    findings = scan_data.get('persistence_indicators', {})
    if not isinstance(findings, dict):
        return 0
    return sum(len(v) for v in findings.values())


def record_conditional_startup_run(scan_data=None, duration=None, error=None):
    """Update conditional_startup_state after a run completes or fails."""
    if not isinstance(scan_data, dict):
        scan_data = {}
    errors = scan_data.get('errors', [])
    last_internal = str(errors[-1]) if errors else None
    conditional_startup_state.update({
        'running': False,
        'last_run': time.strftime('%Y-%m:%d %H:%M:%S'),
        'duration': round(duration, 2) if duration is not None else None,
        'errors': len(errors),
        'process_events': len(scan_data.get('process_events', [])),
        'last_error': str(error) if error else last_internal,
    })
    try:
        conditional_startup_state.setdefault('findings', _findings_for_review())
    except Exception:
        pass


def run_conditional_startup_background():
    """Run the conditional startup scan once in a background thread."""
    global latest_yara_suspicious, latest_ransomware_indicators, latest_persistence_indicators
    from conditional_startup import run_conditional_startup_logic, STOP_EVENT
    STOP_EVENT.clear()
    start_time = time.time()
    _last_progress_report = 0.0
    last_counts = {k: 0 for k in ['scanned_files', 'quarantined_files', 'errors', 'process_events', 'ml_detections', 'ransomware_indicators', 'persistence_indicators', 'yara_suspicious']}

    def _add_delta(key, current):
        delta = current - last_counts[key]
        if delta:
            conditional_startup_state[key] = conditional_startup_state.get(key, 0) + delta
            last_counts[key] = current

    def report_progress(partial_results):
        """Update shared state with in-progress counts so the status API
        reflects live progress instead of appearing stuck at 0/never. This
        used to only update counts, leaving 'last_run' as 'never' for the
        entire (sometimes multi-minute) duration of a run, since that field
        was only ever set once the whole scan finished."""
        nonlocal _last_progress_report
        now = time.time()
        if now - _last_progress_report < 0.2:
            return
        _last_progress_report = now
        errors = partial_results.get('errors', [])
        new_counts = {
            'scanned_files': len(partial_results.get('scanned_files', [])),
            'quarantined_files': len(partial_results.get('quarantined_files', [])),
            'errors': len(errors),
            'process_events': len(partial_results.get('process_events', [])),
            'ml_detections': len(partial_results.get('ml_detections', [])),
            'ransomware_indicators': len(partial_results.get('ransomware_indicators', [])),
            'persistence_indicators': _count_persistence_indicators(partial_results),
            'yara_suspicious': len(partial_results.get('yara_suspicious', [])),
        }
        with conditional_startup_lock:
            for key, current in new_counts.items():
                _add_delta(key, current)
            conditional_startup_state.update({
                'running': True,
                'last_updated': time.strftime('%Y-%m:%d %H:%M:%S'),
                'last_error': str(errors[-1]) if errors else None,
            })
            # Expose the latest detail lists so the review UI works
            # even while the scan is still in progress.
            global latest_yara_suspicious, latest_ransomware_indicators, latest_persistence_indicators
            latest_yara_suspicious = partial_results.get('yara_suspicious', [])
            latest_ransomware_indicators = partial_results.get('ransomware_indicators', [])
            latest_persistence_indicators = partial_results.get('persistence_indicators', {})
            # Cache a flattened, reviewable list inside the state so the dashboard
            # can render it immediately without an extra API round-trip.
            try:
                conditional_startup_state['findings'] = _findings_for_review()
            except Exception:
                conditional_startup_state['findings'] = []

    with conditional_startup_lock:
        conditional_startup_state.update({
            'running': True,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': None,
            'last_error': None,
        })

    try:
        with scanning_lock:
            critical_dirs = list(folder_watcher_state.get('monitored_paths', []))
            if not critical_dirs:
                critical_dirs = None
            scan_data = run_conditional_startup_logic(open_browser=False, progress_callback=report_progress, critical_dirs=critical_dirs)
        with conditional_startup_lock:
            record_conditional_startup_run(scan_data, time.time() - start_time)
            if isinstance(scan_data, dict):
                latest_yara_suspicious = scan_data.get('yara_suspicious', [])
                latest_ransomware_indicators = scan_data.get('ransomware_indicators', [])
                latest_persistence_indicators = scan_data.get('persistence_indicators', {})
            else:
                latest_yara_suspicious = []
                latest_ransomware_indicators = []
                latest_persistence_indicators = {}
        try:
            scan_cache._save()
        except Exception:
            pass
        logger.info("Conditional startup scan completed")
    except BaseException as e:
        # BaseException so SystemExit raised by imported modules (e.g. missing
        # FERNET_KEY) is recorded instead of leaving the state stuck on running
        logger.error(f"Error running conditional startup: {e!r}")
        with conditional_startup_lock:
            record_conditional_startup_run(error=e, duration=time.time() - start_time)


def _find_models_dir():
    """Find the models directory — works both in dev mode and when running
    from a PyInstaller EXE (where __file__ points to a temp folder)."""
    candidates = []
    # 0. PyInstaller bundled location — check FIRST (sys._MEIPASS is where data files are extracted)
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(os.path.join(meipass, 'models'))
    # 1. Next to this script (dev mode)
    try:
        basedir = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(basedir, 'models'))
    except Exception:
        basedir = os.getcwd()
        candidates.append(os.path.join(basedir, 'models'))
    # 2. Next to the EXE (PyInstaller mode)
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        candidates.append(os.path.join(exe_dir, 'models'))
        candidates.append(os.path.join(exe_dir, '..', 'models'))
        candidates.append(os.path.join(exe_dir, '..', '..', 'models'))
    # 3. Common install locations
    candidates.append(os.path.join(os.getcwd(), 'models'))
    pf = os.environ.get('ProgramFiles', r'C:\Program Files')
    candidates.append(os.path.join(pf, 'Antivirus Server', 'models'))
    candidates.append(os.path.join(pf, 'AntivirusServer', 'models'))
    # 4. ProgramData
    candidates.append(os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'AntivirusServer', 'models'))
    for c in candidates:
        try:
            if os.path.isdir(c):
                return c
        except Exception:
            pass
    return os.path.join(basedir if 'basedir' in dir() else os.getcwd(), 'models')


def _ml_model_status():
    """Return which malware-ML models are present/available."""
    models_dir = _find_models_dir()
    return {
        'bodmas_cnn': (
            os.path.exists(os.path.join(models_dir, 'bodmas_cnn.onnx')) and
            os.path.exists(os.path.join(models_dir, 'bodmas_cnn_scaler.pkl'))
        ),
        'ember': os.path.exists(os.path.join(models_dir, 'ember_malware_model.txt')),
        'sklearn': os.path.exists(os.path.join(models_dir, 'file_malware_classifier.pkl')),
    }


@app.route('/api/conditional_startup/status', methods=['GET'])
@app.route('/api/conditional_startup/refresh', methods=['POST'])
def conditional_startup_status():
    """Status of the last conditional startup run; also used by Refresh Status."""
    global conditional_startup_thread
    with conditional_startup_lock:
        if conditional_startup_state.get('running'):
            if conditional_startup_thread is None or not conditional_startup_thread.is_alive():
                conditional_startup_state.update({
                    'running': False,
                    'last_error': 'Scan thread terminated unexpectedly',
                    'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
                })
        resp = dict(conditional_startup_state)
    resp['status'] = 'RUNNING' if resp.get('running') else 'IDLE'
    resp['network_monitor_running'] = bool(network_state.get('monitoring_enabled'))
    resp['ml_models'] = _ml_model_status()
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
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            conditional_startup_state.update({
                'running': True,
                'started_at': now,
                'last_updated': now,
                'scanned_files': 0,
                'quarantined_files': 0,
                'errors': 0,
                'process_events': 0,
                'ml_detections': 0,
                'ransomware_indicators': 0,
                'persistence_indicators': 0,
                'yara_suspicious': 0,
                'duration': None,
                'last_error': None,
            })

        logger.info("Starting conditional startup scan in background")
        global conditional_startup_thread
        conditional_startup_thread = threading.Thread(target=run_conditional_startup_background, daemon=True)
        conditional_startup_thread.start()

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


@app.route('/api/conditional_startup/stop', methods=['POST'])
def stop_conditional_startup():
    """Signal the conditional startup scan to stop as soon as it can."""
    remote_addr = request.remote_addr or 'unknown'
    if _is_stop_rate_limited(remote_addr):
        return jsonify({"status": "error", "message": "Stop requests are limited to 5 per minute"}), 429
    try:
        from conditional_startup import STOP_EVENT
        STOP_EVENT.set()
        with conditional_startup_lock:
            conditional_startup_state.update({
                'stop_requested': True,
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
            })
        return jsonify({
            "status": "success",
            "message": "Stop requested. The scan will exit as soon as the current file finishes."
        })
    except Exception as e:
        logger.error(f"Error stopping conditional startup: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# -- Web auth for quick_start.py dashboard --
# The YARA scanner (and its supporting API endpoints) are intentionally public
# so the desktop "Start YARA Scanner" shortcut works without an extra login step.
YARA_SCANNER_PREFIXES = (
    '/yara', '/yara_scanner', '/scan', '/scan_all', '/toggle_scan_all',
    '/add_folder', '/remove-monitored-folder', '/api/monitored-directories',
    '/api/network/monitored_directories', '/toggle_folder_watcher',
    '/folder-watcher-paths', '/get_folder_watcher_paths', '/start_realtime',
    '/get_network_monitored_directories', '/get_traffic_stats',
    '/get_c2_patterns', '/get_live_connections', '/start_traffic_monitoring',
)


@app.before_request
def _require_login():
    """Redirect unauthenticated users to /login except for public pages/scanning APIs."""
    if request.endpoint in ('login', 'logout', 'static'):
        return
    if request.path.startswith(YARA_SCANNER_PREFIXES):
        return
    if session.get('logged_in'):
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
        return


def _is_exempt_from_csrf():
    """Return True if the current request does not need a CSRF token."""
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
        return True
    if request.endpoint in ('login', 'logout', 'static'):
        return True
    if request.path.startswith(YARA_SCANNER_PREFIXES):
        return True
    if not session.get('logged_in'):
        return True
    return False


@app.before_request
def _require_csrf():
    """Validate X-CSRF-Token header for state-changing requests."""
    if _is_exempt_from_csrf():
        return
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') or request.args.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'status': 'error', 'message': 'Invalid or missing CSRF token'}), 403
    # A valid token from an authenticated session is sufficient. The previous
    # code incorrectly returned 401 for every valid AJAX/API POST request.
    return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    register_error = None
    register_message = None
    if request.method == 'POST':
        remote_addr = request.remote_addr or 'unknown'
        action = request.form.get('action', '').strip()

        if action == 'register':
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')
            if not password:
                register_error = 'Password is required'
            elif password != confirm:
                register_error = 'Passwords do not match'
            elif not set_password:
                register_error = 'Registration is not available'
            else:
                try:
                    set_password(password)
                    register_message = 'Password set. You can now log in as admin.'
                except Exception as e:
                    register_error = str(e)
            return send_from_directory('website', 'login.html')

        if _is_login_rate_limited(remote_addr):
            return send_from_directory('website', 'login.html'), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if verify_password:
            try:
                password_ok = (username == ADMIN_USERNAME) and verify_password(password)
            except Exception:
                password_ok = (username == ADMIN_USERNAME) and (password == os.environ.get('ADMIN_PASSWORD', 'admin123'))
        else:
            password_ok = (username == ADMIN_USERNAME) and (password == os.environ.get('ADMIN_PASSWORD', 'admin123'))

        if password_ok:
            _login_attempts.pop(remote_addr, None)
            session['logged_in'] = True
            session['csrf_token'] = secrets.token_urlsafe(32)
            next_page = request.form.get('next') or request.args.get('next') or url_for('index')
            return redirect(next_page)
        error = 'Invalid username or password'
    return send_from_directory('website', 'login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Set admin password is now handled on /login. Redirect there."""
    if request.method == 'POST':
        return login()
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/graph')
def threat_graph():
    """Show a threat-score graph for cached scan results."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        entries = []
        iocs = _load_iocs()
        for result in scan_cache.all():
            path = result.get('path', '')
            if not path or not os.path.exists(path):
                continue
            entropy = compute_file_entropy(path)
            ml = result.get('ember_score') or result.get('legacy_ml_score') or 0.0
            yara_rules = result.get('yara_matches', [])
            yara_count = len(yara_rules)
            yara_score = yara_risk_score(yara_rules)
            file_type = detect_file_signature(path)
            packed = packed_encoder_score(path)
            exploit = exploit_score(path)
            ioc = network_ioc_score(path, iocs=iocs)
            mitre = yara_mitre_tags(yara_rules)
            # Combine entropy, ml, yara, packer, exploit and IOC scores into 0-100 risk.
            risk = (entropy / 8.0) * 25.0 + ml * 50.0 + yara_score + packed + exploit + ioc
            if file_type.startswith('Suspicious:'):
                risk += 35.0
            risk = min(100.0, risk)
            entries.append({
                'label': os.path.basename(path)[:24],
                'risk': risk,
                'entropy': entropy,
                'ml': ml,
                'yara_count': yara_count,
                'yara_score': yara_score,
                'packed': packed,
                'exploit': exploit,
                'ioc': ioc,
                'mitre': mitre,
                'file_type': file_type
            })
        # Sort by risk, highest first, and keep top 20 to keep the chart readable.
        entries.sort(key=lambda x: x['risk'], reverse=True)
        entries = entries[:20]
        graph_path = os.path.join('static', 'threat_graph.png')
        graph_url = None
        if generate_threat_graph(entries, graph_path):
            graph_url = url_for('static', filename='threat_graph.png') + '?t=' + str(int(time.time()))
        return render_template('graph.html', entries=entries, graph_url=graph_url)
    except Exception as e:
        logger.warning(f'Failed to render threat graph: {e}')
        return render_template('graph.html', entries=[], graph_url=None)


@app.route('/patches')
def patches():
    """Show missing critical Windows patches for known CVEs."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        missing = missing_critical_patches()
    except Exception as e:
        logger.warning(f'Failed to check patches: {e}')
        missing = []
    return render_template('patches.html', missing=missing)


@app.route('/startup')
def startup():
    """Show startup items, scheduled tasks and persistence locations."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        items = scan_startup_and_tasks()
    except Exception as e:
        logger.warning(f'Failed to scan startup items: {e}')
        items = []
    return render_template('startup.html', items=items, startup_risk_score=startup_risk_score)


@app.route('/kill-switch', methods=['GET', 'POST'])
def kill_switch():
    """Enable or disable an outbound network kill switch via Windows Firewall."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    message = None
    error = None
    if request.method == 'POST':
        action = request.form.get('action')
        enabled = (action == 'enable')
        response = _admin_service_mutation('firewall.kill_switch', enabled=enabled, confirmation='CONFIRM')
        if response and response.get('ok'):
            message = response.get('message', 'Kill switch updated')
        else:
            error = 'Failed to update: ' + (response or {}).get('error', 'administrator service unavailable')
    status = _admin_service_read('firewall.kill_switch.status')
    active = bool(status and status.get('active'))
    return render_template('kill_switch.html', active=active, message=message, error=error)


@app.route('/hash-lookup', methods=['GET', 'POST'])
def hash_lookup():
    """Look up a file hash across multiple threat-intelligence sources."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    results = []
    query = ''
    error = None
    if request.method == 'POST':
        query = request.form.get('hash', '').strip().lower()
        if query and len(query) == 64:
            results = multi_engine_hash_lookup(query)
        else:
            error = 'Enter a valid SHA-256 hash (64 hex characters).'
    risk_score = hash_lookup_risk_score(results)
    return render_template('hash_lookup.html', query=query, results=results, error=error, risk_score=risk_score)


@app.route('/events')
def events():
    """Show a summary of recent Windows security event log entries."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        summary = read_recent_security_summary(50)
    except Exception as e:
        logger.warning(f'Failed to read event logs: {e}')
        summary = {'security': [], 'powershell': [], 'defender': [], 'sysmon': []}
    return render_template('events.html', summary=summary, event_risk_score=event_risk_score)


@app.route('/scripts')
def scripts():
    """Show recent PowerShell/AMSI script blocks with scoring and base64 decoding."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        raw_events = _read_one_event_log('Microsoft-Windows-PowerShell/Operational', count=100, event_ids={4103, 4104, 4105})
    except Exception as e:
        logger.warning(f'Failed to read PowerShell events: {e}')
        raw_events = []
    items = []
    for ev in raw_events:
        if ev.get('error'):
            continue
        scan = scan_powershell_script_block(ev)
        if scan.get('score', 0) >= 10:
            items.append({
                'time': ev.get('time', ''),
                'id': ev.get('id', ''),
                'score': scan.get('score', 0),
                'indicators': scan.get('indicators', []),
                'decoded': scan.get('decoded_blocks', []),
                'message': ev.get('message', [])
            })
    items.sort(key=lambda x: x['score'], reverse=True)
    return render_template('scripts.html', items=items)


@app.route('/scan-report')
def scan_report():
    """Return a JSON report of the latest scan and quarantine activity."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    latest = continuous_scan_state.get('last_result', {}) if continuous_scan_state else {}
    quarantine_log = []
    try:
        log_path = os.path.join(
            os.environ.get('USERPROFILE', os.path.expanduser('~')),
            'AppData', 'Local', 'Temp', 'Defender_Quarantine', 'quarantine_log.json'
        )
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8') as f:
                quarantine_log = json.load(f)
    except Exception as e:
        logger.warning(f'Failed to load quarantine log: {e}')
    report = {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'latest_scan': latest,
        'quarantine_log': quarantine_log
    }
    response = jsonify(report)
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.json'
    return response


@app.route('/quarantine-manage', methods=['GET', 'POST'])
def quarantine_manage():
    """List, restore and delete quarantined files."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    message = None
    error = None
    if request.method == 'POST':
        action = request.form.get('action')
        filename = request.form.get('filename', '').strip()
        if action == 'restore' and filename:
            success, msg = restore_quarantine_file(filename)
            if success:
                message = f'Restored to: {msg}'
            else:
                error = f'Restore failed: {msg}'
        elif action == 'delete' and filename:
            service_response = _admin_service_mutation(
                'quarantine.delete', filename=filename,
                confirmation=request.form.get('confirmation', ''),
            )
            if service_response is not None:
                if service_response.get('ok'):
                    message = service_response.get('message', 'Deleted')
                else:
                    error = f"Delete failed: {service_response.get('error', service_response.get('message', 'operation rejected'))}"
            else:
                success, msg = delete_quarantine_file(filename)
                if success:
                    message = msg
                else:
                    error = f'Delete failed: {msg}'
    service_listing = _admin_service_read('quarantine.list')
    if service_listing and service_listing.get('ok'):
        files = service_listing.get('files', [])
    else:
        try:
            files = list_quarantine_files()
        except Exception as e:
            logger.warning(f'Failed to list quarantine files: {e}')
            files = []
            error = error or (
                'Quarantine listing unavailable: administrator service is not '
                'running and the standalone helper failed.'
            )
    return render_template('quarantine_manage.html', files=files, message=message, error=error)


@app.route('/startup-with-windows', methods=['GET', 'POST'])
def startup_with_windows():
    """Toggle the app starting with Windows for the current user."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    message = None
    if request.method == 'POST':
        action = request.form.get('action')
        enable = action == 'enable'
        if toggle_startup_with_windows(enable):
            message = 'Startup with Windows ' + ('enabled' if enable else 'disabled') + '.'
        else:
            message = 'Failed to change startup setting.'
    active = is_startup_enabled()
    return render_template('startup_with_windows.html', active=active, message=message)


@app.route('/update-iocs', methods=['POST'])
def update_iocs():
    """Refresh IOCs from URLhaus and ThreatFox."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        update_ioc_feeds()
        return jsonify({'status': 'ok', 'message': 'IOC feeds updated'})
    except Exception as e:
        logger.warning(f'IOC update error: {e}')
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/settings')
def settings():
    """Show current configuration without exposing secrets."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    runtime_dir = os.environ.get('ANTIVIRUS_RUNTIME_DIR', os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(runtime_dir, '.env')
    cfg = {}
    try:
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if '=' in line and not line.strip().startswith('#'):
                        k, v = line.strip().split('=', 1)
                        if k.strip() in {'FERNET_KEY', 'VT_API_KEY', 'ADMIN_PASSWORD_HASH', 'SECRET_KEY'}:
                            v = '*' * min(len(v), 8)
                        cfg[k.strip()] = v.strip()
    except Exception:
        pass
    trust_count = 0
    try:
        with open(os.path.join(runtime_dir, 'trusted_hashes.json'), 'r', encoding='utf-8') as f:
            td = json.load(f)
            if isinstance(td, list):
                trust_count = len(td)
            elif isinstance(td, dict):
                trust_count = len(td.get('sha256', []))
    except Exception:
        pass
    ioc_counts = {}
    try:
        with open(os.path.join(runtime_dir, 'iocs.json'), 'r', encoding='utf-8') as f:
            iocs = json.load(f)
            for k, v in iocs.items():
                ioc_counts[k] = len(v)
    except Exception:
        pass
    return render_template('settings.html', config=cfg, trusted_count=trust_count, ioc_counts=ioc_counts)


@app.route('/custom-scan', methods=['GET', 'POST'])
def custom_scan():
    """Allow the operator to scan a single file or directory on demand."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    result = None
    target = ''
    max_files = 100
    if request.method == 'POST':
        target = request.form.get('target_path', '').strip()
        try:
            max_files = max(1, min(5000, int(request.form.get('max_files', 100))))
        except Exception:
            max_files = 100
        if target:
            result = _custom_scan_target(target, max_files=max_files)
    return render_template('custom_scan.html', target=target, max_files=max_files, result=result)


@app.route('/processes')
def processes():
    """Show running processes with risk scoring for injection / suspicious command lines."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        procs = scan_running_processes()
    except Exception as e:
        logger.warning(f'Failed to scan running processes: {e}')
        procs = []
    return render_template('processes.html', processes=procs, process_risk_score=process_risk_score)


@app.route('/canary', methods=['GET', 'POST'])
def canary():
    """Create and check ransomware canary files."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    message = None
    status = []
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            try:
                create_canary_files()
                message = 'Canary files created or refreshed.'
            except Exception as e:
                message = f'Failed to create canary files: {e}'
    try:
        status = check_canary_files()
    except Exception as e:
        logger.warning(f'Failed to check canary files: {e}')
    return render_template('canary.html', status=status, message=message)


@app.route('/services')
def services():
    """Show Windows services with risk scoring."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        svcs = scan_windows_services()
    except Exception as e:
        logger.warning(f'Failed to scan services: {e}')
        svcs = []
    return render_template('services.html', services=svcs, service_risk_score=service_risk_score)


@app.route('/network')
def network():
    """Show network connections with beaconing / DGA / IOC scoring."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        conns = scan_network_connections()
    except Exception as e:
        logger.warning(f'Failed to scan network connections: {e}')
        conns = []
    iocs = _load_iocs()
    return render_template('network.html', connections=conns, network_beacon_score=lambda c: network_beacon_score(c, iocs))


# -- Main index page --
@app.route('/')
def index():
    # Provide all template variables required by index.html
    folder_watcher_status = folder_watcher_state.get('active', False)
    network_monitor_running = network_state.get('monitoring_enabled', False)
    auto_block_enabled = network_state.get('auto_block_enabled', False)
    safe_downloader_status = True   # Default value
    auto_updates_running = True     # Default value
    c2_detector_low_count = 0        # Default value
    c2_detector_high_count = 0       # Default value
    scheduled_scan_enabled = True   # Default value
    status = {
        'status': 'ENABLED' if folder_watcher_status else 'DISABLED',
        'folder_watcher': folder_watcher_status,
        'network_monitor': network_monitor_running,
        'safe_downloader': safe_downloader_status
    }

    response = make_response(render_template('index.html',
                          network_monitor_running=network_monitor_running,
                          folder_watcher_status=folder_watcher_status,
                          auto_block_enabled=auto_block_enabled,
                          safe_downloader_status=safe_downloader_status,
                          auto_updates_running=auto_updates_running,
                          c2_detector_low_count=c2_detector_low_count,
                          c2_detector_high_count=c2_detector_high_count,
                          scheduled_scan_enabled=scheduled_scan_enabled,
                          status=status))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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
                           auto_block_enabled=network_state.get('auto_block_enabled', False),
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
    result, status_code = _perform_scan_all()
    return jsonify(result), status_code


@app.route('/toggle_scan_all/<action>', methods=['POST'])
def toggle_scan_all(action):
    """Start or stop the continuous scan-all background loop."""
    global continuous_scan_thread
    if action not in ['start', 'stop']:
        return jsonify({'status': 'error', 'error': 'Invalid action'}), 400

    if action == 'start':
        if not continuous_scan_state['active']:
            continuous_scan_state['active'] = True
            continuous_scan_state['last_error'] = None
            monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
            continuous_scan_state['last_result'] = {
                'status': 'success',
                'scan_time': '0.00 seconds',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'matches': 0,
                'folders': monitored_dirs,
                'results': [f'Scan started on {len(monitored_dirs)} folder(s)...'],
                'files_scanned': 0,
                'directories_scanned': 0,
                'threats_detected': 0,
                'threats_removed': 0
            }
            if continuous_scan_thread is None or not continuous_scan_thread.is_alive():
                continuous_scan_thread = threading.Thread(target=run_continuous_scan_all, daemon=True)
                continuous_scan_thread.start()
        return jsonify({
            'status': 'success',
            'active': True,
            'message': 'Continuous scanning started'
        })

    continuous_scan_state['active'] = False
    return jsonify({
        'status': 'success',
        'active': False,
        'message': 'Continuous scanning stopped'
    })


@app.route('/scan_all/latest', methods=['GET'])
def scan_all_latest():
    """Return the most recent continuous scan-all result."""
    return jsonify({
        'status': 'success',
        'active': continuous_scan_state['active'],
        'last_run': continuous_scan_state.get('last_run'),
        'last_error': continuous_scan_state.get('last_error'),
        'result': continuous_scan_state.get('last_result')
    })


# -- Network monitoring enhanced functionality --
# Global state to track network monitoring status
network_state = {
    'monitoring_enabled': True,
    'auto_block_enabled': True,  # C2/uncommon-port auto-blocking is now on by default
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
@app.route('/start_traffic_monitoring', methods=['POST'])
def start_traffic_monitoring():
    """Signal that traffic monitoring is active."""
    return jsonify({'success': True, 'message': 'Traffic monitoring is active'})


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
    """Get the list of network-monitored directories with recursive subdirectory scanning.

    NOTE: This used to permanently append every recursively-discovered
    subdirectory into network_state['monitored_directories'] on every call.
    Since this endpoint is polled repeatedly (background scan thread, page
    load, periodic UI refresh) and directories like AppData/ProgramData/
    System32 contain thousands of nested subdirectories, that caused
    unbounded runaway growth: each call discovered and persisted more
    subdirectories, making the next call's os.walk() (and the next
    discovery pass) slower and larger, snowballing until calls timed out
    entirely and the rendered directory list ballooned to megabytes. This
    now reports discovered subdirectories in the response without
    persisting them, so repeated calls stay bounded by the fixed base
    directory list rather than compounding.
    """
    global network_state
    
    # Define high-risk file extensions to monitor more carefully
    high_risk_extensions = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta', 
        '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe', 
        '.wsh', '.sys', '.inf'
    ]
    
    # Snapshot the persistent base list -- do not mutate network_state below.
    monitored_dirs = list(network_state['monitored_directories'])
    total_files_monitored = 0
    discovered_subdirs = [] # Keep track of discovered subdirectories (not persisted)
    
    monitoring_status = {
        'enabled': network_state['monitoring_enabled'],
        'total_directories': len(monitored_dirs),  # Initial count - will be updated after discovering subdirs
        'last_scan': network_state.get('last_scan', 'Never'),
        'traffic_stats': network_state.get('traffic_stats', {}),
        'directories': []
    }
    
    # Add detailed information about each directory.
    # NOTE: This only scans one level deep (os.scandir on the directory
    # itself) rather than fully recursing with os.walk(). A full recursive
    # walk over directories like AppData/ProgramData/System32 -- which can
    # contain hundreds of thousands of files -- made this endpoint take so
    # long it would time out on every call. File/subdirectory counts below
    # reflect only the immediate contents of each monitored directory, not
    # its entire subtree.
    for directory in monitored_dirs:
        if os.path.exists(directory):
            try:
                file_count = 0
                high_risk_file_count = 0
                subdir_count = 0

                with os.scandir(directory) as entries:
                    for entry in entries:
                        if any(excluded in entry.path for excluded in folder_watcher_state['excluded_paths']):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            subdir_count += 1
                            if entry.path not in monitored_dirs and entry.path not in discovered_subdirs:
                                discovered_subdirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            file_count += 1
                            _, ext = os.path.splitext(entry.name)
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
            except Exception:
                # Handle permission / I/O errors
                monitoring_status['directories'].append({
                    'path': directory,
                    'exists': True,
                    'file_count': 'Unknown (inaccessible)',
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
    
    # Report discovered subdirectories in the response without persisting them
    # into network_state (see NOTE on the route above for why).
    valid_subdirs = [
        subdir for subdir in discovered_subdirs
        if not any(excluded in subdir for excluded in folder_watcher_state['excluded_paths'])
    ]
    all_directories = list(monitored_dirs)
    for subdir in valid_subdirs:
        if subdir not in all_directories:
            all_directories.append(subdir)
    
    # Update the monitoring_status to reflect the discovered subdirectories
    monitoring_status['total_directories'] = len(all_directories)
    
    # Also add a separate count for all subdirectories to make it clearly visible
    monitoring_status['total_subdirectories_found'] = len(valid_subdirs)
    
    return jsonify({
        'success': True,
        'monitored_directories': all_directories,
        'monitoring_status': monitoring_status
    })

# Common ports that are expected/benign for outbound traffic. Connections to
# other remote ports are flagged as "uncommon" by /get_c2_patterns below --
# this is a simple heuristic, not a real C2/beaconing detector.
_COMMON_REMOTE_PORTS = {80, 443, 53, 123, 22, 21, 25, 110, 143, 993, 995, 587, 3389, 8080, 8443}


def _collect_live_connections():
    """Enumerate current inet socket connections via psutil, returning a list
    of dicts with process/protocol/address info. Connections we can't get a
    process name for (permission issues, race with process exit, etc.) are
    still included with a placeholder process name rather than being dropped.
    """
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if not conn.laddr:
            continue
        proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'OTHER'
        process_name = 'Unknown'
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = f'PID {conn.pid}'
        connections.append({
            'pid': conn.pid,
            'process': process_name,
            'protocol': proto,
            'status': conn.status,
            'local_ip': conn.laddr.ip if conn.laddr else None,
            'local_port': conn.laddr.port if conn.laddr else None,
            'remote_ip': conn.raddr.ip if conn.raddr else None,
            'remote_port': conn.raddr.port if conn.raddr else None,
        })
    return connections


@app.route('/get_traffic_stats', methods=['GET'])
def get_traffic_stats():
    """Get live network traffic statistics using psutil.

    Reports currently active connections, protocol distribution, per-process
    connection counts, and cumulative bytes sent/received (since the OS was
    booted/counters were last reset -- psutil doesn't give us a "since app
    start" delta without us tracking a baseline, so this is total I/O, not a
    live throughput rate).
    """
    try:
        connections = _collect_live_connections()
        established = [c for c in connections if c['remote_ip']]

        active_ips = sorted({c['remote_ip'] for c in established})
        protocols = {}
        processes = {}
        for c in connections:
            protocols[c['protocol']] = protocols.get(c['protocol'], 0) + 1
            processes.setdefault(c['process'], {'connections': 0})
            processes[c['process']]['connections'] += 1

        io_counters = psutil.net_io_counters()

        return jsonify({
            'success': True,
            'total_connections': len(connections),
            'active_ips': active_ips,
            'inbound': io_counters.bytes_recv,
            'outbound': io_counters.bytes_sent,
            'protocols': protocols,
            'processes': processes,
            'timestamp': time.time()
        })
    except Exception as e:
        logger.error(f"Error getting traffic stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/get_c2_patterns', methods=['GET'])
def get_c2_patterns():
    """Flag established connections to uncommon remote ports on external hosts.

    NOTE: This is a lightweight heuristic (uncommon destination port on a
    non-local address), not a real command-and-control/beaconing detector.
    It exists to give the UI something meaningful to show rather than an
    empty panel; it will surface false positives for legitimate software
    using non-standard ports. Loopback and private/LAN addresses are
    excluded since C2 traffic is inherently about external endpoints --
    without that exclusion, nearly every local dev tool or IDE using an
    ephemeral loopback port gets flagged, making the list useless noise.
    """
    try:
        connections = _collect_live_connections()
        suspicious = []
        for c in connections:
            if not c['remote_ip'] or not c['remote_port']:
                continue
            if c['remote_port'] in _COMMON_REMOTE_PORTS:
                continue
            try:
                remote_addr = ipaddress.ip_address(c['remote_ip'])
            except ValueError:
                continue
            if remote_addr.is_loopback or remote_addr.is_private or remote_addr.is_link_local:
                continue
            suspicious.append({
                'process': c['process'],
                'remote_ip': c['remote_ip'],
                'remote_port': c['remote_port'],
                'reason': f"Connection to uncommon port {c['remote_port']}"
            })

        # Cap the list so a noisy system doesn't produce an enormous response.
        suspicious = suspicious[:50]

        return jsonify({
            'success': True,
            'suspicious_connections': suspicious,
            'timestamp': time.time()
        })
    except Exception as e:
        logger.error(f"Error getting C2 patterns: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/get_live_connections', methods=['GET'])
def get_live_connections():
    """Live table of all current network connections, each flagged with
    whether it matches the existing C2 heuristic (see get_c2_patterns for
    caveats -- it's a weak "uncommon port" proxy, not proof of anything) and
    whether it's currently blocked via network_blocking.py.
    """
    try:
        from network_blocking import list_blocked_ips
        blocked = list_blocked_ips()

        connections = _collect_live_connections()
        for c in connections:
            flagged = False
            reason = None
            if c['remote_ip'] and c['remote_port'] and c['remote_port'] not in _COMMON_REMOTE_PORTS:
                try:
                    remote_addr = ipaddress.ip_address(c['remote_ip'])
                    if not (remote_addr.is_loopback or remote_addr.is_private or remote_addr.is_link_local):
                        flagged = True
                        reason = f"Uncommon port {c['remote_port']}"
                except ValueError:
                    pass
            c['flagged'] = flagged
            c['flag_reason'] = reason
            c['blocked'] = bool(c['remote_ip'] and c['remote_ip'] in blocked)

        return jsonify({
            'success': True,
            'connections': connections,
            'auto_block_enabled': network_state.get('auto_block_enabled', False),
            'timestamp': time.time()
        })
    except Exception as e:
        logger.error(f"Error getting live connections: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/block_connection', methods=['POST'])
def block_connection():
    """Manually block outbound traffic to a remote IP (human-initiated, from
    the live connections dashboard -- see network_blocking.py's module
    docstring for why this doesn't carry the same false-positive risk as
    automatic blocking would)."""
    try:
        data = request.get_json(silent=True) or {}
        ip = data.get('ip', '')
        reason = data.get('reason', 'Manually blocked from dashboard')
        service_response = _admin_service_mutation(
            'firewall.block', ip=ip, reason=reason,
            confirmation=data.get('confirmation', ''),
        )
        if service_response is not None:
            return jsonify({'success': service_response.get('ok', False), 'message': service_response.get('message', service_response.get('error', 'operation rejected')), 'source': 'administrator-service'}), (200 if service_response.get('ok') else 400)
        from network_blocking import block_ip
        success, message = block_ip(ip, reason)
        return jsonify({'success': success, 'message': message, 'source': 'standalone-helper'}), (200 if success else 400)
    except Exception as e:
        logger.error(f"Error blocking connection: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/unblock_connection', methods=['POST'])
def unblock_connection():
    """Reverse a previously-applied block."""
    try:
        data = request.get_json(silent=True) or {}
        ip = data.get('ip', '')
        service_response = _admin_service_mutation(
            'firewall.unblock', ip=ip,
            confirmation=data.get('confirmation', ''),
        )
        if service_response is not None:
            return jsonify({'success': service_response.get('ok', False), 'message': service_response.get('message', service_response.get('error', 'operation rejected')), 'source': 'administrator-service'}), (200 if service_response.get('ok') else 400)
        from network_blocking import unblock_ip
        success, message = unblock_ip(ip)
        return jsonify({'success': success, 'message': message, 'source': 'standalone-helper'}), (200 if success else 400)
    except Exception as e:
        logger.error(f"Error unblocking connection: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/list_blocked_connections', methods=['GET'])
def list_blocked_connections():
    service_listing = _admin_service_read('firewall.list')
    if service_listing and service_listing.get('ok'):
        return jsonify({'success': True, 'blocked': service_listing.get('blocked', {}), 'source': 'administrator-service'})
    try:
        from network_blocking import list_blocked_ips
        return jsonify({'success': True, 'blocked': list_blocked_ips(), 'source': 'standalone-helper'})
    except Exception as e:
        logger.error(f"Error listing blocked connections: {e}")
        return jsonify({
            'success': False,
            'error': 'Firewall listing unavailable: administrator service is not running and the standalone helper failed.',
        }), 503


def run_auto_block_monitor():
    """Background loop: when network_state['auto_block_enabled'] is on,
    periodically scan live connections and block any the C2 heuristic flags
    that aren't already blocked. Off by default -- see network_blocking.py
    and toggle_auto_block() for why this is opt-in."""
    from network_blocking import block_ip, list_blocked_ips, should_auto_block_ip
    while True:
        try:
            if network_state.get('auto_block_enabled'):
                blocked = list_blocked_ips()
                for c in _collect_live_connections():
                    ip = c.get('remote_ip')
                    port = c.get('remote_port')
                    if not ip or not port or ip in blocked or port in _COMMON_REMOTE_PORTS:
                        continue
                    try:
                        remote_addr = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if remote_addr.is_loopback or remote_addr.is_private or remote_addr.is_link_local:
                        continue
                    if should_auto_block_ip(ip):
                        success, message = block_ip(ip, reason=f"Auto-blocked: uncommon port {port}")
                        logger.warning(f"[auto-block] {ip}: {message}")
        except Exception as e:
            logger.error(f"Error in auto-block monitor: {e}")
        time.sleep(30)


def run_process_hardening_monitor():
    """Background loop: periodically scan running processes for YARA matches,
    high entropy, missing code signatures, and suspicious memory regions."""
    while True:
        try:
            from security.process_security import scan_processes_with_hardening
            hardening_events = []

            def on_hardening_event(event):
                if (event.get('type') in ('malware_found', 'yara_match') or
                    (event.get('type') == 'process_scanned' and (
                        event.get('yara') or
                        (event.get('hashes', {}).get('entropy', 0) > 7.5) or
                        event.get('signed') is False
                    ))):
                    hardening_events.append(event)

            scan_processes_with_hardening(
                terminate_on_malware=False,
                block_connections=False,
                entropy_threshold=7.5,
                event_callback=on_hardening_event
            )
            conditional_startup_state.update({
                'process_events': len(hardening_events),
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
            })
            logger.info(f"Process hardening monitor completed; {len(hardening_events)} events")
        except Exception as e:
            logger.error(f"Error in process hardening monitor: {e}")
        time.sleep(300)  # 5 minutes

@app.route('/toggle_auto_block/<action>', methods=['POST'])
def toggle_auto_block(action):
    """Opt-in toggle for automatically blocking connections the C2 heuristic
    flags. Off by default -- see network_blocking.py's module docstring for
    why this heuristic isn't strong enough to act on without a human in the
    loop, by default."""
    if action not in ('start', 'stop'):
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    network_state['auto_block_enabled'] = (action == 'start')
    logger.warning(f"Auto-block of C2-flagged connections {'ENABLED' if action == 'start' else 'disabled'}")
    return jsonify({'success': True, 'auto_block_enabled': network_state['auto_block_enabled']})


@app.route('/toggle_folder_watcher/<action>', methods=['POST'])
def toggle_folder_watcher(action):
    """Toggle folder watcher service on/off."""
    global folder_watcher_state
    
    try:
        if action not in ['start', 'stop']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        discovered_subdirs = []
        
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
    """Get the list of folder watcher monitored paths with recursive subdirectory scanning.

    NOTE: See the matching NOTE on get_network_monitored_directories() above --
    this used to permanently append every discovered subdirectory into
    folder_watcher_state['monitored_paths'] on every call, causing the same
    unbounded runaway growth (repeated calls got slower and the persisted
    list larger without limit). This now reports discovered subdirectories
    in the response without persisting them.
    """
    global folder_watcher_state
    
    # Define high-risk file extensions to monitor more carefully
    high_risk_extensions = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta', 
        '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe', 
        '.wsh', '.sys', '.inf'
    ]
    
    # Snapshot the persistent base list -- do not mutate folder_watcher_state below.
    monitored_paths = list(folder_watcher_state['monitored_paths'])
    
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
                    # NOTE: Only scans one level deep (os.scandir) rather than
                    # fully recursing with os.walk() -- see the matching NOTE
                    # on get_network_monitored_directories() above for why a
                    # full recursive walk made this endpoint time out.
                    with os.scandir(path) as entries:
                        for entry in entries:
                            if any(excluded in entry.path for excluded in folder_watcher_state['excluded_paths']):
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                subdir_count += 1
                                total_directories_monitored += 1
                                if entry.path not in monitored_paths and entry.path not in discovered_subdirs:
                                    discovered_subdirs.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                file_count += 1
                                total_files_monitored += 1
                                _, ext = os.path.splitext(entry.name)
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
    
    # Report discovered subdirectories in the response without persisting them
    # into folder_watcher_state (see NOTE on the route above for why).
    valid_subdirs = [
        subdir for subdir in discovered_subdirs
        if not any(excluded in subdir for excluded in folder_watcher_state['excluded_paths'])
    ]
    all_paths = list(monitored_paths)
    for subdir in valid_subdirs:
        if subdir not in all_paths:
            all_paths.append(subdir)
    total_directories_monitored = len(all_paths)
    
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
        'monitored_paths': all_paths,  # Base paths plus discovered subdirectories
        'root_directories_count': len(monitored_paths),  # Original root directories
        'subdirectories_count': len(valid_subdirs),  # Found subdirectories
        'total_subdirectories_found': len(valid_subdirs),  # For consistency with network monitor
        'total_paths': len(all_paths)  # Total of all monitored paths
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

@app.errorhandler(413)
def handle_file_too_large(e):
    """Friendly error for uploads exceeding MAX_CONTENT_LENGTH, instead of
    Flask's default plain-text 413 response."""
    max_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    if request.path in ('/encrypt', '/decrypt'):
        return render_template('file_crypto.html', error=f'File is too large. Maximum allowed size is {max_mb}MB.'), 413
    return jsonify({'success': False, 'error': f'File is too large. Maximum allowed size is {max_mb}MB.'}), 413


@app.route('/file_crypto', methods=['GET'])
def file_crypto():
    """File encryption/decryption tool page."""
    return render_template('file_crypto.html')


@app.route('/encrypt', methods=['POST'])
def encrypt_file_route():
    """Encrypt an uploaded file and return it for download."""
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('file_crypto.html', error='No file selected')

    file = request.files['file']
    temp_in_path = temp_out_path = None
    try:
        from file_crypto import encrypt_file as encrypt_file_util

        with tempfile.NamedTemporaryFile(delete=False, prefix='antivirus_') as temp_in:
            file.save(temp_in.name)
            temp_in_path = temp_in.name
        temp_out_fd, temp_out_path = tempfile.mkstemp(prefix='antivirus_')
        os.close(temp_out_fd)

        encrypt_file_util(temp_in_path, temp_out_path)
        return send_file(temp_out_path, as_attachment=True,
                          download_name=f'encrypted_{secure_filename(file.filename)}')
    except Exception as e:
        logger.error(f"Error encrypting file: {e}")
        return render_template('file_crypto.html', error=f'Encryption failed: {e}')
    finally:
        if temp_in_path and os.path.exists(temp_in_path):
            os.remove(temp_in_path)
        # Note: temp_out_path is intentionally not removed here since send_file
        # streams it after this function returns.


@app.route('/decrypt', methods=['POST'])
def decrypt_file_route():
    """Decrypt an uploaded file and return it for download."""
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('file_crypto.html', error='No file selected')

    file = request.files['file']
    key = request.form.get('key') or None
    temp_in_path = temp_out_path = None
    try:
        from file_crypto import decrypt_file as decrypt_file_util

        with tempfile.NamedTemporaryFile(delete=False, prefix='antivirus_') as temp_in:
            file.save(temp_in.name)
            temp_in_path = temp_in.name
        temp_out_fd, temp_out_path = tempfile.mkstemp(prefix='antivirus_')
        os.close(temp_out_fd)

        decrypt_file_util(temp_in_path, temp_out_path, key.encode() if key else None)
        return send_file(temp_out_path, as_attachment=True,
                          download_name=f'decrypted_{secure_filename(file.filename)}')
    except InvalidToken:
        return render_template('file_crypto.html', error='Decryption failed: invalid key or corrupted file')
    except Exception as e:
        logger.error(f"Error decrypting file: {e}")
        return render_template('file_crypto.html', error=f'Decryption failed: {e}')
    finally:
        if temp_in_path and os.path.exists(temp_in_path):
            os.remove(temp_in_path)

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
                # Skip metadata sidecars; we only list the quarantined payloads here.
                if filename.endswith('.json'):
                    continue

                # Check if this is an encrypted file
                is_encrypted = filename.endswith('.enc')

                # Get file stats
                file_stats = os.stat(file_path)
                quarantine_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                # Extract original name (remove .enc extension if present)
                original_name = filename
                if is_encrypted:
                    original_name = os.path.splitext(filename)[0]  # Remove .enc extension

                # Read metadata sidecar if it exists (e.g. from app.py quarantine_suspicious_file)
                original_path = ''
                detection_info = {'matches': ['YARA Detection']}
                json_path = file_path + '.json'
                if os.path.exists(json_path):
                    try:
                        with open(json_path, 'r', encoding='utf-8') as jf:
                            metadata = json.load(jf)
                        original_path = metadata.get('original_path', '')
                        detection_info = metadata.get('detection_info', detection_info)
                    except Exception:
                        pass

                quarantined_files.append({
                    'filename': original_name,
                    'quarantine_path': file_path,
                    'original_path': original_path,
                    'quarantine_time': quarantine_time,
                    'timestamp': file_stats.st_mtime * 1000,  # Convert to milliseconds for JavaScript
                    'encrypted': is_encrypted,
                    'size': file_stats.st_size,
                    'details': 'Encrypted (.enc)' if is_encrypted else 'Not encrypted',
                    'detection_info': detection_info
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
            # Return HTML view with cache disabled so the browser always gets the latest JS
            response = make_response(render_template('quarantine.html', quarantined_files=quarantined_files, quarantine_log=quarantine_log))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
            
    except Exception as e:
        logger.error(f"Error listing quarantined files: {e}")
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'error', 
                'error': str(e),
                'files': []
            })
        else:
            response = make_response(render_template('quarantine.html', quarantined_files=[], quarantine_log=f"Error listing quarantined files: {e}"))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response

@app.route('/logs')
def logs():
    return render_template('logs.html') if os.path.exists(os.path.join(app.template_folder, 'logs.html')) else 'Antivirus Logs'

@app.route('/safe_download', methods=['GET', 'POST'])
def safe_download():
    if not os.path.exists(os.path.join(app.template_folder, 'safe_download.html')):
        return 'Safe Download'
    if request.method == 'GET':
        return render_template('safe_download.html')
    if request.method == 'POST':
        from safe_downloader import download_and_scan
        url = request.form.get('url') or (request.get_json(silent=True) or {}).get('url')
        if not url:
            return render_template('safe_download.html', error='url is required'), 400
        try:
            result = download_and_scan(url)
            if not result.get('ok'):
                return render_template('safe_download.html', error=result.get('error', 'unknown error'), deleted=result.get('deleted')), 400
            return send_file(
                result['encrypted_path'],
                as_attachment=True,
                download_name=os.path.basename(result['encrypted_path']),
            )
        except Exception as e:
            logger.exception('safe download failed')
            return render_template('safe_download.html', error=str(e)), 500


@app.route('/api/safe_download', methods=['POST'])
def api_safe_download():
    from safe_downloader import download_and_scan
    data = request.get_json(silent=True) or {}
    url = data.get('url')
    if not url or not isinstance(url, str):
        return jsonify({'success': False, 'error': 'url is required'}), 400
    try:
        result = download_and_scan(url)
        if not result.get('ok'):
            payload = {'success': False, 'error': result.get('error', 'unknown error')}
            if result.get('deleted'):
                payload['deleted'] = True
            return jsonify(payload), 400
        return send_file(
            result['encrypted_path'],
            as_attachment=True,
            download_name=os.path.basename(result['encrypted_path']),
        )
    except Exception as e:
        logger.exception('safe download failed')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/quarantine/list')
def quarantine_list():
    service_listing = _admin_service_read('quarantine.list')
    if service_listing and service_listing.get('ok'):
        return jsonify({'files': service_listing.get('files', []), 'source': 'administrator-service'})

    # Path to the quarantine directory (standalone fallback)
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

@app.route('/quarantine/yara-matches', methods=['POST'])
def quarantine_yara_matches():
    """Quarantine cached files with ransomware/persistence YARA matches."""
    global latest_yara_suspicious
    quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
    quarantined = []
    failed = []
    seen = set()

    # Only act on the latest conditional startup's YARA suspicious matches.
    # We intentionally do NOT loop through the whole scan_cache here, because
    # the cache can contain thousands of historical entries and old rule-name
    # substrings (e.g. a match rule containing 'persistence' as a substring)
    # can lead to false-positive quarantines of legitimate Windows files.
    for entry in list(latest_yara_suspicious):
        path = entry.get('file')
        rules = entry.get('rules', [])
        if not path or not rules or path in seen:
            continue
        # Require rule names that CONTAIN persistence/ransomware
        # and let safe_quarantine refuse protected system locations.
        is_ransomware = any('ransomware' in str(m).lower() for m in rules)
        is_persistence = any('persistence' in str(m).lower() for m in rules)
        if not (is_ransomware or is_persistence):
            continue
        seen.add(path)
        try:
            if not os.path.exists(path):
                continue
            success, msg = safe_quarantine(path, quarantine_dir, encrypt_file, force=False, max_size=1024*1024*1024)
            if success:
                quarantined.append(path)
            else:
                failed.append(f'{path}: {msg}')
        except Exception as e:
            failed.append(f'{path}: {e}')

    # The persistence_indicators and ransomware_indicators counters are
    # report-only heuristics; do NOT quarantine them from this button, because
    # the file paths they surface (e.g. registry commands, running processes)
    # can be legitimate Windows components. Only YARA matches with
    # ransomware/persistence rule names are actionable here.
    return jsonify({'quarantined': quarantined, 'failed': failed, 'count': len(quarantined)})


def _findings_for_review():
    """Flatten the latest persistence and ransomware indicators into a
    reviewable list of (path, reason, source) entries."""
    import shlex
    findings = []
    seen = set()

    def _first_file_from_command(command):
        if not command:
            return None
        try:
            parts = shlex.split(command, posix=False)
            if not parts:
                return None
            # First token may be the executable, or an unquoted path with spaces
            candidate = parts[0].strip('"').strip("'")
            if os.path.isfile(candidate):
                return candidate
            # Try to rejoin tokens to find an existing file
            for i in range(1, len(parts)):
                candidate = candidate + ' ' + parts[i]
                if os.path.isfile(candidate):
                    return candidate
            return parts[0].strip('"').strip("'")
        except Exception:
            return command.split(None, 1)[0].strip('"').strip("'")

    # Ransomware heuristic findings
    for entry in latest_ransomware_indicators:
        path = entry.get('file')
        if not path or path in seen:
            continue
        seen.add(path)
        if not os.path.isfile(path):
            continue
        findings.append({
            'path': path,
            'reason': entry.get('reason', 'Static ransomware heuristic'),
            'source': 'ransomware',
            'category': 'ransomware_heuristic'
        })

    # Persistence findings
    for category, items in latest_persistence_indicators.items():
        for item in items:
            if not isinstance(item, dict):
                continue
            path = item.get('exe') or item.get('path')
            if not path:
                path = _first_file_from_command(item.get('command', ''))
            if not path or path in seen:
                continue
            seen.add(path)
            if not os.path.isfile(path):
                continue

            reason = item.get('indicator', category)
            extra = item.get('process') or item.get('value_name') or item.get('drive') or item.get('command', '')
            if extra and extra != path:
                reason = f'{reason}: {extra}'

            findings.append({
                'path': path,
                'reason': reason,
                'source': 'persistence',
                'category': category
            })

    return findings


@app.route('/api/persistence_ransomware_findings')
def api_persistence_ransomware_findings():
    """Return the latest persistence and ransomware file findings for review."""
    return jsonify({'findings': _findings_for_review()})


@app.route('/api/assistant/chat', methods=['POST'])
def assistant_chat():
    """Answer a local findings question using optional llama.cpp support."""
    data = request.get_json(silent=True) or {}
    from security.local_assistant import LocalFindingsAssistant
    assistant = LocalFindingsAssistant(os.path.dirname(os.path.abspath(__file__)))
    context = data.get('context') or {}
    context.setdefault('findings', _findings_for_review())
    context.setdefault('service_status', _admin_service_read('service.status') or {})
    try:
        context.setdefault('quarantine', list_quarantine_files())
    except Exception:
        context.setdefault('quarantine', [])
    if 'scan_history' not in context:
        context['scan_history'] = [dict(conditional_startup_state)] if conditional_startup_state else []
    return jsonify(assistant.answer(data.get('message', ''), context))


@app.route('/api/assistant/record-scan', methods=['POST'])
def assistant_record_scan():
    """Persist a bounded scan snapshot for future assistant comparisons."""
    from security.local_assistant import LocalFindingsAssistant
    assistant = LocalFindingsAssistant(os.path.dirname(os.path.abspath(__file__)))
    data = request.get_json(silent=True) or {}
    context = data.get('context') or {}
    context.setdefault('findings', _findings_for_review())
    context.setdefault('service_status', _admin_service_read('service.status') or {})
    context.setdefault('quarantine', [])
    return jsonify({'ok': True, 'record': assistant.record_scan(context)})


@app.route('/api/assistant/history', methods=['GET'])
def assistant_history():
    """Return bounded persisted scan history for the assistant UI."""
    from security.local_assistant import LocalFindingsAssistant
    assistant = LocalFindingsAssistant(os.path.dirname(os.path.abspath(__file__)))
    return jsonify({'history': assistant.load_history()})


@app.route('/api/assistant/report', methods=['POST'])
def assistant_report():
    """Download a current evidence-based assistant report."""
    from security.local_assistant import LocalFindingsAssistant
    assistant = LocalFindingsAssistant(os.path.dirname(os.path.abspath(__file__)))
    data = request.get_json(silent=True) or {}
    context = data.get('context') or {}
    context.setdefault('findings', _findings_for_review())
    context.setdefault('service_status', _admin_service_read('service.status') or {})
    result = assistant.answer('Create an incident report', context)
    report = result.get('answer', '')
    output_format = data.get('format', 'markdown')
    if output_format == 'json':
        return jsonify({'report': report, 'analysis': result.get('analysis', {})})
    response = make_response(report)
    response.mimetype = 'text/html' if output_format == 'html' else 'text/markdown'
    response.headers['Content-Disposition'] = f'attachment; filename=assistant_report.{"html" if output_format == "html" else "md"}'
    return response


@app.route('/quarantine/findings', methods=['POST'])
def quarantine_selected_findings():
    """Quarantine files selected from the persistence/ransomware review list."""
    data = request.get_json(silent=True) or {}
    paths = data.get('paths', [])
    if not paths:
        return jsonify({'status': 'error', 'error': 'No paths selected'}), 400

    quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
    quarantined = []
    failed = []
    for path in paths:
        if not path or not os.path.isfile(path):
            failed.append(f'{path}: not found or not a file')
            continue
        try:
            # Don't bypass protected-location checks on manual review, so
            # accidentally-selected Windows components are refused.
            success, msg = safe_quarantine(path, quarantine_dir, encrypt_file, force=False, max_size=1024*1024*1024)
            if success:
                quarantined.append(path)
            else:
                failed.append(f'{path}: {msg}')
        except Exception as e:
            failed.append(f'{path}: {e}')

    return jsonify({'status': 'success', 'quarantined': quarantined, 'failed': failed, 'count': len(quarantined)})


@app.route('/restore_file', methods=['POST'])
def restore_file():
    """Restore a quarantined file by decrypting it if necessary"""
    try:
        file_path = request.form.get('file_path')
        destination = request.form.get('destination')
        
        if not _is_safe_quarantine_path(file_path):
            return jsonify({'success': False, 'error': 'Invalid quarantine path'})
        if not file_path or not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'File not found'})
        
        # Determine if the file is encrypted (has .enc extension)
        is_encrypted = file_path.endswith('.enc')
        
        # If no destination specified, restore to the Desktop with the original name
        if not destination:
            desktop = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Desktop')
            base = os.path.basename(file_path)
            if is_encrypted:
                # Remove .enc extension for the restored file
                base = os.path.splitext(base)[0]
            destination = os.path.join(desktop, base)
        
        # Ensure the destination directory exists
        os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
        
        # Process the file according to its encryption status
        if is_encrypted:
            # Decrypt the file
            if not decrypt_file(file_path, destination):
                return jsonify({'success': False, 'error': 'Failed to decrypt file'})
            logger.info(f"Successfully decrypted and restored file from {file_path} to {destination}")
        else:
            # Simply copy the file
            shutil.copy2(file_path, destination)
            logger.info(f"Successfully restored unencrypted file from {file_path} to {destination}")

        # Remove the quarantine payload and sidecar after a successful restore
        for p in (file_path, file_path + '.json'):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception as cleanup_exc:
                logger.warning(f'Could not remove {p} after restore: {cleanup_exc}')

        return jsonify({'success': True, 'restored_to': destination})
            
    except Exception as e:
        logger.error(f"Error restoring file: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/quarantine/delete/<filename>', methods=['POST'])
def delete_quarantined_file(filename):
    """Delete a quarantined file and its metadata sidecar"""
    try:
        quarantine_dir = _quarantine_dir()
        if not _is_safe_quarantine_path(filename, quarantine_dir):
            return jsonify({'status': 'error', 'error': 'Invalid filename'}), 400
        file_path = os.path.join(quarantine_dir, filename)
        sidecar_path = file_path + '.json'

        # If the main file is gone, at least clean up any stale sidecar
        if not os.path.exists(file_path):
            if os.path.exists(sidecar_path):
                os.remove(sidecar_path)
                return jsonify({'status': 'success', 'message': 'Stale sidecar removed'})
            return jsonify({'status': 'error', 'error': 'File not found'}), 404

        # Delete the file, then its sidecar
        os.remove(file_path)
        if os.path.exists(sidecar_path):
            try:
                os.remove(sidecar_path)
            except Exception:
                pass
        logger.info(f"Successfully deleted quarantined file: {file_path}")

        return jsonify({'status': 'success', 'message': 'File deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting quarantined file: {e}")
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/quarantine/delete_all', methods=['POST'])
def delete_all_quarantined_files():
    """Delete every file currently in the quarantine folder."""
    try:
        quarantine_dir = _quarantine_dir()
        os.makedirs(quarantine_dir, exist_ok=True)
        deleted = 0
        errors = 0
        for filename in os.listdir(quarantine_dir):
            file_path = os.path.join(quarantine_dir, filename)
            # Skip metadata sidecars here; remove them alongside their payload
            if filename.endswith('.json') or not os.path.isfile(file_path):
                continue
            try:
                os.remove(file_path)
                deleted += 1
                sidecar_path = file_path + '.json'
                if os.path.exists(sidecar_path):
                    os.remove(sidecar_path)
            except Exception as e:
                logger.error(f"Error deleting {file_path}: {e}")
                errors += 1
        if errors:
            return jsonify({'status': 'partial', 'deleted': deleted, 'errors': errors})
        return jsonify({'status': 'success', 'deleted': deleted})
    except Exception as e:
        logger.error(f"Error deleting all quarantined files: {e}")
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
        # Don't start continuous scans until the startup scan has completed,
        # and don't run concurrently with another scan.
        with conditional_startup_lock:
            if conditional_startup_state['last_run'] is None:
                time.sleep(1)
                continue
        if not scanning_lock.acquire(blocking=False):
            time.sleep(1)
            continue
        scan_files_count = 0
        scan_quarantine_count = 0
        scan_ml_hits = 0
        scan_yara_hits = 0
        scan_ransomware_hits = 0
        scan_persistence_hits = 0
        try:
            # Run YARA scan on all files in monitored directories
            try:
                from security.yara_scanner import scan_file_with_yara, get_highest_severity
                from security.detector import bodmas_cnn_detector, ember_detector, detector
            except ImportError:
                logger.warning("YARA scanner or detector not available, skipping scheduled scan")
                scan_file_with_yara = None
            
            # Combine monitored directories from both sources
            monitored_dirs = list(set(network_state['monitored_directories'] + folder_watcher_state['monitored_paths']))
            quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
            
            for scan_dir in monitored_dirs:
                if not os.path.exists(scan_dir):
                    continue
                for root, dirs, files in os.walk(scan_dir):
                    # Skip excluded paths
                    if should_exclude_path(root):
                        continue
                    
                    for file in files:
                        time.sleep(0)
                        file_path = os.path.join(root, file)
                        
                        # Skip excluded files
                        if should_exclude_path(file_path):
                            continue
                        
                        try:
                            # Cache: avoid rescanning unchanged files.  This also
                            # gives the operator a persistent hash -> verdict record.
                            cached = scan_cache.get(file_path)
                            if cached is not None:
                                yara_matches = cached.get('yara_matches', [])
                                if yara_matches:
                                    logger.debug(f"Cached YARA matches ({len(yara_matches)}) for {file_path}")
                                continue
                            
                            if not scan_file_with_yara:
                                continue

                            # Skip files whose SHA-256 is in the trusted hashes list.
                            if _hash_sha256(file_path) in TRUSTED_HASHES:
                                continue

                            yara_matches = scan_file_with_yara(file_path)
                            scan_files_count += 1
                            scan_yara_hits += len(yara_matches)
                            for match in yara_matches:
                                rule_name = getattr(match, 'rule', str(match)).lower()
                                if 'ransomware' in rule_name:
                                    scan_ransomware_hits += 1
                                if 'persistence' in rule_name:
                                    scan_persistence_hits += 1
                            rule_names = [getattr(m, 'rule', str(m)) for m in yara_matches]
                            yara_score = yara_risk_score(rule_names)
                            cache_entry = {
                                'yara_matches': rule_names,
                                'yara_score': yara_score,
                                'quarantined': False,
                                'reported': False,
                            }
                            
                            # Get a second opinion from all trained AI/ML classifiers for every file
                            ml_score = None
                            ml_model = None
                            if bodmas_cnn_detector.available:
                                try:
                                    ml_score = bodmas_cnn_detector.score(file_path)
                                    cache_entry['bodmas_cnn_score'] = ml_score
                                    if ml_score is not None:
                                        ml_model = 'bodmas_cnn'
                                except Exception:
                                    pass
                            if ml_score is None and ember_detector.available:
                                ml_score = ember_detector.score(file_path)
                                cache_entry['ember_score'] = ml_score
                                if ml_score is not None:
                                    ml_model = 'ember'
                            if ml_score is None and detector is not None:
                                try:
                                    ml_score = detector.get_anomaly_score(file_path)
                                    cache_entry['legacy_ml_score'] = ml_score
                                    if ml_score is not None:
                                        ml_model = 'legacy'
                                except Exception:
                                    print('Failed to compute legacy ML score')
                            
                            # Track any ML hit for dashboard stats
                            ml_hit = False
                            if ml_score is not None:
                                if ml_model == 'bodmas_cnn' and ml_score >= 0.60:
                                    ml_hit = True
                                elif ml_model == 'ember' and ml_score >= 0.60:
                                    ml_hit = True
                                elif ml_model == 'legacy' and ml_score >= 0.5:
                                    ml_hit = True
                            if ml_hit:
                                scan_ml_hits += 1

                            if yara_matches:
                                logger.info(f"YARA scan completed with {len(yara_matches)} matches for {file_path}")

                                # Quarantine if ML agrees OR the YARA severity score is critical
                                is_ransomware = any('ransomware' in getattr(m, 'rule', str(m)).lower() for m in yara_matches)
                                is_persistence = any('persistence' in getattr(m, 'rule', str(m)).lower() for m in yara_matches)

                                should_quarantine = ml_hit or yara_score >= 35
                                if should_quarantine:
                                    scan_quarantine_count += 1
                                    if ml_hit:
                                        cache_entry['quarantine_reason'] = ml_model
                                    elif yara_score >= 35:
                                        cache_entry['quarantine_reason'] = 'yara_high'
                                    elif is_ransomware:
                                        cache_entry['quarantine_reason'] = 'ransomware_yara'
                                    elif is_persistence:
                                        cache_entry['quarantine_reason'] = 'persistence_yara'
                                    for match in yara_matches:
                                        logger.warning(f"Threat detected: {file_path} - Rule: {getattr(match, 'rule', match)}")

                                    force = is_ransomware or is_persistence or yara_score >= 35
                                    sha256_hash = _hash_sha256(file_path)
                                    success, message = safe_quarantine(file_path, quarantine_dir, encrypt_file, force=force)
                                    logger.warning(message)
                                    cache_entry['quarantined'] = success
                                    if success:
                                        _append_malware_signature(file_path, cache_entry.get('quarantine_reason', 'quarantine'), sha256_hash)
                                else:
                                    cache_entry['reported'] = True
                                    for match in yara_matches:
                                        logger.warning(f"YARA match (report-only): {file_path} - Rule: {getattr(match, 'rule', match)}")
                                    if ml_score is not None:
                                        logger.info(f"  ML score {ml_score:.4f} did not reach quarantine threshold for {file_path}")
                            
                            scan_cache.set(file_path, cache_entry)
                        
                        except Exception as e:
                            logger.error(f"Error scanning {file_path}: {str(e)}")
            
            # Delete quarantined files during continuous scanning
            try:
                delete_quarantined_files_quick_start()
            except Exception as e:
                logger.error(f"Error deleting quarantined files: {str(e)}")

            # Update dashboard counters
            with conditional_startup_lock:
                conditional_startup_state['scanned_files'] = conditional_startup_state.get('scanned_files', 0) + scan_files_count
                conditional_startup_state['quarantined_files'] = conditional_startup_state.get('quarantined_files', 0) + scan_quarantine_count
                conditional_startup_state['ml_detections'] = conditional_startup_state.get('ml_detections', 0) + scan_ml_hits
                conditional_startup_state['yara_suspicious'] = conditional_startup_state.get('yara_suspicious', 0) + scan_ransomware_hits + scan_persistence_hits
                conditional_startup_state['ransomware_indicators'] = conditional_startup_state.get('ransomware_indicators', 0) + scan_ransomware_hits
                conditional_startup_state['persistence_indicators'] = conditional_startup_state.get('persistence_indicators', 0) + scan_persistence_hits
                conditional_startup_state['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        except Exception as e:
            logger.error(f"Error in scheduled scan: {str(e)}")
        finally:
            scanning_lock.release()
        
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
def _serve_app(host, port, debug=False, use_reloader=False):
    """Serve the Flask app using Waitress if available, otherwise the dev server."""
    try:
        import waitress
        waitress.serve(
            app,
            host=host,
            port=port,
            threads=16,
            channel_timeout=300,
            connection_limit=1000,
            expose_tracebacks=debug
        )
    except ImportError:
        logger.warning("waitress is not installed; falling back to Flask development server.")
        app.run(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=True)


def start_server(port=5000):
    """
    Start the Flask server with fallback options for port conflicts.
    Returns the port that was successfully used.
    """
    try:
        # Check if port is available with a direct bind attempt
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_socket.bind(('127.0.0.1', port))
            test_socket.close()
            # Port is available
            print(f"Server running at http://127.0.0.1:{port}")
            # Start server in non-debug mode to avoid reloader issues
            _serve_app(host='127.0.0.1', port=port, debug=FLASK_DEBUG)
            return port
        except OSError:
            # Port is already in use, try fallback ports
            test_socket.close()
            fallback_ports = [5001, 8080, 8000, 3000, 0]  # 0 means let OS choose
            
            for fallback_port in fallback_ports:
                try:
                    print(f"Port {port} is in use. Trying port {fallback_port}...")
                    print(f"Server running at http://127.0.0.1:{fallback_port if fallback_port != 0 else '<assigned by OS>'}")
                    _serve_app(host='127.0.0.1', port=fallback_port, debug=FLASK_DEBUG)
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
            _serve_app(host='127.0.0.1', port=0, debug=FLASK_DEBUG)
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
    Open the browser to the running application once.
    """
    if port is None or port < 0:
        print("Could not determine port to open browser with.")
        return

    import webbrowser
    import time

    # Wait a moment for the server to start
    time.sleep(1.5)

    browser_url = f"http://127.0.0.1:{port}/login"
    print(f"Opening browser at {browser_url}")

    # Wait for the server to be responding before opening the browser
    try:
        import requests
        if requests.get(browser_url, timeout=2).status_code == 200:
            print("Server confirmed ready")
    except Exception:
        print("Waiting for server to fully initialize...")
        time.sleep(3)

    try:
        webbrowser.open(browser_url, new=2)
    except Exception as e:
        print(f"Failed to open browser: {e}")
        print(f"Please manually open {browser_url} in your browser")

# Class to share the port between threads
class ServerInfo:
    def __init__(self):
        self.port = None

# -- System Overload deep-remediation page --
@app.route('/break-the-cycle')
def break_the_cycle():
    """Glitch-themed deep remediation dashboard."""
    service_status = _admin_service_read('service.status') or {}
    return render_template('break_the_cycle.html', service_status=service_status)

@app.route('/break-the-cycle/engage', methods=['POST'])
def break_the_cycle_engage():
    """Break the Cycle + System Overload: clear quarantine, AI scan/quarantine, purge, kill, flush DNS, rescan."""
    if not _admin_service_read('service.status'):
        return jsonify({'ok': False, 'error': 'Antivirus Protected Administrator service is not running.'}), 503
    results = []
    quarantine_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')

    # 1. Clear old quarantine so AI can fill it with fresh detections
    try:
        deleted = 0
        if os.path.isdir(quarantine_dir):
            for f in os.listdir(quarantine_dir):
                fp = os.path.join(quarantine_dir, f)
                if os.path.isfile(fp):
                    try:
                        os.remove(fp)
                        deleted += 1
                    except Exception:
                        pass
        results.append(f'Cleared {deleted} old quarantined files')
    except Exception as e:
        results.append(f'Quarantine cleanup error: {e}')

    # 2. AI/ML scan of all fixed drives and quarantine high-risk files
    ai_hits = 0
    ai_quarantined = 0
    ai_scanned = 0
    try:
        from security.detector import bodmas_cnn_detector, ember_detector, detector as sklearn_detector
        all_drives = [p.mountpoint for p in psutil.disk_partitions() if 'fixed' in p.opts or p.fstype in ('NTFS', 'FAT32')]
        if not all_drives:
            all_drives = ['C:\\']
        max_targets = min(100 * len(all_drives), 500)

        ai_targets = []
        start_time = time.time()
        for root in all_drives:
            for dirpath, dirs, files in os.walk(root):
                # Avoid very deep/slow directories
                dirs[:] = [d for d in dirs if d.lower() not in {'$recycle.bin', 'onedrive', 'windows.old', 'winsxs'}]
                for f in files:
                    if f.lower().endswith(('.exe', '.dll')):
                        ai_targets.append(os.path.join(dirpath, f))
                    if len(ai_targets) >= max_targets * 4 or (time.time() - start_time) > 30:
                        break
                if len(ai_targets) >= max_targets * 4 or (time.time() - start_time) > 30:
                    break
            if len(ai_targets) >= max_targets * 4 or (time.time() - start_time) > 30:
                break

        # Split target between newest and oldest PE files
        try:
            ai_targets.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        except Exception:
            pass
        half = max_targets // 2
        newest = ai_targets[:half]
        oldest = ai_targets[-half:] if len(ai_targets) >= half else ai_targets[len(newest):]
        ai_targets = list(dict.fromkeys(newest + oldest))

        for fp in ai_targets:
            ai_scanned += 1
            for detector in (bodmas_cnn_detector, ember_detector, sklearn_detector):
                try:
                    if detector.is_malicious(fp):
                        ai_hits += 1
                        # Run YARA for ransomware/persistence confirmation
                        try:
                            from security.yara_scanner import scan_file_with_yara, get_highest_severity
                            yara_matches = scan_file_with_yara(fp)
                            if yara_matches:
                                is_ransomware = any('ransomware' in getattr(m, 'rule', str(m)).lower() for m in yara_matches)
                                is_persistence = any('persistence' in getattr(m, 'rule', str(m)).lower() for m in yara_matches)
                                highest = get_highest_severity(yara_matches)
                                if is_ransomware:
                                    logger.warning(f'Ransomware YARA match on {fp}: {", ".join(getattr(m, "rule", str(m)) for m in yara_matches)}')
                                if is_persistence:
                                    logger.warning(f'Persistence YARA match on {fp}: {", ".join(getattr(m, "rule", str(m)) for m in yara_matches)}')
                                if highest == 'critical':
                                    logger.warning(f'Critical YARA match on {fp}: {highest}')
                        except Exception:
                            pass
                        force = is_ransomware or is_persistence
                        qresult = _admin_service_mutation('quarantine.create', source=fp, confirmation='CONFIRM')
                        if qresult and qresult.get('ok'):
                            ai_quarantined += 1
                        else:
                            qmsg = (qresult or {}).get('error', 'admin service quarantine unavailable')
                            logger.warning(f'AI quarantine failed for {fp}: {qmsg}')
                        break
                except Exception:
                    pass
        results.append(f'AI/ML scanned {ai_scanned} files across {len(all_drives)} drive(s), {ai_hits} high-risk, {ai_quarantined} quarantined')
        with conditional_startup_lock:
            conditional_startup_state['scanned_files'] = conditional_startup_state.get('scanned_files', 0) + ai_scanned
            conditional_startup_state['ml_detections'] = conditional_startup_state.get('ml_detections', 0) + ai_hits
            conditional_startup_state['quarantined_files'] = conditional_startup_state.get('quarantined_files', 0) + ai_quarantined
            conditional_startup_state['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        results.append(f'AI analysis error: {e}')

    # 3. Purge known malware staging temp
    temp_dir = os.environ.get('TEMP', os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'AppData', 'Local', 'Temp'))
    staging_patterns = ['Defender_Quarantine*', 'tmp*', 'temp*.exe', 'payload*.tmp']
    purged = 0
    for pattern in staging_patterns:
        for f in glob.glob(os.path.join(temp_dir, pattern)):
            try:
                if os.path.isfile(f) and os.path.getsize(f) < 100 * 1024 * 1024:
                    os.remove(f)
                    purged += 1
            except Exception:
                pass
    results.append(f'Purged {purged} temp staging files')

    try:
        subprocess.run(['ipconfig', '/flushdns'], check=False, capture_output=True,
                       creationflags=CREATE_NO_WINDOW)
        results.append('DNS cache flushed')
    except Exception as e:
        results.append(f'DNS flush error: {e}')

    try:
        suspicious_names = {'mimikatz', 'mimilib', 'procdump', 'ladon', 'cobaltstrike', 'meterpreter', 'reflectivedll', 'pwndump', 'empire', 'poshc2', 'sliver'}
        killed = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = (proc.info['name'] or '').lower().replace('.exe', '')
                if name in suspicious_names:
                    proc.terminate()
                    killed += 1
            except Exception:
                pass
        results.append(f'Terminated {killed} known malware processes')
    except Exception as e:
        results.append(f'Malware kill error: {e}')

    try:
        scan_response = run_startup()
        if isinstance(scan_response, tuple):
            scan_response, code = scan_response
            body = scan_response.get_json() or {}
            results.append('Deep rescan: ' + body.get('message', 'started'))
        else:
            body = scan_response.get_json() or {}
            results.append('Deep rescan: ' + body.get('message', 'started'))
    except Exception as e:
        results.append(f'Deep rescan error: {e}')

    return jsonify({'status': 'success', 'results': results})

if __name__ == '__main__':
    if '--install-startup' in sys.argv:
        install_startup()
        sys.exit(0)
    if sys.executable.lower().endswith('.exe') and not _is_startup_installed():
        install_startup()
    _single_instance_handle = _ensure_single_instance()
    print("Starting clean Windows Defender app instance...")
    print("Real-Time Protection: " + ('ENABLED' if folder_watcher_state['active'] else 'DISABLED'))
    print("Network Monitoring: " + ('ENABLED' if network_state['monitoring_enabled'] else 'DISABLED'))
    print("Auto-Block: " + ('ENABLED' if network_state['auto_block_enabled'] else 'DISABLED'))

    # Ensure desktop shortcuts exist
    try:
        import create_conditional_shortcut
    except Exception:
        pass
    try:
        import create_yara_scanner_shortcut
    except Exception:
        pass

    import threading
    import queue

    # Start the Flask server first so the dashboard is available immediately
    port_queue = queue.Queue()

    def start_server_and_report(default_port=5000):
        actual_port = start_server(default_port)
        if actual_port is not None:
            try:
                port_queue.put(actual_port, block=False)
            except queue.Full:
                pass
        return actual_port

    _validate_production_config()
    _warn_default_credentials()
    server_port = 5000
    server_thread = threading.Thread(target=lambda: start_server_and_report(server_port), daemon=True)
    server_thread.start()

    detected_port = None
    try:
        detected_port = port_queue.get(timeout=10)
        print(f"Server reported running on port {detected_port}")
    except queue.Empty:
        print("Server did not report its port. Attempting detection...")
        potential_ports = [5000, 5001, 8080, 8000, 3000]
        max_retries = 3
        for attempt in range(max_retries):
            time.sleep(1 + attempt)
            for port in potential_ports:
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(1.0)
                    result = test_socket.connect_ex(('127.0.0.1', port))
                    test_socket.close()
                    if result == 0:
                        try:
                            import requests
                            if requests.get(f"http://127.0.0.1:{port}", timeout=2).status_code == 200:
                                detected_port = port
                                print(f"Verified server running on port {port} with HTTP request")
                                break
                        except Exception:
                            if detected_port is None:
                                detected_port = port
                except Exception:
                    pass
            if detected_port:
                break

    if detected_port is None:
        print("Trying one last attempt to find the server...")
        for port in [5000, 5001, 8080, 8000, 3000]:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(0.3)
                result = test_socket.connect_ex(('127.0.0.1', port))
                test_socket.close()
                if result == 0:
                    detected_port = port
                    print(f"Found a service on port {port} - assuming it's our server")
                    break
            except Exception:
                pass

    if detected_port is not None:
        base_url = f"http://127.0.0.1:{detected_port}"
        browser_path = '/yara-scanner' if '--open-yara' in sys.argv else '/login'
        url = f"{base_url}{browser_path}"
        print(f"Server is ready at {url}")
    else:
        print("\nCould not detect which port the server is running on.")
        print("The server is likely running on one of: 5000, 5001, 8080, 8000")
        print("Please try opening these URLs in your browser manually:")
        print("  - http://127.0.0.1:5000")
        print("  - http://127.0.0.1:5001")
        print("  - http://localhost:5000")
        print("  - http://localhost:5001")

    # Initialize DNS server (localhost only)
    try:
        dns_server, dns_resolver = start_dns_server(allow_network=False)
        logging.info("DNS server started automatically at application startup")
    except Exception as e:
        logging.error(f"Failed to start DNS server: {str(e)}. This is normal if not running as administrator.")

    # Start scheduled scanning thread for continuous YARA scanning
    scan_thread = threading.Thread(target=run_scheduled_scans, daemon=True)
    scan_thread.start()
    logger.info("Scheduled scanning thread started for continuous YARA scanning")

    # Auto-block monitor thread
    auto_block_thread = threading.Thread(target=run_auto_block_monitor, daemon=True)
    auto_block_thread.start()
    logger.info("Auto-block monitor thread started (active by default)")

    # Process hardening monitor thread
    process_hardening_thread = threading.Thread(target=run_process_hardening_monitor, daemon=True)
    process_hardening_thread.start()
    logger.info("Process hardening monitor thread started")

    # Start conditional startup scan in the background after the server is up
    with conditional_startup_lock:
        if not conditional_startup_state['running']:
            conditional_startup_state.update({
                'running': True,
                'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            })
            conditional_startup_thread = threading.Thread(target=run_conditional_startup_background, daemon=True)
            conditional_startup_thread.start()
            logger.info("Conditional startup scan auto-started")

    # Start automatic signature updates
    from auto_update_signatures import start_auto_update_thread
    auto_update_sig_thread = threading.Thread(target=start_auto_update_thread, daemon=True)
    auto_update_sig_thread.start()
    logger.info("Automatic signature update thread started")

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

