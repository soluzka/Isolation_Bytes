"""Standalone antivirus agent — runs on any Windows PC and reports to the cloud server.

Usage:
    python standalone_agent.py
    python standalone_agent.py --server https://isolation-bytes.com --key YOUR_API_KEY

This script:
- Registers the PC with the cloud server
- Sends heartbeats every 30 seconds with live system stats
- Scans Downloads/Desktop/Temp folders every 5 minutes using YARA rules
- Reports any threats found to the cloud server
- Runs silently in the background

No installation required — just Python + pip install psutil requests
"""
import argparse
import datetime
import hashlib
import ipaddress
import os
import platform
import re
import shutil
import shlex
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse, unquote
import threading
import json

# EARLIEST WINDOWS AGENT BOOTSTRAP:
# Create the LocalAppData runtime JSON state before importing optional scanner
# dependencies. This is intentionally self-contained so a packaged EXE cannot
# skip state creation because psutil, requests, ML, YARA, or another scanner
# module failed to import.
def _bootstrap_runtime_json_files():
    base = os.environ.get('LOCALAPPDATA') or os.path.join(
        os.path.expanduser('~'), 'AppData', 'Local'
    )
    runtime_dir = os.path.abspath(os.path.join(base, 'IsolationBytes'))
    os.makedirs(runtime_dir, exist_ok=True)
    defaults = {
        'scan_state.json': {
            'scan_id': '', 'status': 'idle', 'started_at': '',
            'updated_at': None, 'complete': False, 'files_scanned': 0,
            'quarantined_count': 0, 'threats_blocked': 0, 'findings': 0,
        },
        'conditional_startup_state.json': {
            'running': False, 'run_id': '', 'findings': [],
            'started_at': None, 'last_updated': None, 'scanned_files': 0,
            'quarantined_files': 0, 'errors': 0, 'process_events': 0,
            'ml_detections': 0, 'ransomware_indicators': 0,
            'persistence_indicators': 0, 'yara_suspicious': 0,
        },
        'scanner_results.json': {
            'scanner_counters': {'scanned_files': 0, 'quarantined_files': 0,
                                 'errors': 0, 'process_events': 0,
                                 'ml_detections': 0, 'ransomware_indicators': 0,
                                 'persistence_indicators': 0, 'yara_suspicious': 0},
            'scanner_results': {'errors': [], 'process_events': [],
                                'ml_detections': [], 'ransomware_indicators': [],
                                'persistence_indicators': {},
                                'yara_suspicious': [], 'quarantined_files': []},
        },
        'blocked_files.json': {},
        'scheduled_scan_state.json': {'status': 'idle', 'scanned_files': 0},
        'quarantine_log.json': [],
        'scan_cache.json': {},
    }
    for filename, payload in defaults.items():
        path = os.path.join(runtime_dir, filename)
        if not os.path.isfile(path):
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
    missing = [name for name in defaults if not os.path.isfile(os.path.join(runtime_dir, name))]
    if missing:
        raise RuntimeError(
            f'Isolation Bytes runtime JSON bootstrap failed in {runtime_dir}: {missing}'
        )
    return runtime_dir

_RUNTIME_BOOTSTRAP_DIR = _bootstrap_runtime_json_files()

try:
    import psutil
except ImportError:
    import subprocess as _sp
    _sp_run = getattr(_sp, 'run')
    _sp_run([sys.executable, '-m', 'pip', 'install', 'psutil'],
            capture_output=True, timeout=60,
            creationflags=getattr(_sp, 'CREATE_NO_WINDOW', 0))
    import psutil

try:
    import requests
except ImportError:
    import subprocess as _sp
    _sp_run = getattr(_sp, 'run')
    _sp_run([sys.executable, '-m', 'pip', 'install', 'requests'],
            capture_output=True, timeout=60,
            creationflags=getattr(_sp, 'CREATE_NO_WINDOW', 0))
    import requests

# Import ML analyzer for enhanced threat analysis
try:
    from security.ml_yara_analyzer import get_ml_analyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from utils.subprocess_safe import safe_run, safe_popen, safe_check_output, safe_check_call, safe_list2cmdline
from runtime_paths import runtime_path, ensure_runtime_state_files

DEFAULT_SERVER = "https://isolation-bytes.com"
DEFAULT_API_KEY = os.environ.get('CLOUD_API_KEY', '')
HEARTBEAT_INTERVAL = 10      # seconds between heartbeats
PAIRING_URL_PATH = '/agent/pair'


def _validate_server_url(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError('Invalid server URL')
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Server URL must be http or https')
    if not parsed.hostname or re.search(r'[^A-Za-z0-9._-]', parsed.hostname):
        raise ValueError('Invalid server hostname')
    # Server URLs are base API endpoints: no shell metacharacters, spaces,
    # or query/fragment data that could break command-line construction.
    if re.search(r'[\s&|<>^%"\'\\]', url):
        raise ValueError('Server URL contains disallowed characters')
    return url


def _validate_api_key(key):
    if not isinstance(key, str):
        raise ValueError('API key must be a string')
    if key:
        key = key.strip().strip('"').strip("'")
        if re.search(r'[\s&|<>^%"\'\\]', key):
            raise ValueError('API key contains disallowed characters')
    return key


def _read_api_key_file(path):
    """Read an API key from a local file without placing it on a command line."""
    if not path:
        return ''
    with open(os.path.expandvars(os.path.expanduser(path)), 'r', encoding='utf-8') as handle:
        return _validate_api_key(handle.read().strip())


def _default_credential_file(device_id):
    base = os.environ.get('LOCALAPPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
    agent_dir = os.path.join(base, 'IsolationBytes')
    shared_token = os.path.join(agent_dir, 'device.token')
    if os.path.exists(shared_token):
        return shared_token
    return os.path.join(agent_dir, f'{device_id}.token')


def _default_api_key_file():
    base = os.environ.get('LOCALAPPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
    return os.path.join(base, 'IsolationBytes', 'cloud_api_key.txt')


def _ensure_api_key_file():
    """Create the shared key-file location so the EXE can be placed anywhere."""
    path = _default_api_key_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8'):
                pass
    except OSError as exc:
        _startup_log(f'[ERROR] Could not create API key file {path}: {exc}')
    return path


def _read_device_credential(path):
    if not path:
        return ''
    try:
        with open(os.path.expandvars(os.path.expanduser(path)), 'r', encoding='utf-8') as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return ''


def _write_device_credential(path, value):
    target = os.path.expandvars(os.path.expanduser(path))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'w', encoding='utf-8') as handle:
        handle.write(value)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def _pair_code_from_uri(value):
    """Extract only a valid pairing code from an isolationbytes:// URI."""
    if not isinstance(value, str) or not value.lower().startswith('isolationbytes://'):
        return ''
    parsed = urlparse(value)
    if parsed.scheme.lower() != 'isolationbytes' or parsed.netloc.lower() != 'pair':
        return ''
    code = unquote(parsed.path.lstrip('/')).strip().upper()
    return code if re.fullmatch(r'[A-Z0-9]{8,12}', code) else ''


def _register_windows_uri_handler():
    """Allow the dashboard to launch a moved EXE with its pairing URI."""
    if os.name != 'nt':
        return
    try:
        import winreg
        command = f'"{sys.executable}" "%1"'
        root = winreg.HKEY_CURRENT_USER
        with winreg.CreateKey(root, r'Software\Classes\isolationbytes') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'URL:Isolation Bytes Pairing')
            winreg.SetValueEx(key, 'URL Protocol', 0, winreg.REG_SZ, '')
        with winreg.CreateKey(root, r'Software\Classes\isolationbytes\shell\open\command') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, command)
    except (OSError, ImportError):
        _startup_log('[WARN] Could not register isolationbytes:// URI handler')


def _validate_device_id(device_id):
    if not isinstance(device_id, str):
        raise ValueError('device_id must be a string')
    if device_id and not re.fullmatch(r'[A-Za-z0-9_:-]+', device_id):
        raise ValueError('device_id contains invalid characters')
    return device_id


def _resolve_local_path(filepath):
    """Return an absolute, null-free local path for file operations."""
    if not isinstance(filepath, str):
        raise ValueError('filepath must be a string')
    if '\x00' in filepath:
        raise ValueError('filepath contains null bytes')
    return os.path.abspath(filepath)


def _is_protected_path(filepath):
    """Return True if the path is a system directory that must never be
    modified by automatic scans or remediation."""
    system_root = os.environ.get('SystemRoot', r'C:\Windows').lower()
    protected = [
        system_root,
        r'C:\Program Files',
        r'C:\Program Files (x86)',
        r'C:\ProgramData',
        r'C:\$Recycle.Bin',
        r'C:\Recovery',
        r'C:\Windows.old',
    ]
    path = os.path.abspath(filepath).lower()
    for prefix in protected:
        if path == prefix or path.startswith(prefix + '\\'):
            return True
    return False
SCAN_INTERVAL = 600        # seconds between scans
MAX_FILES_PER_SCAN = float('inf')  # no artificial file-count ceiling
MAX_SCAN_CYCLE_SECONDS = float('inf')  # no artificial wall-clock ceiling
MAX_FILE_SIZE = float('inf')
AGENT_VERSION = "1.8.953.0"
UPDATE_CHECK_INTERVAL = 3600  # check for updates every hour
QUARANTINE_DIR = os.path.join(
    os.environ.get(
        'ANTIVIRUS_RUNTIME_DIR',
        os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'IsolationBytes')
    ),
    'Quarantine'
)
BLOCKED_FILES_REGISTRY = os.path.join(
    os.path.dirname(QUARANTINE_DIR),
    'blocked_files.json'
)


def _startup_log(message):
    """Keep startup failures visible when the frozen agent has no console."""
    try:
        log_dir = os.path.join(
            os.environ.get('LOCALAPPDATA', os.path.join(os.path.expanduser('~'), 'AppData', 'Local')),
            'IsolationBytes',
        )
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, 'agent.log'), 'a', encoding='utf-8') as handle:
            handle.write(f'{datetime.datetime.now().isoformat(timespec="seconds")} {message}\n')
    except OSError:
        pass


class StandaloneAgent:
    _SCAN_STATE_PATH = runtime_path("scan_state.json")

    def _get_yara_scan_state(self):
        """Return and persist the authoritative current-scan state.

        This state is deliberately reset at the beginning of every explicit
        full scan. It lives in LocalAppData so it survives EXE replacement
        without becoming a stale source of scan verdicts.
        """
        state = {
            "scan_id": self._scan_id,
            "status": self._scan_status,
            "started_at": self._scan_started_at,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "complete": self._scan_status == "complete",
            "files_scanned": int(self._files_scanned),
            "quarantined_count": int(self._quarantined_count),
            "threats_blocked": int(self._threats_blocked),
            "findings": int(self._total_findings),
            "ransomware_indicators": int(self._total_ransomware),
            "persistence_indicators": int(self._total_persistence),
            "yara_suspicious": int(self._total_yara),
            "ml_suspicious": int(self._total_ml),
            "scan_dirs": list(self._scan_dirs),
            "next_scan_starts_at_beginning": True,
        }
        try:
            path = self._SCAN_STATE_PATH
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except (OSError, TypeError, ValueError) as exc:
            print(f"[SCAN] Could not persist scan state: {exc}")
        return state

    def _publish_all_runtime_json(self):
        """Publish the current scan generation to every canonical runtime JSON."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scan_state = self._get_yara_scan_state()
        conditional = {
            "running": self._scan_status not in ("idle", "complete"),
            "run_id": self._scan_id,
            "findings": int(self._total_findings),
            "started_at": self._scan_started_at,
            "last_updated": now,
            "last_run": None if self._scan_status not in ("idle", "complete") else now,
            "duration": None,
            "scanned_files": int(self._files_scanned),
            "quarantined_files": int(self._quarantined_count),
            "errors": 0,
            "process_events": 0,
            "ml_detections": int(self._total_ml),
            "ransomware_indicators": int(self._total_ransomware),
            "persistence_indicators": int(self._total_persistence),
            "yara_suspicious": int(self._total_yara),
            "blocked_threats": int(self._threats_blocked),
            "scan_phase": "scanning" if self._scan_status not in ("idle", "complete") else self._scan_status,
            "scanner_counters": {
                "scanned_files": int(self._files_scanned),
                "quarantined_files": int(self._quarantined_count),
                "errors": 0,
                "process_events": 0,
                "ml_detections": int(self._total_ml),
                "ransomware_indicators": int(self._total_ransomware),
                "persistence_indicators": int(self._total_persistence),
                "yara_suspicious": int(self._total_yara),
            },
            "scanner_results": {
                "errors": [],
                "process_events": [],
                "ml_detections": [],
                "ransomware_indicators": [],
                "persistence_indicators": {},
                "yara_suspicious": [],
                "quarantined_files": [],
            },
        }
        targets = {
            runtime_path("scan_state.json"): scan_state,
            runtime_path("conditional_startup_state.json"): conditional,
            runtime_path("scanner_results.json"): conditional,
        }
        for path, payload in targets.items():
            tmp = path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                os.replace(tmp, path)
            except (OSError, TypeError, ValueError) as exc:
                _startup_log(f"[ERROR] Could not publish runtime JSON {path}: {exc}")

    def _reset_scan_state(self):
        """Start one persistent scan generation and publish it immediately."""
        self._scan_id = hashlib.sha256(
            f'{self.device_id}:{self._scan_started_at}:{time.time_ns()}'.encode()
        ).hexdigest()[:24]
        self._files_scanned = 0
        self._threats_blocked = 0
        self._quarantined_count = 0
        self._total_findings = 0
        self._total_ransomware = 0
        self._total_persistence = 0
        self._total_yara = 0
        self._total_ml = 0
        self._scan_progress_reported = 0
        # scan_state.json is written first; then publish the same generation
        # to the other runtime JSON documents.
        self._get_yara_scan_state()
        self._publish_all_runtime_json()

    def _begin_scan_generation(self):
        """Create the active scan state before any scan traversal begins."""
        self._scan_status = 'scanning'
        self._scan_started_at = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        self._reset_scan_state()
        self._publish_all_runtime_json()

    def __init__(self, server_url, api_key='', device_id=None, pair_code=None,
                 credential_file=None):
        self.server_url = _validate_server_url(server_url).rstrip('/')
        self.api_key = _validate_api_key(api_key)
        self.device_id = _validate_device_id(device_id or f'WIN-{socket.gethostname().upper()[:12]}')
        self.pair_code = (pair_code or '').strip().upper()
        self.credential_file = credential_file or _default_credential_file(self.device_id)
        self.device_token = _read_device_credential(self.credential_file)
        self.hostname = socket.gethostname()
        self._running = False
        self._registered = False
        self._files_scanned = 0
        self._threats_blocked = 0
        self._quarantined_count = 0
        # Cumulative finding counters (survive across scan cycles)
        self._total_findings = 0
        self._total_ransomware = 0
        self._total_persistence = 0
        self._total_yara = 0
        self._total_ml = 0
        self._last_report_ok = False
        self._last_report_error = ''
        self._scan_status = 'idle'
        self._scan_started_at = ''
        self._scan_id = ''
        self._scan_progress_reported = 0
        # Initialize the LocalAppData runtime state immediately. The agent
        # must create its JSON state before registration or the first scan so
        # a fresh install never appears to be running with no local state.
        try:
            ensure_runtime_state_files()
            runtime_path()
            self._get_yara_scan_state()
            self._publish_all_runtime_json()
        except Exception as exc:
            _startup_log(f'[ERROR] Could not initialize scan state: {exc}')
        self._continuous_scan_requested = False
        self._continuous_scan_thread = None
        self._scan_lock = threading.Lock()
        self._last_quarantine_error = ''
        self._quarantine_ready = False
        self._cached_network_devices = []
        self._net_scan_thread = None
        self._headers = {'Content-Type': 'application/json'}
        if self.device_token:
            self._headers['X-Device-Token'] = self.device_token
        elif self.api_key:
            self._headers['X-Api-Key'] = self.api_key
        # Scan the ENTIRE PC, not just 3 folders.  Use folder_watcher's
        # discover_all_drives_and_important_folders() which finds every
        # drive (A-Z on Windows), every user profile, Program Files,
        # AppData, system directories, and mounted media on macOS/Linux.
        self._scan_dirs = self._discover_full_scan_dirs()
        # Verify the quarantine destination at startup so a locked/unwritable
        # destination is reported explicitly instead of appearing as a blank
        # "—" in the findings table.
        self._quarantine_ready = self._prepare_quarantine_dir()
        # Quarantine is a per-scan result counter. Existing quarantine contents
        # must never appear as findings in a newly started scan.
        # Load persisted blocked-files registry so unblock works after restart
        self._blocked_files = self._load_blocked_registry()

    def _pair(self):
        if not self.pair_code:
            return bool(self.device_token or self.api_key)
        try:
            response = requests.post(
                f'{self.server_url}{PAIRING_URL_PATH}',
                json={'pair_code': self.pair_code, 'device_id': self.device_id, 'hostname': self.hostname},
                headers={'Content-Type': 'application/json'},
                verify=True, timeout=10)
            if response.status_code != 200:
                print(f"[ERROR] Pairing failed: HTTP {response.status_code} {response.text}")
                return False
            token = response.json().get('device_token', '')
            if not isinstance(token, str) or len(token) < 32:
                print("[ERROR] Pairing response did not contain a valid device credential")
                return False
            _write_device_credential(self.credential_file, token)
            self.device_token = token
            self._headers.pop('X-Api-Key', None)
            self._headers['X-Device-Token'] = token
            self.pair_code = ''
            print(f"[OK] Device paired. Credential stored at {self.credential_file}")
            return True
        except Exception as exc:
            print(f"[ERROR] Pairing failed: {exc}")
            return False

    def _prepare_quarantine_dir(self):
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            probe = os.path.join(
                QUARANTINE_DIR,
                f".isolationbytes_write_test_{os.getpid()}_{time.time_ns()}"
            )
            with open(probe, 'wb') as handle:
                handle.write(b'')
            os.remove(probe)
            return True
        except Exception as exc:
            self._last_quarantine_error = (
                f"Quarantine destination unavailable: {QUARANTINE_DIR} | {exc}"
            )
            print(f"[QUARANTINE] {self._last_quarantine_error}")
            return False

    def _count_existing_quarantined(self):
        """Count files already in the quarantine directory at startup."""
        try:
            if not os.path.isdir(QUARANTINE_DIR):
                return 0
            count = 0
            for entry in os.scandir(QUARANTINE_DIR):
                if entry.is_file() and entry.name.endswith('.enc'):
                    count += 1
            return count
        except Exception:
            return 0

    def _load_blocked_registry(self):
        """Load the persisted blocked file paths from disk.
        Supports both old list format and new dict format with threat types."""
        try:
            if os.path.isfile(BLOCKED_FILES_REGISTRY):
                with open(BLOCKED_FILES_REGISTRY, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    # Upgrade old list format to dict with default threat type
                    return {p: 'yara_match' for p in data}
        except Exception:
            pass
        return {}

    def _save_blocked_registry(self):
        """Persist the blocked file paths list to disk."""
        try:
            reg_dir = os.path.dirname(BLOCKED_FILES_REGISTRY)
            if reg_dir and not os.path.isdir(reg_dir):
                os.makedirs(reg_dir, exist_ok=True)
            with open(BLOCKED_FILES_REGISTRY, 'w', encoding='utf-8') as fh:
                json.dump(self._blocked_files, fh, indent=2)
        except Exception:
            pass

    def _register_blocked_file(self, filepath, threat_type='yara_match'):
        """Track a blocked file in the persistent registry with its threat type."""
        if filepath:
            if isinstance(self._blocked_files, list):
                # Upgrade old list format to dict
                self._blocked_files = {p: 'yara_match' for p in self._blocked_files}
            if filepath not in self._blocked_files:
                self._blocked_files[filepath] = threat_type
                self._save_blocked_registry()
            elif threat_type != 'yara_match':
                self._blocked_files[filepath] = threat_type
                self._save_blocked_registry()

    def _unregister_blocked_file(self, filepath):
        """Remove a file from the blocked registry after unblocking."""
        if isinstance(self._blocked_files, dict):
            if filepath in self._blocked_files:
                del self._blocked_files[filepath]
                self._save_blocked_registry()
        elif filepath in self._blocked_files:
            self._blocked_files.remove(filepath)
            self._save_blocked_registry()

    def _discover_full_scan_dirs(self):
        """Discover all directories to scan across the entire PC.

        This is inlined directly (not imported from folder_watcher) so it
        works even when packaged as a frozen EXE where imports can fail.
        """
        import string as _string
        discovered = []
        seen = set()

        def add(path):
            if not path:
                return
            try:
                if os.path.exists(path) and os.path.isdir(path) and path not in seen:
                    seen.add(path)
                    discovered.append(path)
            except (OSError, ValueError):
                pass

        system = platform.system()
        user_home = os.path.expanduser('~')

        if system == 'Windows':
            # Enumerate ALL drive letters A-Z using Windows API + os.path.exists
            win_drives = set()
            try:
                import ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for i in range(26):
                    if bitmask & (1 << i):
                        win_drives.add(f'{chr(ord("A") + i)}:\\')
            except Exception:
                pass
            for letter in _string.ascii_uppercase:
                drive = f'{letter}:\\'
                if os.path.exists(drive):
                    win_drives.add(drive)

            for drive in sorted(win_drives):
                add(drive)
                # Add common subdirectories on every drive
                for sub in ['Windows', 'Windows\\System32', 'Windows\\Temp',
                            'Program Files', 'Program Files (x86)', 'ProgramData',
                            'Users', 'Users\\Public', 'Users\\Public\\Downloads',
                            'Users\\Public\\Documents', 'Users\\Public\\Desktop',
                            '$Recycle.Bin', 'Temp', 'Downloads', 'Tools', 'Backup',
                            'Scripts', 'Logs', 'Apps', 'Data', 'Games',
                            'Steam', 'SteamLibrary', 'steamapps',
                            'Epic Games', 'Origin Games', 'GOG Games', 'Battle.net']:
                    add(os.path.join(drive, sub))
                # Enumerate ALL top-level directories on the drive
                try:
                    for entry in os.scandir(drive):
                        if entry.is_dir():
                            add(entry.path)
                except (PermissionError, OSError):
                    pass

            # All user profiles
            users_dir = os.path.join(os.environ.get('SystemDrive', 'C:'), 'Users')
            if os.path.exists(users_dir):
                try:
                    for uname in os.listdir(users_dir):
                        upath = os.path.join(users_dir, uname)
                        if os.path.isdir(upath):
                            add(upath)
                            for sub in ['Downloads', 'Documents', 'Desktop', 'Pictures',
                                        'Videos', 'Music', 'AppData', 'AppData\\Local',
                                        'AppData\\Roaming', 'AppData\\Local\\Temp',
                                        'Contacts', 'Favorites', 'Links', 'Saved Games',
                                        'Searches', 'OneDrive']:
                                add(os.path.join(upath, sub))
                except (PermissionError, OSError):
                    pass

        elif system == 'Darwin':
            add('/')
            try:
                for entry in os.scandir('/'):
                    if entry.is_dir():
                        add(entry.path)
            except (PermissionError, OSError):
                pass
            if os.path.exists('/Volumes'):
                try:
                    for vol in os.listdir('/Volumes'):
                        vp = os.path.join('/Volumes', vol)
                        add(vp)
                        try:
                            for entry in os.scandir(vp):
                                if entry.is_dir():
                                    add(entry.path)
                        except (PermissionError, OSError):
                            pass
                except (PermissionError, OSError):
                    pass
            if os.path.exists('/Users'):
                try:
                    for ud in os.listdir('/Users'):
                        up = os.path.join('/Users', ud)
                        if os.path.isdir(up) and ud not in ('Shared', '.'):
                            add(up)
                            for sub in ['Downloads', 'Documents', 'Desktop', 'Pictures',
                                        'Videos', 'Movies', 'Music', 'Library']:
                                add(os.path.join(up, sub))
                except (PermissionError, OSError):
                    pass

        else:  # Linux / ChromeOS
            add('/')
            try:
                for entry in os.scandir('/'):
                    if entry.is_dir():
                        add(entry.path)
            except (PermissionError, OSError):
                pass
            for md in ['/home', '/media', '/mnt', '/run/media']:
                if os.path.exists(md):
                    try:
                        for ud in os.listdir(md):
                            up = os.path.join(md, ud)
                            if os.path.isdir(up):
                                add(up)
                                try:
                                    for sd in os.listdir(up):
                                        sp = os.path.join(up, sd)
                                        if os.path.isdir(sp):
                                            add(sp)
                                except (PermissionError, OSError):
                                    pass
                    except (PermissionError, OSError):
                        pass
            try:
                with open('/proc/mounts', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            add(parts[1])
            except Exception:
                pass

        # Common user folders on all platforms
        for sub in ['Downloads', 'Documents', 'Desktop', 'Pictures', 'Videos', 'Music']:
            add(os.path.join(user_home, sub))

        if not discovered:
            # Last resort fallback
            discovered = [
                os.path.join(user_home, 'Downloads'),
                os.path.join(user_home, 'Desktop'),
                os.path.join(os.environ.get('TEMP', '/tmp')),
            ]

        print(f"[agent] Full PC scan: {len(discovered)} directories discovered")
        return discovered

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def _get_system_info(self):
        try:
            vm = psutil.virtual_memory()
            return {
                'device_id': self.device_id,
                'hostname': self.hostname,
                'os': f'{platform.system()} {platform.release()}',
                'os_version': platform.version(),
                'arch': platform.machine(),
                'cpu': platform.processor() or 'Unknown',
                'ram_mb': int(vm.total / 1024 / 1024),
                'ip': self._get_local_ip(),
                'agent_version': AGENT_VERSION,
                'scan_dirs': list(self._scan_dirs),
                'scan_dir_count': len(self._scan_dirs),
            }
        except Exception:
            return {'device_id': self.device_id, 'hostname': self.hostname}

    # Ports/destinations considered suspicious for outbound connections
    _SUSPICIOUS_PORTS = {6667, 6668, 6669, 1337, 4444, 5555, 9999, 31337, 12345, 27374}
    _SUSPICIOUS_PROCESS_NAMES = {'nc.exe', 'ncat.exe', 'nc.openbsd', 'mimikatz.exe', 'procdump.exe',
                                 'powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
                                 'mshta.exe', 'cscript.exe', 'wscript.exe', 'certutil.exe'}
    # Known-bad IP ranges (TOR exit nodes, bogon, etc.) — simplified check
    _TOR_EXIT_PREFIXES = ()  # populated dynamically if needed

    def _flag_connection(self, conn_info):
        """Return (flag, reasons) for a connection. flag is one of:
        'clean', 'watch', 'suspicious', 'flagged'."""
        reasons = []
        remote_ip = conn_info.get('remote_ip', '')
        remote_port = conn_info.get('remote_port', 0)
        proc = (conn_info.get('process') or '').lower()
        status = conn_info.get('status', '')

        # No remote IP — internal/listener, skip
        if not remote_ip or remote_ip.startswith('127.') or remote_ip == '0.0.0.0':
            return 'clean', []

        # Suspicious destination port (C2, reverse shell, etc.)
        if remote_port in self._SUSPICIOUS_PORTS:
            reasons.append(f'suspicious port {remote_port}')

        # Suspicious process making outbound connection
        if proc in self._SUSPICIOUS_PROCESS_NAMES:
            reasons.append(f'suspicious process {proc}')

        # Established outbound to non-standard port from a shell process
        if status == 'ESTABLISHED' and proc in ('cmd.exe', 'powershell.exe') and remote_port not in (80, 443, 53, 22, 3389, 445, 139, 21, 25, 587, 993, 995):
            reasons.append(f'shell process outbound to port {remote_port}')

        # High port outbound (potential C2 beacon) — not 80/443/53
        if status == 'ESTABLISHED' and remote_port > 10000 and remote_port not in self._SUSPICIOUS_PORTS:
            reasons.append(f'high port {remote_port}')

        # Link-local / bogon ranges
        if remote_ip.startswith('169.254.'):
            reasons.append('link-local destination')

        if not reasons:
            return 'clean', []
        if len(reasons) >= 2 or any('shell' in r or 'C2' in r for r in reasons):
            return 'flagged', reasons
        return 'suspicious' if 'suspicious' in ' '.join(reasons) else 'watch', reasons

    def _get_live_stats(self):
        try:
            vm = psutil.virtual_memory()
            disk = psutil.disk_usage('C:\\' if os.name == 'nt' else '/')
            boot_time = psutil.boot_time()
            uptime_sec = int(time.time() - boot_time)
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            mins = (uptime_sec % 3600) // 60
            # Collect all network connections on this PC
            network_connections = []
            flagged_connections = []
            watched_connections = []
            # Build a pid->name cache once per heartbeat to avoid repeated
            # AccessDenied exceptions for system processes
            pid_name_cache = {}
            try:
                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        pid_name_cache[p.info['pid']] = p.info['name'] or ''
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                for c in psutil.net_connections(kind='inet'):
                    # Skip dead/closing connections — they have no useful process info
                    if c.status in ('TIME_WAIT', 'CLOSE_WAIT', 'CLOSING', 'FIN_WAIT1', 'FIN_WAIT2'):
                        continue
                    # Skip PID=0 (System Idle) — no process name available
                    if not c.pid or c.pid == 0:
                        continue
                    proc_name = ''
                    if c.pid and c.pid > 0:
                        # Try the cache first (built from process_iter which
                        # tolerates AccessDenied better than per-process calls)
                        proc_name = pid_name_cache.get(c.pid, '')
                        if not proc_name:
                            try:
                                proc_name = psutil.Process(c.pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        # Fallbacks: try cmdline / exe path basename
                        if not proc_name:
                            try:
                                cmdline = psutil.Process(c.pid).cmdline()
                                if cmdline:
                                    proc_name = os.path.basename(cmdline[0])
                            except Exception:
                                pass
                        if not proc_name:
                            try:
                                exe = psutil.Process(c.pid).exe()
                                if exe:
                                    proc_name = os.path.basename(exe)
                            except Exception:
                                pass
                        if not proc_name:
                            proc_name = f'PID-{c.pid}'
                    elif c.pid == 0:
                        proc_name = 'System Idle'
                    conn_info = {
                        'pid': c.pid or 0,
                        'process': proc_name,
                        'protocol': 'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                        'status': c.status or 'NONE',
                        'local_ip': c.laddr.ip if c.laddr else '',
                        'local_port': c.laddr.port if c.laddr else 0,
                        'remote_ip': c.raddr.ip if c.raddr else '',
                        'remote_port': c.raddr.port if c.raddr else 0,
                    }
                    flag, reasons = self._flag_connection(conn_info)
                    conn_info['flag'] = flag
                    conn_info['flag_reasons'] = reasons
                    network_connections.append(conn_info)
                    if flag == 'flagged':
                        flagged_connections.append(conn_info)
                    elif flag in ('suspicious', 'watch'):
                        watched_connections.append(conn_info)
            except Exception:
                pass
            # Collect all running processes on this PC
            all_processes = []
            try:
                for p in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status']):
                    try:
                        info = dict(p.info)
                        try:
                            info['exe'] = p.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            info['exe'] = ''
                        all_processes.append(info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass
            # Use cached network devices (scanned in background thread)
            network_devices = self._cached_network_devices
            return {
                'device_id': self.device_id,
                'cpu_usage': int(psutil.cpu_percent(interval=1)),
                'mem_usage': int(vm.percent),
                'disk_usage': int(disk.percent),
                'uptime': f'{days}d {hours}h {mins}m',
                'files_scanned': self._files_scanned,
                'threats_blocked': self._threats_blocked,
                'total_findings': self._total_findings,
                'total_ransomware': self._total_ransomware,
                'total_persistence': self._total_persistence,
                'total_yara': self._total_yara,
                'total_ml': self._total_ml,
                'last_report_ok': self._last_report_ok,
                'last_report_error': self._last_report_error,
                'quarantine_dir': QUARANTINE_DIR,
                'quarantine_ready': self._quarantine_ready,
                'last_quarantine_error': self._last_quarantine_error,
                'blocked_files': dict(self._blocked_files) if isinstance(self._blocked_files, dict) else list(self._blocked_files),
                'quarantined_count': self._quarantined_count,
                'quarantine_files': self._list_quarantine(),
                'network_connections': network_connections,
                'network_devices': network_devices,
                'processes': all_processes,
                'process_count': len(all_processes),
                'connection_count': len(network_connections),
                'flagged_connections': flagged_connections,
                'watched_connections': watched_connections,
                'scan_dirs': self._scan_dirs,
                'dir_file_counts': self._get_dir_file_counts(),
                'flagged_count': len(flagged_connections),
                'watched_count': len(watched_connections),
                'startup_enabled': self._check_startup_enabled(),
                'kill_switch_active': self._is_kill_switch_active(),
            }
        except Exception:
            return {'device_id': self.device_id}

    def _get_dir_file_counts(self):
        """Count files and subdirectories in each scan directory for the heartbeat."""
        counts = {}
        for d in self._scan_dirs:
            try:
                file_count = 0
                subdir_count = 0
                for entry in os.scandir(d):
                    if entry.is_dir():
                        subdir_count += 1
                    else:
                        file_count += 1
                counts[d] = {'files': file_count, 'subdirs': subdir_count}
            except (PermissionError, OSError):
                counts[d] = {'files': 0, 'subdirs': 0}
        return counts

    def _register(self):
        try:
            info = self._get_system_info()
            r = requests.post(f'{self.server_url}/agent/register',
                              json=info, headers=self._headers,
                              verify=True, timeout=10)
            if r.status_code == 200:
                self._registered = True
                print(f"[OK] Registered with {self.server_url} as {self.device_id}")
                return True
            else:
                print(f"[ERROR] Registration failed: HTTP {r.status_code} {r.text}")
        except Exception as e:
            print(f"[ERROR] Registration failed: {e}")
        return False

    def _heartbeat(self):
        try:
            # Runtime state is a connection prerequisite, not a scan side effect.
            # Create/verify the LocalAppData JSON files before collecting any
            # expensive telemetry so a connected agent can never report healthy
            # while silently lacking its local state store.
            runtime_dir = ensure_runtime_state_files()
            required_json = (
                "scan_state.json",
                "conditional_startup_state.json",
                "scanner_results.json",
                "blocked_files.json",
                "scheduled_scan_state.json",
                "quarantine_log.json",
                "scan_cache.json",
            )
            missing = [
                name for name in required_json
                if not os.path.isfile(os.path.join(runtime_dir, name))
            ]
            if missing:
                raise RuntimeError(
                    "runtime JSON bootstrap incomplete: " + ", ".join(missing)
                )
            stats = self._get_live_stats()
            stats["runtime_state_ready"] = True
            stats["runtime_dir"] = runtime_dir
            stats["agent_version"] = AGENT_VERSION
            # Log ALL live connections with process names so the user can see them
            all_conns = stats.get('network_connections', [])
            flagged = stats.get('flagged_connections', [])
            watched = stats.get('watched_connections', [])
            print(f"[NET] {len(all_conns)} live connection(s):")
            for c in all_conns:
                proc = c.get('process') or f"PID-{c.get('pid', 0)}"
                rip = c.get('remote_ip', '')
                rport = c.get('remote_port', 0)
                status = c.get('status', '')
                flag = c.get('flag', 'clean')
                reasons = ', '.join(c.get('flag_reasons', []))
                marker = ''
                if flag == 'flagged':
                    marker = ' [FLAGGED]'
                elif flag == 'suspicious':
                    marker = ' [SUSPICIOUS]'
                elif flag == 'watch':
                    marker = ' [WATCH]'
                if reasons:
                    marker += f' ({reasons})'
                if rip:
                    print(f"  {proc} -> {rip}:{rport} [{status}]{marker}")
                else:
                    print(f"  {proc} listening :{c.get('local_port', 0)} [{status}]{marker}")
            r = requests.post(f'{self.server_url}/agent/heartbeat',
                              json=stats, headers=self._headers,
                              verify=True, timeout=10)
            if r.status_code == 200:
                # Process any pending commands from the server
                try:
                    resp = r.json()
                    cmds = resp.get('commands', [])
                    for cmd in cmds:
                        self._handle_command(cmd)
                except Exception:
                    pass
                return True
            return False
        except Exception as exc:
            print(f"[HEARTBEAT] failed: {exc!r}")
            try:
                _startup_log(f"[HEARTBEAT] failed: {exc!r}")
            except Exception:
                pass
            return False

    def _handle_command(self, cmd):
        """Handle a command from the cloud server."""
        action = cmd.get('action', '')
        if action == 'toggle_startup':
            enable = cmd.get('enable', False)
            ok, msg = self._toggle_startup(enable)
            print(f"[CMD] Toggle startup {'on' if enable else 'off'}: {msg}")
            return
        if action == 'toggle_kill_switch':
            enable = cmd.get('enabled', False)
            ok, msg = self._toggle_kill_switch(enable)
            print(f"[CMD] Kill switch {'enable' if enable else 'disable'}: {msg}")
            # Push the new state to the dashboard right away instead of waiting
            # for the next scheduled heartbeat cycle (up to HEARTBEAT_INTERVAL
            # seconds later).
            try:
                threading.Thread(target=self._heartbeat, daemon=True).start()
            except Exception:
                pass
            return
        if action == 'scan_now':
            print("[CMD] Scan triggered from cloud dashboard — initializing local runtime JSON state first")
            # This is the hard boundary: no scan thread is allowed to start
            # until the canonical LocalAppData JSON documents exist.
            try:
                ensure_runtime_state_files()
                runtime_dir = ensure_runtime_dir()
                required_json = (
                    "scan_state.json",
                    "conditional_startup_state.json",
                    "scanner_results.json",
                    "blocked_files.json",
                    "scheduled_scan_state.json",
                    "quarantine_log.json",
                    "scan_cache.json",
                )
                missing = [
                    name for name in required_json
                    if not os.path.isfile(os.path.join(runtime_dir, name))
                ]
                if missing:
                    raise RuntimeError(
                        "Runtime JSON initialization incomplete: " + ", ".join(missing)
                    )
                self._publish_all_runtime_json()
                print(f"[CMD] Local runtime JSON initialized in {runtime_dir}")
            except Exception as exc:
                self._scan_status = 'error'
                self._last_report_error = f"runtime JSON initialization failed: {exc}"
                _startup_log(f"[ERROR] {self._last_report_error}")
                print(f"[CMD] Scan refused: {self._last_report_error}")
                try:
                    self._report([], report_type='scan_error')
                except Exception:
                    pass
                return
            self._continuous_scan_requested = True
            if self._scan_lock.locked():
                print("[CMD] Scan request accepted: continuous scan is already running")
                return
            # Publish the active generation BEFORE starting the worker thread.
            # This makes the LocalAppData JSON files authoritative immediately
            # when the website command arrives.
            try:
                self._begin_scan_generation()
                self._report([], report_type='scan_progress')
            except Exception as exc:
                self._scan_status = 'error'
                self._last_report_error = f'scan state initialization failed: {exc}'
                self._publish_all_runtime_json()
                self._report([], report_type='scan_error')
                print(f"[CMD] Scan state initialization failed: {exc}")
                return
            try:
                import threading
                t = threading.Thread(target=self._scan_cycle, kwargs={'continuous': True}, name='agent-continuous-scan', daemon=True)
                t.start()
            except Exception as e:
                print(f"[CMD] Scan trigger failed: {e}")
            return
        if action == 'stop_scan':
            # Continuous protection has no cloud stop command. A stale stop
            # request must never terminate or reset the active normal scan.
            print("[CMD] Ignoring stop_scan: continuous normal scan is indefinite")
            return
        if action == 'scan_file':
            filepath = cmd.get('file_path', '')
            if not filepath or not os.path.isfile(filepath):
                print(f"[CMD] Scan file skipped (not a file): {filepath}")
                return
            try:
                import threading
                t = threading.Thread(target=self._scan_single_file, args=(filepath,), daemon=True)
                t.start()
            except Exception as e:
                print(f"[CMD] Scan file failed: {e}")
            return
        if action == 'block_findings':
            findings = cmd.get('findings', [])
            blocked = 0
            failed = 0
            for f in findings:
                fpath = f.get('path', '')
                if fpath and os.path.exists(fpath):
                    ok = self._block_file_in_place(fpath)
                    if ok:
                        blocked += 1
                    else:
                        failed += 1
            print(f"[CMD] Block findings: {blocked} blocked, {failed} failed")
            return
        if action == 'quarantine_findings':
            findings = cmd.get('findings', [])
            quarantined = 0
            failed = 0
            for f in findings:
                fpath = f.get('path', '')
                if not fpath:
                    continue
                # Check original path first
                if os.path.exists(fpath):
                    ok = self._quarantine_file(fpath)
                    if ok:
                        quarantined += 1
                    else:
                        failed += 1
                else:
                    # Try .blocked rename fallback path
                    blocked_path = fpath + '.blocked'
                    if os.path.exists(blocked_path):
                        try:
                            os.rename(blocked_path, fpath)
                            ok = self._quarantine_file(fpath)
                            if ok:
                                quarantined += 1
                            else:
                                failed += 1
                        except Exception:
                            failed += 1
                    else:
                        # File no longer exists
                        self._unregister_blocked_file(fpath)
                        failed += 1
            print(f"[CMD] Quarantine findings: {quarantined} quarantined, {failed} failed")
            # Report updated quarantine list to cloud
            try:
                qfiles = self._list_quarantine()
                requests.post(f'{self.server_url}/agent/report',
                              json={'device_id': self.device_id,
                                    'type': 'quarantine_list',
                                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                    'quarantine_files': qfiles,
                                    'quarantined_count': self._quarantined_count},
                              headers=self._headers, verify=True, timeout=10)
            except Exception:
                pass
            return
        if action == 'unblock_findings':
            findings = cmd.get('findings', [])
            quarantine_after = cmd.get('quarantine_after', False)
            # Build the set of paths: from the command findings plus ALL
            # persisted blocked files (so unblock works after restart).
            paths_to_process = []
            for f in findings:
                fp = f.get('path', '')
                if fp and fp not in paths_to_process:
                    paths_to_process.append(fp)
            blocked_iter = self._blocked_files.keys() if isinstance(self._blocked_files, dict) else self._blocked_files
            for fp in blocked_iter:
                if fp not in paths_to_process:
                    paths_to_process.append(fp)

            if quarantine_after:
                # Quarantine mode: quarantine each file directly.
                # _quarantine_file() unblocks internally per-file, so there
                # is no window where the file is executable.
                # Protected system paths are never quarantined; they are
                # unblocked instead so the file is restored and removed
                # from the blocked list.
                quarantined = 0
                unblocked = 0
                q_failed = 0
                for fpath in paths_to_process:
                    if not fpath:
                        continue
                    if _is_protected_path(fpath):
                        if os.path.exists(fpath):
                            if self._unblock_file(fpath):
                                unblocked += 1
                            else:
                                q_failed += 1
                        else:
                            blocked_path = fpath + '.blocked'
                            if os.path.exists(blocked_path):
                                try:
                                    os.rename(blocked_path, fpath)
                                    if self._unblock_file(fpath):
                                        unblocked += 1
                                    else:
                                        q_failed += 1
                                except Exception:
                                    q_failed += 1
                            else:
                                self._unregister_blocked_file(fpath)
                                q_failed += 1
                        continue
                    # Check original path
                    if os.path.exists(fpath):
                        ok = self._quarantine_file(fpath)
                        if ok:
                            quarantined += 1
                        else:
                            q_failed += 1
                    else:
                        # Try .blocked rename fallback path
                        blocked_path = fpath + '.blocked'
                        if os.path.exists(blocked_path):
                            try:
                                os.rename(blocked_path, fpath)
                                ok = self._quarantine_file(fpath)
                                if ok:
                                    quarantined += 1
                                else:
                                    q_failed += 1
                            except Exception:
                                q_failed += 1
                        else:
                            # File no longer exists — clean up registry
                            self._unregister_blocked_file(fpath)
                            q_failed += 1
                print(f"[CMD] Unblock+Quarantine: {quarantined} quarantined, {unblocked} unblocked (protected), {q_failed} failed")
                # Report updated quarantine list to cloud
                try:
                    qfiles = self._list_quarantine()
                    requests.post(f'{self.server_url}/agent/report',
                                  json={'device_id': self.device_id,
                                        'type': 'quarantine_list',
                                        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                        'quarantine_files': qfiles,
                                        'quarantined_count': self._quarantined_count},
                                  headers=self._headers, verify=True, timeout=10)
                except Exception:
                    pass
                return

            # Unblock-only mode (no quarantine_after)
            unblocked = 0
            failed = 0
            for fpath in paths_to_process:
                # Try the original path first
                if fpath and os.path.exists(fpath):
                    ok = self._unblock_file(fpath)
                    if ok:
                        unblocked += 1
                    else:
                        failed += 1
                else:
                    # Try .blocked rename fallback path
                    blocked_path = fpath + '.blocked'
                    if os.path.exists(blocked_path):
                        try:
                            os.rename(blocked_path, fpath)
                            self._unblock_file(fpath)
                            unblocked += 1
                        except Exception:
                            failed += 1
                    else:
                        # File no longer exists — remove from registry
                        self._unregister_blocked_file(fpath)
                        failed += 1
            print(f"[CMD] Unblock findings: {unblocked} unblocked, {failed} failed")
            return
        if action == 'add_folder':
            folder = cmd.get('folder_path', '')
            if folder and os.path.isdir(folder) and folder not in self._scan_dirs:
                self._scan_dirs.append(folder)
                print(f"[CMD] Added scan folder: {folder}")
            elif folder:
                print(f"[CMD] Add folder skipped (not a dir or already monitored): {folder}")
            return
        if action == 'remove_folder':
            folder = cmd.get('folder_path', '')
            if folder in self._scan_dirs:
                self._scan_dirs.remove(folder)
                print(f"[CMD] Removed scan folder: {folder}")
            else:
                print(f"[CMD] Remove folder not found: {folder}")
            return
        ip = cmd.get('ip', '')
        if not ip:
            return
        if action == 'block_ip':
            ok, msg = self._block_ip(ip, cmd.get('reason', 'Blocked from cloud dashboard'))
            print(f"[CMD] Block {ip}: {msg}")
        elif action == 'unblock_ip':
            ok, msg = self._unblock_ip(ip)
            print(f"[CMD] Unblock {ip}: {msg}")

    def _toggle_startup(self, enable):
        """Toggle the agent starting automatically on boot/login.
        On Windows, uses Task Scheduler with 'highest privileges' so the
        agent runs as admin automatically on every boot — no UAC prompt.
        When frozen (PyInstaller), runs the EXE directly so users don't
        need Python installed."""
        import platform
        system = platform.system().lower()
        try:
            if system == 'windows':
                import os
                task_name = 'IsolationBytesAgent'
                if getattr(sys, 'frozen', False):
                    # Running as a frozen EXE (IsolationBytesAgent.exe)
                    # The scheduled task runs the EXE directly — no Python needed
                    exe = sys.executable
                    cmd_str = safe_list2cmdline([exe, '--server', self.server_url, f'--key={self.api_key}'])
                else:
                    # Running from source — use pythonw.exe + script
                    exe = sys.executable
                    if exe.lower().endswith('python.exe'):
                        exe = exe.replace('python.exe', 'pythonw.exe')
                    script = os.path.abspath(__file__)
                    cmd_str = safe_list2cmdline([exe, script, '--server', self.server_url, f'--key={self.api_key}'])
                if enable:
                    # Create a scheduled task that runs at logon with admin rights
                    # /rl HIGHEST = run with highest privileges (admin)
                    # /sc ONLOGON = trigger at user logon
                    # Delete existing task first (in case it exists with old settings)
                    safe_run(
                        ['schtasks', '/delete', '/tn', task_name, '/f'],
                        capture_output=True, timeout=10,
                        creationflags=0x08000000
                    )
                    # schtasks /tr has a 261-character limit. If the command
                    # string is too long, write a small .bat wrapper to a short
                    # path and register that instead.
                    task_cmd = cmd_str
                    if len(task_cmd) > 260:
                        wrapper_dir = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'IsolationBytes')
                        os.makedirs(wrapper_dir, exist_ok=True)
                        wrapper_path = os.path.join(wrapper_dir, 'agent_start.bat')
                        with open(wrapper_path, 'w', encoding='utf-8') as wf:
                            wf.write(f'@echo off\r\n"{exe}" "{script}" --server "{self.server_url}" --key="{self.api_key}"\r\n')
                        task_cmd = wrapper_path
                    # Create the task with highest privileges
                    result = safe_run(
                        ['schtasks', '/create', '/tn', task_name,
                         '/tr', f'"{task_cmd}"',
                         '/sc', 'ONLOGON',
                         '/rl', 'HIGHEST',
                         '/f'],
                        capture_output=True, text=True, timeout=10,
                        creationflags=0x08000000
                    )
                    if result.returncode == 0:
                        # Also remove old registry entry if it exists
                        safe_run(
                            ['reg', 'delete', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                             '/v', 'IsolationBytesAgent', '/f'],
                            capture_output=True, timeout=10,
                            creationflags=0x08000000
                        )
                        return True, 'Added to Task Scheduler (admin, auto-start on logon)'
                    else:
                        err = (result.stderr or result.stdout or '').strip()
                        # Retry without /rl HIGHEST — works without admin
                        # privileges (agent runs as normal user instead).
                        result2 = safe_run(
                            ['schtasks', '/create', '/tn', task_name,
                             '/tr', f'"{task_cmd}"',
                             '/sc', 'ONLOGON',
                             '/f'],
                            capture_output=True, text=True, timeout=10,
                            creationflags=0x08000000
                        )
                        if result2.returncode == 0:
                            safe_run(
                                ['reg', 'delete', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                                 '/v', 'IsolationBytesAgent', '/f'],
                                capture_output=True, timeout=10,
                                creationflags=0x08000000
                            )
                            return True, 'Added to Task Scheduler (auto-start on logon, non-admin)'
                        # Final fallback: registry Run key
                        safe_run(
                            ['reg', 'add', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                             '/v', 'IsolationBytesAgent', '/t', 'REG_SZ',
                             '/d', cmd_str, '/f'],
                            capture_output=True, timeout=10,
                            creationflags=0x08000000
                        )
                        return True, f'Added to registry startup (schtasks failed: {err})'
                else:
                    # Remove the scheduled task
                    safe_run(
                        ['schtasks', '/delete', '/tn', task_name, '/f'],
                        capture_output=True, timeout=10,
                        creationflags=0x08000000
                    )
                    # Also remove registry entry
                    safe_run(
                        ['reg', 'delete', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                         '/v', 'IsolationBytesAgent', '/f'],
                        capture_output=True, timeout=10,
                        creationflags=0x08000000
                    )
                    return True, 'Removed from Task Scheduler and registry'
            elif system == 'linux':
                import os
                autostart_dir = os.path.expanduser('~/.config/autostart')
                os.makedirs(autostart_dir, exist_ok=True)
                desktop_file = os.path.join(autostart_dir, 'isolationbytes-agent.desktop')
                if enable:
                    exe = sys.executable
                    script = os.path.abspath(__file__)
                    # quote each argument so paths/spaces/special chars cannot
                    # be reinterpreted by the desktop environment's Exec parser
                    exec_line = ' '.join(shlex.quote(a) for a in [exe, script, '--server', self.server_url, f'--key={self.api_key}'])
                    content = f'''[Desktop Entry]
Type=Application
Name=Isolation Bytes Agent
Exec={exec_line}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
'''
                    with open(desktop_file, 'w') as f:
                        f.write(content)
                    return True, 'Added to Linux autostart'
                else:
                    if os.path.exists(desktop_file):
                        os.remove(desktop_file)
                    return True, 'Removed from Linux autostart'
            elif system == 'darwin':
                import plistlib, os
                plist_path = os.path.expanduser('~/Library/LaunchAgents/com.isolationbytes.agent.plist')
                if enable:
                    exe = sys.executable
                    script = os.path.abspath(__file__)
                    plist = {
                        'Label': 'com.isolationbytes.agent',
                        'ProgramArguments': [exe, script, '--server', self.server_url, f'--key={self.api_key}'],
                        'RunAtLoad': True,
                        'KeepAlive': False,
                    }
                    os.makedirs(os.path.dirname(plist_path), exist_ok=True)
                    with open(plist_path, 'wb') as f:
                        plistlib.dump(plist, f)
                    safe_run(['launchctl', 'load', plist_path], capture_output=True, timeout=10)
                    return True, 'Added to macOS LaunchAgents'
                else:
                    if os.path.exists(plist_path):
                        safe_run(['launchctl', 'unload', plist_path], capture_output=True, timeout=10)
                        os.remove(plist_path)
                    return True, 'Removed from macOS LaunchAgents'
            return False, f'Unsupported platform: {system}'
        except Exception as e:
            return False, str(e)

    def _check_startup_enabled(self):
        """Check if the agent is registered for auto-start."""
        import platform
        system = platform.system().lower()
        try:
            if system == 'windows':
                import subprocess
                # Check Task Scheduler first (preferred — runs as admin)
                result = safe_run(
                    ['schtasks', '/query', '/tn', 'IsolationBytesAgent'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=0x08000000
                )
                if result.returncode == 0:
                    return True
                # Fallback: check registry
                result = safe_run(
                    ['reg', 'query', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                     '/v', 'IsolationBytesAgent'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=0x08000000
                )
                return result.returncode == 0
            elif system == 'linux':
                import os
                desktop_file = os.path.expanduser('~/.config/autostart/isolationbytes-agent.desktop')
                return os.path.exists(desktop_file)
            elif system == 'darwin':
                import os
                plist_path = os.path.expanduser('~/Library/LaunchAgents/com.isolationbytes.agent.plist')
                return os.path.exists(plist_path)
        except Exception:
            pass
        return False

    def _validate_ip(self, ip):
        """Return the normalized IP string if valid, otherwise raise ValueError."""
        return str(ipaddress.ip_network(ip, strict=False))

    def _block_ip(self, ip, reason='Blocked'):
        """Block an IP address using the OS-appropriate firewall."""
        import platform
        try:
            ip = self._validate_ip(ip)
        except ValueError:
            return False, f'Invalid IP or CIDR: {ip}'
        system = platform.system().lower()
        try:
            if system == 'windows':
                import subprocess, ctypes
                # Check if we have admin rights
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    # Try to elevate via runas
                    try:
                        params = safe_list2cmdline([
                            'advfirewall', 'firewall', 'add', 'rule',
                            f'name=IsolationBytes_Block_{ip}', 'dir=out', 'action=block',
                            f'remoteip={ip}'
                        ])
                        ctypes.windll.shell32.ShellExecuteW(
                            None, 'runas', 'netsh',
                            params,
                            None, 0  # SW_HIDE
                        )
                        return True, f'Blocked {ip} via Windows Firewall (elevated)'
                    except Exception:
                        return False, f'Admin required to block {ip} — run agent as administrator'
                CREATE_NO_WINDOW = 0x08000000
                result = safe_run(
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     f'name=IsolationBytes_Block_{ip}', 'dir=out', 'action=block',
                     f'remoteip={ip}'],
                    capture_output=True, text=True, timeout=15,
                    creationflags=CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    return True, f'Blocked {ip} via Windows Firewall'
                err = (result.stderr or result.stdout or '').strip()
                return False, f'netsh failed: {err}'
            elif system == 'darwin':
                # macOS — use pfctl
                import subprocess
                # Add to pf table
                safe_run(['pfctl', '-t', 'isolationbytes_blocked', '-T', 'add', ip],
                               capture_output=True, timeout=10)
                # Ensure pf is enabled and table has a block rule
                safe_run(['pfctl', '-e'], capture_output=True, timeout=10)
                safe_run(['pfctl', '-t', 'isolationbytes_blocked', '-T', 'add', ip],
                               capture_output=True, timeout=10)
                return True, f'Blocked {ip} via macOS pfctl'
            else:
                # Linux — use iptables
                import subprocess
                result = safe_run(
                    ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return True, f'Blocked {ip} via iptables'
                # Try with sudo
                result = safe_run(
                    ['sudo', '-n', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return True, f'Blocked {ip} via iptables (sudo)'
                return False, f'iptables failed: {result.stderr.strip()}'
        except Exception as e:
            return False, str(e)

    def _unblock_ip(self, ip):
        """Unblock an IP address using the OS-appropriate firewall."""
        import platform
        try:
            ip = self._validate_ip(ip)
        except ValueError:
            return False, f'Invalid IP or CIDR: {ip}'
        system = platform.system().lower()
        try:
            if system == 'windows':
                import subprocess, ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    try:
                        params = safe_list2cmdline([
                            'advfirewall', 'firewall', 'delete', 'rule',
                            f'name=IsolationBytes_Block_{ip}'
                        ])
                        ctypes.windll.shell32.ShellExecuteW(
                            None, 'runas', 'netsh',
                            params,
                            None, 0
                        )
                        return True, f'Unblocked {ip} via Windows Firewall (elevated)'
                    except Exception:
                        return False, f'Admin required to unblock {ip} — run agent as administrator'
                CREATE_NO_WINDOW = 0x08000000
                result = safe_run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name=IsolationBytes_Block_{ip}'],
                    capture_output=True, text=True, timeout=15,
                    creationflags=CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    return True, f'Unblocked {ip} via Windows Firewall'
                err = (result.stderr or result.stdout or '').strip()
                return False, f'netsh failed: {err}'
            elif system == 'darwin':
                import subprocess
                safe_run(['pfctl', '-t', 'isolationbytes_blocked', '-T', 'delete', ip],
                               capture_output=True, timeout=10)
                return True, f'Unblocked {ip} via macOS pfctl'
            else:
                import subprocess
                result = safe_run(
                    ['iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return True, f'Unblocked {ip} via iptables'
                result = safe_run(
                    ['sudo', '-n', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return True, f'Unblocked {ip} via iptables (sudo)'
                return False, f'iptables failed: {result.stderr.strip()}'
        except Exception as e:
            return False, str(e)

    def _kill_switch_rule_name(self):
        return 'IsolationBytes_KillSwitch'

    def _is_kill_switch_active(self):
        """Check whether the kill-switch firewall rule currently exists."""
        import platform
        system = platform.system().lower()
        try:
            if system == 'windows':
                CREATE_NO_WINDOW = 0x08000000
                result = safe_run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                     f'name={self._kill_switch_rule_name()}'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=CREATE_NO_WINDOW
                )
                return self._kill_switch_rule_name() in (result.stdout or '')
            elif system == 'darwin':
                result = safe_run(['pfctl', '-a', 'isolationbytes', '-s', 'rules'],
                                   capture_output=True, text=True, timeout=10)
                return 'block drop out' in (result.stdout or '')
            else:
                result = safe_run(['iptables', '-C', 'OUTPUT', '-j', 'DROP'],
                                   capture_output=True, text=True, timeout=10)
                return result.returncode == 0
        except Exception:
            return False

    def _run_elevated(self, exe, args, timeout=20):
        """Run exe with the 'runas' verb (triggers UAC) and BLOCK until the
        elevated process actually finishes, unlike a bare ShellExecuteW call.
        Returns True only if the process ran to completion with exit code 0;
        returns False if the UAC prompt was denied/cancelled, the wait timed
        out, or the elevated command itself failed."""
        import ctypes
        from ctypes import wintypes

        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        SW_HIDE = 0
        WAIT_OBJECT_0 = 0

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ('cbSize', wintypes.DWORD),
                ('fMask', ctypes.c_ulong),
                ('hwnd', wintypes.HWND),
                ('lpVerb', wintypes.LPCWSTR),
                ('lpFile', wintypes.LPCWSTR),
                ('lpParameters', wintypes.LPCWSTR),
                ('lpDirectory', wintypes.LPCWSTR),
                ('nShow', ctypes.c_int),
                ('hInstApp', wintypes.HINSTANCE),
                ('lpIDList', ctypes.c_void_p),
                ('lpClass', wintypes.LPCWSTR),
                ('hKeyClass', wintypes.HKEY),
                ('dwHotKey', wintypes.DWORD),
                ('hIconOrMonitor', wintypes.HANDLE),
                ('hProcess', wintypes.HANDLE),
            ]

        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = 'runas'
        sei.lpFile = exe
        sei.lpParameters = safe_list2cmdline(args)
        sei.lpDirectory = None
        sei.nShow = SW_HIDE
        sei.hInstApp = None

        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
            return False
        h_process = sei.hProcess
        if not h_process:
            return False
        try:
            wait_result = ctypes.windll.kernel32.WaitForSingleObject(h_process, int(timeout * 1000))
            if wait_result != WAIT_OBJECT_0:
                return False
            exit_code = wintypes.DWORD(1)
            ctypes.windll.kernel32.GetExitCodeProcess(h_process, ctypes.byref(exit_code))
            return exit_code.value == 0
        finally:
            ctypes.windll.kernel32.CloseHandle(h_process)

    def _toggle_kill_switch(self, enable):
        """Block or restore ALL outbound traffic on this device using the
        OS-appropriate firewall. This is a full network kill switch, unlike
        _block_ip/_unblock_ip which target a single address."""
        import platform
        system = platform.system().lower()
        rule_name = self._kill_switch_rule_name()
        try:
            if system == 'windows':
                import ctypes
                CREATE_NO_WINDOW = 0x08000000
                is_admin = False
                try:
                    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                except Exception:
                    pass
                if enable:
                    if self._is_kill_switch_active():
                        return True, 'Kill switch already active'
                    args = ['advfirewall', 'firewall', 'add', 'rule',
                            f'name={rule_name}', 'dir=out', 'action=block',
                            'enable=yes', 'profile=any',
                            'remoteip=0.0.0.0-255.255.255.255']
                else:
                    args = ['advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
                if not is_admin:
                    try:
                        elevated_ok = self._run_elevated('netsh', args)
                        if not elevated_ok:
                            return False, ('Admin required to change the kill switch: the UAC '
                                            'prompt was not approved, timed out, or the command failed')
                        # ShellExecute only tells us the elevated process's exit code, not
                        # whether the firewall rule actually ended up in the desired state -
                        # verify directly before reporting success.
                        now_active = self._is_kill_switch_active()
                        if enable:
                            if now_active:
                                return True, 'Outbound traffic blocked (elevated)'
                            return False, ('Elevated netsh command ran but the firewall rule was '
                                            'not created - check Windows Firewall permissions')
                        else:
                            if not now_active:
                                return True, 'Outbound traffic restored (elevated)'
                            return False, ('Elevated netsh command ran but the firewall rule still '
                                            'exists - check Windows Firewall permissions')
                    except Exception:
                        return False, 'Admin required to change the kill switch — run agent as administrator'
                result = safe_run(['netsh'] + args, capture_output=True, text=True,
                                   timeout=15, creationflags=CREATE_NO_WINDOW)
                if result.returncode == 0:
                    return True, ('Outbound traffic blocked' if enable else 'Outbound traffic restored')
                err = (result.stderr or result.stdout or '').strip()
                return False, f'netsh failed: {err}'
            elif system == 'darwin':
                if enable:
                    safe_run(['pfctl', '-e'], capture_output=True, timeout=10)
                    result = safe_run(
                        ['sh', '-c', 'echo "block drop out all" | pfctl -a isolationbytes -f -'],
                        capture_output=True, text=True, timeout=10)
                else:
                    result = safe_run(['pfctl', '-a', 'isolationbytes', '-F', 'rules'],
                                       capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return True, ('Outbound traffic blocked' if enable else 'Outbound traffic restored')
                return False, f'pfctl failed: {(result.stderr or result.stdout or "").strip()}'
            else:
                if enable:
                    result = safe_run(['iptables', '-I', 'OUTPUT', '1', '-j', 'DROP'],
                                       capture_output=True, text=True, timeout=10)
                else:
                    result = safe_run(['iptables', '-D', 'OUTPUT', '-j', 'DROP'],
                                       capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return True, ('Outbound traffic blocked' if enable else 'Outbound traffic restored')
                result = safe_run(['sudo', '-n', 'iptables'] +
                                   (['-I', 'OUTPUT', '1', '-j', 'DROP'] if enable else ['-D', 'OUTPUT', '-j', 'DROP']),
                                   capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return True, ('Outbound traffic blocked' if enable else 'Outbound traffic restored')
                return False, f'iptables failed: {(result.stderr or "").strip()}'
        except Exception as e:
            return False, str(e)

    def _ml_scan_file(self, filepath):
        """Lightweight ML-style malware detection using entropy + heuristic
        features. Self-contained — no sklearn/numpy/pefile needed.
        Returns (is_suspicious, ml_score, reason, threat_type) or (False, 0.0, '', 'ml_suspicious')."""
        try:
            if not os.path.isfile(filepath):
                return False, 0.0, '', 'ml_suspicious'
            ext = os.path.splitext(filepath)[1].lower()
            # Only ML-scan executable/script formats
            ml_extensions = {'.exe', '.dll', '.sys', '.scr', '.com', '.pif',
                             '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js',
                             '.wsf', '.hta', '.msi', '.jar', '.lnk', '.reg',
                             '.inf', '.wsh', '.py', '.sh', '.jsp', '.php',
                             '.asp', '.pl', '.rb', '.lua', '.ts', '.class',
                             '.jnlp', '.cpl', '.drv', '.ocx'}
            if ext not in ml_extensions:
                return False, 0.0, '', 'ml_suspicious'
            file_size = os.path.getsize(filepath)
            if file_size == 0 or file_size > MAX_FILE_SIZE:
                return False, 0.0, '', 'ml_suspicious'
            # Read file data (cap at 1MB for entropy calc)
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 1024)
            if not data:
                return False, 0.0, '', 'ml_suspicious'
            # Shannon entropy
            from collections import Counter
            import math
            counts = Counter(data)
            length = len(data)
            entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
            # Heuristic features
            score = 0.0
            reasons = []
            threat_type = 'ml_suspicious'
            # --- RANSOMWARE INDICATORS ---
            ransomware_indicators = 0
            # Ransomware-specific APIs
            ransomware_apis = [b'cryptencrypt', b'cryptdecrypt', b'cryptcreatehash',
                              b'cryptderivekey', b'cryptimportkey', b'cryptgenkey',
                              b'cryptsetkeyparam', b'bcryptencrypt', b'bcryptdecrypt',
                              b'bcryptgeneratekeypair', b'bcryptimportkey']
            # Ransomware-specific strings (in scripts)
            ransomware_strings = ['vssadmin delete', 'vssadmin delete shadows',
                                 'wbadmin delete', 'bcdedit /default',
                                 'bcdedit /set {default}', 'recoveryenabled no',
                                 'shadowcopy', 'shadow copy', 'volumesnapshot',
                                 'encrypt your file', 'encrypt your files',
                                 'decrypt', 'ransom', 'bitcoin', 'wallet',
                                 'pay the ransom', 'restore your files',
                                 'how to decrypt', 'your files are encrypted',
                                 'aes-256', 'rsa-2048', '.locked', '.encrypted',
                                 '.crypto', '.locky', '.crypt', '.ransom',
                                 'readme_decrypt', 'how_to_decrypt',
                                 'your documents', 'your data', 'your photos',
                                 'delete shadow', 'delete backup', 'recovery disabled',
                                 'vssadmin', 'wbadmin', 'bcdedit', 'cipher /w',
                                 'fsutil usn deletejournal', 'fsutil dirty set',
                                 'del /f /s /q', 'rd /s /q', 'format c:',
                                 'diskpart', 'clear-disk', 'remove-partition',
                                 'encrypt', 'crypto', 'keylogger', 'exfiltrat',
                                 'c2 server', 'command and control', 'beacon',
                                 'reverse shell', 'bind shell', 'meterpreter',
                                 'cobalt strike', 'mimikatz', 'lsass',
                                 'procdump', 'sekurlsa', 'logonpasswords',
                                 'sam.hive', 'ntds.dit', 'dcsync',
                                 'pass the hash', 'golden ticket', 'silver ticket',
                                 'kerberoast', 'as-rep roast', 'dump hashes']
            # --- PERSISTENCE INDICATORS ---
            persistence_indicators = 0
            persistence_apis = [b'createservice', b'startservice', b'changeserviceconfig',
                               b'regsetvalue', b'regsetvalueex', b'regcreatekey',
                               b'regcreatekeyex', b'shellnotify', b'shgetfileinfo']
            persistence_strings = ['schtasks /create', 'schtasks /run',
                                  'reg add hkcu\\software\\microsoft\\windows\\currentversion\\run',
                                  'reg add hklm\\software\\microsoft\\windows\\currentversion\\run',
                                  'currentversion\\run', 'startup folder',
                                  'autostart', 'autorun', 'winlogon\\notify',
                                  'winlogon\\shell', 'explorer\\run', 'appinit_dlls',
                                  'userinit', 'task scheduler', 'create task',
                                  'register-service', 'install service',
                                  'registry persistence', 'dll hijack',
                                  'com hijack', 'wmi subscription',
                                  'eventviewer\\', 'logon script',
                                  'reg add', 'reg import', 'regedit /s',
                                  'sc create', 'sc config', 'sc start',
                                  'net start', 'wmic /namespace',
                                  '__eventfilter', '__eventconsumer',
                                  'cmdkey /add', 'runas /savecred',
                                  'set-itemproperty', 'new-itemproperty',
                                  'set-content $env:appdata',
                                  'copy-item $env:temp', 'invoke-wmimethod',
                                  'register-cimindicationevent', 'action=',
                                  'onlogon', 'onstartup', 'onboot',
                                  'currentversion\\explorer', 'image file execution options',
                                  'silentprocessexit', 'gpedit', 'secedit']
            # High entropy = packed/encrypted (common in malware)
            if entropy > 7.0:
                score += 35
                reasons.append(f'high_entropy={entropy:.2f}')
                # Very high entropy in PE = possible ransomware encryption
                ransomware_indicators += 1
            elif entropy > 6.5:
                score += 20
                reasons.append(f'elevated_entropy={entropy:.2f}')
            elif entropy > 6.0:
                score += 10
                reasons.append(f'moderate_entropy={entropy:.2f}')
            # PE header check (MZ)
            is_pe = data[:2] == b'MZ'
            if is_pe:
                if len(data) > 0x40:
                    pe_offset = int.from_bytes(data[0x3c:0x40], 'little')
                    if pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        score += 15
                        reasons.append('pe_executable')
                        lower_data = data[:min(len(data), 8192)].lower()
                        # Check for suspicious imports
                        suspicious_apis = [b'createprocess', b'writeprocessmemory', b'virtualallocex',
                                          b'createremotethread', b'loadlibrary', b'getprocaddress',
                                          b'winexec', b'shellexecute', b'regsetvalue', b'createfile',
                                          b'writefile', b'internetopen', b'socket', b'connect',
                                          b'wsastartup', b'cryptencrypt', b'createservice',
                                          b'createmutex', b'openmutex', b'openprocess',
                                          b'readprocessmemory', b'createnamedpipe',
                                          b'createfilemapping', b'mapviewoffile',
                                          b'setfiletime', b'findfirstfile', b'findnextfile',
                                          b'movefile', b'copyfile', b'deletefile',
                                          b'regopenkey', b'regdeletekey', b'regdeletevalue',
                                          b'shgetspecialfolderpath', b'getmodulefilename',
                                          b'gettempfilename', b'gettemppath', b'urldownloadtofile',
                                          b'messagebox', b'isdebuggerpresent', b'checkremotedebuggerpresent']
                        api_hits = sum(1 for api in suspicious_apis if api in lower_data)
                        if api_hits >= 3:
                            score += 30
                            reasons.append(f'suspicious_apis={api_hits}')
                        elif api_hits >= 1:
                            score += 15
                            reasons.append(f'api_count={api_hits}')
                        # Check ransomware-specific APIs in PE
                        ransomware_api_hits = sum(1 for api in ransomware_apis if api in lower_data)
                        if ransomware_api_hits >= 1:
                            ransomware_indicators += 2
                            reasons.append(f'ransomware_apis={ransomware_api_hits}')
                        # Check persistence-specific APIs in PE
                        persistence_api_hits = sum(1 for api in persistence_apis if api in lower_data)
                        if persistence_api_hits >= 1:
                            persistence_indicators += 2
                            reasons.append(f'persistence_apis={persistence_api_hits}')
            # Script with suspicious patterns
            if ext in {'.ps1', '.vbs', '.js', '.bat', '.cmd', '.py', '.sh', '.pl', '.rb', '.lua', '.jsp', '.php', '.asp', '.wsf', '.hta'}:
                try:
                    text = data.decode('utf-8', errors='ignore').lower()
                    suspicious_patterns = ['invoke-expression', 'iex ', 'downloadstring',
                                          'downloadfile', 'frombase64string', 'system.reflect',
                                          'createobject', 'wscript.shell', 'powershell -enc',
                                          'powershell -e ', 'hidden', 'bypass', 'noprofile',
                                          'certutil -decode', 'bitsadmin', 'reg add',
                                          'schtasks /create', 'net user', 'whoami',
                                          'taskkill', 'disable_realtime', 'vssadmin',
                                          'wbadmin', 'bcdedit', 'shadow copy', 'shadowcopy',
                                          'encrypt your file', 'decrypt', 'bitcoin',
                                          'ransom', 'wallet', 'pay the', 'how to decrypt',
                                          'your files are', 'your data is', '.locked',
                                          '.encrypted', '.crypt', '.locky', '.ransom',
                                          'currentversion\\run', 'startup folder',
                                          'autorun', 'autostart', 'appinit_dlls',
                                          'winlogon', 'register-service', 'install service',
                                          'dll hijack', 'com hijack', 'wmi subscription',
                                          'meterpreter', 'reverse_shell', 'bind_shell',
                                          'nc -e', 'ncat', 'mkfifo', '/dev/tcp',
                                          'base64 -d', 'openssl enc', 'curl -o',
                                          'wget -o', 'powershell.exe -nop',
                                          'cmd.exe /c', 'cmd.exe /k', 'rundll32',
                                          'regsvr32 /s', 'mshta', 'wscript',
                                          'cscript', 'netsh firewall', 'netsh advfirewall',
                                          'disable-uac', 'disable uac', 'set-MpPreference',
                                          'add-mppreference', 'exclusionpath', 'exclusionprocess',
                                          'mimikatz', 'sekurlsa', 'logonpasswords',
                                          'procdump', 'lsass', 'sam.hive', 'ntds.dit',
                                          'dcsync', 'pass the hash', 'golden ticket',
                                          'kerberoast', 'invoke-kerberoast', 'as-rep',
                                          'invoke-bloodhound', 'sharphound', 'beacon',
                                          'cobalt', 'c2 server', 'command and control',
                                          'exfiltrat', 'upload_', 'download_',
                                          'screenshot', 'keylog', 'webcam',
                                          'audio record', 'get-screenshot', 'set-content',
                                          'out-file', 'add-content', 'copy-item',
                                          'move-item', 'remove-item', 'start-process',
                                          'invoke-item', 'new-object', 'comobject']
                    pattern_hits = sum(1 for p in suspicious_patterns if p in text)
                    if pattern_hits >= 2:
                        score += 40
                        reasons.append(f'suspicious_patterns={pattern_hits}')
                    elif pattern_hits >= 1:
                        score += 20
                        reasons.append(f'pattern_count={pattern_hits}')
                    # Check ransomware strings in scripts — each hit adds score + indicators
                    ransomware_str_hits = sum(1 for s in ransomware_strings if s in text)
                    if ransomware_str_hits >= 3:
                        ransomware_indicators += 3
                        score += 30
                        reasons.append(f'ransomware_strings={ransomware_str_hits}')
                    elif ransomware_str_hits >= 2:
                        ransomware_indicators += 2
                        score += 20
                        reasons.append(f'ransomware_strings={ransomware_str_hits}')
                    elif ransomware_str_hits >= 1:
                        ransomware_indicators += 1
                        score += 15
                        reasons.append(f'ransomware_string={ransomware_str_hits}')
                    # Check persistence strings in scripts — each hit adds score + indicators
                    persistence_str_hits = sum(1 for s in persistence_strings if s in text)
                    if persistence_str_hits >= 3:
                        persistence_indicators += 3
                        score += 30
                        reasons.append(f'persistence_strings={persistence_str_hits}')
                    elif persistence_str_hits >= 2:
                        persistence_indicators += 2
                        score += 20
                        reasons.append(f'persistence_strings={persistence_str_hits}')
                    elif persistence_str_hits >= 1:
                        persistence_indicators += 1
                        score += 15
                        reasons.append(f'persistence_string={persistence_str_hits}')
                except Exception:
                    pass
            # Large executable with high entropy = likely packed malware
            if is_pe and file_size > 100000 and entropy > 7.0:
                score += 15
                reasons.append('large_packed_pe')
            # No digital signature check (simplified)
            if is_pe and b'Windows Signature' not in data[:1024]:
                score += 5
            # --- CLASSIFY THREAT TYPE ---
            # Ransomware: needs ransomware indicators >= 1
            if ransomware_indicators >= 1:
                threat_type = 'ransomware'
                score += 20
                reasons.append(f'ransomware_indicators={ransomware_indicators}')
            # Persistence: needs persistence indicators >= 1 (only if not already ransomware)
            if persistence_indicators >= 1 and threat_type == 'ml_suspicious':
                threat_type = 'persistence'
                score += 20
                reasons.append(f'persistence_indicators={persistence_indicators}')
            # Both ransomware AND persistence
            if ransomware_indicators >= 1 and persistence_indicators >= 1:
                threat_type = 'ransomware'  # ransomware takes priority
                score += 10
                reasons.append('ransomware+persistence')
            # Cap score at 100
            score = min(score, 100.0)
            # Threshold: score >= 20 = suspicious (aggressive)
            if score >= 20:
                return True, score, f'ML heuristic: {", ".join(reasons)}', threat_type
            return False, score, '', threat_type
        except Exception:
            return False, 0.0, '', 'ml_suspicious'

    def _scan_file_yara(self, filepath):
        """Scan a file with YARA rules if available.
        Tries the full scanner first, falls back to a direct yara.load()
        on compiled rules so scanning still works in a frozen EXE where
        the security.yara_scanner import can fail."""
        # Supported file types for YARA scanning
        SCAN_EXTENSIONS = {
            # Executables
            '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.msi',
            # Scripts
            '.vbs', '.vbe', '.js', '.wsf', '.hta', '.bat', '.cmd', '.ps1',
            '.py', '.sh', '.pl', '.rb', '.lua', '.ts', '.asp', '.jsp', '.php',
            # Office documents
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods',
            '.odp', '.rtf',
            # Documents
            '.pdf', '.html', '.htm', '.xml', '.json', '.csv', '.md',
            # Archives
            '.zip', '.rar', '.7z', '.gz', '.tar', '.jar',
            # Email
            '.eml', '.msg',
            # Java
            '.class', '.jnlp',
            # System / high-risk
            '.lnk', '.reg', '.inf', '.wsh',
            # Databases
            '.sqlite', '.db',
            # ELF / Mach-O (no extension or generic)
            '.so', '.dylib',
        }
        # Files to always skip (media, logs, crash dumps)
        SKIP_EXTENSIONS = set()
        # Try the full scanner first
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            if base_dir not in sys.path:
                sys.path.insert(0, base_dir)
            from security.yara_scanner import scan_file_with_yara
            return scan_file_with_yara(filepath)
        except Exception:
            pass
        # Fallback: load compiled rules directly with the yara module
        try:
            import yara
            ext = os.path.splitext(filepath)[1].lower()
            # Skip media/log/crash files
            if ext in SKIP_EXTENSIONS:
                return []
            # If the file has a known scannable extension, scan it.
            # Also scan files with no extension (could be ELF/Mach-O binaries)
            # and files with any other extension not in the skip list
            # (YARA rules can match by content, not just extension).
            # Find compiled rules file
            meipass = getattr(sys, '_MEIPASS', None)
            candidates = []
            if meipass:
                candidates.append(os.path.join(meipass, 'compiled_rules.yarc'))
                candidates.append(os.path.join(meipass, 'security', 'compiled_rules.yarc'))
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'compiled_rules.yarc'))
            rules = None
            for c in candidates:
                if os.path.isfile(c):
                    rules = yara.load(c)
                    break
            if rules is None:
                # Try compiling from .yar files directly
                base = os.path.dirname(os.path.abspath(__file__))
                rules_dir = None
                search_dirs = [os.path.join(base, 'security', 'yara_rules')]
                if meipass:
                    search_dirs.append(os.path.join(meipass, 'security', 'yara_rules'))
                for rd in search_dirs:
                    if rd and os.path.isdir(rd):
                        rules_dir = rd
                        break
                if rules_dir:
                    yar_files = []
                    for root, _, files in os.walk(rules_dir):
                        for f in files:
                            if f.endswith('.yar') or f.endswith('.yara'):
                                yar_files.append(os.path.join(root, f))
                    if yar_files:
                        filepaths = {str(i): p for i, p in enumerate(yar_files)}
                        try:
                            rules = yara.compile(filepaths=filepaths, includes=False, error_on_warning=False)
                        except Exception:
                            # Try compiling each file individually, skip failures
                            compiled = []
                            for p in yar_files:
                                try:
                                    r = yara.compile(filepath=p, includes=False, error_on_warning=False)
                                    compiled.append(r)
                                except Exception:
                                    pass
                            rules = compiled if compiled else None
            if rules is None:
                return []
            # Scan the file
            try:
                file_size = os.path.getsize(filepath)
                if file_size > 5 * 1024 * 1024:
                    if isinstance(rules, list):
                        all_matches = []
                        for r in rules:
                            try:
                                m = r.match(filepath, timeout=max(1, int(os.environ.get('YARA_TIMEOUT_SECONDS', '10'))), fast=True)
                                if m:
                                    all_matches.extend(m)
                            except Exception:
                                pass
                        # Apply ML analysis if available
                        if ML_AVAILABLE and all_matches:
                            try:
                                ml_analyzer = get_ml_analyzer()
                                file_metadata = {
                                    'size': file_size,
                                    'type': ext,
                                    'entropy': self._calculate_file_entropy(filepath) if file_size < 10 * 1024 * 1024 else 0,
                                    'suspicious_patterns': self._count_suspicious_patterns(all_matches)
                                }
                                ml_analysis = ml_analyzer.analyze_threat_level(all_matches, file_metadata)
                                # Attach ML analysis to matches
                                for match in all_matches:
                                    match._ml_analysis = ml_analysis
                            except Exception:
                                pass
                        return all_matches
                    else:
                        matches = rules.match(filepath, timeout=max(1, int(os.environ.get('YARA_TIMEOUT_SECONDS', '10'))), fast=True)
                        matches = matches or []
                        # Apply ML analysis if available
                        if ML_AVAILABLE and matches:
                            try:
                                ml_analyzer = get_ml_analyzer()
                                file_metadata = {
                                    'size': file_size,
                                    'type': ext,
                                    'entropy': self._calculate_file_entropy(filepath) if file_size < 10 * 1024 * 1024 else 0,
                                    'suspicious_patterns': self._count_suspicious_patterns(matches)
                                }
                                ml_analysis = ml_analyzer.analyze_threat_level(matches, file_metadata)
                                # Attach ML analysis to matches
                                for match in matches:
                                    match._ml_analysis = ml_analysis
                            except Exception:
                                pass
                        return matches
                else:
                    with open(filepath, 'rb') as fh:
                        data = fh.read()
                    if isinstance(rules, list):
                        all_matches = []
                        for r in rules:
                            try:
                                m = r.match(data=data, timeout=max(1, int(os.environ.get('YARA_TIMEOUT_SECONDS', '10'))), fast=True)
                                if m:
                                    all_matches.extend(m)
                            except Exception:
                                pass
                        # Apply ML analysis if available
                        if ML_AVAILABLE and all_matches:
                            try:
                                ml_analyzer = get_ml_analyzer()
                                file_metadata = {
                                    'size': len(data),
                                    'type': ext,
                                    'entropy': self._calculate_file_entropy_bytes(data),
                                    'suspicious_patterns': self._count_suspicious_patterns(all_matches)
                                }
                                ml_analysis = ml_analyzer.analyze_threat_level(all_matches, file_metadata)
                                # Attach ML analysis to matches
                                for match in all_matches:
                                    match._ml_analysis = ml_analysis
                            except Exception:
                                pass
                        return all_matches
                    else:
                        matches = rules.match(data=data, timeout=max(1, int(os.environ.get('YARA_TIMEOUT_SECONDS', '10'))), fast=True)
                        matches = matches or []
                        # Apply ML analysis if available
                        if ML_AVAILABLE and matches:
                            try:
                                ml_analyzer = get_ml_analyzer()
                                file_metadata = {
                                    'size': len(data),
                                    'type': ext,
                                    'entropy': self._calculate_file_entropy_bytes(data),
                                    'suspicious_patterns': self._count_suspicious_patterns(matches)
                                }
                                ml_analysis = ml_analyzer.analyze_threat_level(matches, file_metadata)
                                # Attach ML analysis to matches
                                for match in matches:
                                    match._ml_analysis = ml_analysis
                            except Exception:
                                pass
                        return matches
            except Exception:
                return []
        except Exception:
            return []

    def _hash_file(self, filepath):
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def _calculate_file_entropy(self, filepath):
        """Calculate Shannon entropy of file for ML analysis."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            return self._calculate_file_entropy_bytes(data)
        except Exception:
            return 0.0

    def _calculate_file_entropy_bytes(self, data):
        """Calculate Shannon entropy of byte data for ML analysis."""
        if not data:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

    def _count_suspicious_patterns(self, matches):
        """Count suspicious patterns in YARA matches for ML analysis."""
        suspicious_count = 0
        for match in matches:
            rule_name = getattr(match, 'rule', '').lower()
            # Count rules with suspicious keywords
            if any(keyword in rule_name for keyword in ['injection', 'hijack', 'obfuscation', 'evasion', 'steal']):
                suspicious_count += 1
        return suspicious_count

    def _scan_directory(self, dirpath, cycle_start=None):
        findings = []
        if not os.path.isdir(dirpath):
            return findings
        if not hasattr(self, '_skipped_files'):
            self._skipped_files = set()
        # Never scan the scanner's own runtime state or quarantine tree.
        # Full-PC roots such as C:\\ and C:\\Users would otherwise recurse
        # into LocalAppData\\IsolationBytes and count historical quarantine
        # artifacts/state files as current scan files.
        runtime_root = os.path.normcase(os.path.abspath(
            os.environ.get(
                'ANTIVIRUS_RUNTIME_DIR',
                os.path.join(
                    os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
                    'IsolationBytes'
                )
            )
        ))
        quarantine_root = os.path.normcase(os.path.abspath(QUARANTINE_DIR))
        excluded_roots = {runtime_root, quarantine_root}

        for root, dirs, files in os.walk(dirpath):
            # Prevent os.walk from descending into Isolation Bytes runtime data.
            dirs[:] = [
                d for d in dirs
                if os.path.normcase(os.path.abspath(os.path.join(root, d))) not in excluded_roots
            ]
            if cycle_start and time.time() - cycle_start > MAX_SCAN_CYCLE_SECONDS:
                break
            for filename in files:
                if not self._running:
                    dirs[:] = []
                    break
                # Global per-cycle file budget (shared across all directories)
                if getattr(self, '_scan_cycle_remaining', 0) <= 0:
                    dirs[:] = []
                    break
                # Per-file time budget guard
                if cycle_start and time.time() - cycle_start > MAX_SCAN_CYCLE_SECONDS:
                    dirs[:] = []
                    break
                filepath = os.path.join(root, filename)
                # Skip files we've already failed to access (persists across scan cycles)
                if filepath in self._skipped_files:
                    continue
                try:
                    if os.path.getsize(filepath) > MAX_FILE_SIZE:
                        continue

                    # Count the file as soon as it has been enumerated and its
                    # metadata can be read.  Containment (block/quarantine),
                    # YARA, ML, and permission checks happen after this point.
                    # This guarantees a blocked/locked threat still advances
                    # the live scan counter instead of falling through to the
                    # outer exception handler before the old increment.
                    self._files_scanned += 1
                    # Publish live YARA progress frequently enough for the
                    # dashboard to track the current file/path without waiting
                    # hundreds of files.
                    # Publish the first completed enumeration immediately, then
                    # continue with small batches. This prevents the dashboard from
                    # appearing stuck at 0 while a slow YARA/ML file is being processed.
                    if (
                        self._files_scanned == 1 or
                        self._files_scanned - self._scan_progress_reported >= 10
                    ):
                        self._report([], report_type='scan_progress')
                        self._scan_progress_reported = self._files_scanned

                    # Skip files we can't read (locked, permission denied)
                    # BUT don't skip files we blocked ourselves — they're
                    # still threats and need to stay in the findings list
                    if not os.access(filepath, os.R_OK):
                        # Check if it's a file we blocked
                        is_blocked = False
                        blocked_ttype = 'yara_match'
                        if isinstance(self._blocked_files, dict):
                            if filepath in self._blocked_files:
                                is_blocked = True
                                blocked_ttype = self._blocked_files[filepath]
                        elif filepath in self._blocked_files:
                            is_blocked = True
                        if is_blocked:
                            # Already blocked — still report it as a finding
                            # with the ORIGINAL threat type so dashboard
                            # counters for ransomware/persistence stay populated
                            findings.append({
                                'path': filepath,
                                'severity': 'high',
                                'reason': f'Blocked threat (previously detected: {blocked_ttype})',
                                'hash': '',
                                'rule': 'blocked_threat',
                                'tags': [],
                                'threat_type': blocked_ttype,
                                'description': 'File blocked in place by Isolation Bytes',
                                'quarantined': False,
                                'blocked': True,
                            })
                            continue
                        self._skipped_files.add(filepath)
                        continue
                    matches = self._scan_file_yara(filepath)
                    if matches:
                        h = self._hash_file(filepath)
                        # Use the scanner's severity metadata (which includes
                        # word-boundary malware-family promotion) instead of
                        # ad-hoc tag/substring checks that produced false
                        # positives on benign rule names.
                        # Provide fallbacks so findings are ALWAYS created even
                        # if the import fails in a frozen PyInstaller EXE.
                        _fallback_rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                        _rank_of = lambda s: _fallback_rank.get(s, 0)
                        get_match_severity = lambda m: 'medium'
                        get_highest_severity = lambda ms: 'medium'
                        try:
                            base_dir = os.path.dirname(os.path.abspath(__file__))
                            if base_dir not in sys.path:
                                sys.path.insert(0, base_dir)
                            from security.yara_scanner import get_match_severity as _gms, get_highest_severity as _ghs, _rank_of as _ro
                            get_match_severity = _gms
                            get_highest_severity = _ghs
                            _rank_of = _ro
                        except Exception:
                            pass
                        highest = get_highest_severity(matches)
                        if not highest:
                            highest = 'medium'
                        # Report all matches (low, medium, high, critical).
                        # Low-severity matches are included so the dashboard
                        # shows YARA suspicious activity and users can review.
                        if _rank_of(highest) >= _rank_of('low'):
                            # Block ALL detections in place (deny execute/read/write)
                            # so even low/medium threats can't run
                            blocked = self._block_file_in_place(filepath)
                            for m in matches:
                                try:
                                    sev = get_match_severity(m) or 'medium'
                                except Exception:
                                    sev = 'medium'
                                tags = list(m.tags) if m.tags else []
                                tags_lower = ' '.join(str(t) for t in tags).lower()
                                rule_lower = str(m.rule).lower()
                                # Also check meta description for classification
                                meta = getattr(m, 'meta', {}) or {}
                                desc = str(meta.get('description', '') or meta.get('Description', '') or '').lower()
                                # Classify threat type from rule name, tags, and description
                                threat_type = 'yara_match'
                                blob_lower = f'{rule_lower} {tags_lower} {desc}'
                                if ('ransom' in blob_lower or 'encrypt' in desc and 'file' in desc
                                        or 'lock' in blob_lower and 'crypt' in blob_lower
                                        or 'vss_delete' in blob_lower or 'shadow_copy' in blob_lower
                                        or 'wbadmin' in blob_lower or 'recovery_disabl' in blob_lower
                                        or 'backup_delete' in blob_lower or 'ransomnote' in blob_lower):
                                    threat_type = 'ransomware'
                                elif ('persist' in blob_lower or 'startup' in blob_lower
                                      or 'autorun' in blob_lower or 'scheduled' in blob_lower
                                      or 'rootkit' in blob_lower or 'keylog' in blob_lower
                                      or 'backdoor' in blob_lower or 'trojan' in blob_lower
                                      or 'rat_' in blob_lower or 'implant' in blob_lower
                                      or 'beacon' in blob_lower or 'c2_' in blob_lower
                                      or 'botnet' in blob_lower or 'worm' in blob_lower
                                      or 'miner' in blob_lower or 'stealer' in blob_lower
                                      or 'dropper' in blob_lower or 'shellcode' in blob_lower
                                      or 'exploit' in blob_lower
                                      or 'cobalt' in blob_lower or 'meterpreter' in blob_lower
                                      or 'webshell' in blob_lower or 'web_shell' in blob_lower
                                      or 'phishing' in blob_lower or 'phish' in blob_lower
                                      or 'spyware' in blob_lower or 'adware' in blob_lower
                                      or 'process_inject' in blob_lower or 'process_hollow' in blob_lower
                                      or 'dll_hijack' in blob_lower or 'api_hook' in blob_lower
                                      or 'code_inject' in blob_lower or 'reflective_load' in blob_lower
                                      or 'amsi_bypass' in blob_lower or 'etw_bypass' in blob_lower
                                      or 'defender_bypass' in blob_lower or 'uac_bypass' in blob_lower
                                      or 'privilege_escal' in blob_lower or 'privesc' in blob_lower
                                      or 'lateral_movement' in blob_lower or 'credsteal' in blob_lower
                                      or 'exfil' in blob_lower or 'security_disabl' in blob_lower
                                      or 'firewall_disabl' in blob_lower or 'antivirus_disabl' in blob_lower):
                                    threat_type = 'persistence'
                                # Register the blocked file with its threat type
                                # so re-scan reports preserve the classification
                                # (do this AFTER append so a registry error
                                # doesn't lose the finding)
                                findings.append({
                                    'path': filepath,
                                    'severity': sev,
                                    'reason': f'YARA rule matched: {m.rule}',
                                    'hash': h,
                                    'rule': m.rule,
                                    'tags': tags,
                                    'threat_type': threat_type,
                                    'description': desc,
                                    'quarantined': False,
                                    'blocked': blocked,
                                })
                                try:
                                    self._register_blocked_file(filepath, threat_type)
                                except Exception:
                                    pass
                                print(f"[FINDING] {filepath} | type={threat_type} | rule={m.rule} | sev={sev}")
                            # Count as a blocked threat only for high/critical
                            # matches, not medium, to avoid inflating the
                            # dashboard counter with low-confidence hits.
                            if _rank_of(highest) >= _rank_of('medium'):
                                self._threats_blocked += 1
                                # Contain first, then automatically quarantine confirmed
                                # high/critical malware. _quarantine_file() delegates to
                                # quarantine_utils, whose canonical destination is
                                # %USERPROFILE%\AppData\Local\Temp\IsolationBytes\\Quarantine.
                                bok = self._block_file_in_place(filepath)
                                if bok:
                                    for f in findings:
                                        if f.get('path') == filepath:
                                            f['blocked'] = True
                                else:
                                    # Block failed — try rename fallback
                                    rok = self._rename_block_fallback(filepath)
                                    for f in findings:
                                        if f.get('path') == filepath:
                                            if rok:
                                                f['blocked'] = True
                                                f['renamed'] = True
                                            else:
                                                f['block_error'] = True
                                # Quarantine confirmed high/critical YARA hits after
                                # containment. Lower-severity matches remain for review.
                                try:
                                    if os.path.exists(filepath):
                                        qok = self._quarantine_file(filepath)
                                        for f in findings:
                                            if f.get('path') == filepath:
                                                f['quarantined'] = bool(qok)
                                                if not qok:
                                                    f['quarantine_error'] = self._last_quarantine_error or 'Quarantine failed; see agent log'
                                                if qok:
                                                    f['blocked'] = False
                                except Exception as qe:
                                    print(f'[QUARANTINE] Failed for {filepath}: {qe}')
                    # ML detection — always run, even on YARA-matched files
                    # so ransomware/persistence indicators are counted
                    ml_suspicious = False
                    try:
                        ml_suspicious, ml_score, ml_reason, ml_ttype = self._ml_scan_file(filepath)
                        if ml_suspicious:
                            h = self._hash_file(filepath)
                            # If YARA already matched, augment the existing finding
                            # with ML classification (upgrade threat_type if ML
                            # found ransomware/persistence)
                            existing = next((f for f in findings if f.get('path') == filepath), None)
                            if existing:
                                existing['ml_score'] = ml_score
                                existing['ml_reason'] = ml_reason
                                if ml_ttype in ('ransomware', 'persistence'):
                                    existing['threat_type'] = ml_ttype
                                existing['tags'] = (existing.get('tags') or []) + ['ml', 'heuristic', ml_ttype]
                            else:
                                blocked = self._block_file_in_place(filepath)
                                findings.append({
                                    'path': filepath,
                                    'severity': 'high' if ml_score >= 60 else 'medium',
                                    'reason': ml_reason,
                                    'hash': h,
                                    'rule': 'ml_heuristic',
                                    'tags': ['ml', 'heuristic', ml_ttype],
                                    'threat_type': ml_ttype,
                                    'description': ml_reason,
                                    'ml_score': ml_score,
                                    'quarantined': False,
                                    'blocked': blocked,
                                })
                                try:
                                    self._register_blocked_file(filepath, ml_ttype)
                                except Exception:
                                    pass
                                self._threats_blocked += 1
                            # Quarantine ML-only findings at a strong-confidence threshold.
                            try:
                                if ml_suspicious and ml_score >= 60 and os.path.exists(filepath):
                                    qok = self._quarantine_file(filepath)
                                    target = next((f for f in findings if f.get('path') == filepath), None)
                                    if target:
                                        target['quarantined'] = bool(qok)
                                        if qok:
                                            target['blocked'] = False
                            except Exception as qe:
                                print(f'[QUARANTINE] ML quarantine failed for {filepath}: {qe}')
                            print(f"[ML FINDING] {filepath} | type={ml_ttype} | score={ml_score} | {ml_reason}")
                    except Exception:
                        pass
                    # Auto-quarantine fallback: if BOTH YARA and ML flagged
                    # the file, move it to the application quarantine directory instead of
                    # leaving it blocked in place.
                    if matches and ml_suspicious:
                        try:
                            ok = self._quarantine_file(filepath)
                            if ok:
                                for f in findings:
                                    if f.get('path') == filepath:
                                        f['quarantined'] = True
                                        f['blocked'] = False
                                print(f"[AUTO-QUARANTINE] {filepath} moved to the application quarantine directory (YARA+ML)")
                        except Exception as e:
                            print(f"[AUTO-QUARANTINE] Failed {filepath}: {e}")
                    self._scan_cycle_remaining -= 1
                except Exception:
                    continue
            if getattr(self, '_scan_cycle_remaining', 0) <= 0:
                break
        return findings

    def _block_file_in_place(self, filepath):
        """Block a malicious file in place by denying all NTFS permissions
        so it can't be executed, read, or modified. Works on Windows only.
        On non-Windows, falls back to removing execute permission via chmod."""
        try:
            filepath = _resolve_local_path(filepath)
            if not os.path.exists(filepath):
                return False
            if _is_protected_path(filepath):
                print(f"[BLOCK] Refusing to block protected system file: {filepath}")
                return False
            if platform.system() == 'Windows':
                import subprocess
                # Use icacls to deny all permissions to Everyone
                # This blocks execute, read, write without deleting the file
                safe_run(
                    ['icacls', filepath, '/deny', 'Everyone:(RX,W,D)'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                # Also deny SYSTEM and Administrators to prevent bypass
                safe_run(
                    ['icacls', filepath, '/deny', 'SYSTEM:(RX,W,D)'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                safe_run(
                    ['icacls', filepath, '/deny', 'Administrators:(RX,W,D)'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                # Set read-only attribute as extra layer
                try:
                    os.chmod(filepath, 0o444)
                except Exception:
                    pass
                self._register_blocked_file(filepath)
                return True
            else:
                # Linux/macOS: remove all permissions
                os.chmod(filepath, 0o000)
                self._register_blocked_file(filepath)
                return True
        except Exception as e:
            print(f"[BLOCK] Failed to block {filepath}: {e}")
            return False

    def _unblock_file(self, filepath):
        """Restore permissions on a previously blocked file."""
        try:
            filepath = _resolve_local_path(filepath)
            if not os.path.exists(filepath):
                return False
            if platform.system() == 'Windows':
                import subprocess
                safe_run(
                    ['icacls', filepath, '/remove:d', 'Everyone'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                safe_run(
                    ['icacls', filepath, '/remove:d', 'SYSTEM'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                safe_run(
                    ['icacls', filepath, '/remove:d', 'Administrators'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                safe_run(
                    ['icacls', filepath, '/grant', 'Everyone:(RX)'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                safe_run(
                    ['icacls', filepath, '/grant', 'SYSTEM:(F)'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                safe_run(
                    ['icacls', filepath, '/grant', 'Administrators:(F)'],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
                try:
                    os.chmod(filepath, 0o755)
                except Exception:
                    pass
                self._unregister_blocked_file(filepath)
                return True
            else:
                os.chmod(filepath, 0o755)
                self._unregister_blocked_file(filepath)
                return True
        except Exception:
            return False

    def _quarantine_file(self, filepath):
        """Move a malicious file into the agent quarantine and expose the
        exact failure when Windows/another process has the source locked."""
        self._last_quarantine_error = ''
        try:
            filepath = _resolve_local_path(filepath)
            if _is_protected_path(filepath):
                self._last_quarantine_error = f"Protected path: {filepath}"
                print(f"[QUARANTINE] Refusing protected path: {filepath}")
                return False
            if not self._prepare_quarantine_dir():
                return False
            if not os.path.exists(filepath):
                self._last_quarantine_error = f"Source disappeared: {filepath}"
                return False

            if isinstance(self._blocked_files, dict) and filepath in self._blocked_files:
                self._unblock_file(filepath)
                time.sleep(0.5)

            try:
                os.chmod(filepath, 0o777)
            except Exception:
                pass

            import hashlib
            h = hashlib.sha256(filepath.encode('utf-8', 'replace')).hexdigest()[:16]
            base = os.path.basename(filepath)
            dest = os.path.join(QUARANTINE_DIR, f"{h}_{base}.enc")

            try:
                shutil.move(filepath, dest)
            except (PermissionError, OSError) as move_err:
                print(f"[QUARANTINE] move failed for {filepath}: {move_err}")
                try:
                    shutil.copy2(filepath, dest)
                    os.remove(filepath)
                except Exception as copy_err:
                    self._last_quarantine_error = (
                        f"Source locked/denied or destination failed: {filepath} | "
                        f"move={move_err} | copy_delete={copy_err}"
                    )
                    print(f"[QUARANTINE] {self._last_quarantine_error}")
                    try:
                        if os.path.exists(dest):
                            os.remove(dest)
                    except OSError:
                        pass
                    return False

            meta = dest + '.meta'
            with open(meta, 'w', encoding='utf-8') as mf:
                mf.write(f"original_path={filepath}\n")
                mf.write(f"quarantined_at={datetime.datetime.now().isoformat()}\n")
                mf.write("blocked_in_place=False\n")
                mf.write("quarantined=True\n")
            self._unregister_blocked_file(filepath)
            self._quarantined_count += 1
            return True
        except Exception as exc:
            self._last_quarantine_error = f"Quarantine exception for {filepath}: {exc}"
            print(f"[QUARANTINE] {self._last_quarantine_error}")
            return False

    def _rename_block_fallback(self, filepath):
        """Last-resort fallback: rename the file with a .blocked extension
        so Windows won't execute it. Also set read-only attribute."""
        try:
            filepath = _resolve_local_path(filepath)
            if _is_protected_path(filepath):
                print(f"[BLOCK] Refusing to rename protected system file: {filepath}")
                return False
            if not os.path.exists(filepath):
                return False
            blocked_path = filepath + '.blocked'
            # If .blocked already exists, add a number
            counter = 1
            while os.path.exists(blocked_path):
                blocked_path = f"{filepath}.blocked.{counter}"
                counter += 1
            os.rename(filepath, blocked_path)
            # Set read-only on the renamed file
            try:
                os.chmod(blocked_path, 0o444)
            except Exception:
                pass
            # On Windows, also try to hide the file
            if platform.system() == 'Windows':
                try:
                    import subprocess
                    safe_run(
                        ['attrib', '+H', '+R', blocked_path],
                        capture_output=True, timeout=5,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                    )
                except Exception:
                    pass
            print(f"[BLOCK] Renamed {filepath} -> {blocked_path} (fallback)")
            return True
        except Exception as e:
            print(f"[BLOCK] Rename fallback also failed for {filepath}: {e}")
            return False

    def _list_quarantine(self):
        """Return a list of quarantined files on this agent."""
        result = []
        try:
            if not os.path.isdir(QUARANTINE_DIR):
                return result
            for entry in os.scandir(QUARANTINE_DIR):
                if not entry.is_file() or not entry.name.endswith('.enc'):
                    continue
                if entry.is_file():
                    meta_path = entry.path + '.meta'
                    original = ''
                    qtime = ''
                    if os.path.exists(meta_path):
                        with open(meta_path, 'r', encoding='utf-8') as mf:
                            for line in mf:
                                if line.startswith('original_path='):
                                    original = line.split('=', 1)[1].strip()
                                elif line.startswith('quarantined_at='):
                                    qtime = line.split('=', 1)[1].strip()
                    result.append({
                        'filename': entry.name,
                        'path': entry.path,
                        'original_path': original,
                        'quarantined_at': qtime,
                        'size': entry.stat().st_size,
                    })
        except Exception:
            pass
        return result

    def _report(self, findings, report_type='scan'):
        try:
            yara_status = self._scan_status
            # Count findings by type for cumulative counters.
            for f in findings:
                ttype = (f.get('threat_type') or '').lower()
                self._total_findings += 1
                if ttype == 'ransomware':
                    self._total_ransomware += 1
                elif ttype == 'persistence':
                    self._total_persistence += 1
                elif ttype == 'ml_suspicious':
                    self._total_ml += 1
                elif ttype in ('yara_match', 'blocked') or f.get('rule'):
                    self._total_yara += 1

            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            base = {
                'device_id': self.device_id,
                'agent_executable': os.path.abspath(sys.executable),
                'agent_frozen': bool(getattr(sys, 'frozen', False)),
                'type': report_type,
                'timestamp': timestamp,
                'files_scanned': self._files_scanned,
                'quarantined_count': self._quarantined_count,
                'quarantine_dir': QUARANTINE_DIR,
                'quarantine_ready': self._quarantine_ready,
                'last_quarantine_error': self._last_quarantine_error,
                'last_scan': timestamp,
                'scan_id': self._scan_id,
                'scan_dirs': list(self._scan_dirs),
                'scan_dir_count': len(self._scan_dirs),
                'scan_status': yara_status,
                'scan_started_at': self._scan_started_at,
                'yara_scan_state': self._get_yara_scan_state(),
                'scan_complete': self._scan_status == 'complete',
                'scan_id': self._scan_id,
                'scan_started_at': self._scan_started_at,
                'scan_status': self._scan_status,
            }

            # Keep each HTTP request well below the server JSON limit while
            # preserving every finding. The cloud reassembles these parts.
            chunk_size = 40
            if not findings:
                payloads = [dict(base, findings=[])]
            else:
                scan_id = self._scan_id
                payloads = []
                total_parts = (len(findings) + chunk_size - 1) // chunk_size
                for index in range(total_parts):
                    payloads.append(dict(
                        base,
                        findings=findings[index * chunk_size:(index + 1) * chunk_size],
                        scan_id=scan_id,
                        scan_part=index,
                        scan_parts=total_parts,
                        scan_complete=(index == total_parts - 1),
                    ))

            all_ok = True
            for data in payloads:
                r = requests.post(f'{self.server_url}/agent/report',
                                  json=data, headers=self._headers,
                                  verify=True, timeout=30)
                if r.status_code != 200:
                    all_ok = False
                    self._last_report_error = f'HTTP {r.status_code}: {r.text[:200]}'
                    break
            self._last_report_ok = all_ok
            if all_ok:
                self._last_report_error = ''
            return all_ok
        except Exception as e:
            self._last_report_ok = False
            self._last_report_error = str(e)
            return False

    def _scan_cycle_once(self, continuous=False, new_generation=False):
        # Only one cloud-triggered full scan may run at a time. Without this
        # guard, repeated scan_now commands can create concurrent os.walk/YARA
        # threads that share the same counters and make progress appear stuck.
        if not self._scan_lock.acquire(blocking=False):
            print("[SCAN] Scan already running; ignoring duplicate scan request")
            return
        try:
            cycle_start = time.time()
            self._scan_cycle_remaining = MAX_FILES_PER_SCAN
            self._scan_status = 'scanning'
            # A continuous scan has ONE persistent generation. Do not reset the
            # counters or JSON state at the end of every directory pass.
            if new_generation or not self._scan_id:
                self._scan_started_at = datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()
                self._reset_scan_state()
            self._publish_all_runtime_json()
            all_findings = []
            scanned_roots = []

            # Publish the new run immediately so the dashboard cannot display
            # an older completed scan as the current run.
            self._report([], report_type='scan_progress')

            for dirpath in self._scan_dirs:
                if not self._running:
                    break
                # Continuous protection has no artificial per-pass file/time
                # ceiling. A pass ends only after the monitored roots have
                # actually been traversed (or an explicit stop occurs).
                if not continuous and time.time() - cycle_start > MAX_SCAN_CYCLE_SECONDS:
                    break
                if not continuous and self._scan_cycle_remaining <= 0:
                    break
                if not os.path.isdir(dirpath):
                    continue

                # A drive root already covers every descendant. Avoid
                # rescanning nested roots and multiplying the workload.
                canonical = os.path.normcase(
                    os.path.abspath(os.path.realpath(dirpath))
                )
                if any(
                    canonical == root or canonical.startswith(root + os.sep)
                    for root in scanned_roots
                ):
                    continue
                try:
                    findings = self._scan_directory(
                        dirpath, cycle_start=cycle_start
                    )
                    all_findings.extend(findings)
                    scanned_roots.append(canonical)
                except Exception as exc:
                    print(f"[SCAN] Directory scan error for {dirpath}: {exc}")
                    continue
            # A continuous scan is never marked complete. Finishing a directory
            # pass only means the next continuous pass begins immediately.
            self._scan_status = 'scanning' if (continuous and self._running) else ('complete' if self._running else 'stopped')
            if all_findings:
                print(
                    f"[ALERT] Found {len(all_findings)} threat(s)! "
                    f"Types: {[f.get('threat_type', '?') for f in all_findings]}"
                )
                self._report(all_findings)
            else:
                self._report([], report_type='heartbeat_scan')
        finally:
            self._scan_lock.release()

    def _scan_cycle(self, continuous=False):
        """Run the normal scanner continuously; never turn a pass into completion."""
        generation_started = False
        while self._running:
            try:
                self._scan_cycle_once(
                    continuous=continuous,
                    new_generation=(continuous and not generation_started) or not continuous,
                )
                if continuous:
                    generation_started = True
            except BaseException as exc:
                # A scanner exception must not terminate continuous scanning.
                self._scan_status = 'scanning' if continuous else 'error'
                self._last_report_error = str(exc)
                print(f"[SCAN] Scan pass failed; continuous mode will retry: {exc!r}")
                try:
                    self._publish_all_runtime_json()
                    self._report([], report_type='scan_error')
                except Exception:
                    pass
            if not self._running:
                break
            # Immediately start the next normal scan pass. There is no
            # watchdog/event mode and no completion state in continuous mode.
            time.sleep(0.1)
        if continuous:
            self._scan_status = 'scanning'
            try:
                self._publish_all_runtime_json()
            except Exception:
                pass

    def _scan_single_file(self, filepath):
        """Scan a single file and report findings immediately."""
        try:
            print(f"[SCAN] Scanning single file: {filepath}")
            matches = self._scan_file_yara(filepath)
            findings = []
            if matches:
                file_hash = self._hash_file(filepath)
                _fallback_rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                _rank_of = lambda s: _fallback_rank.get(s, 0)
                get_match_severity = lambda m: 'medium'
                get_highest_severity = lambda ms: 'medium'
                try:
                    base_dir = os.path.dirname(os.path.abspath(__file__))
                    if base_dir not in sys.path:
                        sys.path.insert(0, base_dir)
                    from security.yara_scanner import get_match_severity as _gms, get_highest_severity as _ghs, _rank_of as _ro
                    get_match_severity = _gms
                    get_highest_severity = _ghs
                    _rank_of = _ro
                except Exception:
                    pass
                highest = get_highest_severity(matches)
                if not highest:
                    highest = 'medium'
                if _rank_of(highest) >= _rank_of('low'):
                    blocked = self._block_file_in_place(filepath)
                    for m in matches:
                        try:
                            sev = get_match_severity(m) or 'low'
                        except Exception:
                            sev = 'medium'
                        tags = list(m.tags) if m.tags else []
                        tags_lower = ' '.join(str(t) for t in tags).lower()
                        rule_lower = str(m.rule).lower()
                        meta = getattr(m, 'meta', {}) or {}
                        desc = str(meta.get('description', '') or meta.get('Description', '') or '').lower()
                        threat_type = 'yara_match'
                        blob_lower = f'{rule_lower} {tags_lower} {desc}'
                        if ('ransom' in blob_lower or 'encrypt' in desc and 'file' in desc
                                or 'lock' in blob_lower and 'crypt' in blob_lower
                                or 'vss_delete' in blob_lower or 'shadow_copy' in blob_lower
                                or 'wbadmin' in blob_lower or 'recovery_disabl' in blob_lower
                                or 'backup_delete' in blob_lower or 'ransomnote' in blob_lower):
                            threat_type = 'ransomware'
                        elif ('persist' in blob_lower or 'startup' in blob_lower
                              or 'autorun' in blob_lower or 'scheduled' in blob_lower
                              or 'rootkit' in blob_lower or 'keylog' in blob_lower
                              or 'backdoor' in blob_lower or 'trojan' in blob_lower
                              or 'rat_' in blob_lower or 'implant' in blob_lower
                              or 'beacon' in blob_lower or 'c2_' in blob_lower
                              or 'botnet' in blob_lower or 'worm' in blob_lower
                              or 'miner' in blob_lower or 'stealer' in blob_lower
                              or 'dropper' in blob_lower or 'shellcode' in blob_lower
                              or 'exploit' in blob_lower
                              or 'cobalt' in blob_lower or 'meterpreter' in blob_lower
                              or 'webshell' in blob_lower or 'web_shell' in blob_lower
                              or 'phishing' in blob_lower or 'phish' in blob_lower
                              or 'spyware' in blob_lower or 'adware' in blob_lower
                              or 'process_inject' in blob_lower or 'process_hollow' in blob_lower
                              or 'dll_hijack' in blob_lower or 'api_hook' in blob_lower
                              or 'code_inject' in blob_lower or 'reflective_load' in blob_lower
                              or 'amsi_bypass' in blob_lower or 'etw_bypass' in blob_lower
                              or 'defender_bypass' in blob_lower or 'uac_bypass' in blob_lower
                              or 'privilege_escal' in blob_lower or 'privesc' in blob_lower
                              or 'lateral_movement' in blob_lower or 'credsteal' in blob_lower
                              or 'exfil' in blob_lower or 'security_disabl' in blob_lower
                              or 'firewall_disabl' in blob_lower or 'antivirus_disabl' in blob_lower):
                            threat_type = 'persistence'
                        findings.append({
                            'path': filepath,
                            'severity': sev,
                            'reason': f'YARA rule matched: {m.rule}',
                            'hash': file_hash,
                            'rule': m.rule,
                            'tags': tags,
                            'threat_type': threat_type,
                            'quarantined': False,
                            'blocked': blocked,
                        })
                        try:
                            self._register_blocked_file(filepath, threat_type)
                        except Exception:
                            pass
                    if _rank_of(highest) >= _rank_of('medium'):
                        self._threats_blocked += 1
                        # Block in place only — no quarantine during scan
                        bok = self._block_file_in_place(filepath)
                        if not bok:
                            rok = self._rename_block_fallback(filepath)
                            for f in findings:
                                if rok:
                                    f['blocked'] = True
                                    f['renamed'] = True
                                else:
                                    f['block_error'] = True
                        else:
                            for f in findings:
                                f['blocked'] = True
                        try:
                            if os.path.exists(filepath):
                                qok = self._quarantine_file(filepath)
                                for f in findings:
                                    if f.get('path') == filepath:
                                        f['quarantined'] = bool(qok)
                                        if qok:
                                            f['blocked'] = False
                        except Exception as qe:
                            print(f'[QUARANTINE] Single-file YARA quarantine failed for {filepath}: {qe}')
            # ML detection for single file scan — always run
            ml_suspicious, ml_score, ml_reason, ml_ttype = self._ml_scan_file(filepath)
            if ml_suspicious:
                file_hash = self._hash_file(filepath)
                existing = next((f for f in findings if f.get('path') == filepath), None)
                if existing:
                    existing['ml_score'] = ml_score
                    existing['ml_reason'] = ml_reason
                    if ml_ttype in ('ransomware', 'persistence'):
                        existing['threat_type'] = ml_ttype
                    existing['tags'] = (existing.get('tags') or []) + ['ml', 'heuristic', ml_ttype]
                else:
                    blocked = self._block_file_in_place(filepath)
                    findings.append({
                        'path': filepath,
                        'severity': 'high' if ml_score >= 60 else 'medium',
                        'reason': ml_reason,
                        'hash': file_hash,
                        'rule': 'ml_heuristic',
                        'tags': ['ml', 'heuristic', ml_ttype],
                        'threat_type': ml_ttype,
                        'description': ml_reason,
                        'ml_score': ml_score,
                        'quarantined': False,
                        'blocked': blocked,
                    })
                    try:
                        self._register_blocked_file(filepath, ml_ttype)
                    except Exception:
                        pass
                    self._threats_blocked += 1
                    try:
                        if ml_score >= 60 and os.path.exists(filepath):
                            qok = self._quarantine_file(filepath)
                            target = next((f for f in findings if f.get('path') == filepath), None)
                            if target:
                                target['quarantined'] = bool(qok)
                                if qok:
                                    target['blocked'] = False
                    except Exception as qe:
                        print(f'[QUARANTINE] Single-file ML quarantine failed for {filepath}: {qe}')
                    print(f"[ML FINDING] {filepath} | type={ml_ttype} | score={ml_score} | {ml_reason}")
            self._report(findings, report_type='single_file_scan')
            if findings:
                print(f"[ALERT] Single file scan found {len(findings)} threat(s)!")
            else:
                print(f"[SCAN] Single file scan clean: {filepath}")
        except Exception as e:
            print(f"[SCAN] Single file scan error: {e}")
            self._report([], report_type='single_file_scan')

    def _command_poll_loop(self):
        """Poll scan/control commands independently every second."""
        while self._running:
            try:
                r = requests.post(
                    f'{self.server_url}/agent/commands/poll',
                    json={'device_id': self.device_id},
                    headers=self._headers,
                    verify=True,
                    timeout=5,
                )
                if r.status_code == 200:
                    commands = r.json().get('commands', [])
                    for cmd in commands:
                        try:
                            self._handle_command(cmd)
                        except Exception as exc:
                            print(f'[CMD] Command failed: {exc!r}')
                elif r.status_code not in (404,):
                    print(f'[CMD] Command poll HTTP {r.status_code}')
            except Exception as exc:
                # Keep polling; transient network failures must not terminate
                # the command receiver or the continuous scanner.
                print(f'[CMD] Command poll failed: {exc!r}')
            for _ in range(10):
                if not self._running:
                    break
                time.sleep(0.1)

    def _heartbeat_loop(self):
        while self._running:
            try:
                ok = self._heartbeat()
                if not ok:
                    print("[WARN] Heartbeat failed — will retry")
            except Exception:
                pass
            for _ in range(HEARTBEAT_INTERVAL):
                if not self._running:
                    break
                time.sleep(1)

    def _voice_command_loop(self):
        """Poll the cloud for queued voice commands and execute them locally."""
        while self._running:
            try:
                r = requests.post(f'{self.server_url}/api/voice/agent/pending',
                                  json={'device_id': self.device_id},
                                  headers=self._headers,
                                  verify=True, timeout=15)
                if r.status_code == 200:
                    for cmd in r.json().get('commands', []):
                        threading.Thread(target=self._execute_voice_command,
                                         args=(cmd,), daemon=True).start()
            except Exception:
                pass
            for _ in range(5):
                if not self._running:
                    break
                time.sleep(1)

    def _execute_voice_command(self, cmd):
        """Execute a queued voice command on this PC and post back the result."""
        job_id = cmd.get('job_id')
        raw = cmd.get('command', '')
        apply_fix = bool(cmd.get('apply_fix', False))
        try:
            import voice_assistant
            intent = voice_assistant.parse_intent(raw)
            result = voice_assistant.run_command(intent, raw_command=raw, apply_fix=apply_fix)
            self._post_voice_result(job_id, 'completed', result)
        except ImportError:
            self._post_voice_result(job_id, 'error',
                                    'This agent build does not support voice commands yet.')
        except Exception as e:
            self._post_voice_result(job_id, 'error', str(e))

    def _post_voice_result(self, job_id, status, result):
        """Report a voice command result back to the cloud queue."""
        try:
            requests.post(f'{self.server_url}/api/voice/agent/result',
                          json={'device_id': self.device_id, 'job_id': job_id,
                                'status': status, 'result': result},
                          headers=self._headers,
                          verify=True, timeout=15)
        except Exception:
            pass

    def _network_scan_loop(self):
        """Background network device scanner — runs every 60 seconds.
        Results are cached so heartbeats don't block on the scan."""
        while self._running:
            try:
                from security.network_devices import scan_network_devices
                devices = scan_network_devices()
                if devices:
                    self._cached_network_devices = devices
                    print(f"[NET] Found {len(devices)} device(s) on network")
            except Exception as e:
                print(f"[NET] Scan error: {e}")
            for _ in range(60):
                if not self._running:
                    break
                time.sleep(1)
                time.sleep(1)

    def _check_for_update(self):
        """Check the cloud for a newer agent EXE and self-update if available."""
        try:
            resp = requests.get(
                f'{self.server_url}/agent/update-check',
                headers=self._headers,
                timeout=15,
            )
            if resp.status_code != 200:
                return
            info = resp.json()
            if not info.get('update_available'):
                return
            server_version = info.get('version', '')
            server_sha = info.get('sha256', '')
            download_url = info.get('download_url', '')
            if not download_url or not server_sha:
                return
            # Validate the update URL matches the configured server to avoid SSRF
            parsed_server = urlparse(self.server_url)
            parsed_url = urlparse(download_url)
            if (parsed_url.scheme != parsed_server.scheme or
                    parsed_url.netloc != parsed_server.netloc or
                    parsed_url.path != '/download/IsolationBytesAgent.exe'):
                print(f"[agent] Ignoring untrusted update URL: {download_url}")
                return
            # Compare versions — if server version is newer, download and replace
            if server_version <= AGENT_VERSION:
                return
            print(f"[agent] Update available: {server_version} (current: {AGENT_VERSION})")
            # Download the new EXE
            dl = requests.get(download_url, timeout=120, stream=True)
            if dl.status_code != 200:
                print(f"[agent] Update download failed: HTTP {dl.status_code}")
                return
            new_bytes = b''
            for chunk in dl.iter_content(chunk_size=65536):
                new_bytes += chunk
            # Verify SHA-256
            import hashlib
            actual_sha = hashlib.sha256(new_bytes).hexdigest()
            if actual_sha != server_sha:
                print(f"[agent] Update checksum mismatch — skipping")
                return
            # Get current EXE path (frozen) or script path
            if getattr(sys, 'frozen', False):
                current_exe = sys.executable
            else:
                current_exe = os.path.abspath(__file__)
            # Write new EXE to a temp file, then swap
            tmp_path = current_exe + '.new'
            with open(tmp_path, 'wb') as f:
                f.write(new_bytes)
            # On Windows, we can't overwrite a running EXE directly.
            # Write a batch script that waits for us to exit, then swaps.
            bat_path = current_exe + '.update.bat'
            old_path = current_exe + '.old'
            restart_cmd = safe_list2cmdline([current_exe, '--server', self.server_url, f'--key={self.api_key}', '--auto-start'])
            bat = f'''@echo off
echo Updating IsolationBytesAgent...
:wait
del "{old_path}" 2>nul
move /y "{current_exe}" "{old_path}" 2>nul
if exist "{current_exe}" goto wait
move /y "{tmp_path}" "{current_exe}" 2>nul
start "" {restart_cmd}
del "{bat_path}" 2>nul
'''
            with open(bat_path, 'w') as f:
                f.write(bat)
            print(f"[agent] Update downloaded — restarting via {bat_path}")
            # Launch the updater batch file and exit
            safe_popen(['cmd', '/c', bat_path], creationflags=0x08000000)
            self._running = False
            os._exit(0)
        except Exception as e:
            print(f"[agent] Update check failed: {e}")

    def _update_loop(self):
        """Periodically check for agent updates."""
        while self._running:
            try:
                self._check_for_update()
            except Exception:
                pass
            for _ in range(UPDATE_CHECK_INTERVAL):
                if not self._running:
                    break
                time.sleep(1)

    def _scan_loop(self):
        while self._running:
            try:
                self._scan_cycle()
            except Exception:
                pass
            for _ in range(SCAN_INTERVAL):
                if not self._running:
                    break
                time.sleep(1)

    def start(self):
        self._running = True
        if not (self.device_token or self.api_key):
            if not self._pair():
                message = "No device credential. Use --pair-code from the website or configure --key."
                print(f"[ERROR] {message}")
                _startup_log(f"[ERROR] {message}")
                self._running = False
                return
        elif self.pair_code and not self._pair():
            self._running = False
            return
        print(f"Starting Isolation Bytes Agent")
        print(f"  Server:  {self.server_url}")
        print(f"  Device:  {self.device_id}")
        print(f"  Host:    {self.hostname}")
        print()

        # Wait for server to be reachable
        print("Connecting to server...")
        for i in range(15):
            if not self._running:
                return
            try:
                r = requests.get(self.server_url, verify=True, timeout=5)
                if r.status_code < 500:
                    print("[OK] Server is reachable")
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            message = "Could not reach server. Check your internet connection."
            print(f"[ERROR] {message}")
            _startup_log(f"[ERROR] {message}")
            self._running = False
            return

        # Register
        for attempt in range(5):
            if not self._running:
                return
            if self._register():
                break
            time.sleep(3)
        if not self._registered:
            message = "Failed to register. Check your API key."
            print(f"[ERROR] {message}")
            _startup_log(f"[ERROR] {message}")
            self._running = False
            return

        # Start heartbeat thread
        hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True, name='Heartbeat')
        hb_thread.start()

        # Poll scan/control commands independently of heartbeat statistics.
        # Heartbeat collection can be expensive on Windows; scan commands must
        # never wait behind process/network enumeration.
        command_thread = threading.Thread(target=self._command_poll_loop, daemon=True, name='AgentCommands')
        command_thread.start()

        # Start voice command polling thread
        voice_thread = threading.Thread(target=self._voice_command_loop, daemon=True, name='VoiceCommands')
        voice_thread.start()

        # Start network device scan thread (background, non-blocking)
        net_thread = threading.Thread(target=self._network_scan_loop, daemon=True, name='NetScan')
        net_thread.start()

        # Start scan thread
        scan_thread = threading.Thread(target=self._scan_loop, daemon=True, name='Scanner')
        scan_thread.start()

        # Start self-update thread (checks for new agent EXE every hour)
        update_thread = threading.Thread(target=self._update_loop, daemon=True, name='Updater')
        update_thread.start()

        print()
        print("Agent is running. Press Ctrl+C to stop.")
        print(f"  Heartbeats: every {HEARTBEAT_INTERVAL}s")
        print(f"  Scans:      every {SCAN_INTERVAL}s")
        print(f"  Updates:    every {UPDATE_CHECK_INTERVAL}s")
        print(f"  Directories: {', '.join(self._scan_dirs)}")
        print()

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down agent...")
            self.stop()

    def stop(self):
        self._running = False
        print("Agent stopped.")


def main():
    _register_windows_uri_handler()
    uri_pair_code = ''
    argv = list(sys.argv[1:])
    if argv:
        uri_pair_code = _pair_code_from_uri(argv[0])
        if uri_pair_code:
            argv.pop(0)
    parser = argparse.ArgumentParser(description='Isolation Bytes Standalone Agent')
    parser.add_argument('--server', default=DEFAULT_SERVER,
                        help=f'Cloud server URL (default: {DEFAULT_SERVER})')
    parser.add_argument('--key', default=DEFAULT_API_KEY,
                        help='API key for authentication')
    parser.add_argument('--key-file', default=None,
                        help='Read the API key from a local file')
    parser.add_argument('--pair-code', default=None,
                        help='One-time code generated in the logged-in website dashboard')
    parser.add_argument('--credential-file', default=None,
                        help='Path for the device credential (default: local app data)')
    parser.add_argument('--device-id', default=None,
                        help='Custom device ID (default: WIN-<hostname>)')
    parser.add_argument('--auto-start', action='store_true',
                        help='Register the agent to start automatically on boot/login')
    parser.add_argument('--background', action='store_true',
                        help='Run the agent in the background (no terminal window)')
    args = parser.parse_args(argv)
    if uri_pair_code and not args.pair_code:
        args.pair_code = uri_pair_code
    api_key = _read_api_key_file(args.key_file) if args.key_file else args.key
    if not api_key and not args.pair_code:
        default_key_file = _ensure_api_key_file()
        if os.path.isfile(default_key_file):
            api_key = _read_api_key_file(default_key_file)
    device_id = args.device_id or f'WIN-{socket.gethostname().upper()[:12]}'

    agent = StandaloneAgent(
        server_url=args.server,
        api_key=api_key,
        device_id=device_id,
        pair_code=args.pair_code,
        credential_file=args.credential_file,
    )

    # A packaged agent is intended to provide persistent real-time protection.
    # Register it on every launch so opening the EXE once also enables future
    # logon startup, even when the launcher omitted --auto-start.
    should_auto_start = args.auto_start or (
        platform.system().lower() == 'windows' and getattr(sys, 'frozen', False)
    )
    if should_auto_start:
        ok, msg = agent._toggle_startup(True)
        print(f"[STARTUP] {msg}")
        if not ok:
            print("[STARTUP] Failed to enable auto-start. Continuing anyway...")

    if args.background:
        import subprocess
        exe = sys.executable
        system = platform.system().lower()
        if system == 'windows' and exe.lower().endswith('python.exe'):
            exe = exe.replace('python.exe', 'pythonw.exe')
        script = os.path.abspath(__file__)
        # Use validated agent attributes instead of raw argparse values
        cmd = [exe, script, '--server', agent.server_url]
        if args.key_file:
            cmd.extend(['--key-file', args.key_file])
        elif agent.device_token:
            cmd.extend(['--credential-file', agent.credential_file])
        else:
            cmd.append(f'--key={agent.api_key}')
        if agent.device_id:
            cmd.append('--device-id')
            cmd.append(agent.device_id)
        kwargs = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
        if system == 'windows':
            kwargs['creationflags'] = 0x08000000  # CREATE_NO_WINDOW
        else:
            kwargs['start_new_session'] = True  # detach from terminal on Linux/macOS
        safe_popen(cmd, **kwargs)
        print("Agent started in background.")
        return

    agent.start()


if __name__ == '__main__':
    main()