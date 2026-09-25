from utils.paths import get_resource_path
import os
import logging
import shutil
import hashlib
import json
import time

# Load the persisted per-install environment before quarantine_file() reads
# FERNET_KEY. The standalone scanner can run without quick_start.py.
try:
    from dotenv import load_dotenv
    import sys as _quarantine_sys
    _local_appdata = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
    _env_candidates = []
    if getattr(_quarantine_sys, 'frozen', False):
        _env_candidates.extend([
            os.path.join(os.path.dirname(_quarantine_sys.executable), '.env'),
            os.path.join(_local_appdata, 'antivirus_server', '.env'),
        ])
    else:
        _env_candidates.extend([
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
            os.path.join(_local_appdata, 'antivirus_server', '.env'),
            os.path.join(os.getcwd(), '.env'),
        ])
    for _env_path in _env_candidates:
        if os.path.exists(_env_path):
            load_dotenv(_env_path, override=False)
            if len(os.environ.get('FERNET_KEY', '')) == 44:
                break
except Exception as _env_error:
    logging.debug('Unable to load quarantine environment: %s', _env_error)

ICACLS_PATH = shutil.which('icacls') or 'icacls'
from cryptography.fernet import Fernet
from security.secure_memory import SecureBuffer
import sys

if getattr(sys, 'frozen', False):
    basedir = os.path.dirname(sys.executable)
else:
    basedir = os.path.dirname(os.path.abspath(__file__))

_userprofile = os.environ.get('USERPROFILE', os.path.expanduser('~'))
QUARANTINE_FOLDER = os.path.join(
    _userprofile, 'AppData', 'Local', 'Temp', 'Defender_Quarantine'
)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

import platform
if platform.system() == 'Windows':
    import subprocess
    import getpass
    if sys.platform == 'win32':
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
    else:
        DETACHED_PROCESS = 0
        CREATE_NO_WINDOW = 0
    username = getpass.getuser()
    try:
        subprocess.run([
            ICACLS_PATH, QUARANTINE_FOLDER,
            '/inheritance:r',
            '/grant:r', f'{username}:F',
            '/remove', 'Users', 'Everyone'
        ], check=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.warning(f'Could not set Windows ACLs on quarantine folder: {e}')
else:
    import stat
    try:
        os.chmod(QUARANTINE_FOLDER, stat.S_IRWXU)
    except Exception as e:
        logging.warning(f'Could not set chmod 700 on quarantine folder: {e}')


def force_unlock_windows(filepath):
    """Try to forcibly unlock a file on Windows using handle.exe if available."""
    if platform.system() == 'Windows':
        import subprocess
        try:
            subprocess.run(['handle.exe', '-c', filepath, '-y'], capture_output=True,
                           check=False, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except Exception as e:
            logging.warning(f'Could not run handle.exe to unlock {filepath}: {e}')


def _add_local_signatures(data, filepath):
    """Append hashes of a quarantined file to the local signature file."""
    try:
        signature_db = os.path.join(basedir, 'malware_signatures.txt')
        existing = set()
        if os.path.exists(signature_db):
            with open(signature_db, 'r', encoding='utf-8') as f:
                existing = set(line.strip().lower() for line in f if ':' in line.strip())
        hashes = [
            ('md5', hashlib.md5(data, usedforsecurity=False).hexdigest()),
            ('sha1', hashlib.sha1(data, usedforsecurity=False).hexdigest()),
            ('sha256', hashlib.sha256(data).hexdigest()),
            ('sha512', hashlib.sha512(data).hexdigest()),
        ]
        try:
            import tlsh
            value = tlsh.hash(data)
            if value != 'TNULL':
                hashes.append(('tlsh', value))
        except Exception:
            pass
        new_lines = []
        for htype, hval in hashes:
            line = f'local_quarantine:{htype}:{hval}'
            if line.lower() not in existing:
                new_lines.append(line)
        if new_lines:
            with open(signature_db, 'a', encoding='utf-8') as f:
                for line in new_lines:
                    f.write(line + '\n')
    except Exception as e:
        logging.error(f'Failed to add local quarantine signatures: {e}')


def _is_valid_webhook_url(url):
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
        return (p.scheme in ('http', 'https') and bool(p.hostname)
                and p.username is None and p.password is None)
    except Exception:
        return False


def _send_alert(reason, original_path, sha256):
    import requests
    webhook = os.environ.get('ALERT_WEBHOOK_URL', '').strip()
    if not webhook or not _is_valid_webhook_url(webhook):
        return
    try:
        requests.post(webhook, json={
            'text': f'Antivirus alert: quarantined {original_path}',
            'reason': reason,
            'sha256': sha256,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }, timeout=10)
    except Exception:
        pass


def _log_quarantine(original_path, quarantine_path, data, reason=''):
    log_path = os.path.join(QUARANTINE_FOLDER, 'quarantine_log.json')
    entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'original_path': original_path,
        'quarantine_path': quarantine_path,
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': len(data),
        'reason': reason or 'unknown'
    }
    try:
        logs = []
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        if not isinstance(logs, list):
            logs = []
        logs.append(entry)
        with open(log_path, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        logging.error(f'Failed to write quarantine log: {e}')


def list_quarantine_files():
    """Return only actual quarantine artifacts, with available metadata."""
    try:
        files = [f for f in os.listdir(QUARANTINE_FOLDER) if f.endswith('.enc')]
    except Exception:
        return []
    log_path = os.path.join(QUARANTINE_FOLDER, 'quarantine_log.json')
    try:
        with open(log_path, 'r', encoding='utf-8') as lf:
            log_entries = json.load(lf) if os.path.exists(log_path) else []
        if not isinstance(log_entries, list):
            log_entries = []
    except Exception:
        log_entries = []
    items = []
    for filename in files:
        full = os.path.join(QUARANTINE_FOLDER, filename)
        try:
            mtime = os.path.getmtime(full)
            size = os.path.getsize(full)
        except OSError:
            continue
        entry = next((e for e in log_entries if e.get('quarantine_path', '').endswith(filename)), {})
        items.append({
            'filename': filename,
            'path': full,
            'original_path': entry.get('original_path', 'unknown'),
            'reason': entry.get('reason', 'unknown'),
            'timestamp': entry.get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))),
            'sha256': entry.get('sha256', ''),
            'size': size
        })
    return items


def restore_quarantine_file(filename, destination=None):
    """Decrypt a quarantine artifact and write it to the requested destination."""
    FERNET_KEY = os.environ.get('FERNET_KEY')
    if isinstance(FERNET_KEY, str):
        FERNET_KEY = FERNET_KEY.encode()
    if not FERNET_KEY or len(FERNET_KEY) != 44:
        return False, 'FERNET_KEY not configured'
    source = os.path.join(QUARANTINE_FOLDER, filename)
    if not os.path.exists(source):
        return False, 'File not found'
    if destination is None:
        log_path = os.path.join(QUARANTINE_FOLDER, 'quarantine_log.json')
        original = None
        try:
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8') as f:
                    for entry in json.load(f):
                        if entry.get('quarantine_path', '').endswith(filename):
                            original = entry.get('original_path')
                            break
        except Exception:
            pass
        if not original:
            return False, 'Cannot determine original path'
        destination = original + '.restored'
    try:
        with open(source, 'rb') as f:
            encrypted = f.read()
        data = Fernet(FERNET_KEY).decrypt(encrypted)
        os.makedirs(os.path.dirname(destination) or '.', exist_ok=True)
        with open(destination, 'wb') as f:
            f.write(data)
        return True, destination
    except Exception as e:
        return False, str(e)


def delete_quarantine_file(filename):
    """Delete a quarantine artifact and its log entry."""
    source = os.path.join(QUARANTINE_FOLDER, filename)
    if not os.path.exists(source):
        return False, 'File not found'
    try:
        os.remove(source)
        log_path = os.path.join(QUARANTINE_FOLDER, 'quarantine_log.json')
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8') as f:
                logs = json.load(f)
            logs = [e for e in logs if not e.get('quarantine_path', '').endswith(filename)]
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2)
        return True, 'Deleted'
    except Exception as e:
        return False, str(e)


def quarantine_file(filepath, reason=''):
    """Return True only after an encrypted artifact is verified and the source is gone."""
    FERNET_KEY = os.environ.get('FERNET_KEY')
    if isinstance(FERNET_KEY, str):
        FERNET_KEY = FERNET_KEY.encode()
    if not FERNET_KEY or len(FERNET_KEY) != 44 or not os.path.isfile(filepath):
        logging.error('Quarantine unavailable: FERNET_KEY is missing/invalid or file is unavailable: %s', filepath)
        return False

    secure_key = SecureBuffer(FERNET_KEY)
    dest = None
    tmp_dest = None
    try:
        fernet = Fernet(secure_key.get_bytes())
        basename = os.path.basename(filepath)
        dest = os.path.join(QUARANTINE_FOLDER, basename + '.enc')
        if os.path.exists(dest):
            dest = os.path.join(QUARANTINE_FOLDER, f"{basename}_{time.strftime('%Y%m%d_%H%M%S')}.enc")
        tmp_dest = dest + '.tmp'

        with open(filepath, 'rb') as f:
            data = f.read()
        encrypted_data = fernet.encrypt(data)
        with open(tmp_dest, 'wb') as ef:
            ef.write(encrypted_data)
            ef.flush()
            os.fsync(ef.fileno())
        os.replace(tmp_dest, dest)

        with open(dest, 'rb') as vf:
            if fernet.decrypt(vf.read()) != data:
                raise IOError('quarantine artifact contents failed verification')

        try:
            os.remove(filepath)
        except PermissionError:
            force_unlock_windows(filepath)
            try:
                os.remove(filepath)
            except Exception:
                try:
                    from security.scan_cache import _kill_processes_locking_file
                    _kill_processes_locking_file(filepath)
                    os.remove(filepath)
                except Exception:
                    pass

        if os.path.exists(filepath):
            logging.error(f'Quarantine source removal failed; keeping finding active: {filepath}')
            try:
                os.remove(dest)
            except OSError:
                pass
            return False

        _log_quarantine(filepath, dest, data, reason)
        _send_alert(reason, filepath, hashlib.sha256(data).hexdigest())
        _add_local_signatures(data, filepath)
        secure_key.zero_and_unlock()
        return True
    except Exception as e:
        logging.error(f'Error encrypting/quarantining {filepath}: {e}')
        for candidate in (tmp_dest, dest):
            if candidate:
                try:
                    if os.path.exists(candidate):
                        os.remove(candidate)
                except OSError:
                    pass
        return False
    finally:
        try:
            secure_key.zero_and_unlock()
        except Exception:
            pass
