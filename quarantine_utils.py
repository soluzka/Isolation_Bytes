from utils.paths import get_resource_path
import os
import logging
import shutil
import tempfile
import hashlib
import json
import time

ICACLS_PATH = shutil.which('icacls') or 'icacls'
from cryptography.fernet import Fernet
from security.secure_memory import SecureBuffer
import sys

if getattr(sys, 'frozen', False):
    basedir = os.path.dirname(sys.executable)
else:
    basedir = os.path.dirname(os.path.abspath(__file__))

# Quarantine files live in the Defender quarantine folder under the user's
# temp directory.  We use USERPROFILE rather than tempfile.gettempdir() so
# the path is consistent whether the server runs as a normal user or elevated
# (tempfile.gettempdir() returns a different path under admin/SYSTEM).
_userprofile = os.environ.get('USERPROFILE', os.path.expanduser('~'))
QUARANTINE_FOLDER = os.path.join(
    _userprofile, 'AppData', 'Local', 'Temp', 'Defender_Quarantine'
)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
# Set strict permissions on the quarantine folder
import platform
import sys
if platform.system() == 'Windows':
    import subprocess
    import getpass
    # --- Windows subprocess window suppression ---
    if sys.platform == 'win32':
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
    else:
        DETACHED_PROCESS = 0
        CREATE_NO_WINDOW = 0
    username = getpass.getuser()
    # Remove inherited permissions and grant full control to current user only
    try:
        subprocess.run([  # nosem; nosec B603
            ICACLS_PATH, QUARANTINE_FOLDER,
            '/inheritance:r',
            f'/grant:r', f'{username}:F',
            '/remove', 'Users', 'Everyone'
        ], check=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.warning(f'Could not set Windows ACLs on quarantine folder: {e}')
else:
    import stat
    try:
        os.chmod(QUARANTINE_FOLDER, stat.S_IRWXU)  # nosec B103
    except Exception as e:
        logging.warning(f'Could not set chmod 700 on quarantine folder: {e}')

import platform

def force_unlock_windows(filepath):
    """Try to forcibly unlock a file on Windows using handle.exe if available."""
    if platform.system() == 'Windows':
        import subprocess
        # handle.exe is a Sysinternals tool; user must have it in PATH
        try:
            subprocess.run(['handle.exe', '-c', filepath, '-y'], capture_output=True, check=False, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosem; nosec B603
        except Exception as e:
            logging.warning(f'Could not run handle.exe to unlock {filepath}: {e}')

def _add_local_signatures(data, filepath):
    """Append the hashes of a quarantined file to the local signature file so
    the same malware is detected by hash next time."""
    try:
        signature_db = os.path.join(basedir, 'malware_signatures.txt')
        existing = set()
        if os.path.exists(signature_db):
            with open(signature_db, 'r', encoding='utf-8') as f:
                existing = set(line.strip().lower() for line in f if ':' in line.strip())
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()

        # TLSH fuzzy hash for catching variants
        tlsh_hash = ''
        try:
            import tlsh
            tlsh_hash = tlsh.hash(data)
            if tlsh_hash == 'TNULL':
                tlsh_hash = ''
        except Exception:
            pass

        # imphash for PE files
        imphash = ''
        try:
            import pefile
            pe = pefile.PE(filepath)
            imphash = pe.get_imphash()
            pe.close()
        except Exception:
            pass

        new_lines = []
        for htype, hval in [('md5', md5), ('sha1', sha1), ('sha256', sha256),
                            ('sha512', sha512), ('tlsh', tlsh_hash), ('imphash', imphash)]:
            if not hval:
                continue
            line = f'local_quarantine:{htype}:{hval}'
            if line.lower() not in existing:
                new_lines.append(line)
        if new_lines:
            with open(signature_db, 'a', encoding='utf-8') as f:
                for line in new_lines:
                    f.write(line + '\n')
            logging.info(f"Added {len(new_lines)} local quarantine signatures")
    except Exception as e:
        logging.error(f"Failed to add local quarantine signatures: {e}")

def _send_alert(reason, original_path, sha256):
    """Send a webhook alert if ALERT_WEBHOOK_URL is configured."""
    import requests
    webhook = os.environ.get('ALERT_WEBHOOK_URL', '').strip()
    if not webhook:
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
    """Append quarantine metadata to the quarantine log."""
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
    """Return a list of quarantine .enc files with metadata from the log."""
    try:
        files = [f for f in os.listdir(QUARANTINE_FOLDER) if f.endswith('.enc')]
    except Exception:
        return []
    log_path = os.path.join(QUARANTINE_FOLDER, 'quarantine_log.json')
    log_entries = []
    try:
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8') as lf:
                log_entries = json.load(lf)
            if not isinstance(log_entries, list):
                log_entries = []
    except Exception:
        pass
    items = []
    for f in files:
        full = os.path.join(QUARANTINE_FOLDER, f)
        mtime = os.path.getmtime(full)
        entry = next((e for e in log_entries if e.get('quarantine_path', '').endswith(f)), {})
        items.append({
            'filename': f,
            'path': full,
            'original_path': entry.get('original_path', 'unknown'),
            'reason': entry.get('reason', 'unknown'),
            'timestamp': entry.get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))),
            'sha256': entry.get('sha256', ''),
            'size': entry.get('size', os.path.getsize(full))
        })
    return items


def restore_quarantine_file(filename, destination=None):
    """Decrypt a quarantine .enc file and write it back to the original or a destination."""
    FERNET_KEY = os.environ.get('FERNET_KEY')
    if FERNET_KEY is not None and isinstance(FERNET_KEY, str):
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
                    logs = json.load(f)
                for entry in logs:
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
        fernet = Fernet(FERNET_KEY)
        data = fernet.decrypt(encrypted)
        os.makedirs(os.path.dirname(destination) or '.', exist_ok=True)
        with open(destination, 'wb') as f:
            f.write(data)
        return True, destination
    except Exception as e:
        return False, str(e)


def delete_quarantine_file(filename):
    """Delete a quarantine .enc file and its log entry."""
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
    import shutil
    from cryptography.fernet import Fernet
    FERNET_KEY = os.environ.get('FERNET_KEY')
    if FERNET_KEY is not None and isinstance(FERNET_KEY, str):
        FERNET_KEY = FERNET_KEY.encode()
    failed_quarantine_folder = os.path.join(basedir, 'failed_quarantine')
    os.makedirs(failed_quarantine_folder, exist_ok=True)
    if not FERNET_KEY or len(FERNET_KEY) != 44:
        logging.error(f"FERNET_KEY environment variable must be set to a valid 44-character Fernet key. Quarantine failed for {filepath}.")
        # Move file to failed_quarantine, but never silently delete when encryption is not possible.
        try:
            shutil.move(filepath, os.path.join(failed_quarantine_folder, os.path.basename(filepath)))
            logging.warning(f"Moved {filepath} to failed_quarantine due to missing/invalid key.")
        except Exception as move_exc:
            logging.error(f"Failed to move {filepath} to failed_quarantine: {move_exc}. Original file left in place.")
        return
    secure_key = SecureBuffer(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
    fernet = Fernet(secure_key.get_bytes())
    basename = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_FOLDER, basename + '.enc')
    try:
        with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
            data = f.read()
        del f
        encrypted_data = fernet.encrypt(data)
        with open(get_resource_path(os.path.join(dest)), 'wb') as ef:
            ef.write(encrypted_data)
        del ef
        logging.warning(f"Quarantined (encrypted): {filepath}")
        _log_quarantine(filepath, dest, data, reason)
        _send_alert(reason, filepath, hashlib.sha256(data).hexdigest())
        _add_local_signatures(data, filepath)
        try:
            from security.virus_total import check_and_update
            check_and_update(filepath)
        except Exception:
            pass
        secure_key.zero_and_unlock()
        if os.path.exists(filepath):
            try:
                os.remove(filepath)  # Delete the original file after quarantining
            except PermissionError:
                force_unlock_windows(filepath)
                try:
                    os.remove(filepath)
                except Exception as e2:
                    logging.error(f"Still failed to delete {filepath} after unlock attempt: {e2}")
                    # Kill processes that have the file locked, then retry
                    try:
                        from security.scan_cache import _kill_processes_locking_file
                        _kill_processes_locking_file(filepath)
                        os.remove(filepath)
                        logging.warning(f"Deleted {filepath} after killing locking process")
                    except Exception as e3:
                        logging.error(f"Could not delete {filepath} after killing processes: {e3}")
                        # Schedule for deletion on next reboot via MoveFileEx
                        try:
                            import ctypes
                            MOVEFILE_DELAY_UNTIL_REBOOT = 4
                            ctypes.windll.kernel32.MoveFileExW(
                                filepath, None, MOVEFILE_DELAY_UNTIL_REBOOT)
                            logging.warning(f"Scheduled {filepath} for deletion on next reboot")
                        except Exception:
                            logging.error(f"Could not schedule {filepath} for reboot deletion")
        else:
            logging.warning(f"File already missing when attempting to remove: {filepath}")
    except Exception as e:
        logging.error(f"Error encrypting/quarantining {filepath}: {e}")
        # Move file to failed_quarantine
        try:
            shutil.move(filepath, os.path.join(failed_quarantine_folder, os.path.basename(filepath)))
            logging.warning(f"Moved {filepath} to failed_quarantine due to encryption error.")
        except Exception as move_exc:
            logging.error(f"Failed to move {filepath} to failed_quarantine: {move_exc}. Original file left in place.")