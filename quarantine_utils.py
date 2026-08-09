from utils.paths import get_resource_path
import os
import logging
import shutil
import tempfile
from cryptography.fernet import Fernet
import sys

if getattr(sys, 'frozen', False):
    basedir = os.path.dirname(sys.executable)
else:
    basedir = os.path.dirname(os.path.abspath(__file__))

# Quarantine files live in the Defender quarantine folder under the temp directory
QUARANTINE_FOLDER = os.path.join(tempfile.gettempdir(), 'Defender_Quarantine')
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
            'icacls', QUARANTINE_FOLDER,
            '/inheritance:r',
            f'/grant:r', f'{username}:F',
            '/remove', 'Users', 'Everyone'
        ], check=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.warning(f'Could not set Windows ACLs on quarantine folder: {e}')
else:
    import stat
    try:
        os.chmod(QUARANTINE_FOLDER, 0o700)  # nosec B103
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

def quarantine_file(filepath):
    import shutil
    from cryptography.fernet import Fernet
    FERNET_KEY = os.environ.get('FERNET_KEY')
    if FERNET_KEY is not None and isinstance(FERNET_KEY, str):
        FERNET_KEY = FERNET_KEY.encode()
    if FERNET_KEY is not None and isinstance(FERNET_KEY, str):
        FERNET_KEY = FERNET_KEY.encode()
    failed_quarantine_folder = os.path.join(basedir, 'failed_quarantine')
    os.makedirs(failed_quarantine_folder, exist_ok=True)
    if not FERNET_KEY or len(FERNET_KEY) != 44:
        logging.error(f"FERNET_KEY environment variable must be set to a valid 44-character Fernet key. Quarantine failed for {filepath}.")
        # Move file to failed_quarantine
        try:
            shutil.move(filepath, os.path.join(failed_quarantine_folder, os.path.basename(filepath)))
            logging.warning(f"Moved {filepath} to failed_quarantine due to missing/invalid key.")
        except Exception as move_exc:
            logging.error(f"Failed to move {filepath} to failed_quarantine: {move_exc}. Attempting forced delete.")
            try:
                os.remove(filepath)
                logging.warning(f"Force deleted {filepath} after failed quarantine.")
            except Exception as del_exc:
                logging.error(f"Failed to force delete {filepath}: {del_exc}")
        return
    secure_key = SecureBuffer(FERNET_KEY)
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
        secure_key.zero_and_unlock()
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
        else:
            logging.warning(f"File already missing when attempting to remove: {filepath}")
    except Exception as e:
        logging.error(f"Error encrypting/quarantining {filepath}: {e}")
        # Move file to failed_quarantine
        try:
            shutil.move(filepath, os.path.join(failed_quarantine_folder, os.path.basename(filepath)))
            logging.warning(f"Moved {filepath} to failed_quarantine due to encryption error.")
        except Exception as move_exc:
            logging.error(f"Failed to move {filepath} to failed_quarantine: {move_exc}. Attempting forced delete.")
            try:
                os.remove(filepath)
                logging.warning(f"Force deleted {filepath} after failed quarantine.")
            except Exception as del_exc:
                logging.error(f"Failed to force delete {filepath}: {del_exc}")
                
class SecureBuffer:
    def __init__(self, key):
        self.key = key

    def get_bytes(self):
        return self.key  # Return the stored key

    def zero_and_unlock(self):
        # Securely wipe the stored key if necessary
        self.key = b'\x00' * len(self.key)