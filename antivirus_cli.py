from utils.paths import get_resource_path
import os
import shutil
import sys
import argparse

POWERSHELL_PATH = shutil.which('powershell') or 'powershell'
import os
import logging
import os
from scan_utils import scan_file_for_viruses
from security.secure_message import encrypt_message  # Ensure encrypt_message is imported
    
def file_hashes(filepath):
    import hashlib
    hashes = {}
    try:
        with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data, usedforsecurity=False).hexdigest()  # nosem
            hashes['sha1'] = hashlib.sha1(data, usedforsecurity=False).hexdigest()  # nosem
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()  # Add SHA-512 hash
    except Exception as e:
        logging.error(f"Error calculating hashes for {filepath}: {e}")
    return hashes

def scan_file_for_viruses_with_test_flag(filepath):
    if os.environ.get('FORCE_MALWARE') == '1':
        return True, True, 'Test: malware detected'
    try:
        if os.path.getsize(filepath) == 0:
            return False, False, "Empty file, skipping scan."
    except Exception as e:
        logging.error(f"Error checking file size for {filepath}: {e}")
    sigs = load_signatures()
    hashes = file_hashes(filepath)
    if any(h in sigs for h in hashes.values()):
        return True, True, 'Malware detected by hash match'
    return scan_file_for_viruses(filepath, sigs) if 'sigs' in scan_file_for_viruses.__code__.co_varnames else scan_file_for_viruses(filepath)

def get_basedir():
    import sys
    if 'ANTIVIRUS_RUNTIME_DIR' in os.environ:
        return os.environ['ANTIVIRUS_RUNTIME_DIR']
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASEDIR = get_basedir()
QUARANTINE_DIR = os.path.join(BASEDIR, 'quarantine')
LOG_FILE = os.path.join(BASEDIR, 'antivirus.log')
SIGNATURE_DB = os.path.join(BASEDIR, 'malware_signatures.txt')
os.makedirs(QUARANTINE_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

def load_signatures():
    sig_path = SIGNATURE_DB if os.path.exists(SIGNATURE_DB) else get_resource_path('malware_signatures.txt')
    if not os.path.exists(sig_path):
        logging.warning(f"Signature database not found: {sig_path}")
        return set()
    try:
        signatures = set()
        with open(sig_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Accept both bare hashes and source:hash_type:hash lines
                if ':' in line:
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        signatures.add(parts[2].lower())
                else:
                    signatures.add(line.lower())
        logging.info(f"Loaded {len(signatures)} signatures from {SIGNATURE_DB}")
        return signatures
    except Exception as e:
        logging.error(f"Error loading signatures: {e}")
        return set()

def update_signatures():
    """Update malware signatures from remote sources"""
    try:
        # Define remote signature sources
        signature_sources = [
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/",  # Example YARA rules
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/"  # Another YARA rules source
        ]
        
        # Create or update signature database
        with open(get_resource_path(os.path.join(SIGNATURE_DB)), 'w') as f:
            for source in signature_sources:
                try:
                    response = requests.get(source, timeout=30)
                    if response.status_code == 200:
                        signatures = response.text.splitlines()
                        for sig in signatures:
                            f.write(sig.strip() + "\n")
                        logging.info(f"Successfully updated signatures from {source}")
                except Exception as e:
                    logging.error(f"Error updating signatures from {source}: {e}")
        
        logging.info("Malware signatures updated successfully")
        return True
        
    except Exception as e:
        logging.error(f"Error updating signatures: {e}")
        return False

def scan_path(path):
    try:
        if not os.path.exists(path):
            print(f"Path not found: {path}")
            return
    except Exception as e:
        logging.error(f"Error accessing path {path}: {e}")
        return
    if os.path.isfile(path):
        _, malware, msg = scan_file_for_viruses_with_test_flag(path)
        print(f"Scan result for {path}: {msg}")
        if malware:
            if quarantine_file(path):
                print(f"[!] File {path} quarantined and deleted.")
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                scan_path(os.path.join(root, file))
    else:
        print(f"Path not found: {path}")

from cryptography.fernet import Fernet

def quarantine_file(filepath):
    basename = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_DIR, basename + '.enc')
    # Confirm with user before quarantining (deleting) the file
    confirm = input(f"Are you sure you want to quarantine and delete '{filepath}'? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("Quarantine cancelled by user.")
        logging.info(f"Quarantine cancelled by user for {filepath}")
        return False
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
    except Exception as e:
        logging.error(f"Error creating quarantine directory: {e}")
        return False
    try:
        key = os.environ.get('FERNET_KEY')
        if not key:
            print('FERNET_KEY not set in environment.')
            return False
        fernet = Fernet(key)
        if not os.path.isfile(filepath):
            print(f"File not found: {filepath}")
            logging.error(f"File not found for quarantine: {filepath}")
            return False
        with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(get_resource_path(os.path.join(dest)), 'wb') as f:
            f.write(encrypted)
        os.remove(filepath)
        logging.warning(encrypt_message(f"Quarantined file: {filepath}"))
        print(f"[!] Infected file moved to quarantine (encrypted): {dest}")
        return True
    except Exception as e:
        import traceback
        print(f"Failed to quarantine {filepath}: {e}")
        traceback.print_exc()
        logging.error(f"Failed to quarantine {filepath}: {e}")
        return False

def list_quarantine():
    try:
        files = os.listdir(QUARANTINE_DIR)
        if not files:
            print("Quarantine is empty.")
        else:
            print("Quarantined files:")
            for f in files:
                print(f"- {f}")
    except Exception as e:
        logging.error(f"Error listing quarantine files: {e}")

from cryptography.fernet import Fernet

def release_from_quarantine(filename, dest_dir):
    src = os.path.join(QUARANTINE_DIR, filename)
    if filename.endswith('.enc'):
        out_name = filename[:-4]
    else:
        out_name = filename
    dest = os.path.join(dest_dir, out_name)
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except Exception as e:
        logging.error(f"Error creating destination directory {dest_dir}: {e}")
        return
    if os.path.exists(src):
        key = os.environ.get('FERNET_KEY')
        if not key:
            print('FERNET_KEY not set in environment.')
            return
        fernet = Fernet(key)
        with open(get_resource_path(os.path.join(src)), 'rb') as f:
            encrypted = f.read()
        try:
            decrypted = fernet.decrypt(encrypted)
        except Exception as e:
            print(f'Failed to decrypt: {e}')
            return
        with open(get_resource_path(os.path.join(dest)), 'wb') as f:
            f.write(decrypted)
        os.remove(src)
        print(f"Released {out_name} to {dest_dir} and removed {filename} from quarantine")
    else:
        print(f"File not found in quarantine: {filename}")

def delete_from_quarantine(filename):
    src = os.path.join(QUARANTINE_DIR, filename)
    if not os.path.exists(src):
        print(f"File not found in quarantine: {filename}")
        logging.error(f"File not found in quarantine for deletion: {filename}")
        return
    confirm = input(f"Are you sure you want to permanently delete '{filename}' from quarantine? [y/N]: ").strip().lower()
    if confirm != 'y':
        print("Deletion cancelled by user.")
        logging.info(f"Deletion cancelled by user for {filename}")
        return
    try:
        os.remove(src)
        logging.info(f"Deleted {filename} from quarantine.")
        print(f"Deleted {filename} from quarantine.")
        logging.warning(f"Deleted {filename} from quarantine.")
    except FileNotFoundError:
        logging.error(f"File not found in quarantine: {filename}")
    except Exception as e:
        logging.error(f"Error deleting {filename} from quarantine: {e}")

def show_logs():
    try:
        with open(get_resource_path(os.path.join(LOG_FILE)), 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print("Log file not found.")
    except Exception as e:
        logging.error(f"Error reading log file: {e}")

# --- Update Mechanisms ---
__version__ = "1.0.0"

def update_defender_signatures():
    """
    Update system antivirus signatures.
    Windows: Windows Defender (Update-MpSignature)
    macOS/Linux/ChromeOS: ClamAV (freshclam)
    """
    import platform
    import shutil
    system = platform.system()
    if system == 'Windows':
        try:
            result = subprocess.run(  # nosem; nosec B603
                [POWERSHELL_PATH, '-Command', 'Update-MpSignature'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("Windows Defender signatures updated successfully.")
            else:
                print(f"Failed to update signatures: {result.stderr}")
        except Exception as e:
            print(f"Error updating signatures: {e}")
    else:
        freshclam = shutil.which('freshclam')
        if not freshclam:
            print("ClamAV not installed. Install with: brew install clamav (macOS) or sudo apt install clamav (Linux)")
            return
        try:
            result = subprocess.run(  # nosem; nosec B603
                [freshclam, '--no-warnings'],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print("ClamAV signatures updated successfully.")
            else:
                print(f"Failed to update ClamAV signatures: {result.stderr}")
        except Exception as e:
            print(f"Error updating ClamAV signatures: {e}")

def check_for_app_update(current_version, update_url):
    """
    Check for a new version of the app from a remote source.
    update_url: URL to a text file with the latest version string.
    """
    import requests
    try:
        resp = requests.get(update_url, timeout=10)
        resp.raise_for_status()
        latest_version = resp.text.strip()
        if latest_version != current_version:
            print(f"Update available: {latest_version} (current: {current_version})")
            print("Visit the project website or release page to download the new version.")
        else:
            print("App is up to date.")
    except Exception as e:
        print(f"Failed to check for updates: {e}")

def monitor():
    print("Starting real-time protection (folder monitoring)...")
    import os
    import sys
    import subprocess
    # --- Windows subprocess window suppression ---
    if sys.platform == 'win32':
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
    else:
        DETACHED_PROCESS = 0
        CREATE_NO_WINDOW = 0
    basedir = os.path.dirname(os.path.abspath(__file__))
    folder_watcher_path = os.path.join(basedir, 'folder_watcher.py')
    subprocess.Popen([  # nosem; nosec B603
        sys.executable, folder_watcher_path
    ], creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(
        description="Antivirus CLI - Protect your files with scanning, "
                    "quarantine, and monitoring."
    )
    subparsers = parser.add_subparsers(dest='command')

    scan_parser = subparsers.add_parser('scan', help='Scan a file or folder')
    scan_parser.add_argument('path', help='Path to file or folder to scan')

    subparsers.add_parser('monitor', help='Start real-time folder monitoring')

    quarantine_parser = subparsers.add_parser('quarantine', help='Manage quarantine')
    quarantine_subparsers = quarantine_parser.add_subparsers(dest='quarantine_action', required=True)

    quarantine_list_parser = quarantine_subparsers.add_parser('list', help='List quarantined files')
    # No additional arguments

    quarantine_release_parser = quarantine_subparsers.add_parser('release', help='Release a file from quarantine')
    quarantine_release_parser.add_argument('file', help='Quarantined file to release')
    quarantine_release_parser.add_argument('dest', help='Destination directory to release the file to')

    quarantine_delete_parser = quarantine_subparsers.add_parser('delete', help='Delete a file from quarantine')
    quarantine_delete_parser.add_argument('file', help='Quarantined file to delete')

    args = parser.parse_args()

    try:
        if args.command == 'scan':
            if not args.path:
                print('Please provide a --path to scan.')
                return
            scan_path(args.path)
        elif args.command == 'quarantine':
            if args.quarantine_action == 'list':
                list_quarantine()
            elif args.quarantine_action == 'release':
                if not args.file or not args.dest:
                    print('Please provide <file> (quarantined) and <dest> (destination).')
                    return
                release_from_quarantine(args.file, args.dest)
            elif args.quarantine_action == 'delete':
                if not args.file:
                    print('Please provide <file> to delete from quarantine.')
                    return
                delete_from_quarantine(args.file)
        elif args.command == 'logs':
            show_logs()
        elif args.command == 'monitor':
            monitor()
        elif args.command == 'update-signatures':
            update_defender_signatures()
        elif args.command == 'check-update':
            check_for_app_update(__version__, args.update_url)
    except Exception as e:
        logging.error(f"Error in main CLI execution: {e}")

if __name__ == "__main__":
    main()