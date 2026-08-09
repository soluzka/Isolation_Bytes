"""
Central configuration module for all network and crypto settings.
Import this module wherever you need access to API keys, endpoints, or encryption settings.
"""
import os
from dotenv import load_dotenv
load_dotenv()

# --- Base Directory ---
BASEDIR = os.path.dirname(os.path.abspath(__file__))

# --- Crypto Settings ---
FERNET_KEY = os.environ.get('FERNET_KEY')
if not FERNET_KEY or len(FERNET_KEY) != 44:
    raise EnvironmentError("FERNET_KEY environment variable must be set to a valid 44-character Fernet key.")

# --- Network/Open Threat Intelligence Settings ---
# Free, open blocklists and threat feeds (no API key required)
OPEN_BLOCKLISTS = [
    # FireHOL Level 1 (IPs known to be malicious)
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    # Emerging Threats Compromised IPs
    "https://rules.emergingthreats.net/blocklists/compromised-ips.txt",
    # Abuse.ch SSL Blacklist
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    # URLHaus (malicious URLs)
    "https://urlhaus.abuse.ch/downloads/text/"
]

# Local scanning settings
USE_CLAMAV = True  # Set to True to use ClamAV if available
USE_YARA = True    # Set to True to use YARA rules if available
CUSTOM_SIGNATURE_PATH = os.path.join(BASEDIR, 'malware_signatures.txt')  # Your own signature DB

# Safe Downloader API (local, no API key needed by default)
SAFE_API_KEY = os.environ.get('SAFE_API_KEY', '')
SAFE_API_URL = os.environ.get('SAFE_API_URL', 'http://localhost:5000/api/safe_download')

# Project Honey Pot HTTP:BL / DNSBL API Key (for threat intelligence lookups)
HTTPBL_API_KEY = os.environ.get('HTTPBL_API_KEY', '')  # Set this in your .env or system environment

# Encrypted/quarantine folders
import sys
import platform

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASEDIR = get_basedir()
import tempfile
QUARANTINE_FOLDER = os.path.join(tempfile.gettempdir(), 'Defender_Quarantine')
FAILED_QUARANTINE_FOLDER = os.path.join(BASEDIR, 'failed_quarantine')
ENCRYPTED_FOLDER = os.path.join(BASEDIR, 'encrypted')

# Ensure folders exist
for folder in [QUARANTINE_FOLDER, FAILED_QUARANTINE_FOLDER, ENCRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# --- Feature Flags ---
USE_YARA = True  # Set to True to enable YARA scanning

# Set strict permissions on quarantine folders
if platform.system() == 'Windows':
    import subprocess
    import getpass
    username = getpass.getuser()
    for folder in [QUARANTINE_FOLDER, FAILED_QUARANTINE_FOLDER]:
        try:
            subprocess.run([  # nosem; nosec B603
                'icacls', folder,
                '/inheritance:r',
                f'/grant:r', f'{username}:F',
                '/remove', 'Users', 'Everyone'
            ], check=True, capture_output=True)
        except Exception as e:
            print(f'Could not set Windows ACLs on {folder}: {e}')
else:
    import stat
    for folder in [QUARANTINE_FOLDER, FAILED_QUARANTINE_FOLDER]:
        try:
            os.chmod(folder, stat.S_IRWXU)  # nosec B103
        except Exception as e:
            print(f'Could not set chmod 700 on {folder}: {e}')
