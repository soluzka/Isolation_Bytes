from utils.paths import get_resource_path
import os
import hashlib
import logging
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

API_KEY = os.environ.get('VT_API_KEY', '')
VT_URL = 'https://www.virustotal.com/api/v3/files/'


def get_basedir():
    import sys
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan_file_virustotal(filepath):
    """Submit a file hash to VirusTotal for scanning (requires API key)."""
    if not API_KEY or not os.path.isfile(filepath):
        return None
    try:
        with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        headers = {'x-apikey': API_KEY}
        resp = requests.get(VT_URL + file_hash, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logging.warning(f"VirusTotal scan failed for {filepath}: {e}")
        return None


def is_malicious(filepath):
    """Return True if VirusTotal reports the file as malicious/suspicious."""
    report = scan_file_virustotal(filepath)
    if not report:
        return False
    try:
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return int(stats.get('malicious', 0)) + int(stats.get('suspicious', 0)) > 0
    except Exception:
        return False


def _signature_db_path():
    return os.path.join(get_basedir(), 'malware_signatures.txt')


def add_signatures(filepath):
    """If VT says the file is malicious, add its hashes to the local signature file."""
    if not API_KEY or not os.path.isfile(filepath):
        return False
    try:
        with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
            data = f.read()
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()

        signature_db = _signature_db_path()
        existing = set()
        if os.path.exists(signature_db):
            with open(signature_db, 'r', encoding='utf-8') as f:
                existing = set(line.strip().lower() for line in f if ':' in line.strip())

        new_lines = []
        for htype, hval in [('md5', md5), ('sha1', sha1), ('sha256', sha256), ('sha512', sha512)]:
            line = f'virustotal:{htype}:{hval}'
            if line.lower() not in existing:
                new_lines.append(line)

        if new_lines:
            with open(signature_db, 'a', encoding='utf-8') as f:
                for line in new_lines:
                    f.write(line + '\n')
            logging.info(f"Added {len(new_lines)} VirusTotal-derived signatures")
        return True
    except Exception as e:
        logging.error(f"Failed to add VirusTotal signatures for {filepath}: {e}")
        return False


def check_and_update(filepath):
    """Check a file on VirusTotal and, if malicious, add its hashes locally."""
    if is_malicious(filepath):
        return add_signatures(filepath)
    return False
