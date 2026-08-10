from utils.paths import get_resource_path
import os

import requests

def get_basedir():
    import sys
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

SIGNATURE_DB = os.path.join(get_basedir(), 'malware_signatures.txt')
MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/'

def download_hashes():
    """Download SHA1 and SHA256 hashes from MalwareBazaar in the format the
    scanner expects: source:hash_type:hash"""
    api_key = os.environ.get('MALWAREBAZAAR_API_KEY', '')
    headers = {}
    if api_key:
        headers['API-KEY'] = api_key
    resp = requests.post(MALWAREBAZAAR_API, data={"query": "get_recent"}, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    signatures = set()
    if data.get("data"):
        for entry in data["data"]:
            sha256 = entry.get("sha256_hash")
            if sha256:
                signatures.add(f"malwarebazaar:sha256:{sha256}")
            sha1 = entry.get("sha1_hash")
            if sha1:
                signatures.add(f"malwarebazaar:sha1:{sha1}")
    return signatures

def load_local_hashes():
    if not os.path.exists(SIGNATURE_DB):
        return set()
    with open(get_resource_path(os.path.join(SIGNATURE_DB)), 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_hashes(all_hashes):
    with open(get_resource_path(os.path.join(SIGNATURE_DB)), 'w') as f:
        for h in sorted(all_hashes):
            f.write(h + '\n')

def update_signatures():
    remote = download_hashes()
    local = load_local_hashes()
    all_hashes = remote | local
    save_hashes(all_hashes)

if __name__ == '__main__':
    update_signatures()