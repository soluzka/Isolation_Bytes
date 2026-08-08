from utils.paths import get_resource_path
import os

import requests
import os

def get_basedir():
    import sys
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

SIGNATURE_DB = os.path.join(get_basedir(), 'malware_signatures.txt')
MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/'

def download_hashes():
    # print('Downloading latest malware hashes from MalwareBazaar API...')  # Removed to reduce spam
    resp = requests.post(MALWAREBAZAAR_API, data={"query": "get_recent"}, timeout=60)
    # print(f"API status code: {resp.status_code}")  # Removed to reduce spam
    # print(f"API response: {resp.text[:1000]}")  # Removed to reduce spam
    resp.raise_for_status()
    data = resp.json()
    hashes = set()
    if data.get("data"):
        for entry in data["data"]:
            sha256 = entry.get("sha256_hash")
            if sha256:
                hashes.add(sha256)
    # print(f'Downloaded {len(hashes):,} hashes.')  # Removed to reduce spam
    return hashes

def load_local_hashes():
    if not os.path.exists(SIGNATURE_DB):
        return set()
    with open(get_resource_path(os.path.join(SIGNATURE_DB)), 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_hashes(all_hashes):
    with open(get_resource_path(os.path.join(SIGNATURE_DB)), 'w') as f:
        for h in sorted(all_hashes):
            f.write(h + '\n')
    # print(f'Saved {len(all_hashes):,} hashes to {SIGNATURE_DB}')  # Removed to reduce spam

def update_signatures():
    remote = download_hashes()
    local = load_local_hashes()
    all_hashes = remote | local
    save_hashes(all_hashes)

if __name__ == '__main__':
    update_signatures()