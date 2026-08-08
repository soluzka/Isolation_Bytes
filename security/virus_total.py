from utils.paths import get_resource_path
import os

import requests
import os

API_KEY = os.environ.get('VT_API_KEY', '')

VT_URL = 'https://www.virustotal.com/api/v3/files/'

def get_basedir():
    import sys
    import os
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def scan_file_virustotal(filepath):
    """
    Submit a file hash to VirusTotal for scanning (requires API key).
    """
    import hashlib
    if not API_KEY or not os.path.isfile(filepath):
        return None
    with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    headers = {'x-apikey': API_KEY}
    resp = requests.get(VT_URL + file_hash, headers=headers)
    if resp.status_code == 200:
        return resp.json()
    return None