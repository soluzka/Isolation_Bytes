from utils.paths import get_resource_path
import os

# NOTE: For local development, the API server should be run with HTTP (not HTTPS) on port 5000.
import os
import sys
import requests
import logging
import tempfile
import shutil
from file_crypto import encrypt_file
from scan_utils import scan_file_for_viruses

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def extract_archive(filepath, extract_dir):
    import zipfile
    import tarfile

    filename = filepath.lower()
    try:
        if filename.endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif filename.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz')):
            with tarfile.open(get_resource_path(os.path.join(filepath)), 'r:*') as tar:
                tar.extractall(extract_dir, filter="data")
        return True
    except Exception as e:
        logging.error(f"Extraction failed for {filepath}: {e}")
        return False

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description='Safely download, scan, extract, and encrypt files from the internet using the app.py API.'
    )
    parser.add_argument('url', help='URL of the file to download')
    parser.add_argument('encrypted_output', help='Path to save the encrypted file')
    parser.add_argument('--api-url', default='http://localhost:5000/api/safe_download', help='URL of the app.py API endpoint')
    parser.add_argument('--api-key', default=None, help='API key for authentication (or set SAFE_API_KEY env var)')
    args = parser.parse_args()

    logging.basicConfig(
        filename='safe_downloader.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    api_key = args.api_key or os.environ.get('SAFE_API_KEY')
    if not api_key:
        # print('API key required. Provide with --api-key or set SAFE_API_KEY env var.')  # Removed to reduce spam
        sys.exit(1)

    ENCRYPTED_FOLDER = os.environ.get('ENCRYPTED_FOLDER') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encrypted')
    os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
    fernet_key = os.environ.get('FERNET_KEY')
    if not fernet_key or len(fernet_key) != 44:
        # print('[ERROR] FERNET_KEY environment variable must be set to a valid 44-character Fernet key.')  # Removed to reduce spam
        sys.exit(1)

    api_url = args.api_url
    url = args.url
    output_encrypted = args.encrypted_output

    try:
        headers = {'X-API-KEY': api_key, 'Content-Type': 'application/json'}
        payload = {'url': url}
        logging.info(f"Requesting API: {api_url} with url={url}")
        resp = requests.post(
            api_url, headers=headers, data=json.dumps(payload), timeout=30
        )
        if resp.status_code != 200:
            try:
                error = resp.json().get('error', resp.text)
            except Exception:
                error = resp.text
            # print(f"API error: {error}")  # Removed to reduce spam
            logging.error(f"API error: {error}")
            sys.exit(1)
        data = resp.json()
        download_url = data.get('download_url')
        if not download_url:
            # print('No download URL returned from API.')  # Removed to reduce spam
            sys.exit(1)
        logging.info(f"Downloading encrypted file from {download_url}")
        r = requests.get(download_url, stream=True, timeout=60)
        if r.status_code == 200:
            temp_dir = tempfile.mkdtemp()
            download_path = os.path.join(temp_dir, os.path.basename(download_url))
            with open(get_resource_path(os.path.join(download_path)), 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            # print(f"Downloaded file saved to: {download_path}")  # Removed to reduce spam
            logging.info(f"Downloaded file saved to: {download_path}")

            try:
                # Enhanced virus scanning with better result handling
                scan_success, malware_found, scan_message = scan_file_for_viruses(download_path)
                logging.info(f"Virus scan result for '{download_path}': success={scan_success}, malware_found={malware_found}, message='{scan_message}'")

                if not scan_success:
                    logging.error(f"Virus scanning failed for {download_path}: {scan_message}")
                    os.remove(download_path)
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    sys.exit(1)

                if malware_found:
                    logging.warning(f"Malware detected in downloaded file {download_path}: {scan_message}")
                    os.remove(download_path)
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    sys.exit(1)

                # Only continue if scan passed
                with open(get_resource_path(os.path.join(output_encrypted)), 'wb') as f:
                    encrypt_file(download_path, f)
                logging.info(f"Encrypted file saved to: {output_encrypted}")
                os.remove(download_path)
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                logging.error(f"Error during download/scan/encrypt: {e}")
                # Defensive cleanup
                if os.path.exists(download_path):
                    os.remove(download_path)
                shutil.rmtree(temp_dir, ignore_errors=True)
                sys.exit(1)
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()