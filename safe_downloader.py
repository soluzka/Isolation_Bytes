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
from utils.extract import _safe_members
import ipaddress
import re
import socket
from urllib.parse import urlparse, urljoin

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _is_safe_url(url):
    """Validate that a URL is safe for server-side fetching.

    Blocks non-HTTP(S) schemes, embedded credentials, and any host that is a
    private/loopback/link-local/multicast/reserved IP or that resolves to one.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    host = parsed.hostname
    if not host:
        return False
    host = host.lower().strip()
    # Reject common loopback/localhost names
    if host in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
        return False
    # Reject literal IP addresses with private/restricted scopes
    try:
        addr = ipaddress.ip_address(host)
        if (addr.is_private or addr.is_loopback or addr.is_link_local or
                addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            return False
    except ValueError:
        pass  # Not a literal IP; fall through to DNS check

    # Reject hostnames whose DNS resolution currently points to internal IPs.
    # This is best-effort (DNS rebinding can still bypass it), so callers should
    # also avoid following unchecked redirects.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for _, _, _, _, sockaddr in infos:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
            if (addr.is_private or addr.is_loopback or addr.is_link_local or
                    addr.is_multicast or addr.is_reserved or addr.is_unspecified):
                return False
        except ValueError:
            continue
    return True


def _is_same_origin(url1, url2):
    """Return True if two URLs share scheme, host, and port."""
    try:
        a, b = urlparse(url1), urlparse(url2)
        port_a = a.port or (443 if a.scheme == 'https' else 80)
        port_b = b.port or (443 if b.scheme == 'https' else 80)
        return (a.scheme and a.scheme == b.scheme and
                a.hostname and a.hostname == b.hostname and
                port_a == port_b)
    except Exception:
        return False


def _safe_filename(name):
    """Sanitize a filename derived from a URL/path."""
    if not isinstance(name, str):
        name = str(name)
    name = name.replace('\x00', '')
    name = os.path.basename(name.replace('/', os.sep).replace('\\', os.sep))
    if name in ('', '.', '..') or '..' in name:
        name = 'download'
    name = re.sub(r'[^A-Za-z0-9_.\-]', '_', name)
    if not name:
        name = 'download'
    return name[:120]


def _sanitize_url(url):
    """Validate a URL for safe server-side fetching and return it.

    Acts as a CodeQL-recognized sanitizer: the returned URL has been verified
    to use HTTP(S), carry no embedded credentials, and point at a host that is
    not a private/loopback/link-local/multicast/reserved address (both as a
    literal IP and via DNS resolution). Raises ValueError if unsafe.
    """
    if not _is_safe_url(url):
        raise ValueError(f'Unsafe or invalid URL: {url}')
    return url


def _safe_get(url, max_redirects=5):
    """Fetch a URL after validation and with explicit redirect validation."""
    current = _sanitize_url(url)
    for _ in range(max_redirects):
        r = requests.get(current, stream=True, timeout=60, allow_redirects=False)  # codeql[py/full-ssrf]
        if r.is_redirect:
            location = r.headers.get('Location')
            if not location:
                return r
            current = _sanitize_url(urljoin(current, location))
            continue
        return r
    raise ValueError(f'Too many redirects from {url}')


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
                tar.extractall(extract_dir, members=_safe_members(tar), filter="data")
        return True
    except Exception as e:
        logging.error(f"Extraction failed for {filepath}: {e}")
        return False

def download_and_scan(url, encrypted_output=None, encrypted_folder=None):
    """Download `url`, scan it, and encrypt it to disk. Return a status dict."""
    if not encrypted_folder:
        encrypted_folder = os.environ.get('ENCRYPTED_FOLDER') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encrypted')
    os.makedirs(encrypted_folder, exist_ok=True)
    url_path = url.split('?')[0]
    name = _safe_filename(os.path.basename(url_path) or 'download')
    if not encrypted_output:
        encrypted_output = os.path.join(encrypted_folder, f'{name}.enc')
    encrypted_output = os.path.abspath(encrypted_output)
    if '\x00' in encrypted_output:
        raise ValueError('encrypted_output contains null bytes')
    temp_dir = tempfile.mkdtemp(prefix='safe_downloader_')
    try:
        download_path = os.path.join(temp_dir, name)
        r = _safe_get(url)
        r.raise_for_status()
        with open(get_resource_path(os.path.join(download_path)), 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        scan_targets = []
        extract_dir = os.path.join(temp_dir, 'extracted')
        if extract_archive(download_path, extract_dir):
            for root, _, files in os.walk(extract_dir):
                for fn in files:
                    scan_targets.append(os.path.join(root, fn))
        else:
            scan_targets = [download_path]

        for target in scan_targets:
            scan_success, malware_found, scan_message = scan_file_for_viruses(target)
            if not scan_success:
                return {'ok': False, 'deleted': True, 'error': f'scan failed for {target}: {scan_message}'}
            if malware_found:
                return {'ok': False, 'deleted': True, 'error': f'malware detected in {target}: {scan_message}'}

        encrypt_file(download_path, encrypted_output)
        return {'ok': True, 'encrypted_path': encrypted_output}
    finally:
        if os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


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
        # The encrypted file URL must come from the same API server we just
        # authenticated to, otherwise a malicious/compromised API could drive
        # SSRF or exfiltration.
        if not _is_same_origin(download_url, args.api_url):
            logging.error(f"Download URL does not match API origin: {download_url}")
            sys.exit(1)
        logging.info(f"Downloading encrypted file from {download_url}")
        r = requests.get(download_url, stream=True, timeout=60)
        if r.status_code == 200:
            temp_dir = tempfile.mkdtemp(prefix='safe_downloader_')
            name = _safe_filename(urlparse(download_url).path or 'download.enc')
            download_path = os.path.join(temp_dir, name)
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
                encrypt_file(download_path, output_encrypted)
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