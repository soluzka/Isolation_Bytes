import os
import sys
import json
import logging
import ipaddress
import requests
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

API_KEY = os.environ.get('URLHAUS_API_KEY', '')


def get_basedir():
    if 'ANTIVIRUS_RUNTIME_DIR' in os.environ:
        return os.environ['ANTIVIRUS_RUNTIME_DIR']
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def update_urlhaus_blocklists():
    """Fetch recent malicious URLs from URLhaus and append hosts to the
    phishing blocklists. Requires a free URLHAUS_API_KEY."""
    if not API_KEY:
        logging.debug("URLhaus API key not set; skipping")
        return 0
    try:
        domain_list = os.path.join(get_basedir(), 'blocklists', 'phishing_domains.txt')
        ip_list = os.path.join(get_basedir(), 'blocklists', 'phishing_ips.txt')

        existing_domains = set()
        existing_ips = set()
        for path, existing in [(domain_list, existing_domains), (ip_list, existing_ips)]:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    existing.update(line.strip() for line in f if line.strip())

        url = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'
        resp = requests.get(
            url,
            headers={'Auth-Key': API_KEY},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get('query_status') != 'ok':
            logging.warning(f"URLhaus query returned status: {data.get('query_status')}")
            return 0

        new_domains = []
        new_ips = []
        for entry in data.get('urls', []):
            raw_url = entry.get('url', '')
            if not raw_url:
                continue
            try:
                host = urlparse(raw_url).hostname
                if not host:
                    continue
                if _is_ip(host):
                    if host not in existing_ips:
                        new_ips.append(host)
                else:
                    if host not in existing_domains:
                        new_domains.append(host)
            except Exception as exc:
                logging.debug("Failed to parse URLhaus entry %r: %s", raw_url, exc)

        if new_domains:
            with open(domain_list, 'a', encoding='utf-8') as f:
                for d in new_domains:
                    f.write(d + '\n')
            logging.info(f"Added {len(new_domains)} URLhaus phishing domains")
        if new_ips:
            with open(ip_list, 'a', encoding='utf-8') as f:
                for ip in new_ips:
                    f.write(ip + '\n')
            logging.info(f"Added {len(new_ips)} URLhaus phishing IPs")
        return len(new_domains) + len(new_ips)

    except requests.exceptions.Timeout:
        logging.warning("URLhaus update timed out")
        return 0
    except Exception as e:
        logging.error(f"Failed to update URLhaus blocklists: {e}")
        return 0


if __name__ == '__main__':
    count = update_urlhaus_blocklists()
    print(f"Added {count} URLhaus entries")
