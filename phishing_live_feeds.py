from utils.paths import get_resource_path
import os

import requests
import logging
import os

# Public phishing feeds (no API key required)
URLHAUS_DOMAINS_URL = "https://urlhaus.abuse.ch/downloads/text/"
ABUSECH_DOMAINS_URL = "https://feodotracker.abuse.ch/downloads/domainblocklist.txt"
ABUSEIPDB_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
# If these fail, you can manually download and place the files in the blocklists/ folder.

BLOCKLISTS_DIR = os.path.join(os.path.dirname(__file__), "blocklists")
PHISHING_DOMAINS_FILE = os.path.join(BLOCKLISTS_DIR, "phishing_domains.txt")
PHISHING_IPS_FILE = os.path.join(BLOCKLISTS_DIR, "phishing_ips.txt")

os.makedirs(BLOCKLISTS_DIR, exist_ok=True)

def update_phishing_domains():
    domains = set()
    try:
        # URLhaus
        r = requests.get(URLHAUS_DOMAINS_URL, timeout=30)
        if r.ok:
            for line in r.text.splitlines():
                if line.startswith('http'):
                    try:
                        domain = line.split('/')[2]
                        domains.add(domain)
                    except Exception:
                        pass
        # Abuse.ch
        r = requests.get(ABUSECH_DOMAINS_URL, timeout=30)
        if r.ok:
            for line in r.text.splitlines():
                if line and not line.startswith('#'):
                    domains.add(line.strip())
        with open(get_resource_path(os.path.join(PHISHING_DOMAINS_FILE)), 'w') as f:
            for d in sorted(domains):
                f.write(d + '\n')
        logging.info(f"Updated phishing domains: {len(domains)} entries.")
    except Exception as e:
        logging.error(f"Failed to update phishing domains: {e}")
    return domains

def update_phishing_ips():
    ips = set()
    try:
        # AbuseIPDB/FeodoTracker
        r = requests.get(ABUSEIPDB_FEED_URL, timeout=30)
        if r.ok:
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.add(line)
        with open(get_resource_path(os.path.join(PHISHING_IPS_FILE)), 'w') as f:
            for ip in sorted(ips):
                f.write(ip + '\n')
        logging.info(f"Updated phishing IPs: {len(ips)} entries.")
    except Exception as e:
        logging.error(f"Failed to update phishing IPs: {e}")
    return ips

def update_all_blocklists():
    update_phishing_domains()
    update_phishing_ips()

if __name__ == "__main__":
    update_all_blocklists()