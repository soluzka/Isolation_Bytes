from utils.paths import get_resource_path
import os

import os
import re
import ipaddress
from typing import List, Tuple
import logging
import unicodedata
import idna

BLOCKLISTS_DIR = os.path.join(os.path.dirname(__file__), "blocklists")
PHISHING_DOMAINS_FILE = os.path.join(BLOCKLISTS_DIR, "phishing_domains.txt")
PHISHING_IPS_FILE = os.path.join(BLOCKLISTS_DIR, "phishing_ips.txt")

BUILTIN_PHISHING_DOMAINS = [
    'login.microsoftonline.com.phish.example',
    'secure-update.example',
    'paypal-account-security.example',
]

BUILTIN_PHISHING_IPS = [
    '185.234.219.191',
    '91.219.236.179',
]

def load_blocklist(path, fallback):
    try:
        if os.path.exists(path):
            with open(get_resource_path(os.path.join(path)), 'r') as f:
                return set(line.strip() for line in f if line.strip())
    except Exception:
        pass
    return set(fallback)

PHISHING_DOMAINS = load_blocklist(PHISHING_DOMAINS_FILE, BUILTIN_PHISHING_DOMAINS)
PHISHING_IPS = load_blocklist(PHISHING_IPS_FILE, BUILTIN_PHISHING_IPS)

# Improved regex for IP addresses and suspicious URLs
IP_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
URL_REGEX = re.compile(r'https?://(?:[\w.-]+|xn--[\w-]+)(?:/\S*)?')

# Suspicious TLDs (expand as needed)
SUSPICIOUS_TLDS = {'.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.zip', '.xyz'}


def is_phishing_ip(ip: str) -> bool:
    # Check if IP is in known phishing list or is a public IP (not RFC1918/private)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip in PHISHING_IPS:
            return True
        if not ip_obj.is_private and not ip_obj.is_loopback:
            # Optionally, add more logic for suspicious ranges
            return False  # Only block known for now
    except ValueError:
        pass
    return False


def is_phishing_url(url: str) -> bool:
    # Check against blocklist
    for domain in PHISHING_DOMAINS:
        if domain in url:
            return True
    # Heuristic: suspicious TLD
    try:
        tld = '.' + url.split('.')[-1].split('/')[0].lower()
        if tld in SUSPICIOUS_TLDS:
            return True
    except Exception:
        pass
    # Heuristic: excessive subdomains
    try:
        host = url.split('//')[1].split('/')[0]
        if host.count('.') > 3:
            return True
    except Exception:
        pass
    # Heuristic: unicode/homograph attacks
    try:
        host = url.split('//')[1].split('/')[0]
        decoded = idna.decode(host.encode('utf-8'))
        if any(ord(c) > 127 for c in decoded):
            return True
    except Exception:
        pass
    return False


try:
    from phishing_ml import ml_phishing_score
except ImportError:
    def ml_phishing_score(text: str) -> float:
        """
        Fallback ML stub if phishing_ml.py is not available.
        Returns a conservative score of 0.5 to err on the side of caution.
        """
        return 0.5

def scan_file_for_phishing(file_path: str) -> List[Tuple[str, str]]:
    """
    Scans a file for suspicious IPs, phishing URLs, and applies heuristics/ML.
    Returns a list of tuples: (type, value)
    """
    results = []
    try:
        with open(get_resource_path(os.path.join(file_path)), 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Check for suspicious IPs
            for ip in set(IP_REGEX.findall(content)):
                if is_phishing_ip(ip):
                    results.append(('ip', ip))
                    
            # Check for suspicious URLs
            for url in set(URL_REGEX.findall(content)):
                if is_phishing_url(url):
                    results.append(('url', url))
            
            # ML/heuristic scan
            try:
                score = ml_phishing_score(content)
            except Exception as e:
                logging.error(f"ML scoring error: {e}")
                score = 0.5  # Use conservative default score on error
            if score > 0.8:  # High confidence threshold
                results.append(('ml', f"ML phishing score: {score:.2f} (high confidence)"))
            elif score > 0.6:  # Medium confidence
                results.append(('ml', f"ML phishing score: {score:.2f} (medium confidence)"))
    except Exception as e:
                logging.error(f"ML scoring error: {e}")
                results.append(('error', f"ML scoring failed: {str(e)}"))
                
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
        results.append(('error', str(e)))
        
    return results
import os
import shutil
import requests

# Utility to trigger live feed/blocklist updates
from phishing_live_feeds import update_all_blocklists

def refresh_blocklists():
    update_all_blocklists()
    global PHISHING_DOMAINS, PHISHING_IPS
    PHISHING_DOMAINS = load_blocklist(PHISHING_DOMAINS_FILE, BUILTIN_PHISHING_DOMAINS)
    PHISHING_IPS = load_blocklist(PHISHING_IPS_FILE, BUILTIN_PHISHING_IPS)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python phishing_detector.py <file_to_scan>")
    else:
        file_to_scan = sys.argv[1]
        findings = scan_file_for_phishing(file_to_scan)
        if findings:
            print("Phishing indicators found:")
            for kind, value in findings:
                print(f"  [{kind}] {value}")
            # Quarantine the file
            quarantine_dir = os.path.join(os.path.dirname(file_to_scan), "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            dest = os.path.join(quarantine_dir, os.path.basename(file_to_scan))
            try:
                shutil.move(file_to_scan, dest)
                print(f"File '{file_to_scan}' has been quarantined to '{dest}'.")
            except Exception as e:
                print(f"Failed to quarantine file: {e}")
        else:
            print("No phishing indicators detected.")