import os
import sys
import json
import logging
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

API_KEY = os.environ.get('THREATFOX_API_KEY', '')


def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def update_threatfox_signatures(days=1):
    """Fetch recent file hashes from ThreatFox and append them to malware_signatures.txt."""
    if not API_KEY:
        logging.debug("ThreatFox API key not set; skipping")
        return 0
    signature_db = os.path.join(get_basedir(), 'malware_signatures.txt')
    try:
        existing = set()
        if os.path.exists(signature_db):
            with open(signature_db, 'r', encoding='utf-8') as f:
                existing = set(line.strip().lower() for line in f if ':' in line.strip())

        url = 'https://threatfox-api.abuse.ch/api/v1/'
        payload = json.dumps({'query': 'get_iocs', 'days': days})
        resp = requests.post(
            url,
            data=payload,
            headers={'Content-Type': 'application/json', 'Auth-Key': API_KEY},
            timeout=60
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get('query_status') != 'ok':
            logging.warning(f"ThreatFox query returned status: {data.get('query_status')}")
            return 0

        new_lines = []
        for ioc in data.get('data', []):
            ioc_type = ioc.get('ioc_type', '')
            ioc_value = ioc.get('ioc', '')
            if ioc_type in ('sha256_hash', 'sha1_hash', 'md5_hash') and ioc_value:
                htype = ioc_type.replace('_hash', '')
                line = f'threatfox:{htype}:{ioc_value}'
                if line.lower() not in existing:
                    new_lines.append(line)

        if new_lines:
            with open(signature_db, 'a', encoding='utf-8') as f:
                for line in new_lines:
                    f.write(line + '\n')
            logging.info(f"Added {len(new_lines)} ThreatFox signatures")
        return len(new_lines)

    except requests.exceptions.Timeout:
        logging.warning("ThreatFox update timed out")
        return 0
    except Exception as e:
        logging.error(f"Failed to update ThreatFox signatures: {e}")
        return 0


if __name__ == '__main__':
    count = update_threatfox_signatures()
    print(f"Added {count} ThreatFox signatures")
