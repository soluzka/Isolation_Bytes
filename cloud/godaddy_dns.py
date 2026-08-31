#!/usr/bin/env python3
"""GoDaddy DNS-01 challenge solver for ACME certificate issuance.

Uses the GoDaddy API with a Personal Access Token (PAT) to create/delete
TXT records for DNS-01 challenges. This bypasses the need for port 80
to be open (HTTP-01 challenge).

Usage:
    python godaddy_dns.py create <domain> <token>
    python godaddy_dns.py delete <domain> <token>
"""
import sys
import json
import requests
import time

TOKEN = 'gd_pat_nPtsrrr2zjljEbheV6vk5hXNGoNc8tvCQq5D2Ug0pTJ_56cfa605'
API_BASE = 'https://api.godaddy.com'
HEADERS = {
    'Authorization': f'Bearer {TOKEN}',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}


def get_domain_root(fqdn):
    """Extract the root domain from an FQDN."""
    parts = fqdn.rstrip('.').split('.')
    # Handle common TLDs
    if len(parts) >= 2:
        return '.'.join(parts[-2:]), '.'.join(parts[:-2])
    return fqdn, ''


def create_txt_record(fqdn, value):
    """Create a TXT record for the DNS-01 challenge."""
    root, prefix = get_domain_root(fqdn)
    record_name = prefix if prefix else '@'

    # For _acme-challenge.domain.com, root is domain.com, prefix is _acme-challenge
    url = f'{API_BASE}/v1/domains/{root}/records/TXT/{record_name}'
    data = [{'data': value, 'ttl': 600}]

    print(f'Creating TXT record: {record_name}.{root} -> {value}')
    r = requests.put(url, headers=HEADERS, json=data, timeout=30)
    if r.status_code == 200:
        print('TXT record created successfully')
        # Wait for DNS propagation
        print('Waiting 30s for DNS propagation...')
        time.sleep(30)
        return True
    else:
        print(f'Error creating TXT record: {r.status_code} {r.text}')
        return False


def delete_txt_record(fqdn, value):
    """Delete the TXT record after the challenge is complete."""
    root, prefix = get_domain_root(fqdn)
    record_name = prefix if prefix else '@'

    url = f'{API_BASE}/v1/domains/{root}/records/TXT/{record_name}'
    r = requests.delete(url, headers=HEADERS, timeout=30)
    if r.status_code == 204:
        print(f'TXT record deleted: {record_name}.{root}')
        return True
    else:
        print(f'Error deleting TXT record: {r.status_code} {r.text}')
        return False


def main():
    if len(sys.argv) < 2:
        print('Usage:')
        print('  python godaddy_dns.py create <fqdn> <value>')
        print('  python godaddy_dns.py delete <fqdn> <value>')
        sys.exit(1)

    action = sys.argv[1]
    if action == 'create' and len(sys.argv) == 4:
        create_txt_record(sys.argv[2], sys.argv[3])
    elif action == 'delete' and len(sys.argv) == 4:
        delete_txt_record(sys.argv[2], sys.argv[3])
    else:
        print(f'Unknown action: {action}')
        sys.exit(1)


if __name__ == '__main__':
    main()
