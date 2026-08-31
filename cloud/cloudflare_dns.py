#!/usr/bin/env python3
"""Cloudflare DNS-01 challenge solver for ACME certificate issuance.

Uses the Cloudflare API (API token preferred) to create/delete the
_acme-challenge TXT record. This bypasses HTTP-01 and works behind the
Cloudflare proxy because validation is done against DNS.

Usage:
    python cloud/cloudflare_dns.py create <fqdn> <value>
    python cloud/cloudflare_dns.py delete <fqdn> [<value>]

Environment:
    CLOUDFLARE_API_TOKEN - Cloudflare API token with Zone:Read + DNS:Edit
                           permissions for the target zone.
    Optionally:
    CLOUDFLARE_API_EMAIL + CLOUDFLARE_API_KEY (legacy global key).
"""
import os
import re
import sys
import time
import logging
import requests

API_BASE = 'https://api.cloudflare.com/client/v4'

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)


def _validate_fqdn(fqdn):
    """Allow only standard DNS FQDNs with underscore/hyphen labels."""
    if not isinstance(fqdn, str) or not fqdn or len(fqdn) > 253:
        return False
    if fqdn.startswith('.') or fqdn.endswith('.'):
        return False
    label = r'[A-Za-z0-9_]([A-Za-z0-9\-_]{0,61}[A-Za-z0-9])?'
    return re.fullmatch(f'({label}\\.)+[A-Za-z]{{2,}}', fqdn) is not None


def _headers():
    """Build Cloudflare API request headers."""
    token = os.environ.get('CLOUDFLARE_API_TOKEN', '').strip()
    if token:
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
    email = os.environ.get('CLOUDFLARE_API_EMAIL', '').strip()
    key = os.environ.get('CLOUDFLARE_API_KEY', '').strip()
    if not email or not key:
        raise RuntimeError(
            'Set CLOUDFLARE_API_TOKEN or both CLOUDFLARE_API_EMAIL and CLOUDFLARE_API_KEY'
        )
    return {
        'X-Auth-Email': email,
        'X-Auth-Key': key,
        'Content-Type': 'application/json',
    }


def _request(method, path, **kwargs):
    """Make a Cloudflare API request and return the JSON payload."""
    url = f'{API_BASE}{path}'
    headers = _headers()
    resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    try:
        data = resp.json()
    except Exception:
        data = {'errors': [{'message': resp.text}]}
    if not resp.ok:
        errors = data.get('errors', [])
        msg = errors[0].get('message', 'unknown') if errors else resp.text
        raise RuntimeError(f'Cloudflare API {method} {path} failed ({resp.status_code}): {msg}')
    return data


def _find_zone(fqdn):
    """Return the zone ID and matching zone name for an FQDN."""
    parts = fqdn.rstrip('.').split('.')
    # Walk from the full FQDN down to the TLD, looking for a matching zone.
    for start in range(len(parts) - 1):
        candidate = '.'.join(parts[start:])
        data = _request('GET', '/zones', params={'name': candidate})
        zones = data.get('result', [])
        for zone in zones:
            if zone.get('name') == candidate:
                return zone['id'], candidate
    raise RuntimeError(f'No Cloudflare zone found for {fqdn}')


def _record_id(zone_id, fqdn, value=None):
    """Return the ID of an existing TXT record, optionally matching value."""
    params = {'type': 'TXT', 'name': fqdn.rstrip('.')}
    data = _request('GET', f'/zones/{zone_id}/dns_records', params=params)
    for rec in data.get('result', []):
        if value is None or rec.get('content') == value:
            return rec['id']
    return None


def create_txt_record(fqdn, value):
    """Create (or update) the _acme-challenge TXT record."""
    if not _validate_fqdn(fqdn):
        raise ValueError(f'Invalid FQDN: {fqdn}')
    zone_id, _ = _find_zone(fqdn)
    record_name = fqdn.rstrip('.')
    payload = {'type': 'TXT', 'name': record_name, 'content': value, 'ttl': 120}

    existing_id = _record_id(zone_id, fqdn)
    if existing_id:
        _request('PUT', f'/zones/{zone_id}/dns_records/{existing_id}', json=payload)
        log.info(f'Updated TXT record: {record_name}')
    else:
        _request('POST', f'/zones/{zone_id}/dns_records', json=payload)
        log.info(f'Created TXT record: {record_name}')
    return True


def delete_txt_record(fqdn, value=None):
    """Delete the _acme-challenge TXT record. If value is supplied, only
    delete the record with matching content."""
    if not _validate_fqdn(fqdn):
        raise ValueError(f'Invalid FQDN: {fqdn}')
    zone_id, _ = _find_zone(fqdn)
    deleted = False
    params = {'type': 'TXT', 'name': fqdn.rstrip('.')}
    data = _request('GET', f'/zones/{zone_id}/dns_records', params=params)
    for rec in data.get('result', []):
        if value is None or rec.get('content') == value:
            _request('DELETE', f'/zones/{zone_id}/dns_records/{rec["id"]}')
            log.info(f'Deleted TXT record: {rec["name"]}')
            deleted = True
    return deleted


def wait_for_dns(fqdn, expected_value, max_wait=180, nameservers=None):
    """Wait for the TXT record to be visible via public DNS resolvers."""
    nameservers = nameservers or ['1.1.1.1', '8.8.8.8']
    try:
        import dns.resolver
    except ImportError:
        log.warning('dnspython not installed; skipping DNS propagation check')
        return True

    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameservers
    resolver.timeout = 5
    resolver.lifetime = 5

    log.info(f'Waiting for DNS propagation (max {max_wait}s)...')
    start = time.time()
    while time.time() - start < max_wait:
        try:
            answers = resolver.resolve(fqdn.rstrip('.'), 'TXT')
            for rdata in answers:
                val = str(rdata).strip('"')
                if expected_value in val:
                    log.info(f'DNS propagated! Found: {val[:50]}...')
                    return True
        except Exception:
            pass
        time.sleep(10)
    log.warning('DNS propagation timeout - proceeding anyway')
    return True


def main():
    if 'CLOUDFLARE_API_TOKEN' not in os.environ and (
        'CLOUDFLARE_API_EMAIL' not in os.environ or 'CLOUDFLARE_API_KEY' not in os.environ
    ):
        print('Error: set CLOUDFLARE_API_TOKEN or both CLOUDFLARE_API_EMAIL and CLOUDFLARE_API_KEY')
        sys.exit(1)

    if len(sys.argv) < 3:
        print('Usage:')
        print('  python cloudflare_dns.py create <fqdn> <value>')
        print('  python cloudflare_dns.py delete <fqdn> [<value>]')
        sys.exit(1)

    action = sys.argv[1]
    fqdn = sys.argv[2]
    value = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        if action == 'create':
            if not value:
                print('Error: value required for create')
                sys.exit(1)
            create_txt_record(fqdn, value)
        elif action == 'delete':
            delete_txt_record(fqdn, value)
        else:
            print(f'Unknown action: {action}')
            sys.exit(1)
    except Exception as e:
        log.error(f'Failed: {e}', exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
