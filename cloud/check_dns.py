"""Check DNS TXT records for the configured CERT_DOMAIN.

Useful for verifying that the ACME _acme-challenge TXT record has propagated
before or after running get_cert.py.
"""
import os
import sys

DOMAIN = os.environ.get('CERT_DOMAIN', 'isolation-bytes.com').strip('.')
RECORD = f'_acme-challenge.{DOMAIN}'

nameservers = ['1.1.1.1', '8.8.8.8']

try:
    import dns.resolver
except ImportError:
    print('dnspython is required: pip install dnspython')
    sys.exit(1)

resolver = dns.resolver.Resolver()
resolver.nameservers = nameservers
resolver.timeout = 5
resolver.lifetime = 5

print(f'Querying {RECORD} TXT via {nameservers}...')
try:
    answers = resolver.resolve(RECORD, 'TXT')
    found = False
    for rdata in answers:
        val = str(rdata).strip('"')
        print(f'TXT {RECORD:40} -> {val}')
        found = True
    if not found:
        print('No TXT records found.')
except Exception as e:
    print(f'Query failed: {e}')
    sys.exit(1)
