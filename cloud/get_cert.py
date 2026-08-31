#!/usr/bin/env python3
r"""Get a Let's Encrypt certificate using DNS-01 challenge via Cloudflare DNS.

This completely bypasses the need for port 80 to be open and works when the
site is proxied through Cloudflare, because validation is performed against DNS.

Usage:
    python get_cert.py

Output:
    C:\caddy\certs\isolation-bytes.com.crt  (certificate + chain)
    C:\caddy\certs\isolation-bytes.com.key  (private key)

Environment:
    CLOUDFLARE_API_TOKEN  (preferred) or CLOUDFLARE_API_EMAIL + CLOUDFLARE_API_KEY
    CERT_DOMAIN           (default: isolation-bytes.com)
    CERT_DIR              (default: C:/caddy/certs)
"""
import os
import re
import sys
import time
import logging
import hashlib
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# ACME client
from acme import client as acme_client
from acme import messages
from acme import challenges as acme_challenges
from acme import crypto_util as acme_crypto_util
import josepy

# Cloudflare DNS solver
import cloudflare_dns


def _validate_fqdn(fqdn):
    """Allow only standard DNS FQDNs with underscore/hyphen labels."""
    if not isinstance(fqdn, str) or not fqdn or len(fqdn) > 253:
        return False
    if fqdn.startswith('.') or fqdn.endswith('.'):
        return False
    label = r'[A-Za-z0-9_]([A-Za-z0-9\-_]{0,61}[A-Za-z0-9])?'
    return re.fullmatch(f'({label}\\.)+[A-Za-z]{{2,}}', fqdn) is not None


# Configuration
DOMAIN = os.environ.get('CERT_DOMAIN', 'isolation-bytes.com').strip()
if not _validate_fqdn(DOMAIN):
    raise SystemExit(f'Invalid CERT_DOMAIN value: {DOMAIN!r}')
default_cert_dir = 'C:/caddy/certs' if os.name == 'nt' else '/opt/antivirus-server/certs'
CERT_DIR = Path(os.environ.get('CERT_DIR', default_cert_dir))
ACME_DIR = 'https://acme-v02.api.letsencrypt.org/directory'

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)


def wait_for_dns(fqdn, expected_value, max_wait=180):
    """Wait for the TXT record to propagate using Cloudflare/Google resolvers."""
    log.info(f'Waiting for DNS propagation (max {max_wait}s)...')
    try:
        import dns.resolver
    except ImportError:
        log.warning('dnspython not installed; skipping propagation check')
        return True

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']
    resolver.timeout = 5
    resolver.lifetime = 5

    start = time.time()
    while time.time() - start < max_wait:
        try:
            answers = resolver.resolve(fqdn, 'TXT')
            for rdata in answers:
                val = str(rdata).strip('"')
                if expected_value in val:
                    log.info(f'DNS propagated! Found: {val[:50]}...')
                    return True
        except Exception:
            pass
        time.sleep(10)
    log.warning('DNS propagation timeout - proceeding anyway')
    return True  # Proceed anyway, Let's Encrypt will verify


def get_certificate():
    """Main function to get a certificate via DNS-01 challenge."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Generate account key
    log.info('Generating ACME account key...')
    account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    account_key_pem = account_key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )
    account_jwk = josepy.JWKRSA(key=account_key)

    # Generate domain private key
    log.info(f'Generating private key for {DOMAIN}...')
    domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    domain_key_pem = domain_key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )

    # Save private key
    key_path = CERT_DIR / f'{DOMAIN}.key'
    key_path.write_bytes(domain_key_pem)
    log.info(f'Saved private key: {key_path}')

    # Create CSR
    log.info('Creating CSR...')
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(DOMAIN),
            x509.DNSName(f'www.{DOMAIN}'),
        ]),
        critical=False,
    ).sign(domain_key, hashes.SHA256())

    csr_pem = csr.public_bytes(Encoding.PEM)

    # Connect to ACME server
    log.info('Connecting to Let\'s Encrypt...')
    net = acme_client.ClientNetwork(
        account=None,
        key=account_jwk,
        alg=josepy.RS256,
        verify_ssl=True,
    )
    directory = messages.Directory.from_json(net.get(ACME_DIR).json())
    client = acme_client.ClientV2(directory, net=net)

    # Register account
    log.info('Registering ACME account...')
    registration = messages.NewRegistration.from_data(
        contact=('mailto:admin@' + DOMAIN,),
        terms_of_service_agreed=True,
    )
    client.new_account(registration)
    log.info('Account registered')

    # Order certificate — new_order takes CSR PEM bytes directly
    log.info(f'Ordering certificate for {DOMAIN} and www.{DOMAIN}...')
    order = client.new_order(csr_pem)
    log.info('Order created')

    # Solve challenges
    for authz in order.authorizations:
        domain = authz.body.identifier.value
        log.info(f'Processing authorization for {domain}...')

        # Find DNS-01 challenge
        dns_challenge = None
        for chall in authz.body.challenges:
            if isinstance(chall.chall, acme_challenges.DNS01):
                dns_challenge = chall
                break

        if not dns_challenge:
            log.error(f'No DNS-01 challenge found for {domain}')
            return False

        # Compute the TXT record value
        response, txt_value = dns_challenge.chall.response_and_validation(account_jwk)
        txt_name = dns_challenge.chall.validation_domain_name(domain)

        # Create TXT record
        if not cloudflare_dns.create_txt_record(txt_name, txt_value):
            log.error(f'Failed to create TXT record for {domain}')
            return False

        # Wait for DNS propagation — give it extra time for Let's Encrypt resolvers
        wait_for_dns(txt_name, txt_value, max_wait=300)

        # Answer challenge
        log.info('Answering challenge...')
        client.answer_challenge(dns_challenge, response)

        # Wait for authorization — give Let's Encrypt time to verify
        log.info('Waiting for authorization (up to 5 min)...')
        deadline = time.time() + 300
        authz_state = None
        while time.time() < deadline:
            authz_state, _ = client.poll(authz)
            status = authz_state.body.status
            log.info(f'  Authorization status: {status}')
            if status in (messages.STATUS_VALID, messages.STATUS_INVALID):
                break
            time.sleep(5)

        # Only clean up TXT record AFTER verification is done
        cloudflare_dns.delete_txt_record(txt_name)

        if authz_state.body.status != messages.STATUS_VALID:
            # Try to get error details
            try:
                for chall in authz_state.body.challenges:
                    if chall.error:
                        log.error(f'Challenge error: {chall.error}')
            except Exception:
                pass
            log.error(f'Authorization failed for {domain}: status={authz_state.body.status}')
            return False
        log.info(f'Authorization valid for {domain}')

    # Finalize order
    log.info('Finalizing order...')
    import datetime as dt
    deadline = dt.datetime.now() + dt.timedelta(seconds=120)
    order = client.finalize_order(order, deadline)

    # Download certificate
    log.info('Downloading certificate...')
    cert_chain_pem = order.fullchain_pem

    cert_path = CERT_DIR / f'{DOMAIN}.crt'
    cert_path.write_text(cert_chain_pem, encoding='utf-8')
    log.info(f'Saved certificate: {cert_path}')

    # Also save as fullchain.pem and privkey.pem for Caddy
    (CERT_DIR / 'fullchain.pem').write_text(cert_chain_pem, encoding='utf-8')
    (CERT_DIR / 'privkey.pem').write_bytes(domain_key_pem)
    log.info('Saved fullchain.pem and privkey.pem')

    return True


if __name__ == '__main__':
    log.info(f'Starting DNS-01 certificate acquisition for {DOMAIN}')
    log.info(f'Certificates will be saved to {CERT_DIR}')
    try:
        if get_certificate():
            log.info('SUCCESS! Certificate obtained.')
            log.info(f'  Certificate: {CERT_DIR / (DOMAIN + ".crt")}')
            log.info(f'  Private key: {CERT_DIR / (DOMAIN + ".key")}')
            log.info('Update your Caddyfile to use these certificates.')
            sys.exit(0)
        else:
            log.error('FAILED to obtain certificate.')
            sys.exit(1)
    except Exception as e:
        log.error(f'Exception: {e}', exc_info=True)
        sys.exit(1)
