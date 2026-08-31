"""Generate a signed credentials file for a customer."""
import os
import sys
import json
import base64
import hashlib
import argparse
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def _load_private_key():
    key_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'license_keys')
    key_path = os.path.join(key_dir, 'private.pem')
    if not os.path.exists(key_path):
        raise FileNotFoundError(f'Private key not found at {key_path}. Generate it first.')
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _hash_password(password, salt):
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def generate(username, password, machine_id, days):
    salt = base64.urlsafe_b64encode(os.urandom(16)).decode('ascii')
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).timestamp() if days > 0 else None
    data = {
        'username': username,
        'machine_id': machine_id,
        'salt': salt,
        'password_hash': _hash_password(password, salt),
    }
    if exp:
        data['exp'] = int(exp)

    private = _load_private_key()
    data_str = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = private.sign(data_str, padding.PKCS1v15(), hashes.SHA256())
    payload = dict(data)
    payload['signature'] = base64.b64encode(signature).decode('ascii')
    return payload


def main():
    parser = argparse.ArgumentParser(description='Generate signed Antivirus Server credentials.')
    parser.add_argument('--username', required=True)
    parser.add_argument('--password', required=True)
    parser.add_argument('--machine-id', required=True)
    parser.add_argument('--days', type=int, default=365, help='License validity in days; 0 = never.')
    parser.add_argument('--output', default='credentials.lic', help='Output file name.')
    args = parser.parse_args()

    payload = generate(args.username, args.password, args.machine_id, args.days)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)

    encoded = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('ascii')
    print(f'Credentials written to {args.output}')
    print('---BASE64---')
    print(encoded)
    print('---END---')


if __name__ == '__main__':
    main()
