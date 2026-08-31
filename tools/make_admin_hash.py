"""Generate a hard-to-crack admin username and secure password hash.

Supports bcrypt (preferred) and PBKDF2-HMAC-SHA256.
Outputs ready-to-use lines for your .env and cloud/.env files.

Usage:
    python tools/make_admin_hash.py
    python tools/make_admin_hash.py --username my_custom_admin --password my_secret_pass
    python tools/make_admin_hash.py --generate-username --generate-password
"""
import argparse
import hashlib
import os
import secrets
import string
import sys

try:
    import bcrypt
except ImportError:
    bcrypt = None


def generate_secure_username(prefix='soluzka_adm_', length=12):
    chars = string.ascii_lowercase + string.digits
    token = ''.join(secrets.choice(chars) for _ in range(length))
    return f"{prefix}{token}"


def generate_secure_password(length=24):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


def hash_password(password: str) -> str:
    if bcrypt:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    else:
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return f"pbkdf2:sha256:100000${salt}${h}"


def main():
    parser = argparse.ArgumentParser(description="Generate admin username and password hash.")
    parser.add_argument("--username", "-u", default="", help="Custom username (optional).")
    parser.add_argument("--password", "-p", default="", help="Password to hash (optional).")
    parser.add_argument("--generate-username", action="store_true", help="Generate a hard-to-guess username.")
    parser.add_argument("--generate-password", action="store_true", help="Generate a strong 24-character password.")
    args = parser.parse_args()

    username = args.username.strip()
    if not username or args.generate_username:
        username = generate_secure_username()

    password = args.password
    if not password or args.generate_password:
        password = generate_secure_password()
        print(f"\n[+] Generated Secure Password: {password}")
        print("    (Save this in a safe password manager!)\n")

    pw_hash = hash_password(password)

    print("=" * 60)
    print("ADMIN CREDENTIALS & HASH CONFIGURATION")
    print("=" * 60)
    print(f"Username:      {username}")
    print(f"Password Hash: {pw_hash}")
    print("-" * 60)
    print("Add to cloud/.env (or .env.server):")
    print(f"CLOUD_ADMIN_USERNAME={username}")
    print(f"CLOUD_ADMIN_PASSWORD_HASH={pw_hash}")
    print("-" * 60)
    print("Add to .env (for local dashboard):")
    print(f"ADMIN_USERNAME={username}")
    print(f"ADMIN_PASSWORD_HASH={pw_hash}")
    print("=" * 60)


if __name__ == '__main__':
    main()
