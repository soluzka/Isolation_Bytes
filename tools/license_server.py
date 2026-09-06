"""Simple Flask license server that talks to Square and issues signed licenses.

Environment variables (or a .env in the same folder):
    SQUARE_ACCESS_TOKEN   - Square API access token
    SQUARE_LOCATION_ID    - Square location ID
    SQUARE_ENVIRONMENT    - 'sandbox' or 'production' (default: sandbox)
    LICENSE_PRICE_CENTS   - Expected payment amount in cents (default: 1999 = $19.99)
    LICENSE_DAYS          - License validity in days (default: 365)
    PRIVATE_KEY           - Path to RSA private PEM (default: ..\license_keys\private.pem)
    PUBLIC_KEY            - Path to RSA public PEM (default: ..\license_keys\public.pem)
    FLASK_PORT            - Port to listen on (default: 5001)

Run:
    python tools/license_server.py
"""
import base64
import hashlib
import json
import os
import secrets
import smtplib
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from dotenv import load_dotenv
from flask import Flask, jsonify, request


BASE_DIR = Path(__file__).resolve().parent.parent
server_env = BASE_DIR / '.env.server'
if server_env.exists():
    load_dotenv(server_env, override=True)
else:
    load_dotenv(BASE_DIR / '.env', override=False)

app = Flask(__name__)


def _get(key, default=None):
    return os.environ.get(key, default)


SQUARE_TOKEN = _get('SQUARE_ACCESS_TOKEN')
SQUARE_LOCATION = _get('SQUARE_LOCATION_ID')
SQUARE_ENV = _get('SQUARE_ENVIRONMENT', 'sandbox').lower()
FIRST_PRICE_CENTS = int(_get('FIRST_PRICE_CENTS', '1999'))
RENEWAL_PRICE_CENTS = int(_get('RENEWAL_PRICE_CENTS', '999'))
LICENSE_DAYS = int(_get('LICENSE_DAYS', '365'))
MAX_DEVICES = int(_get('MAX_DEVICES_PER_PAYMENT', '1'))
ISSUED_PATH = Path(_get('ISSUED_LICENSES_FILE', BASE_DIR / 'issued_licenses.json'))
MACHINE_LICENSES_PATH = Path(_get('MACHINE_LICENSES_FILE', BASE_DIR / 'machine_licenses.json'))

SMTP_HOST = _get('SMTP_HOST', '')
SMTP_PORT = int(_get('SMTP_PORT', '587'))
SMTP_USER = _get('SMTP_USER', '')
SMTP_PASS = _get('SMTP_PASS', '')
FROM_EMAIL = _get('FROM_EMAIL', SMTP_USER)

PRIVATE_KEY = Path(_get('PRIVATE_KEY', BASE_DIR / 'license_keys' / 'private.pem'))
PUBLIC_KEY = Path(_get('PUBLIC_KEY', BASE_DIR / 'license_keys' / 'public.pem'))

SQUARE_HOST = 'https://connect.squareupsandbox.com' if SQUARE_ENV == 'sandbox' else 'https://connect.squareup.com'


def _load_private_key():
    if not PRIVATE_KEY.exists():
        raise FileNotFoundError(f'Private key not found: {PRIVATE_KEY}')
    with open(PRIVATE_KEY, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _hash_password(password, salt):
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return h


def _sign_license(license_data: dict):
    private_key = _load_private_key()
    signable = {k: v for k, v in license_data.items() if k != 'signature'}
    payload = json.dumps(signable, sort_keys=True, separators=(',', ':'))
    signature = private_key.sign(
        payload.encode('utf-8'),
        crypto_padding.PKCS1v15(),
        hashes.SHA256()
    )
    license_data['signature'] = base64.b64encode(signature).decode('ascii')
    return license_data


def _search_payment_by_email(email):
    if not SQUARE_TOKEN:
        raise RuntimeError('SQUARE_ACCESS_TOKEN not configured on the server')
    email = email.strip().lower()
    now = datetime.now(timezone.utc)
    begin = now - timedelta(days=30)
    url = f"{SQUARE_HOST}/v2/payments?begin_time={begin.isoformat()}&end_time={now.isoformat()}&sort_order=DESC"
    try:
        req = urllib.request.Request(
            url,
            headers={
                'Authorization': f'Bearer {SQUARE_TOKEN}',
                'Square-Version': '2024-06-04',
                'Content-Type': 'application/json'
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f'Square API error: {e.code} {body}')

    for payment in data.get('payments', []):
        if payment.get('status') != 'COMPLETED':
            continue
        payment_email = (payment.get('receipt_email') or payment.get('buyer_email_address') or '').strip().lower()
        if payment_email != email:
            continue
        amount = payment.get('amount_money', {}).get('amount', 0)
        if amount in (FIRST_PRICE_CENTS, RENEWAL_PRICE_CENTS):
            return payment['id']
    raise RuntimeError(f'No completed payment found for email {email} in the last 30 days. Make sure you used the same email at checkout.')


def _verify_square_payment(raw_id):
    if not SQUARE_TOKEN:
        raise RuntimeError('SQUARE_ACCESS_TOKEN not configured on the server')

    raw_id = raw_id.strip()
    payment = None

    # Try as a payment ID first.
    try:
        req = urllib.request.Request(
            f'{SQUARE_HOST}/v2/payments/{raw_id}',
            headers={
                'Authorization': f'Bearer {SQUARE_TOKEN}',
                'Square-Version': '2024-06-04',
                'Content-Type': 'application/json'
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        payment = data.get('payment')
    except urllib.error.HTTPError as e:
        if e.code != 404:
            body = e.read().decode('utf-8', errors='ignore')
            raise RuntimeError(f'Square API error: {e.code} {body}')

    # If not found, try as an order ID and list its payments.
    if not payment:
        try:
            req = urllib.request.Request(
                f'{SQUARE_HOST}/v2/payments?order_id={raw_id}',
                headers={
                    'Authorization': f'Bearer {SQUARE_TOKEN}',
                    'Square-Version': '2024-06-04',
                    'Content-Type': 'application/json'
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            payments = data.get('payments', [])
            payment = payments[0] if payments else None
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore')
            raise RuntimeError(f'Square API error: {e.code} {body}')

    if not payment:
        raise RuntimeError('No Square payment found for the given ID')

    status = payment.get('status')
    amount = payment.get('amount_money', {}).get('amount', 0)
    currency = payment.get('amount_money', {}).get('currency', 'USD')
    location_id = payment.get('location_id')

    if status != 'COMPLETED':
        raise RuntimeError(f'Payment status is {status}, not COMPLETED')
    if SQUARE_LOCATION and location_id and location_id != SQUARE_LOCATION:
        raise RuntimeError('Payment was not made at the expected Square location')
    if amount not in (FIRST_PRICE_CENTS, RENEWAL_PRICE_CENTS):
        raise RuntimeError(f'Payment amount was {amount} {currency}, expected {FIRST_PRICE_CENTS} or {RENEWAL_PRICE_CENTS}')

    return True


def _load_issued():
    if not ISSUED_PATH.exists():
        return {}
    try:
        with open(ISSUED_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_issued(data):
    try:
        with open(ISSUED_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f'Warning: could not write issued licenses: {e}')


def _allowed_for_payment(payment_id, machine_id):
    issued = _load_issued()
    record = issued.get(payment_id, {'machine_ids': []})
    machine_ids = record.get('machine_ids', [])
    if machine_id in machine_ids:
        return True
    if len(machine_ids) >= MAX_DEVICES:
        return False
    machine_ids.append(machine_id)
    record['machine_ids'] = machine_ids
    issued[payment_id] = record
    _save_issued(issued)
    return True


def _load_machine_licenses():
    if not MACHINE_LICENSES_PATH.exists():
        return {}
    try:
        with open(MACHINE_LICENSES_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_machine_licenses(data):
    try:
        with open(MACHINE_LICENSES_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f'Warning: could not write machine licenses: {e}')


def _send_license_email(to_email, license_json):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, FROM_EMAIL, to_email]):
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = 'Your Antivirus Server license'
        msg.attach(MIMEText(
            'Thank you for your purchase.\n\n'
            'Your machine-bound license is attached as license.lic.\n'
            'Paste it into the Antivirus Server login window to activate.\n\n'
            'Do not share this license.\n',
            'plain'
        ))
        lic_bytes = json.dumps(license_json, indent=2).encode('utf-8')
        part = MIMEApplication(lic_bytes, _subtype='lic', _encoder=base64.b64encode)
        part.add_header('Content-Disposition', 'attachment; filename="license.lic"')
        msg.attach(part)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        print(f'License emailed to {to_email}')
    except Exception as e:
        print(f'Failed to email license: {e}')


PERMANENT_EXPIRY = int(datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())


def _build_license(machine_id, username, password, payment_id='', permanent=False):
    salt = secrets.token_hex(16)
    now = int(datetime.now(timezone.utc).timestamp())
    machine_lic = _load_machine_licenses()
    previous_exp = machine_lic.get(machine_id, {}).get('exp', 0)

    if permanent:
        exp = PERMANENT_EXPIRY
    else:
        base = max(now, previous_exp)
        exp = base + (LICENSE_DAYS * 86400)

    machine_lic[machine_id] = {'exp': exp, 'payment_id': payment_id}
    _save_machine_licenses(machine_lic)

    lic = {
        'machine_id': machine_id,
        'username': username,
        'salt': salt,
        'password_hash': _hash_password(password, salt),
        'exp': exp,
        'payment_id': payment_id,
    }
    return _sign_license(lic)


@app.route('/redeem', methods=['POST'])
def redeem():
    try:
        data = request.get_json(force=True, silent=True) or {}
        machine_id = data.get('machine_id', '').strip()
        payment_id = data.get('payment_id', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()

        if not machine_id or not username or not password:
            return jsonify({'error': 'machine_id, username, and password are required'}), 400
        if not payment_id and not email:
            return jsonify({'error': 'payment_id or email is required'}), 400

        if not payment_id:
            payment_id = _search_payment_by_email(email)

        _verify_square_payment(payment_id)
        if not _allowed_for_payment(payment_id, machine_id):
            return jsonify({'error': f'This payment already has {MAX_DEVICES} device(s) activated.'}), 400

        machine_lic = _load_machine_licenses()
        previous_exp = machine_lic.get(machine_id, {}).get('exp', 0)
        now = int(datetime.now(timezone.utc).timestamp())
        is_permanent = (previous_exp <= now) or (previous_exp == PERMANENT_EXPIRY)
        license_obj = _build_license(machine_id, username, password, payment_id, permanent=is_permanent)
        if email:
            _send_license_email(email, license_obj)
        return jsonify(license_obj), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/reset', methods=['POST'])
def reset():
    try:
        data = request.get_json(force=True, silent=True) or {}
        machine_id = data.get('machine_id', '').strip()
        payment_id = data.get('payment_id', '').strip()
        new_password = data.get('new_password', '')
        username = data.get('username', 'admin').strip()

        if not machine_id or not payment_id or not new_password:
            return jsonify({'error': 'machine_id, payment_id, and new_password are required'}), 400

        _verify_square_payment(payment_id)
        issued = _load_issued()
        if machine_id not in issued.get(payment_id, {}).get('machine_ids', []):
            return jsonify({'error': 'This device is not activated on this payment.'}), 400
        license_obj = _build_license(machine_id, username, new_password, payment_id, extend=False)
        return jsonify(license_obj), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/validate', methods=['POST'])
def validate():
    try:
        data = request.get_json(force=True, silent=True) or {}
        machine_id = data.get('machine_id', '').strip()
        payment_id = data.get('payment_id', '').strip()

        if not machine_id or not payment_id:
            return jsonify({'error': 'machine_id and payment_id are required'}), 400

        _verify_square_payment(payment_id)

        # Payment status is COMPLETED and not refunded, so still valid.
        return jsonify({'valid': True}), 200

    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'ok': True, 'square_token_set': bool(SQUARE_TOKEN)}), 200


if __name__ == '__main__':
    port = int(_get('FLASK_PORT', '5001'))
    print(f'License server starting on port {port}')
    print(f'Square environment: {SQUARE_ENV}')
    print(f'First-year price: {FIRST_PRICE_CENTS} cents')
    print(f'Renewal price: {RENEWAL_PRICE_CENTS} cents')
    print(f'License days: {LICENSE_DAYS}')
    print(f'Max devices per payment: {MAX_DEVICES}')
    print(f'Private key: {PRIVATE_KEY}')
    app.run(host='0.0.0.0', port=port)
