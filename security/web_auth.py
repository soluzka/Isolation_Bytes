from utils.paths import get_resource_path
import os

from flask import session, redirect, url_for, request, render_template_string
import functools
import os
import json
import bcrypt
import pyotp
from flask import session, redirect, url_for, request, render_template_string, flash

auth_file = os.path.join(os.path.dirname(__file__), 'auth_data.json')

# --- Password/TOTP Management ---
def _load_auth_data():
    if not os.path.exists(auth_file):
        with open(get_resource_path(os.path.join(auth_file)), 'w') as f:
            json.dump({}, f)
        return {}
    with open(get_resource_path(os.path.join(auth_file)), 'r') as f:
        return json.load(f)

def _save_auth_data(data):
    with open(get_resource_path(os.path.join(auth_file)), 'w') as f:
        json.dump(data, f)

def set_password(password):
    data = _load_auth_data()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    data['password_hash'] = hashed.decode('utf-8')
    _save_auth_data(data)


def set_password_hash(password_hash):
    """Store a pre-generated bcrypt hash string directly."""
    data = _load_auth_data()
    data['password_hash'] = password_hash
    _save_auth_data(data)

def verify_password(password):
    data = _load_auth_data()
    hash_str = data.get('password_hash')
    if not hash_str:
        return False
    return bcrypt.checkpw(password.encode(), hash_str.encode('utf-8'))

def get_totp_secret():
    data = _load_auth_data()
    if 'totp_secret' not in data:
        # Generate and save new TOTP secret
        secret = pyotp.random_base32()
        data['totp_secret'] = secret
        _save_auth_data(data)
    return data['totp_secret']

def verify_totp(token):
    secret = get_totp_secret()
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# --- Login Form ---
LOGIN_FORM = '''
<form method="post">
    <input type="password" name="password" placeholder="Password" required/>
    <input type="text" name="totp" placeholder="2FA Code" required/>
    <button type="submit">Login</button>
</form>
'''

# --- Decorator for authentication ---
def login_required(view_func):
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if session.get('logged_in'):
            return view_func(*args, **kwargs)
        if request.method == 'POST':
            password = request.form.get('password')
            totp_token = request.form.get('totp')
            if verify_password(password) and verify_totp(totp_token):
                session['logged_in'] = True
                return redirect(url_for(request.endpoint))
            else:
                flash('Invalid password or 2FA code.', 'error')
        # Show QR code for TOTP setup if not configured
        secret = get_totp_secret()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name="admin@antivirus", issuer_name="AntivirusDashboard")
        qr_html = f'<p>Scan this QR with your authenticator app:</p><img src="https://api.qrserver.com/v1/create-qr-code/?data={totp_uri}&size=150x150" alt="QR Code"/><p>Or enter secret: <b>{secret}</b></p>'
        return render_template_string(LOGIN_FORM + qr_html)
    return wrapped