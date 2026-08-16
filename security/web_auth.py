import os
import json
import bcrypt
import pyotp
import functools
from flask import session, redirect, url_for, request, render_template_string, flash

def _auth_data_path():
    app_data = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'antivirus_server')
    os.makedirs(app_data, exist_ok=True)
    return os.path.join(app_data, 'auth_data.json')

auth_file = _auth_data_path()

# --- Password/TOTP Management ---
def _load_auth_data():
    if not os.path.exists(auth_file):
        with open(auth_file, 'w') as f:
            json.dump({}, f)
        return {}
    with open(auth_file, 'r') as f:
        return json.load(f)

def _save_auth_data(data):
    with open(auth_file, 'w') as f:
        json.dump(data, f)

def set_password(password):
    """Legacy single-admin setter. Creates a default 'admin' user."""
    data = _load_auth_data()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users = data.setdefault('users', {})
    users['admin'] = hashed.decode('utf-8')
    data['password_hash'] = users['admin']
    _save_auth_data(data)


def set_password_hash(password_hash):
    """Store a pre-generated bcrypt hash string directly."""
    data = _load_auth_data()
    users = data.setdefault('users', {})
    users['admin'] = password_hash
    data['password_hash'] = password_hash
    _save_auth_data(data)

def has_auth_data():
    return bool(_load_auth_data().get('users'))


def verify_password(password):
    data = _load_auth_data()
    hash_str = data.get('password_hash')
    if not hash_str:
        return False
    return bcrypt.checkpw(password.encode(), hash_str.encode('utf-8'))


def _hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')


def register_user(username, password):
    """Register a new user. Returns (success, message)."""
    if not username or not password:
        return False, 'Username and password are required'
    if not username.isalnum():
        return False, 'Username must be alphanumeric'
    data = _load_auth_data()
    users = data.setdefault('users', {})
    if username in users:
        return False, 'Username already exists'
    users[username] = _hash_password(password)
    _save_auth_data(data)
    return True, 'User created'


def verify_user(username, password):
    """Verify a username/password against the user database."""
    data = _load_auth_data()
    users = data.get('users', {})
    hash_str = users.get(username)
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