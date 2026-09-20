import os
import json
import stat
import time
import bcrypt
import pyotp
import functools
import logging
from flask import session, redirect, url_for, request, render_template_string, flash

logger = logging.getLogger(__name__)

def _auth_data_path():
    app_data = os.path.abspath(os.path.expandvars(os.environ.get(
        'ANTIVIRUS_RUNTIME_DIR',
        os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'IsolationBytes')
    )))
    os.makedirs(app_data, exist_ok=True)
    auth_file = os.path.join(app_data, 'auth_data.json')
    # Set restrictive permissions on auth data file (owner read/write only)
    if os.path.exists(auth_file):
        try:
            os.chmod(auth_file, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logger.warning(f"Could not set restrictive permissions on auth file: {e}")
    return auth_file

auth_file = _auth_data_path()

# --- Password/TOTP Management ---
def _load_auth_data():
    if not os.path.exists(auth_file):
        with open(auth_file, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        # Set restrictive permissions on new file
        try:
            os.chmod(auth_file, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logger.warning(f"Could not set restrictive permissions on auth file: {e}")
        return {}
    with open(auth_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def _save_auth_data(data):
    with open(auth_file, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    # Ensure restrictive permissions after saving
    try:
        os.chmod(auth_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        logger.warning(f"Could not set restrictive permissions on auth file: {e}")

def set_password(password):
    """Legacy single-admin setter. Creates a default 'admin' user."""
    # SECURITY: Enforce minimum password strength
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    
    data = _load_auth_data()
    # Use higher work factor for bcrypt (12 rounds instead of default 10)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
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
    # SECURITY: Enhanced validation
    if not username or not password:
        return False, 'Username and password are required'
    
    # Username validation
    if not username.isalnum():
        return False, 'Username must be alphanumeric'
    if len(username) < 3 or len(username) > 32:
        return False, 'Username must be 3-32 characters'
    
    # Password validation (same strength requirements as set_password)
    if len(password) < 12:
        return False, 'Password must be at least 12 characters long'
    if not any(c.isupper() for c in password):
        return False, 'Password must contain at least one uppercase letter'
    if not any(c.islower() for c in password):
        return False, 'Password must contain at least one lowercase letter'
    if not any(c.isdigit() for c in password):
        return False, 'Password must contain at least one digit'
    
    data = _load_auth_data()
    users = data.setdefault('users', {})
    if username in users:
        return False, 'Username already exists'
    
    # Use higher work factor for bcrypt
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode('utf-8')
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
            
            # SECURITY: Add basic rate limiting tracking
            if 'failed_attempts' not in session:
                session['failed_attempts'] = 0
                session['last_attempt'] = 0
            
            # Check for brute force protection (5 attempts in 5 minutes)
            current_time = int(time.time())
            if (session['failed_attempts'] >= 5 and 
                current_time - session['last_attempt'] < 300):
                flash('Too many failed attempts. Please wait 5 minutes.', 'error')
                return render_template_string(LOGIN_FORM)
            
            if verify_password(password) and verify_totp(totp_token):
                # Reset failed attempts on successful login
                session['failed_attempts'] = 0
                session['logged_in'] = True
                # Set session security
                session.permanent = True  # Make session permanent
                return redirect(url_for(request.endpoint))
            else:
                # Increment failed attempts
                session['failed_attempts'] += 1
                session['last_attempt'] = current_time
                remaining_attempts = 5 - session['failed_attempts']
                flash(f'Invalid password or 2FA code. {remaining_attempts} attempts remaining.', 'error')
        # Show QR code for TOTP setup if not configured
        secret = get_totp_secret()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name="admin@antivirus", issuer_name="AntivirusDashboard")
        qr_html = f'<p>Scan this QR with your authenticator app:</p><img src="https://api.qrserver.com/v1/create-qr-code/?data={totp_uri}&size=150x150" alt="QR Code"/><p>Or enter secret: <b>{secret}</b></p>'
        return render_template_string(LOGIN_FORM + qr_html)
    return wrapped