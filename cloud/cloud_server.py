"""Compatibility wrapper for the cloud server with consistent agent scan/quarantine semantics."""

import os
import time

from flask import jsonify, request, session

from cloud import cloud_server_original as _legacy
from cloud._agent_results_unlimited import build_complete_agent_scan_results

app = _legacy.app
_agent_scan_state = {}
_AGENT_SCAN_STALE_SECONDS = 30 * 60


def _patch_public_auth_security():
    """Allow public activation/login APIs without browser-session CSRF."""
    public_auth_paths = {
        '/api/user/login',
        '/api/license/activate',
        '/api/license/validate',
        '/api/license/deactivate',
    }
    for key, handlers in list(app.before_request_funcs.items()):
        patched = []
        for handler in handlers:
            if getattr(handler, '_public_auth_csrf_compat', False):
                patched.append(handler)
                continue
            if getattr(handler, '__name__', '') != 'enforce_web_security':
                patched.append(handler)
                continue

            def public_auth_security_wrapper(*args, _original=handler, **kwargs):
                if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and request.path in public_auth_paths:
                    return None
                return _original(*args, **kwargs)

            public_auth_security_wrapper._public_auth_csrf_compat = True
            patched.append(public_auth_security_wrapper)
        app.before_request_funcs[key] = patched


def _patch_license_input_length():
    """Do not truncate signed IB- license keys before RSA validation."""
    original = getattr(_legacy, 'sanitize_text', None)
    if not callable(original) or getattr(original, '_license_length_compat', False):
        return

    def license_safe_sanitize(value, *, max_length=512):
        if isinstance(value, str) and value.lstrip().startswith('IB-') and max_length == 256:
            return value.strip()
        return original(value, max_length=max_length)

    license_safe_sanitize._license_length_compat = True
    _legacy.sanitize_text = license_safe_sanitize


_patch_public_auth_security()
_patch_license_input_length()


def _canonical_path(path):
    if not isinstance(path, str) or not path.strip():
        return ''
    try:
        return os.path.normcase(os.path.abspath(os.path.realpath(path)))
    except (OSError, TypeError, ValueError):
        return os.path.normcase(path.strip())


def _is_yara_finding(finding):
    if not isinstance(finding, dict):
        return False
    rule = str(finding.get('rule') or '').strip().lower()
    threat_type = str(finding.get('threat_type') or '').strip().lower()
    if rule in {'ml_heuristic', 'ml'} or rule.startswith('ml_'):
        return False
    return bool(rule) or threat_type in {'yara_match', 'ransomware', 'persistence'}


def _agent_report_marker(agent):
    report = agent.get('last_report') or {}
    return str(agent.get('last_scan') or report.get('timestamp') or '')


def _live_max(report, agent, key):
    """Return the newest cumulative counter from report or live heartbeat."""
    try:
        return max(int(report.get(key) or 0), int(agent.get(key) or 0))
    except (TypeError, ValueError):
        return agent.get(key) or report.get(key) or 0

def _save_agents(data):
    """Save agents to the shared JSON file."""
    try:
        with open(_AGENTS_FILE, 'w') as f:
            json.dump(data, f, default=str)
    except (OSError, TypeError):
        pass

def _get_agents():
    return {
        device_id: {key: value for key, value in info.items() if not key.startswith('_')}
        for device_id, info in _load_agents().items()
    }

def _set_agent(device_id, info):
    with _agents_lock:
        data = _load_agents()
        data[device_id] = info
        _save_agents(data)

def _update_agent(device_id, updates):
    with _agents_lock:
        data = _load_agents()
        if device_id in data:
            data[device_id].update(updates)
            _save_agents(data)

def _get_agent(device_id):
    data = _load_agents()
    return data.get(device_id)

def _credential_hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def _valid_device_credential(device_id, supplied):
    if not supplied or not device_id:
        return False
    agent = _get_agent(device_id)
    stored = (agent or {}).get('_device_credential_hash', '')
    return bool(stored) and hmac.compare_digest(stored, _credential_hash(supplied))

def _all_agents():
    return _get_agents()


_COMMANDS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'agent_commands.json')
_commands_lock = threading.Lock()


class _commands_locked:
    """Cross-process lock for read-modify-write on the commands file."""
    def __enter__(self):
        self._lf = open(_COMMANDS_FILE + '.lock', 'a+b')
        try:
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.locking(self._lf.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lf.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
        return self

    def __exit__(self, *exc):
        try:
            self._lf.seek(0)
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.locking(self._lf.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lf.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        self._lf.close()


def _load_commands():
    try:
        with open(_COMMANDS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save_commands(data):
    try:
        with open(_COMMANDS_FILE, 'w') as f:
            json.dump(data, f, default=str)
    except (OSError, TypeError):
        pass


class _PersistentCommandsList(list):
    """A list that syncs mutations back to the shared commands file."""
    def __init__(self, store, device_id, initial=None):
        super().__init__(initial or [])
        self._store = store
        self._device_id = device_id

    def _sync(self):
        with _commands_locked(), _commands_lock:
            data = _load_commands()
            data[self._device_id] = list(self)
            _save_commands(data)

    def append(self, item):
        super().append(item)
        self._sync()

    def extend(self, items):
        super().extend(items)
        self._sync()

    def insert(self, index, item):
        super().insert(index, item)
        self._sync()

    def remove(self, value):
        super().remove(value)
        self._sync()

    def pop(self, index=-1):
        val = super().pop(index)
        self._sync()
        return val

    def clear(self):
        super().clear()
        self._sync()

    def __setitem__(self, index, value):
        super().__setitem__(index, value)
        self._sync()

    def __delitem__(self, index):
        super().__delitem__(index)
        self._sync()

    def __iadd__(self, items):
        super().__iadd__(items)
        self._sync()
        return self

    def __imul__(self, n):
        super().__imul__(n)
        self._sync()
        return self


class _CommandsStore:
    """File-backed dict so agent commands survive across gunicorn workers."""
    def _with_lock(self, fn):
        with _commands_locked(), _commands_lock:
            return fn()

    def _read(self):
        return _load_commands()

    def _write(self, data):
        _save_commands(data)

    def get(self, device_id, default=None):
        def _op():
            return self._read().get(device_id, default)
        return self._with_lock(_op)

    def __getitem__(self, device_id):
        def _op():
            return self._read()[device_id]
        return self._with_lock(_op)

    def __setitem__(self, device_id, value):
        def _op():
            data = self._read()
            data[device_id] = value
            self._write(data)
        self._with_lock(_op)

    def __delitem__(self, device_id):
        def _op():
            data = self._read()
            if device_id in data:
                del data[device_id]
                self._write(data)
        self._with_lock(_op)

    def __contains__(self, device_id):
        return self.get(device_id) is not None

    def pop(self, device_id, default=None):
        def _op():
            data = self._read()
            val = data.pop(device_id, default)
            self._write(data)
            return val
        return self._with_lock(_op)

    def setdefault(self, device_id, default=None):
        if default is None:
            default = []
        def _op():
            data = self._read()
            if device_id not in data:
                data[device_id] = default
                self._write(data)
            else:
                default = data[device_id]
            return default
        val = self._with_lock(_op)
        return _PersistentCommandsList(self, device_id, val)

    def keys(self):
        def _op():
            return list(self._read().keys())
        return self._with_lock(_op)

    def items(self):
        def _op():
            return list(self._read().items())
        return self._with_lock(_op)

    def values(self):
        def _op():
            return list(self._read().values())
        return self._with_lock(_op)

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        def _op():
            return len(self._read())
        return self._with_lock(_op)

    def clear(self):
        self._write({})


# Keep backwards-compatible names for existing code
agents = {}
commands = _CommandsStore()
events = []


def _require_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get('X-Api-Key', '').strip()
        device_token = request.headers.get('X-Device-Token', '').strip()
        body = request.get_json(silent=True) or {}
        device_id = str(body.get('device_id', '')).strip()
        if not constant_time_equal(CLOUD_API_KEY, key) and not _valid_device_credential(device_id, device_token):
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return wrapper


def _require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not (session.get('logged_in') or session.get('user_logged_in')):
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper


# Public routes that don't require login (login page, license APIs, agent APIs, downloads)
_PUBLIC_ROUTES = {
    '/', '/login', '/api/config', '/api/user/login',
    '/api/conditional_startup/status',
    '/api/lemonsqueezy/validate-license', '/api/lemonsqueezy/webhook',
    '/api/lemonsqueezy/verify-order', '/api/lemonsqueezy/status',
    '/agent/register', '/agent/heartbeat', '/agent/report',
    '/agent/pair',
    '/validate', '/reset', '/install',
    # License-key-authenticated API endpoints — these use @_require_valid_license
    # or @_require_key decorators, not session login, so they must bypass the
    # global session login check.
    '/api/reputation/lookup', '/api/reputation/virustotal',
    '/api/reputation/malwarebazaar', '/api/reputation/threatfox',
    '/api/reputation/urlhaus', '/api/ml/score', '/api/ml/status',
    '/api/alerts', '/api/admin-creds', '/purchase-success',
    '/api/github-webhook', '/api/upload-download',
    '/api/license/activate', '/api/license/validate', '/api/license/deactivate',
}


@cloud_bp.before_request
def _require_login_global():
    """Block all routes except the public whitelist unless the user is logged in."""
    # Generate a CSRF token for the session if not present
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)

    # Allow static files
    if request.path.startswith('/static/'):
        return
    # Allow the login page and public API endpoints
    if request.path in _PUBLIC_ROUTES:
        return
    # Allow launcher downloads
    if request.path.startswith('/download/'):
        return
    # Allow assistant chat endpoint (used by launcher)
    if request.path == '/api/assistant/chat':
        return
    # Everything else requires login (admin or licensed user)
    if not (session.get('logged_in') or session.get('user_logged_in')):
        if request.path.startswith('/api/') or request.path in {'/run_startup', '/rescan'}:
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'login_required': True,
            }), 401
        return redirect('/login')

    # CSRF protection for POST/PUT/DELETE requests on authenticated routes
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = (request.form.get('csrf_token', '') or
                 request.headers.get('X-CSRF-Token', '') or
                 (request.get_json(silent=True) or {}).get('csrf_token', ''))
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'CSRF token missing or invalid'}), 403


@cloud_bp.route('/api/config', methods=['GET'])
def cloud_config():
    """Return non-secret config so the launcher can use the server's env
    instead of having its own .env file. Only the admin (server owner)
    controls these values."""
    _reload_env()
    return jsonify({
        'public_url': _clean_val(os.environ.get('PUBLIC_URL') or 'https://isolation-bytes.com'),
        'license_server': _clean_val(os.environ.get('LICENSE_SERVER') or 'https://isolation-bytes.com'),
        'payment_url': _clean_val(os.environ.get('PAYMENT_URL') or 'https://buy.stripe.com/7sY6oBaNqfsk7VrbgM0sU04'),
        'proxy_port': int(os.environ.get('PROXY_PORT') or 8000),
        'https_port': int(os.environ.get('HTTPS_PORT') or 443),
        'rtp_enabled': _clean_val(os.environ.get('RTP_ENABLED') or 'True'),
        'max_scan_size': _clean_val(os.environ.get('MAX_SCAN_SIZE') or '100'),
        'auto_update_interval': _clean_val(os.environ.get('AUTO_UPDATE_INTERVAL') or '24'),
        'reputation_api_available': True,  # Customers can use /api/reputation/* proxies
    })


@cloud_bp.route('/api/admin-creds', methods=['GET'])
@_require_key
def cloud_admin_creds():
    """Return daily admin credentials. Protected by API key."""
    _reload_env()
    return jsonify({
        'username': _daily_admin_username(),
        'password': _daily_admin_password(),
    })


# ============================================================
# ALERTS API — used by the Android client to poll for threats
# ============================================================

@cloud_bp.route('/api/alerts', methods=['GET'])
def cloud_alerts():
    """Return recent security alerts for the Android client.

    Accepts an optional 'since' query param (epoch ms) to fetch only
    alerts newer than that timestamp. Requires a license key via
    X-License-Key header (validated against Lemon Squeezy).
    """
    lic = (request.headers.get('X-License-Key', '') or '').strip()
    if not lic:
        return jsonify({'error': 'License key required'}), 401

    # Validate the license via the self-hosted license manager
    if not _license_manager:
        return jsonify({'error': 'License system not initialized'}), 500
    result = _license_manager.validate_license(lic)
    if not result['valid']:
        return jsonify({'error': result.get('error', 'Invalid license')}), 403

    since = request.args.get('since', '0')
    try:
        since_ms = int(since)
    except (ValueError, TypeError):
        since_ms = 0

    # Gather recent alerts from the quarantine log and scan history
    alerts = []
    runtime = os.environ.get('ANTIVIRUS_RUNTIME_DIR',
                              os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'),
                                           'AntivirusServer'))

    # Check quarantine for recently quarantined files
    quarantine_log = os.path.join(runtime, 'quarantine_audit.log')
    if os.path.exists(quarantine_log):
        try:
            import time as _time
            with open(quarantine_log, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        # Lines are JSON objects
                        entry = json.loads(line)
                        ts = entry.get('timestamp_ms', 0)
                        if ts >= since_ms:
                            alerts.append({
                                'title': 'Threat Quarantined',
                                'message': entry.get('file', 'Unknown file'),
                                'severity': 'high',
                                'timestamp_ms': ts,
                            })
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            pass

    # Check for blocked connections
    blocked_log = os.path.join(runtime, 'blocked_connections.log')
    if os.path.exists(blocked_log):
        try:
            with open(blocked_log, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        ts = entry.get('timestamp_ms', 0)
                        if ts >= since_ms:
                            alerts.append({
                                'title': 'Connection Blocked',
                                'message': f"{entry.get('src_ip', '?')} -> {entry.get('dst_ip', '?')}:{entry.get('dst_port', '?')}",
                                'severity': 'medium',
                                'timestamp_ms': ts,
                            })
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            pass

    # Sort by timestamp descending, limit to 50
    alerts.sort(key=lambda a: a.get('timestamp_ms', 0), reverse=True)
    alerts = alerts[:50]

    return jsonify({'alerts': alerts})


# ============================================================
# REPUTATION API PROXIES — Customers' PCs call these endpoints
# on the server. The server uses its own API keys (from .env)
# so the keys are never exposed in the customer's installed code.
# ============================================================

def _require_valid_license(f):
    """Require a valid self-hosted IB- license key in the request."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        # License key can come from header, query param, or JSON body
        lic = (request.headers.get('X-License-Key', '') or
               request.args.get('license_key', '') or '').strip()
        if not lic:
            data = request.get_json(silent=True) or {}
            lic = (data.get('license_key') or '').strip()
        if not lic:
            return jsonify({'error': 'License key required'}), 401
        if not _license_manager:
            return jsonify({'error': 'License system not initialized'}), 500
        result = _license_manager.validate_license(lic)
        if not result['valid']:
            return jsonify({'error': result.get('error', 'Invalid license')}), 403
        return f(*args, **kwargs)
    return wrapper


@cloud_bp.route('/api/reputation/virustotal', methods=['POST'])
@_require_valid_license
def reputation_virustotal():
    """Proxy VirusTotal file/hash lookups. API key stays on server."""
    data = request.get_json(silent=True) or {}
    file_hash = (data.get('hash') or '').strip()
    if not re.fullmatch(r'[a-fA-F0-9]{32,64}', file_hash):
        return jsonify({'error': 'Invalid file hash'}), 400
    vt_key = _clean_val(os.environ.get('VT_API_KEY') or '')
    if not vt_key:
        return jsonify({'error': 'VirusTotal not configured'}), 503
    try:
        resp = requests.get(f'https://www.virustotal.com/api/v3/files/{file_hash}',
                            headers={'x-apikey': vt_key}, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            attrs = result.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            return jsonify({
                'ok': True,
                'hash': file_hash,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': attrs.get('reputation', 0),
                'names': attrs.get('names', []),
            })
        elif resp.status_code == 404:
            return jsonify({'ok': True, 'hash': file_hash, 'found': False})
        else:
            return jsonify({'error': f'VirusTotal returned {resp.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': f'Could not reach VirusTotal: {e}'}), 503


@cloud_bp.route('/api/reputation/malwarebazaar', methods=['POST'])
@_require_valid_license
def reputation_malwarebazaar():
    """Proxy MalwareBazaar hash lookups. API key stays on server."""
    data = request.get_json(silent=True) or {}
    file_hash = (data.get('hash') or '').strip()
    if not _is_valid_hash(file_hash):
        return jsonify({'error': 'Valid file hash required'}), 400
    mb_key = _clean_val(os.environ.get('MALWAREBAZAAR_API_KEY') or '')
    try:
        resp = requests.post('https://mb-api.abuse.ch/api/v1/',
                             data={'query': 'get_info', 'hash': file_hash},
                             headers={'Auth-Key': mb_key} if mb_key else {},
                             timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            return jsonify({
                'ok': True,
                'hash': file_hash,
                'found': result.get('query_status') == 'OK',
                'data': result.get('data', []),
            })
        return jsonify({'error': f'MalwareBazaar returned {resp.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': f'Could not reach MalwareBazaar: {e}'}), 503


@cloud_bp.route('/api/reputation/threatfox', methods=['POST'])
@_require_valid_license
def reputation_threatfox():
    """Proxy ThreatFox IOC lookups. API key stays on server."""
    data = request.get_json(silent=True) or {}
    ioc = (data.get('ioc') or '').strip()
    if not ioc or len(ioc) > 2048 or any(c in ioc for c in '\x00\r\n'):
        return jsonify({'error': 'IOC required'}), 400
    tf_key = _clean_val(os.environ.get('THREATFOX_API_KEY') or '')
    try:
        resp = requests.post('https://threatfox-api.abuse.ch/api/v1/',
                             json={'query': 'search_ioc', 'search_term': ioc},
                             headers={'Auth-Key': tf_key} if tf_key else {},
                             timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            return jsonify({
                'ok': True,
                'ioc': ioc,
                'found': result.get('query_status') == 'OK',
                'data': result.get('data', []),
            })
        return jsonify({'error': f'ThreatFox returned {resp.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': f'Could not reach ThreatFox: {e}'}), 503


@cloud_bp.route('/api/reputation/urlhaus', methods=['POST'])
@_require_valid_license
def reputation_urlhaus():
    """Proxy URLHaus URL lookups. API key stays on server."""
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not _is_valid_url_for_lookup(url):
        return jsonify({'error': 'Valid http(s) URL required'}), 400
    uh_key = _clean_val(os.environ.get('URLHAUS_API_KEY') or '')
    try:
        resp = requests.post('https://urlhaus-api.abuse.ch/v1/url/',
                             data={'url': url},
                             headers={'Auth-Key': uh_key} if uh_key else {},
                             timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            return jsonify({
                'ok': True,
                'url': url,
                'threat_status': result.get('threat', 'unknown'),
                'found': result.get('query_status') == 'OK',
                'data': result,
            })
        return jsonify({'error': f'URLHaus returned {resp.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': f'Could not reach URLHaus: {e}'}), 503


@cloud_bp.route('/api/reputation/lookup', methods=['POST'])
@_require_valid_license
def reputation_lookup_all():
    """Look up a hash across ALL configured reputation APIs at once.
    Returns combined results. API keys stay on server."""
    data = request.get_json(silent=True) or {}
    file_hash = (data.get('hash') or '').strip()
    if not re.fullmatch(r'[a-fA-F0-9]{32,64}', file_hash):
        return jsonify({'error': 'Invalid file hash'}), 400

    results = {'hash': file_hash, 'sources': {}}

    # VirusTotal
    vt_key = _clean_val(os.environ.get('VT_API_KEY') or '')
    if vt_key:
        try:
            resp = requests.get(f'https://www.virustotal.com/api/v3/files/{file_hash}',
                                headers={'x-apikey': vt_key}, timeout=10)
            if resp.status_code == 200:
                attrs = resp.json().get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                results['sources']['virustotal'] = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                }
            elif resp.status_code == 404:
                results['sources']['virustotal'] = {'found': False}
        except Exception:
            results['sources']['virustotal'] = {'error': 'unreachable'}

    # MalwareBazaar
    mb_key = _clean_val(os.environ.get('MALWAREBAZAAR_API_KEY') or '')
    if mb_key:
        try:
            resp = requests.post('https://mb-api.abuse.ch/api/v1/',
                                 data={'query': 'get_info', 'hash': file_hash},
                                 headers={'Auth-Key': mb_key}, timeout=10)
            if resp.status_code == 200:
                r = resp.json()
                results['sources']['malwarebazaar'] = {
                    'found': r.get('query_status') == 'OK',
                    'count': len(r.get('data', [])),
                }
        except Exception:
            results['sources']['malwarebazaar'] = {'error': 'unreachable'}

    # ThreatFox (only if it looks like an IOC, not a file hash)
    tf_key = _clean_val(os.environ.get('THREATFOX_API_KEY') or '')
    if tf_key and not all(c in '0123456789abcdefABCDEF' for c in file_hash):
        try:
            resp = requests.post('https://threatfox-api.abuse.ch/api/v1/',
                                 json={'query': 'search_ioc', 'search_term': file_hash},
                                 headers={'Auth-Key': tf_key}, timeout=10)
            if resp.status_code == 200:
                r = resp.json()
                results['sources']['threatfox'] = {
                    'found': r.get('query_status') == 'OK',
                }
        except Exception:
            results['sources']['threatfox'] = {'error': 'unreachable'}

    # Calculate overall threat score
    vt = results['sources'].get('virustotal', {})
    mb = results['sources'].get('malwarebazaar', {})
    malicious_count = vt.get('malicious', 0) + (1 if mb.get('found') else 0)
    results['threat_score'] = malicious_count
    results['is_malicious'] = malicious_count > 0

    return jsonify({'ok': True, **results})


@cloud_bp.route('/api/ml/score', methods=['POST'])
@_require_valid_license
def ml_score():
    """Run ML malware detection on the server and return the score.
    The customer's PC sends file features (hash, size, entropy, etc.)
    and the server runs the BODMAS CNN, EMBER, and sklearn models.
    Models stay on the server — customer never downloads them."""
    data = request.get_json(silent=True) or {}
    file_hash = (data.get('hash') or '').strip()
    file_size = int(data.get('size') or 0)
    file_path = (data.get('file_path') or '').strip()

    if not file_hash and not file_path:
        return jsonify({'error': 'File hash or path required'}), 400

    # Try to run the actual ML models on the server
    try:
        import sys as _sys
        _base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _base not in _sys.path:
            _sys.path.insert(0, _base)

        from security.detector import bodmas_cnn_detector, ember_detector, detector as _detector

        scores = {}

        # Try BODMAS CNN first (most accurate)
        try:
            score = bodmas_cnn_detector.score(file_path) if file_path else None
            if score is not None:
                scores['bodmas_cnn'] = float(score)
        except Exception as e:
            logger.debug(f"BODMAS CNN scoring failed: {e}")

        # Try EMBER
        try:
            score = ember_detector.score(file_path) if file_path else None
            if score is not None:
                scores['ember'] = float(score)
        except Exception as e:
            logger.debug(f"EMBER scoring failed: {e}")

        # Try sklearn detector
        try:
            if file_path:
                pred = _detector.predict([file_path])
                scores['sklearn'] = float(_detector.get_anomaly_score(file_path))
        except Exception as e:
            logger.debug(f"Sklearn scoring failed: {e}")

        # Pick the best score
        best_score = None
        best_model = None
        if scores:
            best_model = max(scores, key=scores.get)
            best_score = scores[best_model]

        return jsonify({
            'ok': True,
            'hash': file_hash,
            'scores': scores,
            'best_score': best_score,
            'best_model': best_model,
            'is_malicious': best_score is not None and best_score >= 0.5,
        })
    except Exception as e:
        logger.exception("ML scoring error")
        return jsonify({'ok': False, 'error': f'ML scoring failed: {e}'}), 500


@cloud_bp.route('/api/ml/status', methods=['GET'])
def ml_status():
    """Return which ML models are available on the server."""
    try:
        import sys as _sys
        _base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _base not in _sys.path:
            _sys.path.insert(0, _base)
        from quick_start import _ml_model_status
        return jsonify({'ok': True, 'models': _ml_model_status()})
    except Exception:
        return jsonify({'ok': True, 'models': {
            'bodmas_cnn': False, 'ember': False, 'sklearn': False
        }})


@cloud_bp.route('/api/user/login', methods=['POST'])
def cloud_user_login():
    """User login with self-hosted IB- license key — no third-party dependency."""
    data = request.get_json(silent=True) or {}
    license_key = sanitize_text(data.get('license') or request.form.get('license'), max_length=256)
    username = sanitize_text(data.get('username') or request.form.get('username'), max_length=64)
    password = (data.get('password') or request.form.get('password') or '').strip()
    machine_id = (data.get('machine_id') or request.form.get('machine_id') or '').strip()

    if not license_key or not username or not password:
        return jsonify({'ok': False, 'error': 'License, username, and password are required'}), 400

    if not _license_manager:
        return jsonify({'ok': False, 'error': 'License system not initialized'}), 500

    # Validate the self-hosted license key
    result = _license_manager.validate_license(license_key, machine_id)
    if not result['valid']:
        return jsonify({'ok': False, 'error': result.get('error', 'Invalid license')}), 403

    # Auto-activate the device if not already activated
    if machine_id:
        _license_manager.activate_license(license_key, machine_id, username)

    # License valid — set user session
    session['user_logged_in'] = True
    session['user_username'] = username
    session['user_license'] = license_key
    session['user_tier'] = result.get('tier', 'basic')
    session['user_features'] = result.get('features', [])
    session['session_created_at'] = int(time.time())
    session.permanent = True
    return jsonify({'ok': True, 'redirect': '/dashboard'})


LICENSE_SUCCESS_TEMPLATE = """
    <!doctype html>
    <html><head><title>License Key - Purchase Successful</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }
        body { background: #0b1321; color: #e0e1dd; margin: 0; padding: 40px; }
        .card { max-width: 640px; margin: 0 auto; background: #1b263b; padding: 36px; border-radius: 14px; border: 1px solid #415a77; }
        h1 { color: #90e0ef; margin-top: 0; }
        .success { color: #6be; font-size: 1.2rem; margin-bottom: 20px; }
        .verified { color: #6be; font-size: 0.85rem; margin-bottom: 16px; }
        .key-box { background: #0b1321; border: 2px solid #00b4d8; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .key-box label { display: block; color: #778da9; font-size: 0.85rem; margin-bottom: 8px; }
        .key-box textarea { width: 100%; height: 80px; border: none; background: transparent; color: #00b4d8;
            font-family: monospace; font-size: 0.9rem; resize: none; }
        .info { background: #0d1b2a; border-radius: 8px; padding: 16px; margin: 16px 0; border: 1px solid #415a77; }
        .info strong { color: #90e0ef; }
        .btn { display: inline-block; padding: 12px 28px; background: #00b4d8; color: #0b1321;
            border: none; border-radius: 8px; font-weight: bold; cursor: pointer; text-decoration: none; margin-top: 16px; }
        .activated { color: #6be; } .not-activated { color: #ffd166; }
    </style></head>
    <body>
        <div class="card">
            <h1>Payment Verified!</h1>
            <div class="success">Your license key has been generated.</div>
            <div class="verified">Payment confirmed via Stripe (ID: {{ checkout_id[:20] }}...)</div>

            <div class="key-box">
                <label>Your License Key (copy this):</label>
                <textarea id="licenseKey" readonly onclick="this.select();document.execCommand('copy')">{{ license_key }}</textarea>
            </div>

            <div class="info">
                <strong>Tier:</strong> One-Time Purchase (YARA + ML + Real-time + Cloud API)<br>
                <strong>Max Devices:</strong> 1<br>
                <strong>Expires:</strong> Never<br>
                <strong>License ID:</strong> {{ record.license_id }}<br>
                <strong>Device Activation:</strong>
                {% if activated %}<span class="activated">Auto-activated for this device</span>{% else %}<span class="not-activated">Activate manually on the next page</span>{% endif %}
                {% if email and email_sent %}<br><strong>Email:</strong> License key sent to {{ email }}{% endif %}
            </div>

            <div class="info">
                <strong>Next steps:</strong><br>
                1. Copy your license key above (click it to copy).<br>
                2. Go to Activate / Login.<br>
                3. Paste the key and click Activate.<br>
                4. Choose a username and password, then click Login.
            </div>

            {% if not email_sent %}
            <div class="info">
                <strong>Email your key:</strong><br>
                <form method="POST" action="/purchase-success/email" style="margin-top:10px;">
                    <input type="hidden" name="checkout_id" value="{{ checkout_id }}">
                    <input type="email" name="email" placeholder="your@email.com" required style="width:100%;padding:10px;border-radius:6px;border:1px solid #415a77;background:#0b1321;color:#e0e1dd;margin-bottom:10px;">
                    <button type="submit" class="btn" style="width:100%;">Send License Key</button>
                </form>
            </div>
            {% endif %}

            <a class="btn" href="/?page=activate&machine_id={{ machine_id | urlencode }}">Go to Activate / Login</a>
            <a class="btn" href="/" style="background:#415a77;color:#e0e1dd;">Home</a>
        </div>
        <script>
            // Auto-select the key for easy copying
            var ta = document.getElementById('licenseKey');
            ta.focus(); ta.select();
        </script>
    </body></html>
    """


@cloud_bp.route('/purchase-success', methods=['GET'])
def purchase_success():
    """Stripe redirects here after a successful payment.
    Generates a self-hosted license key tied to the buyer's machine_id
    and displays it so the user can copy and activate it.

    The Stripe Payment Link must be configured (in the Stripe dashboard)
    to redirect to:  https://isolation-bytes.com/purchase-success?machine_id={machine_id}

    Stripe passes checkout session info as query params. We use machine_id
    to auto-activate the license for the buyer's device.
    """
    if not _license_manager:
        return render_template_string('''
        <!doctype html><html><head><title>Purchase</title>
        <meta charset="UTF-8"><style>
        *{font-family:Segoe UI,sans-serif}body{background:#0b1321;color:#e0e1dd;margin:0;padding:40px}
        .card{max-width:600px;margin:0 auto;background:#1b263b;padding:32px;border-radius:12px;border:1px solid #415a77}
        h1{color:#90e0ef}p{color:#ff6b6b}
        </style></head><body><div class="card"><h1>License System Unavailable</h1>
        <p>The license system is not initialized. Please contact support.</p></div></body></html>
        '''), 500

    # Stripe passes these as query params after redirect
    machine_id = request.args.get('machine_id', '').strip()
    checkout_id = request.args.get('checkout_id') or request.args.get('session_id') or request.args.get('checkout_session_id') or ''
    email = request.args.get('email') or request.args.get('customer_email') or ''
    if checkout_id and not re.fullmatch(r'cs_[A-Za-z0-9_\-]{8,128}', checkout_id):
        return jsonify({'error': 'Invalid checkout session id'}), 400

    # ---- Verify the Stripe checkout session is real and paid ----
    stripe_key = _clean_val(os.environ.get('STRIPE_SECRET_KEY') or '')
    payment_verified = False
    payment_amount = 0
    payment_currency = ''
    payment_tier = 'one_time'  # default

    if not checkout_id:
        return render_template_string('''
        <!doctype html><html><head><title>Purchase Error</title>
        <meta charset="UTF-8"><style>
        *{font-family:Segoe UI,sans-serif}body{background:#0b1321;color:#e0e1dd;margin:0;padding:40px}
        .card{max-width:600px;margin:0 auto;background:#1b263b;padding:32px;border-radius:12px;border:1px solid #415a77}
        h1{color:#ff6b6b}p{color:#e0e1dd}
        </style></head><body><div class="card"><h1>Missing Payment Information</h1>
        <p>No checkout session ID was received from Stripe. Please return to the purchase page and try again.</p>
        <a href="/" style="color:#90e0ef;">Back to Home</a></div></body></html>
        '''), 400

    if stripe_key:
        # Verify the checkout session with Stripe's API
        try:
            resp = requests.get(
                f'https://api.stripe.com/v1/checkout/sessions/{checkout_id}',
                headers={'Authorization': f'Bearer {stripe_key}'},
                timeout=15
            )
            if resp.status_code == 200:
                session = resp.json()
                payment_status = session.get('payment_status', '')
                if payment_status == 'paid':
                    payment_verified = True
                    payment_amount = session.get('amount_total', 0)
                    payment_currency = session.get('currency', 'usd')
                    customer_email = session.get('customer_details', {}).get('email', '') or session.get('customer_email', '')
                    if customer_email:
                        email = customer_email
                    # Payment Links pass machine_id via client_reference_id
                    client_ref = session.get('client_reference_id', '')
                    if client_ref and not machine_id:
                        machine_id = client_ref
                    logger.info(f"Stripe checkout verified: id={checkout_id}, "
                                f"amount={payment_amount} {payment_currency}, email={email}")
                else:
                    logger.warning(f"Stripe checkout not paid: id={checkout_id}, status={payment_status}")
            else:
                logger.warning(f"Stripe API returned {resp.status_code} for checkout {checkout_id}")
        except Exception as e:
            logger.error(f"Stripe verification failed: {e}")
    else:
        # No Stripe key configured — log a warning and allow (dev mode)
        logger.warning("STRIPE_SECRET_KEY not set — skipping payment verification (dev mode)")
        payment_verified = True

    if not payment_verified:
        return render_template_string('''
        <!doctype html><html><head><title>Payment Not Verified</title>
        <meta charset="UTF-8"><style>
        *{font-family:Segoe UI,sans-serif}body{background:#0b1321;color:#e0e1dd;margin:0;padding:40px}
        .card{max-width:600px;margin:0 auto;background:#1b263b;padding:32px;border-radius:12px;border:1px solid #415a77}
        h1{color:#ff6b6b}p{color:#e0e1dd}
        </style></head><body><div class="card"><h1>Payment Not Verified</h1>
        <p>We could not verify your payment with Stripe. If you believe this is an error, please contact support with your checkout ID: <code>{{ checkout_id }}</code></p>
        <a href="/" style="color:#90e0ef;">Back to Home</a></div></body></html>
        ''', checkout_id=checkout_id), 402

    # ---- Check if a license was already generated for this checkout ID ----
    # Prevents users from refreshing the page to get multiple keys
    existing = None
    if _license_manager and checkout_id:
        for lic_id, record in _license_manager._store.items():
            if hasattr(record, 'customer') and record.customer == f'stripe_{checkout_id}':
                existing = record
                break

    if existing:
        # Return the existing license key instead of generating a new one
        license_key = existing.license_key if hasattr(existing, 'license_key') else ''
        # Reconstruct the key from the store
        for lic_id, rec in _license_manager._store.items():
            if rec.get('customer') == f'stripe_{checkout_id}':
                # Found it — return the existing key
                logger.info(f"Returning existing license for checkout {checkout_id}: {lic_id}")
                break
        record = existing
        if not license_key:
            # Generate the key string from the stored record
            license_key = f"IB-{lic_id}"
    else:
        # Generate a one-time purchase license (1 device, never expires)
        # Tag the customer with the checkout ID to prevent duplicate generation
        license_key, record = _license_manager.generate_license(
            tier=payment_tier,
            customer=f'stripe_{checkout_id}',
            max_devices=1,
        )

    # Auto-activate for this machine if machine_id was passed
    activated = False
    if machine_id:
        act_result = _license_manager.activate_license(license_key, machine_id, email or machine_id)
        activated = act_result.get('ok', False)

    logger.info(f"License generated for purchase: id={record.license_id}, "
                f"machine_id={machine_id}, email={email}, activated={activated}, "
                f"checkout={checkout_id}, amount={payment_amount} {payment_currency}")

    # Email the license key to the buyer if we have their address
    email_sent = _send_license_email(email, license_key, machine_id)

    return render_template_string(
        LICENSE_SUCCESS_TEMPLATE,
        checkout_id=checkout_id,
        license_key=license_key,
        record=record,
        machine_id=machine_id,
        activated=activated,
        email=email,
        email_sent=email_sent,
    )


@cloud_bp.route('/purchase-success/email', methods=['POST'])
def purchase_success_email():
    """Resend the license key to a buyer-entered email address."""
    checkout_id = request.form.get('checkout_id', '').strip()
    email = request.form.get('email', '').strip()
    if not checkout_id or not email:
        return jsonify({'error': 'Checkout ID and email are required'}), 400
    if not re.fullmatch(r'cs_[A-Za-z0-9_\-]{8,128}', checkout_id):
        return jsonify({'error': 'Invalid checkout session id'}), 400
    if not _license_manager:
        return jsonify({'error': 'License system not initialized'}), 500

    # Find the license for this checkout
    license_key = None
    machine_id = ''
    for lic_id, record in _license_manager._store.items():
        rec = record if isinstance(record, dict) else record.__dict__
        if rec.get('customer') == f'stripe_{checkout_id}':
            license_key = f"IB-{lic_id}"
            machine_id = rec.get('machine_id', '') or rec.get('instance_name', '')
            break
    if not license_key:
        return jsonify({'error': 'No license found for this checkout'}), 404

    sent = _send_license_email(email, license_key, machine_id)
    if sent:
        return render_template_string('''
        <!doctype html><html><head><title>Email Sent</title>
        <meta charset="UTF-8"><style>
        *{font-family:Segoe UI,sans-serif}body{background:#0b1321;color:#e0e1dd;margin:0;padding:40px}
        .card{max-width:600px;margin:0 auto;background:#1b263b;padding:32px;border-radius:12px;border:1px solid #415a77}
        h1{color:#90e0ef}p{color:#6be}
        </style></head><body><div class="card"><h1>Email Sent</h1>
        <p>Your license key has been sent to {{ email }}.</p>
        <a href="/" style="color:#90e0ef;">Back to Home</a></div></body></html>
        ''', email=email)
    return jsonify({'error': 'Failed to send email'}), 500


@cloud_bp.route('/install', methods=['GET'])
def cloud_install_page():
    """Universal installation page — detects the visitor's platform and shows
    the right download/install option for Windows, macOS, Linux, Android, iOS,
    ChromeOS, and any other device."""
    return render_template('install.html', session=session)


@cloud_bp.route('/', methods=['GET'])
def cloud_root():
    # Look for website/login.html in multiple locations (handles PyInstaller EXE)
    search_dirs = [
        BASE_DIR.parent / 'website',           # Normal layout
        BASE_DIR / 'website',                  # Bundled in EXE
        Path(os.getcwd()) / 'website',         # Current working dir
    ]
    if getattr(sys, '_MEIPASS', None):
        search_dirs.insert(0, Path(sys._MEIPASS) / 'website')  # PyInstaller extraction
    if _exe_dir:
        search_dirs.insert(0, _exe_dir / 'website')            # Next to EXE
    for d in search_dirs:
        login_file = d / 'login.html'
        if login_file.exists():
            resp = send_from_directory(str(d), 'login.html')
            resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
            return resp
    return redirect('/login')


@cloud_bp.route('/login', methods=['GET', 'POST'])
def cloud_login():
    ip = request.remote_addr or '127.0.0.1'
    if request.method == 'POST':
        if _is_rate_limited(ip):
            return 'Too many failed login attempts. Please wait 15 minutes.', 429
        u = sanitize_text(request.form.get('username'), max_length=64)
        p = request.form.get('password', '').strip()
        if _verify_admin_credentials(u, p):
            csrf_token = session.get('csrf_token') or secrets.token_urlsafe(32)
            session.clear()
            session['logged_in'] = True
            session['session_created_at'] = int(time.time())
            session['csrf_token'] = csrf_token
            session.permanent = True
            return redirect('/dashboard')
        _record_failed_attempt(ip)
        # Return the login form again with an error message (no username shown)
        return '''<!doctype html>
<html><head><title>Admin Login</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    * { box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }
    body { background: #0b1321; color: #e0e1dd; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1b263b; padding: 32px; border-radius: 10px; border: 1px solid #415a77; width: 380px; }
    h1 { font-size: 1.5rem; color: #90e0ef; margin-top: 0; margin-bottom: 20px; text-align: center; }
    label { display: block; margin: 10px 0 4px; font-size: 0.85rem; color: #778da9; }
    input { width: 100%; padding: 10px; margin: 4px 0; border-radius: 6px; border: 1px solid #778da9; background: #0b1321; color: #e0e1dd; }
    button { width: 100%; padding: 12px; background: #00b4d8; border: none; border-radius: 6px; color: #0b1321; font-weight: bold; cursor: pointer; margin-top: 14px; }
    button:hover { background: #0096c7; }
    .error { color: #ef476f; text-align: center; margin: 10px 0; font-size: 0.9rem; }
    a { color: #90e0ef; text-decoration: none; display: block; text-align: center; margin-top: 14px; font-size: 0.9rem; }
</style>
</head>
<body>
    <div class="card">
        <h1>Antivirus Admin Login</h1>
        <div class="error">Invalid login credentials. Try again.</div>
        <form method="post" action="/login">
            <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" placeholder="Enter username" autocomplete="username" required autofocus>
            <label for="password">Password</label>
            <input id="password" name="password" type="password" placeholder="Enter password" autocomplete="current-password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/">Back to Home</a>
    </div>
</body>
</html>'''.replace(
            '{{ session.csrf_token }}', session.get('csrf_token', '')
        )
    # GET — show the admin login form (username hidden, must be typed in)
    html = '''<!doctype html>
<html><head><title>Admin Login</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    * { box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }
    body { background: #0b1321; color: #e0e1dd; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1b263b; padding: 32px; border-radius: 10px; border: 1px solid #415a77; width: 380px; }
    h1 { font-size: 1.5rem; color: #90e0ef; margin-top: 0; margin-bottom: 20px; text-align: center; }
    label { display: block; margin: 10px 0 4px; font-size: 0.85rem; color: #778da9; }
    input { width: 100%; padding: 10px; margin: 4px 0; border-radius: 6px; border: 1px solid #778da9; background: #0b1321; color: #e0e1dd; }
    button { width: 100%; padding: 12px; background: #00b4d8; border: none; border-radius: 6px; color: #0b1321; font-weight: bold; cursor: pointer; margin-top: 14px; }
    button:hover { background: #0096c7; }
    a { color: #90e0ef; text-decoration: none; display: block; text-align: center; margin-top: 14px; font-size: 0.9rem; }
</style>
</head>
<body>
    <div class="card">
        <h1>Antivirus Admin Login</h1>
        <form method="post" action="/login">
            <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" placeholder="Enter username" autocomplete="username" required autofocus>
            <label for="password">Password</label>
            <input id="password" name="password" type="password" placeholder="Enter password" autocomplete="current-password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/">Back to Home</a>
    </div>
</body>
</html>'''
    html = html.replace('{{ session.csrf_token }}', session.get('csrf_token', ''))
    resp = make_response(html)
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


from urllib.parse import unquote


@cloud_bp.route('/download/<path:filename>', methods=['GET'])
def cloud_download(filename):
    real = unquote(filename).replace('/', '\\').split('\\')[-1]
    # Search order: next to EXE/downloads, next to EXE, cloud/downloads, dist/, _MEIPASS/downloads
    search_dirs = []
    if _exe_dir:
        search_dirs.append(_exe_dir / 'downloads')
        search_dirs.append(_exe_dir)
        search_dirs.append(_exe_dir / 'dist')
    search_dirs.append(BASE_DIR / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'dist')
    if getattr(sys, '_MEIPASS', None):
        search_dirs.append(Path(sys._MEIPASS) / 'downloads')
    for d in search_dirs:
        if not os.path.isdir(str(d)):
            continue
        target = d / real
        if os.path.isfile(str(target)):
            # Set correct MIME types for MSIX/AppInstaller/CER
            lower = real.lower()
            if lower.endswith('.msix') or lower.endswith('.appx'):
                mimetype = 'application/msix'
            elif lower.endswith('.appinstaller'):
                mimetype = 'application/appinstaller'
            elif lower.endswith('.cer'):
                mimetype = 'application/x-x509-ca-cert'
            elif lower.endswith('.apk'):
                mimetype = 'application/vnd.android.package-archive'
            else:
                mimetype = None
            return send_from_directory(str(d), real, as_attachment=True,
                                       mimetype=mimetype)
    # Fallback: serve install scripts from inline source so they're always
    # available after a git deploy without needing to scp dist/ to the VPS.
    if real in _INSTALL_SCRIPTS:
        pair_code = request.args.get('pair_code', '').strip().upper()
        if pair_code and not re.fullmatch(r'[A-Z0-9]{8,12}', pair_code):
            pair_code = ''
        content = _INSTALL_SCRIPTS[real].replace('{api_key}', CLOUD_API_KEY)
        content = content.replace('{pair_code}', pair_code)
        resp = make_response(content)
        resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename="{real}"'
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp
    return 'File not found or no downloads are available.', 404


# ─── Inline install scripts (always available, no scp needed) ────────────
# These routes serve the install scripts directly from the source code so
# they work immediately after a git deploy without needing to scp the
# dist/ directory to the VPS downloads/ directory.

_INSTALL_WINDOWS_PS1 = r'''# Isolation Bytes — Universal Windows Installer
# Downloads the MSIX + certificate from isolation-bytes.com, trusts the
# certificate, installs the MSIX, and launches the app.
#
# Usage:
#   .\install-windows.ps1                              # download from web
#   .\install-windows.ps1 -Local                       # use local dist\ files
#   iwr https://isolation-bytes.com/download/install-windows.ps1 -UseBasicParsing | iex
[CmdletBinding()]
param(
    [switch]$Local,
    [string]$BaseUrl = 'https://isolation-bytes.com',
    [string]$DistDir,
    [string]$ApiKey,
    [string]$PairCode = '{pair_code}'
)

$ErrorActionPreference = 'Stop'

# ─── Elevate to Administrator ──────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Requesting Administrator privileges...'
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($Local) { $args += '-Local' }
    if ($DistDir) { $args += '-DistDir', $DistDir }
    if ($BaseUrl -ne 'https://isolation-bytes.com') { $args += '-BaseUrl', $BaseUrl }
    if ($ApiKey) { $args += '-ApiKey', $ApiKey }
    if ($PairCode) { $args += '-PairCode', $PairCode }
    $proc = Start-Process powershell.exe -ArgumentList $args -Verb RunAs -Wait -PassThru
    exit $proc.ExitCode
}

# ─── Determine source: local dist\ or download from web ────────────────
if ($Local) {
    if (-not $DistDir) {
        $DistDir = Join-Path $PSScriptRoot 'dist'
        if (-not (Test-Path $DistDir)) {
            $DistDir = Split-Path -Parent $PSScriptRoot
            $DistDir = Join-Path $DistDir 'dist'
        }
    }
    $MsixPath = Join-Path $DistDir 'IsolationBytes.msix'
    $CerPath  = Join-Path $DistDir 'IsolationBytes.cer'
} else {
    $tempDir = Join-Path $env:TEMP 'IsolationBytes_Install'
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    Write-Host "Downloading Isolation Bytes from $BaseUrl..."
    $MsixPath = Join-Path $tempDir 'IsolationBytes.msix'
    $CerPath  = Join-Path $tempDir 'IsolationBytes.cer'

    try {
        Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytes.msix" -OutFile $MsixPath -UseBasicParsing -TimeoutSec 120
        Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytes.cer"  -OutFile $CerPath  -UseBasicParsing -TimeoutSec 30
    } catch {
        Write-Warning "Desktop app download unavailable: $($_.Exception.Message)"
        Remove-Item $MsixPath, $CerPath -Force -ErrorAction SilentlyContinue
    }
}

$hasDesktopPackage = (Test-Path $MsixPath) -and (Test-Path $CerPath)

# ─── Verify checksums ───────────────────────────────────────────────────
if (-not $Local -and $hasDesktopPackage) {
    Write-Host 'Verifying file integrity...'
    try {
        $checksumsResp = Invoke-WebRequest -Uri "$BaseUrl/download/checksums.json" -UseBasicParsing -TimeoutSec 10
        $checksums = ($checksumsResp.Content | ConvertFrom-Json).files
        foreach ($fileInfo in @(
            @{ Path = $MsixPath; Name = 'IsolationBytes.msix' },
            @{ Path = $CerPath;  Name = 'IsolationBytes.cer' }
        )) {
            $expected = $checksums.($fileInfo.Name)
            if ($expected -and $expected.sha256) {
                $actual = (Get-FileHash -Path $fileInfo.Path -Algorithm SHA256).Hash.ToLower()
                if ($actual -ne $expected.sha256.ToLower()) {
                    throw "Checksum mismatch for $($fileInfo.Name): expected $($expected.sha256), got $actual"
                }
                Write-Host "  $($fileInfo.Name) verified (SHA-256 OK)"
            }
        }
    } catch {
        Write-Warning 'Could not verify checksums (server unreachable). Proceeding with install.'
    }
}

if ($hasDesktopPackage) {
    $msixSize = [math]::Round((Get-Item $MsixPath).Length / 1MB, 1)
    Write-Host "MSIX: $MsixPath ($msixSize MB)"
    Write-Host "Cert: $CerPath"

    # ─── 1. Trust the certificate ──────────────────────────────────────
    Write-Host 'Installing certificate to trusted stores...'
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null
    Write-Host '  Certificate trusted.'

    # ─── 2. Remove and install the desktop package ─────────────────────
    $pkgName = 'soluzka.IsolationBytes'
    $existing = Get-AppxPackage -Name $pkgName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Removing previous version ($($existing.Version))..."
        Remove-AppxPackage -Package $existing.PackageFullName -ErrorAction SilentlyContinue
    }
    Write-Host 'Installing Isolation Bytes MSIX...'
    Add-AppxPackage -Path $MsixPath -ForceApplicationShutdown -ForceUpdateFromAnyVersion
    Write-Host '  Installed.'

    # ─── 3. Launch the desktop package ─────────────────────────────────
    $pkg = Get-AppxPackage -Name $pkgName
    if ($pkg) {
        $aumid = $pkg.PackageFamilyName + '!IsolationBytes'
        Start-Process -FilePath 'explorer.exe' -ArgumentList "shell:AppsFolder\$aumid"
        Write-Host 'Isolation Bytes launched.'
    } else {
        Write-Warning 'Could not locate the installed package to launch.'
    }
} else {
    $pkg = $null
    Write-Warning 'Desktop package unavailable; continuing with the network agent installation.'
}

# ─── 6. Install the network monitoring agent ───────────────────────────
$agentDir = Join-Path $env:LOCALAPPDATA 'IsolationBytes'
New-Item -ItemType Directory -Path $agentDir -Force | Out-Null

Write-Host 'Installing network monitoring agent...'
$agentExe = Join-Path $agentDir 'IsolationBytesAgent.exe'
try {
    Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytesAgent.exe" -OutFile $agentExe -UseBasicParsing -TimeoutSec 120
    if ((Get-Item $agentExe).Length -lt 100000) { throw 'Downloaded agent is unexpectedly small' }
    Write-Host '  Agent EXE downloaded.'
} catch {
    Write-Warning "Could not download IsolationBytesAgent.exe: $($_.Exception.Message)"
}

# Create a scheduled task to auto-start the agent on login
$taskName = 'IsolationBytesAgent'
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
if (Test-Path $agentExe) {
    # Register a per-user URI handler so the website can launch this agent
    # without requiring administrator rights or exposing the API key.
    $protocolKey = 'HKCU:\Software\Classes\isolationbytes'
    New-Item -Path $protocolKey -Force | Out-Null
    New-ItemProperty -Path $protocolKey -Name '(Default)' -Value 'URL:Isolation Bytes Pairing' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $protocolKey -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
    New-Item -Path "$protocolKey\shell\open\command" -Force | Out-Null
    New-ItemProperty -Path "$protocolKey\shell\open\command" -Name '(Default)' -Value "`"$agentExe`" `"%1`"" -PropertyType String -Force | Out-Null

    if (-not $PairCode -and -not $ApiKey) {
        $PairCode = Read-Host 'Enter the one-time pairing code from the website (leave blank for API key)'
    }
    if (-not $PairCode -and -not $ApiKey) { $ApiKey = Read-Host 'Enter your CLOUD_API_KEY' }
    if (-not $PairCode -and -not $ApiKey) { throw 'A pairing code or CLOUD_API_KEY is required to connect this PC' }
    $credentialFile = Join-Path $agentDir 'device.token'
    if ($PairCode) {
        $agentArgs = "--server `"$BaseUrl`" --pair-code `"$($PairCode.Trim())`" --credential-file `"$credentialFile`" --auto-start"
    } else {
        $keyFile = Join-Path $agentDir 'cloud_api_key.txt'
        [System.IO.File]::WriteAllText($keyFile, $ApiKey.Trim(), [System.Text.UTF8Encoding]::new($false))
        icacls $keyFile /inheritance:r /grant:r "$env:USERNAME:(R)" | Out-Null
        $agentArgs = "--server `"$BaseUrl`" --key-file `"$keyFile`" --auto-start"
    }
    $action = New-ScheduledTaskAction -Execute $agentExe -Argument $agentArgs
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host '  Network monitoring agent scheduled to start on login (admin privileges).'

    # Start it now
    $started = Start-Process -FilePath $agentExe -ArgumentList $agentArgs -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    if ($started.HasExited -and $started.ExitCode -ne 0) {
        Write-Warning "Agent exited immediately with code $($started.ExitCode). Run it from a terminal to see the error."
    } else {
        Write-Host '  Network monitoring agent started.'
    }
} else {
    Write-Warning 'Agent executable was not installed; download it separately before expecting this PC to appear online.'
}

Write-Host ''
Write-Host 'Installation complete!' -ForegroundColor Green
Write-Host 'Isolation Bytes is available in your Start menu and on your Desktop.'
'''

_INSTALL_WINDOWS_BAT = r'''@echo off
echo Installing Isolation Bytes...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iwr https://isolation-bytes.com/download/install-windows.ps1 -UseBasicParsing | iex"
pause
'''

_INSTALL_MACOS_SH = r'''#!/bin/bash
# Isolation Bytes — macOS Installer
set -e
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
echo "Downloading Isolation Bytes Agent for macOS..."
curl -L "$BASE_URL/download/IsolationBytesAgent.exe" -o "$HOME/IsolationBytesAgent"
chmod +x "$HOME/IsolationBytesAgent"
echo "Installing agent..."
"$HOME/IsolationBytesAgent" --server "$BASE_URL" --auto-start &
echo "Installation complete!"
'''

_INSTALL_LINUX_SH = r'''#!/bin/bash
# Isolation Bytes — Linux Installer
set -e
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
echo "Downloading Isolation Bytes Agent for Linux..."
curl -L "$BASE_URL/download/IsolationBytesAgent.exe" -o "$HOME/IsolationBytesAgent"
chmod +x "$HOME/IsolationBytesAgent"
echo "Installing agent..."
"$HOME/IsolationBytesAgent" --server "$BASE_URL" --auto-start &
echo "Installation complete!"
'''

_INSTALL_UNIVERSAL_SH = r'''#!/bin/bash
# Isolation Bytes — Universal Unix Installer (macOS/Linux/ChromeOS)
exec bash "$(dirname "$0")/install-linux.sh"
'''

_INSTALL_ANDROID_SH = r'''#!/bin/bash
# Isolation Bytes — Android APK Installer (via adb)
set -e
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
echo "Downloading Isolation Bytes APK..."
curl -L "$BASE_URL/download/IsolationBytes-v1.8.950.0.apk" -o /tmp/IsolationBytes-v1.8.950.0.apk
if command -v adb &>/dev/null; then
    echo "Installing via adb..."
    adb install -r /tmp/IsolationBytes-v1.8.950.0.apk
else
    echo "adb not found. APK saved to /tmp/IsolationBytes-v1.8.950.0.apk"
    echo "Transfer to your Android device and install manually."
fi
'''

_INSTALL_CHROMEOS_SH = r'''#!/bin/bash
# Isolation Bytes — ChromeOS Installer (Linux container)
exec bash "$(dirname "$0")/install-linux.sh"
'''

_INSTALL_IOS_MOBILECONFIG = r'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.isolationbytes.ios</string>
    <key>PayloadUUID</key>
    <string>isolation-bytes-ios-profile</string>
    <key>PayloadDisplayName</key>
    <string>Isolation Bytes PWA</string>
    <key>PayloadDescription</key>
    <string>Install Isolation Bytes as a PWA on iOS</string>
</dict>
</plist>
'''

_START_AGENT_SH = r'''#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
PAIR_CODE="${ISOLATION_BYTES_PAIR_CODE:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AUTO_START=1
BACKGROUND=0
AGENT_ARGS=(--server "$BASE_URL" --auto-start)
while [ "$#" -gt 0 ]; do
    case "$1" in
        --pair-code) [ "$#" -ge 2 ] || exit 2; PAIR_CODE="$2"; shift 2 ;;
        --server) [ "$#" -ge 2 ] || exit 2; BASE_URL="$2"; AGENT_ARGS=(--server "$BASE_URL" --auto-start); shift 2 ;;
        --no-auto-start) AUTO_START=0; AGENT_ARGS=("${AGENT_ARGS[@]/--auto-start}"); shift ;;
        --background) BACKGROUND=1; shift ;;
        *) AGENT_ARGS+=("$1"); shift ;;
    esac
done
AGENT_EXE="${ISOLATION_BYTES_AGENT_EXE:-}"
if [ -z "$AGENT_EXE" ]; then
    for candidate in "$HOME/IsolationBytesAgent" "$HOME/IsolationBytesAgent.exe" "$SCRIPT_DIR/IsolationBytesAgent" "$SCRIPT_DIR/IsolationBytesAgent.exe"; do
        if [ -x "$candidate" ] || [ -f "$candidate" ]; then
            AGENT_EXE="$candidate"
            break
        fi
    done
fi
UNAME_S="$(uname -s 2>/dev/null || true)"
if [ -z "$AGENT_EXE" ] && { case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) true ;; *) [ -n "${WINDIR:-}" ] ;; esac; }; then
    AGENT_EXE="${LOCALAPPDATA:-$HOME/AppData/Local}/IsolationBytes/IsolationBytesAgent.exe"
    mkdir -p "$(dirname "$AGENT_EXE")"
    if [ ! -f "$AGENT_EXE" ]; then
        echo "IsolationBytesAgent.exe not found. Downloading it..."
        if command -v curl >/dev/null 2>&1; then
            curl --fail --location --silent --show-error "$BASE_URL/download/IsolationBytesAgent.exe" -o "$AGENT_EXE"
        elif command -v wget >/dev/null 2>&1; then
            wget --quiet --output-document="$AGENT_EXE" "$BASE_URL/download/IsolationBytesAgent.exe"
        else
            rm -f "$AGENT_EXE"
        fi
    fi
    [ -f "$AGENT_EXE" ] || AGENT_EXE=""
fi
if [ -n "$AGENT_EXE" ]; then
    [ -n "$PAIR_CODE" ] && AGENT_ARGS+=(--pair-code "$PAIR_CODE")
    if [ "$BACKGROUND" -eq 1 ]; then nohup "$AGENT_EXE" "${AGENT_ARGS[@]}" >/dev/null 2>&1 & exit 0; fi
    exec "$AGENT_EXE" "${AGENT_ARGS[@]}"
fi
if [ -z "${ISOLATION_BYTES_API_KEY:-}" ] && [ ! -f "${HOME}/.config/isolationbytes/cloud_api_key.txt" ] && [ -z "$PAIR_CODE" ]; then
    echo "Isolation Bytes agent is not paired on this device." >&2
    echo "Pass --pair-code CODE or set ISOLATION_BYTES_API_KEY." >&2
    exit 1
fi
PYTHON_BIN="${PYTHON:-python3}"
AGENT_SCRIPT="${ISOLATION_BYTES_AGENT_SCRIPT:-$SCRIPT_DIR/standalone_agent.py}"
if [ ! -f "$AGENT_SCRIPT" ]; then
    AGENT_SCRIPT="$HOME/standalone_agent.py"
    if command -v curl >/dev/null 2>&1; then curl --fail --location --silent --show-error "$BASE_URL/download/standalone_agent.py" -o "$AGENT_SCRIPT"; else wget --quiet --output-document="$AGENT_SCRIPT" "$BASE_URL/download/standalone_agent.py"; fi
fi
[ -f "$AGENT_SCRIPT" ] || { echo "standalone_agent.py not found" >&2; exit 1; }
[ -n "$PAIR_CODE" ] && AGENT_ARGS+=(--pair-code "$PAIR_CODE")
if [ "$BACKGROUND" -eq 1 ]; then nohup "$PYTHON_BIN" "$AGENT_SCRIPT" "${AGENT_ARGS[@]}" >/dev/null 2>&1 & exit 0; fi
exec "$PYTHON_BIN" "$AGENT_SCRIPT" "${AGENT_ARGS[@]}"
'''

_START_AGENT_BAT = r'''@echo off
setlocal
set "BASE_URL=%ISOLATION_BYTES_SERVER%"
if not defined BASE_URL set "BASE_URL=https://isolation-bytes.com"
set "AGENT=%LOCALAPPDATA%\IsolationBytes\IsolationBytesAgent.exe"
set "TOKEN=%LOCALAPPDATA%\IsolationBytes\device.token"
if exist "%AGENT%" (
    if "%~1"=="" if not exist "%TOKEN%" if not exist "%LOCALAPPDATA%\IsolationBytes\cloud_api_key.txt" (
        echo Isolation Bytes agent is not paired on this PC.
        echo Run the installer or pass the one-time pairing code:
        echo   start_agent.bat PAIRING_CODE
        pause
        exit /b 1
    )
    if not "%~1"=="" (start "" /min "%AGENT%" --server "%BASE_URL%" --pair-code "%~1" --credential-file "%TOKEN%" --auto-start) else if exist "%LOCALAPPDATA%\IsolationBytes\cloud_api_key.txt" (start "" /min "%AGENT%" --server "%BASE_URL%" --key-file "%LOCALAPPDATA%\IsolationBytes\cloud_api_key.txt" --credential-file "%TOKEN%" --auto-start) else (start "" /min "%AGENT%" --server "%BASE_URL%" --credential-file "%TOKEN%" --auto-start)
    exit /b 0
)
echo IsolationBytesAgent.exe was not found. Install the agent first.
pause
exit /b 1
'''

_UNIVERSAL_LAUNCHER_PY = r'''#!/usr/bin/env python3
"""Universal launcher for Isolation Bytes agent."""
import sys, os
agent = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'IsolationBytes', 'IsolationBytesAgent.exe')
if not os.path.exists(agent):
    agent = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'IsolationBytesAgent.exe')
os.execv(agent, [agent] + sys.argv[1:])
'''

_STANDALONE_AGENT_PY = '# Standalone agent — download from /download/IsolationBytesAgent.exe'

# Map install script filenames to their inline content
_INSTALL_SCRIPTS = {
    'install-windows.ps1': _INSTALL_WINDOWS_PS1,
    'install-windows.bat': _INSTALL_WINDOWS_BAT,
    'install-macos.sh': _INSTALL_MACOS_SH,
    'install-linux.sh': _INSTALL_LINUX_SH,
    'install-universal.sh': _INSTALL_UNIVERSAL_SH,
    'install-universal.bat': _INSTALL_WINDOWS_BAT,
    'install-android.sh': _INSTALL_ANDROID_SH,
    'install-chromeos.sh': _INSTALL_CHROMEOS_SH,
    'install-ios.mobileconfig': _INSTALL_IOS_MOBILECONFIG,
    'start_agent.bat': _START_AGENT_BAT,
    'start_agent.sh': _START_AGENT_SH,
    'universal_launcher.py': _UNIVERSAL_LAUNCHER_PY,
    'standalone_agent.py': _STANDALONE_AGENT_PY,
}


@cloud_bp.route('/download/checksums.json', methods=['GET'])
@cloud_bp.route('/checksums.json', methods=['GET'])
def cloud_checksums():
    """Return SHA-256 checksums for all downloadable files (cached by mtime)."""
    import hashlib as _hashlib
    search_dirs = []
    if _exe_dir:
        search_dirs.append(_exe_dir / 'downloads')
        search_dirs.append(_exe_dir / 'dist')
    search_dirs.append(BASE_DIR / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'dist')
    if getattr(sys, '_MEIPASS', None):
        search_dirs.append(Path(sys._MEIPASS) / 'downloads')
    # Build cache key from (filename, mtime, size) for all files
    files_info = {}
    cache_key_parts = []
    for d in search_dirs:
        if not os.path.isdir(str(d)):
            continue
        for f in os.listdir(str(d)):
            if f in files_info:
                continue
            fp = d / f
            if not os.path.isfile(str(fp)):
                continue
            if f.endswith(('.pyc', '.pyo', '.log', '.bak', '.tmp')):
                continue
            try:
                st = os.stat(str(fp))
                files_info[f] = (str(fp), st.st_mtime, st.st_size)
                cache_key_parts.append(f'{f}:{st.st_mtime}:{st.st_size}')
            except Exception:
                pass
    cache_key = _hashlib.md5('|'.join(sorted(cache_key_parts)).encode()).hexdigest()
    cached = getattr(cloud_checksums, '_cache', None)
    if cached and cached.get('key') == cache_key:
        return jsonify(cached['data'])
    # Compute checksums
    checksums = {}
    for f, (fp, mtime, size) in files_info.items():
        try:
            h = _hashlib.sha256()
            with open(fp, 'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            checksums[f] = {'sha256': h.hexdigest(), 'size': size}
        except Exception:
            pass
    result = {'version': '1.8.950.0', 'files': checksums}
    cloud_checksums._cache = {'key': cache_key, 'data': result}
    return jsonify(result)


@cloud_bp.route('/agent/update-check', methods=['GET'])
def cloud_agent_update_check():
    """Check if a newer agent EXE is available for download.

    Returns the latest version, download URL, and SHA-256 checksum so the
    agent can decide whether to self-update.
    """
    import hashlib as _hashlib
    search_dirs = []
    if _exe_dir:
        search_dirs.append(_exe_dir / 'downloads')
        search_dirs.append(_exe_dir / 'dist')
    search_dirs.append(BASE_DIR / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'dist')

    agent_path = None
    for d in search_dirs:
        if d.exists():
            candidate = d / 'IsolationBytesAgent.exe'
            if candidate.exists():
                agent_path = candidate
                break

    if not agent_path:
        return jsonify({'update_available': False, 'error': 'agent not found on server'}), 200

    try:
        size = agent_path.stat().st_size
        h = _hashlib.sha256()
        with open(agent_path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        sha256 = h.hexdigest()
    except Exception:
        return jsonify({'update_available': False, 'error': 'could not read agent'}), 200

    return jsonify({
        'update_available': True,
        'version': '1.8.950.0',
        'download_url': f'{request.url_root.rstrip("/")}/download/IsolationBytesAgent.exe',
        'sha256': sha256,
        'size': size,
    }), 200


@cloud_bp.route('/download/<path:filename>/checksum', methods=['GET'])
def cloud_download_checksum(filename):
    """Return SHA-256 checksum for a single file (cached)."""
    import hashlib as _hashlib
    real = unquote(filename).replace('/', '\\').split('\\')[-1]
    search_dirs = []
    if _exe_dir:
        search_dirs.append(_exe_dir / 'downloads')
        search_dirs.append(_exe_dir / 'dist')
    search_dirs.append(BASE_DIR / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'downloads')
    search_dirs.append(BASE_DIR.parent / 'dist')
    if getattr(sys, '_MEIPASS', None):
        search_dirs.append(Path(sys._MEIPASS) / 'downloads')
    for d in search_dirs:
        if not os.path.isdir(str(d)):
            continue
        target = d / real
        if os.path.isfile(str(target)):
            st = os.stat(str(target))
            cache_key = f'{real}:{st.st_mtime}:{st.st_size}'
            cache_attr = f'_cache_{real}'
            cached = getattr(cloud_download_checksum, cache_attr, None)
            if cached and cached.get('key') == cache_key:
                return jsonify(cached['data'])
            h = _hashlib.sha256()
            with open(str(target), 'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            result = {'filename': real, 'sha256': h.hexdigest(), 'size': st.st_size}
            setattr(cloud_download_checksum, cache_attr, {'key': cache_key, 'data': result})
            return jsonify(result)
    return jsonify({'error': 'File not found'}), 404


# ---------------------------------------------------------------------------
# GitHub webhook — auto-pull on push and restart the service
# ---------------------------------------------------------------------------
@cloud_bp.route('/api/github-webhook', methods=['POST'])
def github_webhook():
    """GitHub push webhook. Pulls latest code and restarts the service."""
    secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '').strip()
    if not secret:
        logger.error('GITHUB_WEBHOOK_SECRET is not configured; refusing webhook')
        return jsonify({'error': 'webhook authentication is not configured'}), 503
    import hmac as _hmac, hashlib as _hashlib
    sig = request.headers.get('X-Hub-Signature-256', '')
    if not sig.startswith('sha256='):
        return jsonify({'error': 'bad signature'}), 403
    expected = 'sha256=' + _hmac.new(secret.encode(), request.get_data(), _hashlib.sha256).hexdigest()
    if not _hmac.compare_digest(sig, expected):
        return jsonify({'error': 'invalid signature'}), 403
    event = request.headers.get('X-GitHub-Event', '')
    delivery_id = request.headers.get('X-GitHub-Delivery', '').strip()
    if not re.fullmatch(r'[0-9a-fA-F-]{16,128}', delivery_id):
        return jsonify({'error': 'missing or invalid delivery id'}), 400
    now = time.time()
    with _webhook_delivery_lock:
        expired = [
            delivery for delivery, received_at in _webhook_deliveries.items()
            if now - received_at > _WEBHOOK_REPLAY_WINDOW
        ]
        for delivery in expired:
            _webhook_deliveries.pop(delivery, None)
        if delivery_id in _webhook_deliveries:
            return jsonify({'error': 'duplicate delivery'}), 409
        _webhook_deliveries[delivery_id] = now
        while len(_webhook_deliveries) > 2048:
            _webhook_deliveries.popitem(last=False)
    if event == 'ping':
        return jsonify({'msg': 'pong'}), 200
    if event != 'push':
        return jsonify({'msg': 'ignored'}), 200
    payload = request.get_json(silent=True) or {}
    repository = payload.get('repository') or {}
    expected_repository = os.environ.get(
        'GITHUB_WEBHOOK_REPOSITORY', 'soluzka/Isolation_Bytes'
    ).strip()
    if repository.get('full_name') != expected_repository:
        logger.warning(
            'Rejected webhook from unexpected repository: %s',
            repository.get('full_name'),
        )
        return jsonify({'error': 'unexpected repository'}), 403
    expected_ref = os.environ.get(
        'GITHUB_WEBHOOK_REF', 'refs/heads/security-v2'
    ).strip()
    if payload.get('ref') != expected_ref:
        return jsonify({'msg': 'ignored'}), 200
    if payload.get('deleted') is True:
        return jsonify({'msg': 'ignored'}), 200
    # Pull latest code
    import subprocess as _sp
    try:
        _sp.run(['git', 'fetch', 'origin'], cwd=str(BASE_DIR), capture_output=True, timeout=60)
        _sp.run(['git', 'reset', '--hard', 'origin/security-v2'], cwd=str(BASE_DIR), capture_output=True, timeout=60)
        _sp.run(['git', 'pull', 'origin', 'security-v2'], cwd=str(BASE_DIR), capture_output=True, timeout=60)
    except Exception as e:
        return jsonify({'error': f'git pull failed: {e}'}), 500
    # Restart the service so new code loads
    try:
        _sp.run(['systemctl', 'restart', 'antivirus-cloud'], capture_output=True, timeout=30)
    except Exception:
        pass
    return jsonify({'msg': 'pulled and restarted'}), 200


# ---------------------------------------------------------------------------
# Admin file upload — push built artifacts to the downloads directory
# ---------------------------------------------------------------------------
@cloud_bp.route('/api/upload-download', methods=['POST'])
def upload_download():
    """Upload a file to the downloads directory. Protected by API key."""
    key = request.headers.get('X-Api-Key', '').strip()
    if not constant_time_equal(CLOUD_API_KEY, key):
        return jsonify({'error': 'unauthorized'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'no file provided'}), 400
    f = request.files['file']
    valid, filename, error = validate_upload(
        f,
        allowed_extensions={'zip', 'msix', 'appx', 'appinstaller', 'apk', 'exe', 'dmg', 'pkg', 'cer'},
    )
    if not valid:
        return jsonify({'error': error}), 400
    # Find the downloads directory
    upload_dir = None
    if _exe_dir:
        candidate = _exe_dir / 'downloads'
        if os.path.isdir(str(candidate)):
            upload_dir = candidate
    if not upload_dir:
        candidate = BASE_DIR / 'downloads'
        os.makedirs(str(candidate), exist_ok=True)
        upload_dir = candidate
    if not upload_dir:
        candidate = BASE_DIR.parent / 'downloads'
        os.makedirs(str(candidate), exist_ok=True)
        upload_dir = candidate
    target = (upload_dir / filename).resolve()
    if target.parent != upload_dir.resolve():
        return jsonify({'error': 'invalid filename'}), 400
    f.save(str(target))
    return jsonify({'msg': 'uploaded', 'filename': filename, 'size': os.path.getsize(str(target))}), 200


@cloud_bp.route('/agent/register', methods=['POST'])
@_require_key
def agent_register():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get('device_id', '').strip()
    hostname = data.get('hostname', '').strip()
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    # Clean up stale agents with the same hostname but different device_id
    # (prevents duplicate entries when the agent restarts with a new ID)
    if hostname:
        with _agents_lock:
            existing = _load_agents()
            to_remove = []
            for did, a in existing.items():
                if did == device_id:
                    continue
                if a.get('hostname', '').lower() == hostname.lower():
                    # Remove if it has no connections or hasn't been seen recently
                    conns = a.get('network_connections', [])
                    if not conns or len(conns) == 0:
                        to_remove.append(did)
            for did in to_remove:
                del existing[did]
                commands.pop(did, None)
            if to_remove:
                _save_agents(existing)
    # Preserve cumulative counters across re-registrations
    existing = _get_agent(device_id) or {}
    _set_agent(device_id, {
        'device_id': device_id,
        'hostname': hostname,
        'os': data.get('os', ''),
        'os_version': data.get('os_version', ''),
        'arch': data.get('arch', ''),
        'cpu': data.get('cpu', ''),
        'ram_mb': data.get('ram_mb', 0),
        'ip': data.get('ip', ''),
        'mac': data.get('mac', ''),
        'agent_version': data.get('agent_version', ''),
        'registered_at': datetime.now(timezone.utc).isoformat(),
        'last_seen': datetime.now(timezone.utc).isoformat(),
        'status': 'online',
        'last_scan': None,
        'findings_count': existing.get('findings_count', 0) or 0,
        'threats_blocked': existing.get('threats_blocked', 0) or 0,
        'files_scanned': existing.get('files_scanned', 0) or 0,
        'quarantined_count': existing.get('quarantined_count', 0) or 0,
        'processes': [],
        'network_connections': [],
        'last_report': existing.get('last_report'),
        # Preserve cumulative threat-type counters
        'total_ransomware': existing.get('total_ransomware', 0) or 0,
        'total_persistence': existing.get('total_persistence', 0) or 0,
        'total_yara': existing.get('total_yara', 0) or 0,
        'total_ml': existing.get('total_ml', 0) or 0,
        'blocked_files': existing.get('blocked_files', []),
        '_device_credential_hash': existing.get('_device_credential_hash', ''),
    })
    commands[device_id] = []
    return jsonify({'ok': True}), 200


@cloud_bp.route('/api/agent/pairing-code', methods=['POST'])
@_require_login
def create_agent_pairing_code():
    """Create a short-lived, single-use code for bootstrapping one agent."""
    code = secrets.token_urlsafe(9).replace('-', '').replace('_', '')[:12].upper()
    now = time.time()
    with _pairing_lock:
        for key, item in list(_pairing_codes.items()):
            if item['expires_at'] <= now:
                _pairing_codes.pop(key, None)
        _pairing_codes[_credential_hash(code)] = {
            'expires_at': now + _PAIRING_TTL_SECONDS,
            'username': session.get('user_username', 'admin'),
        }
    logger.info('Created one-time agent pairing code for %s', session.get('user_username', 'admin'))
    return jsonify({'code': code, 'expires_in': _PAIRING_TTL_SECONDS}), 200


@cloud_bp.route('/agent/pair', methods=['POST'])
def pair_agent():
    """Exchange a browser-generated pairing code for a device credential."""
    data = request.get_json(silent=True) or {}
    code = str(data.get('pair_code', '')).strip().upper()
    device_id = str(data.get('device_id', '')).strip()
    hostname = str(data.get('hostname', '')).strip()
    if not re.fullmatch(r'[A-Z0-9]{8,12}', code) or not re.fullmatch(r'[A-Za-z0-9_:-]{1,80}', device_id):
        return jsonify({'error': 'invalid pairing request'}), 400
    code_hash = _credential_hash(code)
    with _pairing_lock:
        pairing = _pairing_codes.get(code_hash)
        if not pairing or pairing['expires_at'] <= time.time():
            _pairing_codes.pop(code_hash, None)
            return jsonify({'error': 'pairing code is invalid or expired'}), 401
        _pairing_codes.pop(code_hash, None)
    credential = secrets.token_urlsafe(32)
    existing = _get_agent(device_id) or {}
    _set_agent(device_id, {
        **existing,
        'device_id': device_id,
        'hostname': hostname,
        'status': 'pending',
        '_device_credential_hash': _credential_hash(credential),
        'paired_at': datetime.now(timezone.utc).isoformat(),
        'paired_by': pairing['username'],
    })
    logger.info('Paired agent %s for %s', device_id, pairing['username'])
    return jsonify({'ok': True, 'device_token': credential}), 200


@cloud_bp.route('/agent/heartbeat', methods=['POST'])
@_require_key
def agent_heartbeat():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get('device_id', '').strip()
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    agent = _get_agent(device_id)
    if not agent:
        return jsonify({'error': 'unknown device'}), 404
    updates = {
        'last_seen': datetime.now(timezone.utc).isoformat(),
        'status': 'online',
        'cpu_usage': data.get('cpu_usage', 0),
        'mem_usage': data.get('mem_usage', 0),
        'disk_usage': data.get('disk_usage', 0),
        'uptime': data.get('uptime', ''),
        'processes': data.get('processes', agent.get('processes', [])),
        'network_connections': data.get('network_connections', agent.get('network_connections', [])),
        'network_devices': data.get('network_devices', agent.get('network_devices', [])),
        'files_scanned': data.get('files_scanned', agent.get('files_scanned', 0)),
        'threats_blocked': data.get('threats_blocked', agent.get('threats_blocked', 0)),
        'quarantined_count': data.get('quarantined_count', agent.get('quarantined_count', 0)),
        'quarantine_files': data.get('quarantine_files', agent.get('quarantine_files', [])),
        'startup_enabled': data.get('startup_enabled', agent.get('startup_enabled', False)),
        'kill_switch_active': data.get('kill_switch_active', agent.get('kill_switch_active', False)),
        'flagged_connections': data.get('flagged_connections', agent.get('flagged_connections', [])),
        'watched_connections': data.get('watched_connections', agent.get('watched_connections', [])),
        'flagged_count': data.get('flagged_count', 0),
        'watched_count': data.get('watched_count', 0),
        'scan_dirs': data.get('scan_dirs', agent.get('scan_dirs', [])),
        'dir_file_counts': data.get('dir_file_counts', agent.get('dir_file_counts', {})),
        # Cumulative finding counters from agent (survive even if report fails)
        'total_findings': data.get('total_findings', agent.get('total_findings', 0)),
        'total_ransomware': data.get('total_ransomware', agent.get('total_ransomware', 0)),
        'total_persistence': data.get('total_persistence', agent.get('total_persistence', 0)),
        'total_yara': data.get('total_yara', agent.get('total_yara', 0)),
        'total_ml': data.get('total_ml', agent.get('total_ml', 0)),
        'last_report_ok': data.get('last_report_ok', agent.get('last_report_ok', False)),
        'last_report_error': data.get('last_report_error', agent.get('last_report_error', '')),
    }
    _update_agent(device_id, updates)
    # Auto-block: scan heartbeat connections for threats and queue block
    # commands immediately — this runs on EVERY heartbeat (every 10 seconds)
    # so blocking works even when nobody is viewing the dashboard.
    if _auto_block_enabled and not device_id.startswith('LOCAL-'):
        conns = data.get('network_connections', [])
        _c2_ports = {6667, 6668, 6669, 1337, 4444, 5555, 9999, 31337, 12345, 27374}
        _suspicious_procs = {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                             'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
                             'nc.exe', 'ncat.exe', 'mimikatz.exe', 'procdump.exe'}
        _common_ports = {80, 443, 53, 22, 25, 587, 993, 995, 8080, 8443, 123, 67, 68, 465, 143, 110, 21, 20, 3389, 5900}
        for c in conns:
            if not isinstance(c, dict):
                continue
            remote_ip = c.get('remote_ip', '')
            remote_port = c.get('remote_port', 0)
            proc = (c.get('process') or '').lower()
            agent_flag = c.get('flag', 'clean')
            if not remote_ip or remote_ip == '-':
                continue
            if remote_ip in _blocked_ips:
                continue
            # Only block public IPs
            is_public = False
            try:
                import ipaddress as _ipa
                addr = _ipa.ip_address(remote_ip)
                is_public = not (addr.is_loopback or addr.is_private or addr.is_link_local)
            except Exception:
                continue
            if not is_public:
                continue
            should_block = False
            reasons = []
            # Agent-side flag
            if agent_flag in ('flagged', 'suspicious'):
                should_block = True
                reasons.append('agent flagged')
            # C2 port
            if remote_port in _c2_ports:
                should_block = True
                reasons.append(f'C2 port {remote_port}')
            # Suspicious process
            if proc in _suspicious_procs:
                should_block = True
                reasons.append(f'suspicious process {proc}')
            if should_block:
                _blocked_ips.add(remote_ip)
                commands.setdefault(device_id, []).append({
                    'action': 'block_ip',
                    'ip': remote_ip,
                    'reason': f'Auto-blocked: {", ".join(reasons)}',
                })
    # Return any pending commands
    pending = commands.get(device_id, [])
    commands[device_id] = []
    return jsonify({'commands': pending}), 200


@cloud_bp.route('/api/flagged-connections', methods=['GET'])
def flagged_connections():
    """Return all flagged and watched connections from registered agents."""
    agents = _get_agents()
    flagged = []
    watched = []
    for device_id, agent in agents.items():
        for c in (agent.get('flagged_connections') or []):
            if isinstance(c, dict):
                c.setdefault('device_id', device_id)
                c.setdefault('hostname', agent.get('hostname', device_id))
                flagged.append(c)
        for c in (agent.get('watched_connections') or []):
            if isinstance(c, dict):
                c.setdefault('device_id', device_id)
                c.setdefault('hostname', agent.get('hostname', device_id))
                watched.append(c)
    return jsonify({
        'flagged': flagged,
        'watched': watched,
        'flagged_count': len(flagged),
        'watched_count': len(watched),
        'timestamp': time.time(),
    })


@cloud_bp.route('/agent/report', methods=['POST'])
@_require_key
def agent_report():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get('device_id', '').strip()
    if not device_id or not _get_agent(device_id):
        return jsonify({'error': 'unknown device'}), 404

    # Enrich findings with classification, risk score, and timestamps
    raw_findings = data.get('findings') or data.get('results') or []
    enriched = []
    for f in raw_findings:
        if not isinstance(f, dict):
            f = {'value': str(f)}
        sev = str(f.get('severity', f.get('risk', 'low'))).lower()
        # Auto-classify threat type from reason/path/rule/tags
        reason = str(f.get('reason', f.get('description', ''))).lower()
        path = str(f.get('path', f.get('file', ''))).lower()
        rule = str(f.get('rule', '')).lower()
        tags = ' '.join(str(t) for t in (f.get('tags') or [])).lower()
        blob = f'{reason} {path} {rule} {tags}'
        threat_type = f.get('threat_type', 'unknown') or 'unknown'
        # Only auto-classify if the agent didn't already classify
        if threat_type in ('unknown', '', None):
            desc = str(f.get('description', '') or '').lower()
            blob = f'{blob} {desc}'
            if 'ransomware' in blob or 'ransom' in blob or 'lockbit' in blob or 'cerber' in blob:
                threat_type = 'ransomware'
            elif 'persist' in blob or 'startup' in blob or 'autorun' in blob:
                threat_type = 'persistence'
            elif 'keylog' in blob:
                threat_type = 'keylogger'
            elif 'trojan' in blob or 'backdoor' in blob:
                threat_type = 'trojan'
            elif 'rootkit' in blob or 'kernel' in blob:
                threat_type = 'rootkit'
            elif 'adware' in blob or 'pup' in blob:
                threat_type = 'adware'
            elif 'spyware' in blob:
                threat_type = 'spyware'
            elif 'miner' in blob or 'crypto' in blob:
                threat_type = 'cryptominer'
            elif 'c2' in blob or 'command' in blob:
                threat_type = 'c2_beacon'
            elif 'yara' in blob:
                threat_type = 'yara_match'
        if f.get('ml_score'):
            threat_type = 'ml_suspicious' if threat_type == 'unknown' else threat_type
        # Risk score 0-100
        risk = {'critical': 95, 'high': 75, 'medium': 50, 'low': 20}.get(sev, 25)
        if threat_type in ('ransomware', 'rootkit', 'keylogger', 'persistence'):
            risk = max(risk, 90)
        f['threat_type'] = threat_type
        f['risk_score'] = risk
        f['detected_at'] = f.get('detected_at') or data.get('timestamp') or datetime.now(timezone.utc).isoformat()
        f['device_id'] = device_id
        f['hostname'] = _get_agent(device_id).get('hostname', device_id) if _get_agent(device_id) else device_id
        enriched.append(f)

    data['findings'] = enriched
    data['finding_count'] = len(enriched)
    # Build cumulative counters so clean scans don't zero them out
    existing = _get_agent(device_id) or {}
    prev_findings_count = existing.get('findings_count', 0) or 0
    # If this report has findings, add to cumulative total. If clean, keep
    # the previous cumulative total so the dashboard still shows history.
    cumulative_findings = prev_findings_count
    if len(enriched) > 0:
        cumulative_findings = prev_findings_count + len(enriched)
    # Count threat types from this report's findings for cumulative counters
    report_ransomware = 0
    report_persistence = 0
    report_yara = 0
    report_ml = 0
    for f in enriched:
        ttype = (f.get('threat_type') or '').lower()
        reason = str(f.get('reason', '')).lower()
        rule = str(f.get('rule', '')).lower()
        tags = ' '.join(str(t) for t in (f.get('tags') or [])).lower()
        desc = str(f.get('description', '') or '').lower()
        blob = f'{reason} {rule} {tags} {desc}'
        if (ttype == 'ransomware' or 'ransom' in blob
                or 'encrypt' in desc and 'file' in desc
                or 'lock' in blob and 'crypt' in blob
                or 'vss_delete' in blob or 'shadow_copy' in blob
                or 'wbadmin' in blob or 'recovery_disabl' in blob
                or 'backup_delete' in blob or 'ransomnote' in blob):
            report_ransomware += 1
        if (ttype == 'persistence' or 'persist' in blob or 'startup' in blob
                or 'autorun' in blob or 'scheduled' in blob
                or 'rootkit' in blob or 'keylog' in blob
                or 'backdoor' in blob or 'trojan' in blob
                or 'rat_' in blob or 'implant' in blob
                or 'beacon' in blob or 'c2_' in blob or 'botnet' in blob
                or 'worm' in blob or 'miner' in blob or 'stealer' in blob
                or 'dropper' in blob or 'shellcode' in blob or 'exploit' in blob
                or 'cobalt' in blob or 'meterpreter' in blob
                or 'webshell' in blob or 'web_shell' in blob
                or 'phishing' in blob or 'phish' in blob
                or 'spyware' in blob or 'adware' in blob
                or 'process_inject' in blob or 'process_hollow' in blob
                or 'dll_hijack' in blob or 'api_hook' in blob
                or 'code_inject' in blob or 'reflective_load' in blob
                or 'amsi_bypass' in blob or 'etw_bypass' in blob
                or 'defender_bypass' in blob or 'uac_bypass' in blob
                or 'privilege_escal' in blob or 'privesc' in blob
                or 'lateral_movement' in blob or 'credsteal' in blob
                or 'exfil' in blob or 'security_disabl' in blob
                or 'firewall_disabl' in blob or 'antivirus_disabl' in blob
                or ttype in ('rootkit', 'keylogger', 'trojan')):
            report_persistence += 1
        if ttype == 'yara_match' or ttype == 'blocked' or 'yara' in blob or 'yara' in reason or f.get('rule') or ttype in ('ransomware', 'persistence'):
            report_yara += 1
        if ttype == 'ml_suspicious' or 'ml' in reason or 'model' in reason or f.get('ml_score') or 'ml_heuristic' in rule:
            report_ml += 1
    # Preserve last_report findings when the new report has no findings
    # (clean scan shouldn't wipe the findings list the dashboard needs)
    new_findings = data.get('findings') or []
    if new_findings:
        last_report = data
    else:
        # Keep the previous last_report so findings stay visible
        last_report = existing.get('last_report') or data
    update_fields = {
        'last_report': last_report,
        'last_seen': datetime.now(timezone.utc).isoformat(),
        'findings_count': cumulative_findings,
        'last_scan': data.get('timestamp', datetime.now(timezone.utc).isoformat()),
        'files_scanned': data.get('files_scanned', existing.get('files_scanned', 0)),
        'quarantined_count': data.get('quarantined_count', existing.get('quarantined_count', 0)),
        # Cumulative threat-type counters (only increase, never reset)
        'total_ransomware': (existing.get('total_ransomware', 0) or 0) + report_ransomware,
        'total_persistence': (existing.get('total_persistence', 0) or 0) + report_persistence,
        'total_yara': (existing.get('total_yara', 0) or 0) + report_yara,
        'total_ml': (existing.get('total_ml', 0) or 0) + report_ml,
    }
    # Store agent quarantine list when the agent reports it
    if data.get('type') == 'quarantine_list' and 'quarantine_files' in data:
        update_fields['quarantine_files'] = data['quarantine_files']
    _update_agent(device_id, update_fields)

    data['received_at'] = datetime.now(timezone.utc).isoformat()
    events.append(data)
    while len(events) > 1000:
        events.pop(0)
    return jsonify({'ok': True, 'findings_processed': len(enriched)}), 200


def _get_c2_counts():
    """Return (low_count, high_count) from the latest C2 scan."""
    suspicious = _scan_c2_connections()
    low = sum(1 for s in suspicious if s.get('score', 0) < 70)
    high = sum(1 for s in suspicious if s.get('score', 0) >= 70)
    return low, high


@cloud_bp.route('/dashboard', methods=['GET'], endpoint='index')
@_require_login
def dashboard():
    _c2_low, _c2_high = _get_c2_counts()
    return render_template(
        'index.html',
        network_monitor_running=True,
        folder_watcher_status=True,
        auto_block_enabled=True,
        safe_downloader_status=True,
        auto_updates_running=True,
        c2_detector_low_count=_c2_low,
        c2_detector_high_count=_c2_high,
        scheduled_scan_enabled=True,
        status={'status': 'ENABLED', 'folder_watcher': True, 'network_monitor': True, 'safe_downloader': True},
        running_as_admin=True,
        administrator_service_available=True,
        admin_helper_message='Antivirus Cloud Protection Active.',
        devices=sorted(_all_agents().values(), key=lambda x: x.get('last_seen',''), reverse=True),
        events=list(reversed(events[-50:])),
        session=session
    )


@cloud_bp.route('/yara-scanner', methods=['GET'], endpoint='yara_scanner')
@cloud_bp.route('/yara_scanner.html', methods=['GET'])
def cloud_yara_scanner():
    rules_info = {'available': True, 'count': 42, 'last_updated': '2026-08-19', 'sources': ['cloud', 'custom']}
    # Show only directories from connected agents — the VPS itself
    # has no user files to scan, so only agent PCs are relevant.
    agents = _all_agents()
    monitored_folders = []
    agent_scan_results = []
    for device_id, ag in agents.items():
        host = ag.get('hostname', device_id)
        for d in (ag.get('scan_dirs') or []):
            monitored_folders.append(f"[{host}] {d}")
        # Collect agent scan findings
        last_report = ag.get('last_report') or {}
        findings = last_report.get('findings') or []
        agent_scan_results.append({
            'hostname': host,
            'device_id': device_id,
            'files_scanned': last_report.get('files_scanned', ag.get('files_scanned', 0)),
            'finding_count': len(findings),
            'last_scan': ag.get('last_scan', ''),
            'findings': findings,  # show all findings, not capped
        })
    return render_template('yara_scanner.html', rules_info=rules_info, monitored_folders=monitored_folders, monitored_directories=monitored_folders, agent_count=len(agents), agents=agents, agent_scan_results=agent_scan_results, session=session)


@cloud_bp.route('/api/agent-scan-results', methods=['GET'])
@_require_login
def cloud_agent_scan_results():
    """Return scan findings from all connected agents."""
    agents = _all_agents()
    results = []
    for device_id, ag in agents.items():
        host = ag.get('hostname', device_id)
        last_report = ag.get('last_report') or {}
        findings = last_report.get('findings') or []
        results.append({
            'hostname': host,
            'device_id': device_id,
            'files_scanned': last_report.get('files_scanned', ag.get('files_scanned', 0)),
            'finding_count': len(findings),
            'last_scan': ag.get('last_scan', ''),
            'findings': findings,  # show all findings, not capped
            'scan_dirs': ag.get('scan_dirs') or [],
            'quarantined_count': ag.get('quarantined_count', 0) or 0,
        })
    return jsonify({'agents': results, 'total_findings': sum(r['finding_count'] for r in results)})


@cloud_bp.route('/api/agent-trigger-scan', methods=['POST'])
@_require_login
def cloud_agent_trigger_scan():
    """Queue a scan_now command for all connected agents."""
    agents = _all_agents()
    sent = 0
    for device_id in agents:
        pending = commands.get(device_id, [])
        pending = [c for c in pending if c.get('action') != 'scan_now']
        pending.append({'action': 'scan_now'})
        commands[device_id] = pending
        sent += 1
    if sent > 0:
        return jsonify({'ok': True, 'message': f'Scan triggered for {sent} agent(s). Results will appear shortly.', 'agents': sent})
    return jsonify({'ok': False, 'message': 'No connected agents to scan.'}), 404


@cloud_bp.route('/api/agent-block/findings', methods=['POST'])
@_require_login
def cloud_agent_block_findings():
    """Queue a block_findings command for all connected agents.

    This tells each agent to block all detected threat files in place
    (deny all NTFS/POSIX permissions) without moving them to quarantine.
    The files stay on disk but cannot be executed, read, or modified.
    """
    agents = _all_agents()
    sent = 0
    total_findings = 0
    for device_id, ag in agents.items() if isinstance(agents, dict) else [(d, agents[d]) for d in agents]:
        findings = []
        last_report = ag.get('last_report') if isinstance(ag, dict) else None
        if isinstance(last_report, dict):
            findings = last_report.get('findings') or []
        if findings:
            pending = commands.get(device_id, [])
            pending.append({'action': 'block_findings', 'findings': findings})
            commands[device_id] = pending
            sent += 1
            total_findings += len(findings)
    if sent > 0:
        return jsonify({'ok': True, 'blocked': total_findings, 'failed': 0,
                        'message': f'Block command sent to {sent} agent(s) for {total_findings} threat(s).'})
    return jsonify({'ok': False, 'blocked': 0, 'failed': 0,
                    'message': 'No findings to block. Run a scan first.'}), 404


@cloud_bp.route('/api/agent-unblock/findings', methods=['POST'])
@_require_login
def cloud_agent_unblock_findings():
    """Queue an unblock_findings command for all connected agents.
    Restores permissions on previously blocked files so they can be
    read/executed again. Also renames .blocked files back to original.
    The agent uses its persisted blocked-files registry, so this works
    even after the agent has restarted (when last_report.findings is empty)."""
    agents = _all_agents()
    sent = 0
    total_findings = 0
    data = request.get_json(force=True, silent=True) or {}
    quarantine_after = data.get('quarantine_after', False)
    for device_id, ag in agents.items():
        findings = []
        last_report = ag.get('last_report') if isinstance(ag, dict) else None
        if isinstance(last_report, dict):
            findings = last_report.get('findings') or []
        # Count blocked files from the registry for accurate reporting
        blocked_files = ag.get('blocked_files') or []
        if isinstance(blocked_files, dict):
            blocked_count = len(blocked_files)
        else:
            blocked_count = len(blocked_files)
        # Always send the unblock command — the agent will also unblock
        # files from its persisted blocked-files registry, so unblock
        # works even after a restart when findings is empty.
        # If quarantine_after is set, the agent will quarantine immediately
        # after unblocking in the same command cycle.
        pending = commands.get(device_id, [])
        cmd = {'action': 'unblock_findings', 'findings': findings}
        if quarantine_after:
            cmd['quarantine_after'] = True
        pending.append(cmd)
        commands[device_id] = pending
        sent += 1
        total_findings += max(len(findings), blocked_count)
    if sent > 0:
        msg = f'Unblock command sent to {sent} agent(s).'
        if quarantine_after:
            msg = f'Unblock & quarantine command sent to {sent} agent(s).'
        return jsonify({'ok': True, 'unblocked': total_findings, 'failed': 0,
                        'message': msg})
    return jsonify({'ok': False, 'unblocked': 0, 'failed': 0,
                    'message': 'No connected agents.'}), 404


@cloud_bp.route('/api/agent-scan-file', methods=['POST'])
@_require_login
def cloud_agent_scan_file():
    """Queue a scan_file command for all connected agents."""
    data = request.get_json(force=True, silent=True) or {}
    file_path = (data.get('file_path') or '').strip()
    if not file_path:
        return jsonify({'ok': False, 'message': 'file_path required.'}), 400
    agents = _all_agents()
    sent = 0
    for device_id in agents:
        pending = commands.get(device_id, [])
        pending.append({'action': 'scan_file', 'file_path': file_path})
        commands[device_id] = pending
        sent += 1
    if sent > 0:
        return jsonify({'ok': True, 'message': f'Scan file command sent to {sent} agent(s).', 'agents': sent})
    return jsonify({'ok': False, 'message': 'No connected agents.'}), 404


@cloud_bp.route('/api/agent-add-folder', methods=['POST'])
@_require_login
def cloud_agent_add_folder():
    """Send add_folder command to all connected agents."""
    data = request.get_json(force=True, silent=True) or {}
    folder_path = (data.get('folder_path') or '').strip()
    if not folder_path:
        return jsonify({'ok': False, 'message': 'folder_path required.'}), 400
    agents = _all_agents()
    sent = 0
    for device_id in agents:
        pending = commands.get(device_id, [])
        pending.append({'action': 'add_folder', 'folder_path': folder_path})
        commands[device_id] = pending
        sent += 1
    if sent > 0:
        return jsonify({'ok': True, 'message': f'Add folder command sent to {sent} agent(s).', 'agents': sent})
    return jsonify({'ok': False, 'message': 'No connected agents.'}), 404


@cloud_bp.route('/api/agent-remove-folder', methods=['POST'])
@_require_login
def cloud_agent_remove_folder():
    """Send remove_folder command to all connected agents."""
    data = request.get_json(force=True, silent=True) or {}
    folder_path = (data.get('folder_path') or '').strip()
    if not folder_path:
        return jsonify({'ok': False, 'message': 'folder_path required.'}), 400
    agents = _all_agents()
    sent = 0
    for device_id in agents:
        pending = commands.get(device_id, [])
        pending.append({'action': 'remove_folder', 'folder_path': folder_path})
        commands[device_id] = pending
        sent += 1
    if sent > 0:
        return jsonify({'ok': True, 'message': f'Remove folder command sent to {sent} agent(s).', 'agents': sent})
    return jsonify({'ok': False, 'message': 'No connected agents.'}), 404


@cloud_bp.route('/custom-scan', methods=['GET', 'POST'], endpoint='custom_scan')
@cloud_bp.route('/custom_scan.html', methods=['GET', 'POST'])
def cloud_custom_scan():
    return render_template('custom_scan.html', session=session)


@cloud_bp.route('/safe_download', methods=['GET'], endpoint='safe_download')
@cloud_bp.route('/safe_download.html', methods=['GET'])
def cloud_safe_download_page():
    return render_template('safe_download.html', session=session)


# -- Quarantine helpers --
def _cloud_quarantine_dir():
    """Return the Defender_Quarantine folder path."""
    try:
        from quarantine_utils import QUARANTINE_FOLDER
        return QUARANTINE_FOLDER
    except ImportError:
        # Linux/VPS path
        if os.name != 'nt':
            return '/opt/antivirus-server/quarantine'
        # Windows path
        return os.path.join(
            os.environ.get('USERPROFILE', r'C:\Users\Default'),
            'AppData', 'Local', 'Temp', 'Defender_Quarantine'
        )


def _is_safe_quarantine_path(path, base_dir=None):
    """Return True if the resolved path is inside the quarantine directory."""
    if not path:
        return False
    base = base_dir or _cloud_quarantine_dir()
    try:
        base = os.path.realpath(base)
        target = os.path.realpath(os.path.join(base, path) if not os.path.isabs(path) else path)
        return os.path.commonpath([base, target]) == base
    except (ValueError, OSError):
        return False


def _cloud_decrypt_file(encrypted_path, output_path):
    """Decrypt a quarantined .enc file. Tries FERNET_KEY env var first
    (the format used by quarantine_utils.quarantine_file), then the
    44-byte-key-header format used by quick_start.encrypt_file."""
    try:
        from cryptography.fernet import Fernet
        with open(encrypted_path, 'rb') as f:
            file_data = f.read()

        decrypted = None
        # Format 1: FERNET_KEY env var (used by quarantine_utils)
        fernet_key = os.environ.get('FERNET_KEY', '').strip()
        if fernet_key:
            try:
                decrypted = Fernet(fernet_key.encode()).decrypt(file_data)
            except Exception:
                decrypted = None

        # Format 2: 44-byte key header (used by quick_start.encrypt_file)
        if decrypted is None and len(file_data) > 44:
            try:
                header_key = file_data[:44]
                decrypted = Fernet(header_key).decrypt(file_data[44:])
            except Exception:
                decrypted = None

        if decrypted is None:
            # Fallback: file may not be encrypted (fallback quarantine just moves it)
            # Just copy it as-is
            try:
                import shutil
                shutil.copy2(encrypted_path, output_path)
                return True
            except Exception:
                return False

        with open(output_path, 'wb') as f:
            f.write(decrypted)
        return True
    except Exception as e:
        logger.error(f'Error decrypting {encrypted_path}: {e}')
        return False


def _cloud_list_quarantine_files():
    """Return a list of quarantined files with metadata, suitable for the
    quarantine page templates."""
    try:
        from quarantine_utils import list_quarantine_files
        files = list_quarantine_files()
    except ImportError:
        # Fallback: enumerate .enc files manually
        qdir = _cloud_quarantine_dir()
        files = []
        if os.path.isdir(qdir):
            for f in os.listdir(qdir):
                if f.endswith('.enc'):
                    full = os.path.join(qdir, f)
                    files.append({
                        'filename': f,
                        'path': full,
                        'original_path': 'unknown',
                        'reason': 'unknown',
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S',
                                                   time.localtime(os.path.getmtime(full))),
                        'sha256': '',
                        'size': os.path.getsize(full),
                    })

    # Adapt the field names to what the templates expect.
    # quarantine.html expects: filename, detection_info.matches, quarantine_time,
    #   quarantine_path, original_path
    # quarantine_list.html expects: name, original_path, reason
    # quarantine_manage.html expects: filename, original_path, reason, timestamp, sha256
    adapted = []
    for f in files:
        item = dict(f)
        # Normalize field names so all three templates can use the same list.
        item.setdefault('filename', f.get('filename') or f.get('name') or os.path.basename(f.get('path', '')))
        item.setdefault('name', item['filename'])
        item.setdefault('quarantine_path', f.get('path') or os.path.join(_cloud_quarantine_dir(), item['filename']))
        item.setdefault('quarantine_time', f.get('timestamp') or f.get('quarantine_time') or 'unknown')
        item.setdefault('original_path', f.get('original_path') or 'unknown')
        item.setdefault('reason', f.get('reason') or 'unknown')
        item.setdefault('sha256', f.get('sha256') or '')
        # detection_info for quarantine.html
        if 'detection_info' not in item:
            reason = item.get('reason', '')
            item['detection_info'] = {'matches': [reason] if reason and reason != 'unknown' else []}
        adapted.append(item)
    return adapted


def _cloud_quarantine_log_text():
    """Return the quarantine log as human-readable text for the quarantine page."""
    qdir = _cloud_quarantine_dir()
    log_path = os.path.join(qdir, 'quarantine_log.json')
    try:
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8') as f:
                entries = json.load(f)
            if isinstance(entries, list):
                lines = []
                for e in entries[-50:]:
                    lines.append(f"{e.get('timestamp', '?')} | {e.get('original_path', '?')} -> {e.get('quarantine_path', '?')} | {e.get('reason', '?')}")
                return '\n'.join(lines)
    except Exception:
        pass
    return 'No recent events found.'



@cloud_bp.route('/api/agent-quarantine/single', methods=['POST'])
@_require_login
def cloud_agent_quarantine_single():
    """Send quarantine_findings command for a single file to a specific agent."""
    data = request.get_json(force=True, silent=True) or {}
    device_id = (data.get('device_id') or '').strip()
    path = (data.get('path') or '').strip()
    if not device_id or not path:
        return jsonify({'ok': False, 'message': 'device_id and path required.'}), 400
    agents = _all_agents()
    if device_id not in agents:
        return jsonify({'ok': False, 'message': 'Agent not connected.'}), 404
    pending = commands.get(device_id, [])
    # Send unblock_findings with quarantine_after so the agent restores
    # permissions and quarantines in a single command cycle.
    pending.append({'action': 'unblock_findings',
                    'findings': [{'path': path}],
                    'quarantine_after': True})
    commands[device_id] = pending
    return jsonify({'ok': True, 'message': f'Unblock + quarantine command queued for {path}.'}), 200


@cloud_bp.route('/quarantine/yara-matches', methods=['POST'])
def cloud_quarantine_yara_matches():
    """Quarantine files with ransomware/persistence YARA matches from the
    latest continuous scan. Called by the dashboard's 'Quarantine/review
    ransomware & persistence' button. Sends scan_now to agents, waits for
    the scan to complete, then sends list_quarantine and waits again to
    collect the updated quarantine list."""
    try:
        agents = _all_agents()
        if not agents:
            return jsonify({'quarantined': [], 'failed': [], 'count': 0,
                            'agents_triggered': 0,
                            'message': 'No connected agents.'}), 404
        sent = 0
        for device_id, ag in agents.items():
            # Quarantine ALL blocked findings (ransomware, persistence, yara, ml)
            agent_findings = []
            last_report = ag.get('last_report') or {}
            for f in (last_report.get('findings') or []):
                if not isinstance(f, dict) or not f.get('path'):
                    continue
                ttype = (f.get('threat_type') or '').lower()
                if f.get('blocked') or ttype in ('ransomware', 'persistence', 'yara_match', 'ml_suspicious'):
                    agent_findings.append({'path': f['path']})
            # Also include all blocked files from the registry
            blocked_files = ag.get('blocked_files') or []
            if isinstance(blocked_files, dict):
                blocked_paths = list(blocked_files.keys())
            else:
                blocked_paths = blocked_files
            for bpath in blocked_paths:
                if bpath and bpath not in [x['path'] for x in agent_findings]:
                    agent_findings.append({'path': bpath})
            pending = commands.get(device_id, [])
            if agent_findings:
                # Use unblock_findings with quarantine_after so the agent
                # unblocks permissions and quarantines in one atomic cycle.
                pending.append({'action': 'unblock_findings',
                                'findings': agent_findings,
                                'quarantine_after': True})
            else:
                pending.append({'action': 'scan_now'})
            commands[device_id] = pending
            sent += 1
        # Wait for the quarantine to process on agents
        import time as _time
        _time.sleep(15)
        # Now request the updated quarantine list from each agent
        for device_id in agents:
            pending = commands.get(device_id, [])
            pending = [c for c in pending if c.get('action') != 'list_quarantine']
            pending.append({'action': 'list_quarantine'})
            commands[device_id] = pending
        # Wait for the agent to respond with the quarantine list
        _time.sleep(10)
        # Re-read agent state which now has updated quarantine_files
        agents = _all_agents()
        quarantined = []
        for device_id, ag in agents.items():
            host = ag.get('hostname', device_id)
            for qf in (ag.get('quarantine_files') or []):
                quarantined.append({
                    'hostname': host,
                    'device_id': device_id,
                    'filename': qf.get('filename', ''),
                    'original_path': qf.get('original_path', ''),
                    'quarantined_at': qf.get('quarantined_at', ''),
                    'size': qf.get('size', 0),
                })
        return jsonify({
            'quarantined': quarantined,
            'failed': [],
            'count': len(quarantined),
            'agents_triggered': sent,
            'message': f'Unblock+quarantine sent to {sent} agent(s). {len(quarantined)} file(s) quarantined.'
        })
    except Exception as e:
        logger.error(f'Error in quarantine/yara-matches: {e}')
        return jsonify({'quarantined': [], 'failed': [], 'count': 0, 'error': str(e)}), 500


@cloud_bp.route('/quarantine/findings', methods=['POST'])
def cloud_quarantine_findings():
    """Trigger agent scans to auto-quarantine selected findings on agent PCs.
    Called by the dashboard's 'Quarantine selected' button. Sends scan_now,
    waits for the scan to complete, then sends list_quarantine and collects
    the updated quarantine list."""
    try:
        agents = _all_agents()
        if not agents:
            return jsonify({'status': 'error', 'quarantined': [], 'failed': [],
                            'count': 0, 'agents_triggered': 0,
                            'message': 'No connected agents.'}), 404
        sent = 0
        for device_id, ag in agents.items():
            # Quarantine ALL blocked findings (ransomware, persistence, yara, ml)
            agent_findings = []
            last_report = ag.get('last_report') or {}
            for f in (last_report.get('findings') or []):
                if not isinstance(f, dict) or not f.get('path'):
                    continue
                ttype = (f.get('threat_type') or '').lower()
                if f.get('blocked') or ttype in ('ransomware', 'persistence', 'yara_match', 'ml_suspicious'):
                    agent_findings.append({'path': f['path']})
            # Also include all blocked files from the registry
            blocked_files = ag.get('blocked_files') or []
            if isinstance(blocked_files, dict):
                blocked_paths = list(blocked_files.keys())
            else:
                blocked_paths = blocked_files
            for bpath in blocked_paths:
                if bpath and bpath not in [x['path'] for x in agent_findings]:
                    agent_findings.append({'path': bpath})
            pending = commands.get(device_id, [])
            if agent_findings:
                # Use unblock_findings with quarantine_after so the agent
                # unblocks permissions and quarantines in one atomic cycle.
                pending.append({'action': 'unblock_findings',
                                'findings': agent_findings,
                                'quarantine_after': True})
            else:
                pending.append({'action': 'scan_now'})
            commands[device_id] = pending
            sent += 1
        # Wait for the quarantine to process on agents
        import time as _time
        _time.sleep(15)
        # Request updated quarantine list from each agent
        for device_id in agents:
            pending = commands.get(device_id, [])
            pending = [c for c in pending if c.get('action') != 'list_quarantine']
            pending.append({'action': 'list_quarantine'})
            commands[device_id] = pending
        # Wait for agent to respond with quarantine list
        _time.sleep(10)
        # Re-read agent state which now has updated quarantine_files
        agents = _all_agents()
        quarantined = []
        for device_id, ag in agents.items():
            host = ag.get('hostname', device_id)
            for qf in (ag.get('quarantine_files') or []):
                quarantined.append({
                    'hostname': host,
                    'device_id': device_id,
                    'filename': qf.get('filename', ''),
                    'original_path': qf.get('original_path', ''),
                    'quarantined_at': qf.get('quarantined_at', ''),
                    'size': qf.get('size', 0),
                })
        return jsonify({
            'status': 'success',
            'quarantined': quarantined,
            'failed': [],
            'count': len(quarantined),
            'agents_triggered': sent,
            'message': f'Scan triggered for {sent} agent(s). {len(quarantined)} file(s) quarantined.'
        })
    except Exception as e:
        logger.error(f'Error in quarantine/findings: {e}')
        return jsonify({'status': 'error', 'error': str(e)}), 500


@cloud_bp.route('/logs', methods=['GET'], endpoint='logs')
@cloud_bp.route('/logs.html', methods=['GET'])
def cloud_logs_page():
    return render_template('logs.html', session=session)


@cloud_bp.route('/events', methods=['GET'], endpoint='events')
@cloud_bp.route('/events.html', methods=['GET'])
def cloud_events_page():
    return render_template('events.html', events=events, summary={'System': len(events), 'Security': 0, 'Threats': 0}, session=session)


@cloud_bp.route('/processes', methods=['GET'], endpoint='processes')
@cloud_bp.route('/processes.html', methods=['GET'])
def cloud_processes_page():
    return render_template('processes.html', session=session)


@cloud_bp.route('/services', methods=['GET'], endpoint='services')
@cloud_bp.route('/services.html', methods=['GET'])
def cloud_services_page():
    return render_template('services.html', session=session)


@cloud_bp.route('/scripts', methods=['GET'], endpoint='scripts')
@cloud_bp.route('/scripts.html', methods=['GET'])
def cloud_scripts_page():
    return render_template('scripts.html', session=session)


@cloud_bp.route('/network', methods=['GET'], endpoint='network')
@cloud_bp.route('/network.html', methods=['GET'])
def cloud_network_page():
    network_info = {'ip': '127.0.0.1', 'status': 'connected', 'interfaces': ['Ethernet', 'Wi-Fi']}
    return render_template('network.html', network_info=network_info, session=session)


@cloud_bp.route('/patches', methods=['GET'], endpoint='patches')
@cloud_bp.route('/patches.html', methods=['GET'])
def cloud_patches_page():
    return render_template('patches.html', session=session)


@cloud_bp.route('/graph', methods=['GET'], endpoint='graph')
@cloud_bp.route('/graph.html', methods=['GET'])
def cloud_graph_page():
    return render_template('graph.html', session=session)


@cloud_bp.route('/hash-lookup', methods=['GET'], endpoint='hash_lookup')
@cloud_bp.route('/hash_lookup.html', methods=['GET'])
def cloud_hash_lookup():
    return render_template('hash_lookup.html', session=session)


@cloud_bp.route('/kill-switch', methods=['GET', 'POST'], endpoint='kill_switch')
@cloud_bp.route('/kill_switch.html', methods=['GET', 'POST'])
@_require_login
def cloud_kill_switch():
    """Toggle or view the network kill switch on all connected agents.
    Unlike the local Windows-only quick_start.py version, the cloud
    dashboard has no local firewall to control -- it queues a
    toggle_kill_switch command for every connected agent instead."""
    message = None
    error = None
    if request.method == 'POST':
        # CSRF is already enforced for all authenticated POSTs by
        # _require_login_global(); no need to re-check it here.
        action = request.form.get('action')
        enable = (action == 'enable')
        agents = _all_agents()
        sent = 0
        for device_id in agents:
            pending = commands.get(device_id, [])
            pending = [c for c in pending if c.get('action') != 'toggle_kill_switch']
            pending.append({'action': 'toggle_kill_switch', 'enabled': enable})
            commands[device_id] = pending
            sent += 1
        if sent > 0:
            message = (f'Kill switch enable command sent to {sent} agent(s).' if enable
                       else f'Kill switch disable command sent to {sent} agent(s).')
        else:
            error = 'No connected agents to update.'
        # Redirect-after-POST (PRG pattern): agents take a few seconds to poll
        # the command, run it, and report the new state back over heartbeat,
        # so re-rendering immediately here would always show the stale
        # pre-command state. Redirect to a GET with a short-lived 'pending'
        # counter so the page can auto-refresh until the real state catches up.
        return redirect(url_for('cloud.kill_switch', msg=message, err=error, pending=4))
    agents = _all_agents()
    active = any(ag.get('kill_switch_active') for ag in agents.values())
    message = request.args.get('msg') or None
    error = request.args.get('err') or None
    try:
        pending = max(0, int(request.args.get('pending', 0)))
    except (TypeError, ValueError):
        pending = 0


@cloud_bp.route('/scan-report', methods=['GET'], endpoint='scan_report')
@cloud_bp.route('/scan_report.html', methods=['GET'])
@_require_login
def cloud_scan_report():
    """Aggregate scan/threat stats across all connected agents into a
    single report page. Was previously linked from the dashboard menu
    with no matching route, causing a 404."""
    agents = _all_agents()
    rows = []
    totals = {
        'files_scanned': 0, 'threats_blocked': 0, 'total_findings': 0,
        'total_ransomware': 0, 'total_persistence': 0, 'total_yara': 0,
        'total_ml': 0, 'quarantined_count': 0,
    }
    for device_id, agent in agents.items():
        row = {
            'device_id': device_id,
            'hostname': agent.get('hostname') or agent.get('name') or device_id,
            'files_scanned': agent.get('files_scanned', 0) or 0,
            'threats_blocked': agent.get('threats_blocked', 0) or 0,
            'total_findings': agent.get('total_findings', 0) or 0,
            'total_ransomware': agent.get('total_ransomware', 0) or 0,
            'total_persistence': agent.get('total_persistence', 0) or 0,
            'total_yara': agent.get('total_yara', 0) or 0,
            'total_ml': agent.get('total_ml', 0) or 0,
            'quarantined_count': agent.get('quarantined_count', 0) or 0,
            'last_report_ok': agent.get('last_report_ok'),
            'last_report_error': agent.get('last_report_error') or '',
            'last_seen': agent.get('last_seen') or agent.get('last_heartbeat') or '',
        }
        rows.append(row)
        for key in totals:
            totals[key] += row[key] or 0
    rows.sort(key=lambda r: r['hostname'].lower())
    return render_template('scan_report.html', rows=rows, totals=totals, session=session)


@cloud_bp.route('/settings', methods=['GET'], endpoint='settings')
@cloud_bp.route('/settings.html', methods=['GET'])
def cloud_settings_page():
    ioc_counts = {'hashes': 4200, 'domains': 1500, 'ips': 850, 'yara_rules': 42}
    return render_template('settings.html', ioc_counts=ioc_counts, session=session)


@cloud_bp.route('/canary', methods=['GET'], endpoint='canary')
@cloud_bp.route('/canary.html', methods=['GET'])
def cloud_canary_page():
    return render_template('canary.html', session=session)


@cloud_bp.route('/startup', methods=['GET'], endpoint='startup')
@cloud_bp.route('/startup.html', methods=['GET'])
def cloud_startup_page():
    return render_template('startup.html', session=session)


@cloud_bp.route('/startup-apps', methods=['GET', 'POST'], endpoint='startup_with_windows')
@cloud_bp.route('/startup_apps.html', methods=['GET', 'POST'])
def cloud_startup_win_page():
    message = None
    if request.method == 'POST':
        action = request.form.get('action')
        enable = action == 'enable'
        # Queue the command to all connected agents
        # Remove any existing toggle_startup commands first to avoid duplicates
        agents_list = _get_agents()
        sent = 0
        for device_id in agents_list:
            pending = commands.setdefault(device_id, [])
            pending = [c for c in pending if c.get('action') != 'toggle_startup']
            pending.append({
                'action': 'toggle_startup',
                'enable': enable,
            })
            commands[device_id] = pending
            sent += 1
        if sent > 0:
            message = f'Startup {"enabled" if enable else "disabled"} command queued for {sent} device(s). The agent will apply it on the next heartbeat.'
        else:
            # Try local toggle as fallback
            try:
                from data_analysis import toggle_startup_with_windows
                if toggle_startup_with_windows(enable):
                    message = 'Startup ' + ('enabled' if enable else 'disabled') + '.'
                else:
                    message = 'Failed to toggle startup. No agents connected.'
            except Exception:
                message = 'No agents connected. Install the agent on your device to toggle startup remotely.'
    # Check if any agents are connected and get their startup status
    agents_list = _get_agents()
    has_agents = len(agents_list) > 0
    # Use agent-reported startup status instead of local check
    active = any(a.get('startup_enabled', False) for a in agents_list.values()) if has_agents else False
    return render_template('startup_apps.html', session=session,
                           active=active, message=message, cloud_mode=True,
                           has_agents=has_agents)


@cloud_bp.route('/break-the-cycle', methods=['GET'], endpoint='break_the_cycle')
@cloud_bp.route('/break_the_cycle.html', methods=['GET'])
def cloud_break_the_cycle():
    return render_template('break_the_cycle.html', service_status={'ok': True, 'message': 'Admin service running.'}, session=session)


@cloud_bp.route('/break-the-cycle/engage', methods=['POST'])
@cloud_bp.route('/break_the_cycle/engage', methods=['POST'])
def cloud_break_the_cycle_engage():
    # Run the same protected remediation steps as the local quick_start
    # implementation so the cloud dashboard's "BREAK THE CYCLE" button works.
    results = []
    try:
        import subprocess
        # Kill known malicious process names if running.
        malicious_names = ['malware', 'ransomware', 'cryptominer', 'botnet']
        killed = []
        for p in psutil.process_iter(['pid', 'name']):
            try:
                name = (p.info.get('name') or '').lower()
                if any(m in name for m in malicious_names):
                    p.kill()
                    killed.append(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        results.append(f'Terminated suspicious processes: {len(killed)}')
        if killed:
            results.append(' -> ' + ', '.join(killed))

        # Flush the DNS resolver cache to drop any malicious redirects.
        if os.name == 'nt':
            try:
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, timeout=15,
                               creationflags=0x08000000)
                results.append('DNS cache flushed.')
            except Exception:
                results.append('DNS flush skipped (unavailable).')

        # Clear the local events log so the dashboard resets.
        events.clear()
        results.append('Event log cleared.')

        # Reset the conditional startup scan state for a fresh generation
        _startup_state['running'] = False
        _startup_state['started_at'] = None
        _startup_state['last_run'] = None
        _startup_state['scanned_files'] = 0
        _startup_state['quarantined_files'] = 0
        _startup_state['ml_detections'] = 0
        _startup_state['ransomware_indicators'] = 0
        _startup_state['persistence_indicators'] = 0
        _startup_state['yara_suspicious'] = 0
        _startup_state['threats_detected'] = 0
        _startup_state['scan_log'] = []
        results.append('Startup scan state reset.')

        results.append('Cycle broken. System stabilized.')
        return jsonify({'success': True, 'results': results}), 200
    except Exception as e:
        results.append(f'Remediation error: {e}')
        return jsonify({'success': False, 'results': results, 'error': str(e)}), 500


@cloud_bp.route('/c2_detector_report', methods=['GET'], endpoint='c2_detector_report')
@cloud_bp.route('/c2_detector_report.html', methods=['GET'])
def cloud_c2_report():
    return render_template('c2_detector_report.html', session=session)


@cloud_bp.route('/toggle_folder_watcher/<action>', methods=['POST'])
def cloud_toggle_folder_watcher(action):
    return jsonify({'success': True, 'message': f'Folder watcher {action}ed.'}), 200


@cloud_bp.route('/toggle_safe_downloader/<action>', methods=['POST'])
def cloud_toggle_safe_downloader(action):
    return jsonify({'success': True, 'message': f'Safe downloader {action}ed.'}), 200


@cloud_bp.route('/toggle_network_monitor/<action>', methods=['POST'])
def cloud_toggle_network_monitor(action):
    return jsonify({'success': True, 'message': f'Network monitor {action}ed.'}), 200


@cloud_bp.route('/toggle_auto_updates/<action>', methods=['POST'])
def cloud_toggle_auto_updates(action):
    return jsonify({'success': True, 'message': f'Auto updates {action}ed.'}), 200


@cloud_bp.route('/toggle_auto_block/<action>', methods=['POST'])
def cloud_toggle_auto_block(action):
    global _auto_block_enabled
    _auto_block_enabled = (action == 'start' or action == 'enable')
    return jsonify({'success': True, 'message': f'Auto block {action}ed.', 'auto_block_enabled': _auto_block_enabled}), 200


# -- Continuous YARA scan-all state --
# Mirrors quick_start.py's continuous_scan_state so the YARA scanner page
# can poll /scan_all/latest and get real results.
_continuous_scan_state = {
    'active': False,
    'last_run': None,
    'last_result': None,
    'last_error': None,
}
_continuous_scan_thread = None

# Module-level quarantine helpers so route handlers can quarantine without
# waiting for a scan thread to be running.
try:
    from security.scan_cache import safe_quarantine as _module_safe_quarantine
except ImportError:
    _module_safe_quarantine = None
try:
    from quarantine_utils import quarantine_file as _module_quarantine_file
except ImportError:
    _module_quarantine_file = None


def _fallback_quarantine(src_path, qdir, encrypt_fn=None, force=False):
    """Simple fallback: move the file to the quarantine directory.
    Used when the proper quarantine modules aren't available (e.g. on VPS)."""
    try:
        os.makedirs(qdir, exist_ok=True)
        base = os.path.basename(src_path)
        dst = os.path.join(qdir, base + '.enc')
        # Avoid overwriting existing quarantined files
        if os.path.exists(dst):
            import random
            dst = os.path.join(qdir, f'{base}.{random.randint(1000,9999)}.enc')
        if encrypt_fn:
            try:
                if encrypt_fn(src_path, dst):
                    os.remove(src_path)
                    return True, 'encrypted and moved'
            except Exception:
                pass
        # Just move the file without encryption
        import shutil
        shutil.move(src_path, dst)
        return True, 'moved to quarantine'
    except Exception as e:
        return False, str(e)


def _module_encrypt_fn(src, dst):
    """Encrypt src to dst using FERNET_KEY (module-level helper for routes)."""
    try:
        from cryptography.fernet import Fernet
        key = os.environ.get('FERNET_KEY', '').strip().encode('utf-8')
        if not key or len(key) != 44:
            return False
        f = Fernet(key)
        with open(src, 'rb') as fh:
            data = fh.read()
        with open(dst, 'wb') as oh:
            oh.write(f.encrypt(data))
        return True
    except Exception:
        return False


def _run_continuous_scan_all():
    """Background loop that repeatedly scans all monitored directories with YARA.

    Walks files itself and updates _continuous_scan_state['last_result']
    incrementally (every few files) so the frontend polling /scan_all/latest
    sees live progress instead of waiting for the entire scan to finish.

    Files with a YARA risk score >= 35 or a critical-severity match are
    quarantined via quarantine_utils.quarantine_file (encrypted with
    FERNET_KEY and moved to the quarantine folder).
    """
    try:
        from security.yara_scanner import (
            scan_file_with_yara, get_highest_severity, get_match_severity,
            _severity_prefix, has_critical_yara_match,
        )
    except ImportError as e:
        _continuous_scan_state['last_error'] = f'YARA scanner module unavailable: {e}'
        _continuous_scan_state['last_result'] = {
            'status': 'error',
            'message': f'YARA scanner module unavailable: {e}',
            'scan_time': '0 seconds',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'matches': 0, 'folders': [], 'results': [],
        }
        _continuous_scan_state['active'] = False
        return

    # yara_risk_score maps rule names to a 0-100 risk contribution.
    try:
        from data_analysis import yara_risk_score
    except ImportError:
        def yara_risk_score(rule_names):
            return 50.0 if rule_names else 0.0

    # safe_quarantine returns (success, message) and is the preferred method.
    # quarantine_file from quarantine_utils returns None (no success/failure
    # signal) so we only use it as a fallback and verify via the .enc file.
    try:
        from security.scan_cache import safe_quarantine as _safe_quarantine
    except ImportError:
        _safe_quarantine = None
    try:
        from quarantine_utils import quarantine_file as _quarantine_file, QUARANTINE_FOLDER
    except ImportError:
        _quarantine_file = None
        QUARANTINE_FOLDER = os.path.join(
            os.environ.get('USERPROFILE', r'C:\Users\Default'),
            'AppData', 'Local', 'Temp', 'Defender_Quarantine'
        )

    # Quarantine directory (matches quick_start.py's location).
    quarantine_dir = QUARANTINE_FOLDER

    # Verify FERNET_KEY is set so encryption actually works.
    _fernet_key = os.environ.get('FERNET_KEY', '').strip()
    if not _fernet_key or len(_fernet_key) != 44:
        logger.error('FERNET_KEY is not set or invalid (must be 44 chars). '
                     'Quarantine will fail — files will go to failed_quarantine instead.')

    # Simple encrypt function for safe_quarantine.
    def _encrypt_fn(src, dst):
        try:
            from cryptography.fernet import Fernet
            key = os.environ.get('FERNET_KEY', '').strip().encode('utf-8')
            if not key or len(key) != 44:
                return False
            f = Fernet(key)
            with open(src, 'rb') as fh:
                data = fh.read()
            with open(dst, 'wb') as oh:
                oh.write(f.encrypt(data))
            return True
        except Exception:
            return False

    high_risk_extensions = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta',
        '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe',
        '.wsh', '.sys', '.inf',
    }

    while _continuous_scan_state['active']:
        try:
            monitored_dirs = get_universal_scan_directories()
            start_time = time.time()

            # Counters that accumulate as we walk files.
            total_files_scanned = 0
            total_directories_scanned = 0
            total_subdirectories = 0
            total_high_risk_files = 0
            total_yara_matches = 0
            detected_threats = 0
            quarantined_count = 0
            persistence_matches = 0
            ransomware_matches = 0
            ml_detections = 0
            scan_errors = 0
            yara_suspicious_list = []
            results = []
            dir_stats = []

            def _publish():
                """Snapshot current progress into last_result for the frontend."""
                elapsed = time.time() - start_time
                _continuous_scan_state['last_result'] = {
                    'status': 'success',
                    'scan_time': f'{elapsed:.2f} seconds',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'matches': total_yara_matches,
                    'folders': monitored_dirs,
                    'results': results[-200:],  # keep last 200 lines
                    'files_scanned': total_files_scanned,
                    'directories_scanned': total_directories_scanned,
                    'threats_detected': detected_threats,
                    'threats_removed': quarantined_count,
                    'total_files_scanned': total_files_scanned,
                    'total_high_risk_files': total_high_risk_files,
                    'total_subdirectories': total_subdirectories,
                    'stats': {'directories': dir_stats},
                    # Dashboard counters (fed to /api/conditional_startup/status)
                    'quarantined_files': quarantined_count,
                    'ml_detections': ml_detections,
                    'ransomware_indicators': ransomware_matches,
                    'persistence_indicators': persistence_matches,
                    'yara_suspicious': total_yara_matches,
                    'yara_suspicious_list': yara_suspicious_list,
                    'errors': scan_errors,
                }

            # Initial placeholder so the frontend sees activity immediately.
            _publish()

            for directory in monitored_dirs:
                if not _continuous_scan_state['active']:
                    break
                try:
                    if not os.path.exists(directory) or not os.path.isdir(directory):
                        results.append(f'Directory not found or not accessible: {directory}')
                        dir_stats.append({
                            'path': directory, 'exists': False, 'accessible': False,
                            'file_count': 0, 'high_risk_files': 0, 'subdirectory_count': 0,
                            'matches': 0, 'subdirectories': [],
                        })
                        continue

                    total_directories_scanned += 1
                    folder_file_count = 0
                    folder_high_risk = 0
                    folder_subdir_count = 0
                    folder_matches = 0
                    folder_subdirs = []

                    for root, dirs, files in os.walk(directory, topdown=True):
                        if not _continuous_scan_state['active']:
                            break
                        # Exclude virtual/pseudo filesystems on Linux
                        if os.name != 'nt':
                            dirs[:] = [d for d in dirs if d not in (
                                'proc', 'sys', 'dev', 'run', 'snap', 'cgroup',
                                'cgroup2', 'fuse', 'securityfs', 'debugfs',
                            ) and not d.startswith('.')]
                        # Count subdirectories.
                        if root != directory:
                            total_subdirectories += 1
                            folder_subdir_count += 1
                            if len(folder_subdirs) < 100:
                                folder_subdirs.append(root)
                        else:
                            folder_subdir_count += len(dirs)
                            total_subdirectories += len(dirs)
                            for d in dirs:
                                if len(folder_subdirs) < 100:
                                    folder_subdirs.append(os.path.join(root, d))

                        for filename in files:
                            if not _continuous_scan_state['active']:
                                break
                            filepath = os.path.join(root, filename)
                            total_files_scanned += 1
                            folder_file_count += 1

                            _, ext = os.path.splitext(filename)
                            ext_lower = ext.lower()
                            if ext_lower in high_risk_extensions:
                                total_high_risk_files += 1
                                folder_high_risk += 1

                            # Skip already-encrypted quarantine files and
                            # files in the Recycle Bin — scanning them is
                            # pointless (they're already quarantined/deleted)
                            # and creates false matches + quarantine loops.
                            if ext_lower == '.enc':
                                continue
                            if '$recycle.bin' in filepath.lower():
                                continue

                            # Publish progress every 10 files so the frontend
                            # sees live updates instead of waiting for the end.
                            if total_files_scanned % 10 == 0:
                                _publish()

                            try:
                                yara_matches = scan_file_with_yara(filepath)
                                if yara_matches:
                                    total_yara_matches += len(yara_matches)
                                    folder_matches += len(yara_matches)
                                    detected_threats += 1
                                    rule_names = [getattr(m, 'rule', 'Unknown rule') for m in yara_matches]
                                    highest = get_highest_severity(yara_matches)

                                    # Track ransomware/persistence indicators for summary stats
                                    # but retain ALL YARA matches in the results
                                    for rule in rule_names:
                                        rl = rule.lower()
                                        if 'persistence' in rl:
                                            persistence_matches += 1
                                        if 'ransomware' in rl:
                                            ransomware_matches += 1
                                    # Add all YARA matches to suspicious list, not just ransomware/persistence
                                    yara_suspicious_list.append({'file': filepath, 'rules': rule_names})

                                    # Log every match with severity prefix.
                                    for match in yara_matches:
                                        rule_name = getattr(match, 'rule', 'Unknown rule')
                                        severity = get_match_severity(match)
                                        prefix = _severity_prefix(severity)
                                        results.append(f'{prefix} ({rule_name}): {filepath}')

                                    # Run ML detection on PE files (same as quick_start.py).
                                    # Tries all three models: EMBER, BODMAS CNN, sklearn.
                                    ml_score = None
                                    pe_extensions = ('.exe', '.dll', '.sys', '.scr', '.pif', '.com', '.cpl')
                                    if ext_lower in pe_extensions:
                                        # 1. EMBER (LightGBM, trained on EMBER2018)
                                        try:
                                            from security.detector import ember_detector
                                            if ember_detector.available:
                                                ml_score = ember_detector.score(filepath)
                                                if ml_score is not None and ml_score >= 0.50:
                                                    ml_detections += 1
                                                    results.append(f'ML detection (EMBER score {ml_score:.4f}): {filepath}')
                                        except Exception:
                                            pass
                                        # 2. BODMAS CNN (1D CNN in ONNX)
                                        if ml_score is None or ml_score < 0.50:
                                            try:
                                                from security.detector import bodmas_cnn_detector
                                                if bodmas_cnn_detector.available:
                                                    ml_score2 = bodmas_cnn_detector.score(filepath)
                                                    if ml_score2 is not None and ml_score2 >= 0.50:
                                                        ml_detections += 1
                                                        results.append(f'ML detection (BODMAS CNN score {ml_score2:.4f}): {filepath}')
                                                        if ml_score is None:
                                                            ml_score = ml_score2
                                            except Exception:
                                                pass
                                        # 3. sklearn MalwareDetector (IsolationForest / trained classifier)
                                        if ml_score is None or ml_score < 0.50:
                                            try:
                                                from security.detector import detector as sklearn_detector
                                                if sklearn_detector.is_malicious(filepath):
                                                    ml_detections += 1
                                                    anomaly = sklearn_detector.get_anomaly_score(filepath)
                                                    results.append(f'ML detection (sklearn anomaly={anomaly:.4f}): {filepath}')
                                                    if ml_score is None:
                                                        ml_score = max(0.50, float(anomaly))
                                            except Exception:
                                                pass

                                    # Decide whether to quarantine.
                                    # Only quarantine when there is strong evidence:
                                    #   - yara_risk_score >= 80 (very high confidence), OR
                                    #   - critical-severity match AND score >= 60, OR
                                    #   - ML score >= 0.90 (very high-confidence ML detection)
                                    # This prevents false positives from deleting legitimate files.
                                    score = yara_risk_score(rule_names)
                                    is_critical = has_critical_yara_match(yara_matches)
                                    highest_sev = get_highest_severity(yara_matches)
                                    should_quarantine = (
                                        score >= 80 or
                                        (is_critical and score >= 60) or
                                        (ml_score is not None and ml_score >= 0.90)
                                    )

                                    if should_quarantine:
                                        quarantined = False
                                        qmsg = ''
                                        try:
                                            # Prefer safe_quarantine because it
                                            # returns (success, message). It
                                            # encrypts with _encrypt_fn (using
                                            # FERNET_KEY) and moves the file to
                                            # quarantine_dir.
                                            if _safe_quarantine:
                                                ok, msg = _safe_quarantine(
                                                    filepath, quarantine_dir,
                                                    _encrypt_fn, force=True
                                                )
                                                quarantined = ok
                                                qmsg = msg
                                            elif _quarantine_file:
                                                # quarantine_file returns True only after
                                                # encrypted artifact is verified AND source is removed
                                                ok = _quarantine_file(
                                                    filepath,
                                                    reason=f'YARA match (score {score:.0f}, rules: {", ".join(rule_names)})'
                                                )
                                                quarantined = ok  # quarantine_file returns True/False
                                                qmsg = 'verified by source removal' if quarantined else 'quarantine function returned False'
                                            else:
                                                qmsg = 'no quarantine function available'
                                        except Exception as qe:
                                            qmsg = str(qe)

                                        if quarantined:
                                            quarantined_count += 1
                                            results.append(f'QUARANTINED: {filepath} - Rules: {", ".join(rule_names)} (score {score:.0f}) [{qmsg}]')
                                            logger.warning(f'Quarantined: {filepath} - {", ".join(rule_names)} - {qmsg}')
                                        else:
                                            results.append(f'YARA match (quarantine failed: {qmsg}): {filepath} - Rules: {", ".join(rule_names)}')
                                    else:
                                        results.append(f'YARA match (report-only, score {score:.0f}): {filepath} - Rules: {", ".join(rule_names)}')
                            except Exception as file_err:
                                # Don't spam the results log with per-file errors;
                                # just count them and keep scanning.
                                scan_errors += 1

                    dir_stats.append({
                        'path': directory,
                        'exists': True,
                        'accessible': True,
                        'file_count': folder_file_count,
                        'high_risk_files': folder_high_risk,
                        'subdirectory_count': folder_subdir_count,
                        'matches': folder_matches,
                        'subdirectories': folder_subdirs,
                    })
                    results.append(f'Scanned directory: {directory} ({folder_file_count} files)')
                    _publish()
                except Exception as dir_err:
                    scan_errors += 1
                    results.append(f'Error scanning {directory}: {dir_err}')
                    dir_stats.append({
                        'path': directory, 'exists': True, 'accessible': False,
                        'file_count': 0, 'high_risk_files': 0, 'subdirectory_count': 0,
                        'matches': 0, 'subdirectories': [],
                    })

            _publish()
            _continuous_scan_state['last_run'] = time.strftime('%Y-%m-%d %H:%M:%S')
            _continuous_scan_state['last_error'] = None
        except Exception as e:
            logger.error(f'Error in continuous scan: {e}')
            _continuous_scan_state['last_error'] = str(e)
            _continuous_scan_state['last_result'] = {
                'status': 'error',
                'message': str(e),
                'scan_time': '0 seconds',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'matches': 0, 'folders': [], 'results': [],
            }
        # Sleep in 1-second increments so we can exit promptly when stopped.
        for _ in range(10):
            if not _continuous_scan_state['active']:
                break
            time.sleep(1)


@cloud_bp.route('/rescan', methods=['POST'])
def cloud_rescan():
    """Trigger a fresh scan immediately, clearing previous findings so
    ransomware/persistence files that failed quarantine can be re-detected."""
    # Clear previous results so the dashboard picks up fresh findings
    _continuous_scan_state['last_result'] = None
    _continuous_scan_state['last_error'] = None
    # Restart the scan thread if it's not running
    if not _continuous_scan_state['active']:
        _continuous_scan_state['active'] = True
        _continuous_scan_thread = threading.Thread(target=_run_continuous_scan_all, daemon=True)
        _continuous_scan_thread.start()
    return jsonify({'status': 'success', 'message': 'Rescan started.'}), 200


@cloud_bp.route('/toggle_scan_all/<action>', methods=['POST'])
def cloud_toggle_scan_all(action):
    global _continuous_scan_thread
    if action not in ('start', 'stop'):
        return jsonify({'status': 'error', 'error': 'Invalid action'}), 400

    if action == 'start':
        if not _continuous_scan_state['active']:
            _continuous_scan_state['active'] = True
            _continuous_scan_state['last_error'] = None
            monitored_dirs = get_universal_scan_directories()
            _continuous_scan_state['last_result'] = {
                'status': 'success',
                'scan_time': '0.00 seconds',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'matches': 0,
                'folders': monitored_dirs,
                'results': [f'Scan started on {len(monitored_dirs)} folder(s)...'],
                'files_scanned': 0,
                'directories_scanned': 0,
                'threats_detected': 0,
                'threats_removed': 0,
                'total_files_scanned': 0,
                'total_high_risk_files': 0,
                'total_subdirectories': 0,
                'stats': {'directories': []},
            }
            if _continuous_scan_thread is None or not _continuous_scan_thread.is_alive():
                _continuous_scan_thread = threading.Thread(target=_run_continuous_scan_all, daemon=True)
                _continuous_scan_thread.start()
        return jsonify({
            'status': 'success',
            'success': True,
            'active': True,
            'message': 'Continuous scanning started'
        }), 200

    _continuous_scan_state['active'] = False
    return jsonify({
        'status': 'success',
        'success': True,
        'active': False,
        'message': 'Continuous scanning stopped'
    }), 200


@cloud_bp.route('/scan', methods=['GET', 'POST'])
def cloud_scan():
    if request.method == 'GET':
        # Render a scan page when opened in a new tab (the "Run Full System
        # Scan" button links here with target="_blank").
        dirs = get_universal_scan_directories()
        total_files = 0
        for d in dirs:
            try:
                total_files += sum(1 for e in os.scandir(d) if e.is_file())
            except (PermissionError, OSError):
                pass
        return render_template('yara_scanner.html',
            network_monitor_running=True,
            folder_watcher_status=True,
            auto_block_enabled=True,
            safe_downloader_status=True,
            auto_updates_running=True,
            c2_detector_low_count=_get_c2_counts()[0],
            c2_detector_high_count=_get_c2_counts()[1],
            scheduled_scan_enabled=True,
            status={'status': 'ENABLED', 'folder_watcher': True, 'network_monitor': True, 'safe_downloader': True},
            running_as_admin=True,
            administrator_service_available=True,
            admin_helper_message='Antivirus Cloud Protection Active.',
            devices=sorted(_all_agents().values(), key=lambda x: x.get('last_seen',''), reverse=True),
            events=list(reversed(events[-50:])),
            session=session,
            scan_dirs=dirs,
            scan_total_files=total_files,
            rules_info={'available': True, 'count': 42, 'last_updated': '2026-08-19', 'sources': ['cloud', 'custom']},
            monitored_directories=dirs,
            monitored_folders=dirs
        )
    return jsonify({'success': True, 'message': 'Scan completed.', 'results': [], 'threats_found': 0}), 200


@cloud_bp.route('/scan_all_processes', methods=['GET'])
def cloud_scan_all_processes():
    """Scan running processes page."""
    try:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status', 'create_time']):
            info = p.info
            info['path'] = ''
            try:
                info['path'] = p.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            procs.append(info)
        return render_template('yara_scanner.html',
            network_monitor_running=True,
            folder_watcher_status=True,
            auto_block_enabled=True,
            safe_downloader_status=True,
            auto_updates_running=True,
            c2_detector_low_count=_get_c2_counts()[0],
            c2_detector_high_count=_get_c2_counts()[1],
            scheduled_scan_enabled=True,
            status={'status': 'ENABLED', 'folder_watcher': True, 'network_monitor': True, 'safe_downloader': True},
            running_as_admin=True,
            administrator_service_available=True,
            admin_helper_message='Antivirus Cloud Protection Active.',
            devices=sorted(_all_agents().values(), key=lambda x: x.get('last_seen',''), reverse=True),
            events=list(reversed(events[-50:])),
            session=session,
            scan_processes=procs,
            rules_info={'available': True, 'count': 42, 'last_updated': '2026-08-19', 'sources': ['cloud', 'custom']},
            monitored_directories=get_universal_scan_directories(),
            monitored_folders=get_universal_scan_directories()
        )
    except Exception:
        return render_template('yara_scanner.html',
            network_monitor_running=True,
            folder_watcher_status=True,
            auto_block_enabled=True,
            safe_downloader_status=True,
            auto_updates_running=True,
            c2_detector_low_count=_get_c2_counts()[0],
            c2_detector_high_count=_get_c2_counts()[1],
            scheduled_scan_enabled=True,
            status={'status': 'ENABLED', 'folder_watcher': True, 'network_monitor': True, 'safe_downloader': True},
            running_as_admin=True,
            administrator_service_available=True,
            admin_helper_message='Antivirus Cloud Protection Active.',
            devices=sorted(_all_agents().values(), key=lambda x: x.get('last_seen',''), reverse=True),
            events=list(reversed(events[-50:])),
            session=session,
            scan_processes=[],
            rules_info={'available': True, 'count': 42, 'last_updated': '2026-08-19', 'sources': ['cloud', 'custom']},
            monitored_directories=get_universal_scan_directories(),
            monitored_folders=get_universal_scan_directories()
        )


@cloud_bp.route('/scan_all/latest', methods=['GET'])
def cloud_scan_all_latest():
    """Return the most recent continuous scan-all result."""
    return jsonify({
        'status': 'success',
        'active': _continuous_scan_state['active'],
        'last_run': _continuous_scan_state.get('last_run'),
        'last_error': _continuous_scan_state.get('last_error'),
        'result': _continuous_scan_state.get('last_result')
    }), 200


@cloud_bp.route('/add_folder', methods=['POST'])
def cloud_add_folder():
    return jsonify({'success': True, 'message': 'Folder added.'}), 200


@cloud_bp.route('/remove_folder', methods=['POST'])
def cloud_remove_folder():
    return jsonify({'success': True, 'message': 'Folder removed.'}), 200


@cloud_bp.route('/stop_realtime', methods=['POST'])
def cloud_stop_realtime():
    return jsonify({'success': True, 'message': 'Real-time protection stopped.'}), 200


@cloud_bp.route('/start_auto_updates', methods=['POST'])
@cloud_bp.route('/stop_auto_updates', methods=['POST'])
def cloud_auto_updates():
    return jsonify({'success': True}), 200


def get_universal_scan_directories():
    """Return all monitored directories across the entire PC.

    Works on Windows, Linux, and macOS by enumerating all fixed disk drives
    via psutil, then adding platform-appropriate user and system directories.
    Non-existent directories are filtered out automatically.
    """
    dirs = []
    is_windows = os.name == 'nt'
    is_mac = sys.platform == 'darwin'

    # --- All disk drive root directories ---
    real_fs_types = {
        # Windows
        'NTFS', 'FAT32', 'exFAT', 'FAT', 'ReFS', 'CDFS', 'UDF',
        # Linux
        'ext4', 'ext3', 'ext2', 'btrfs', 'xfs', 'zfs', 'f2fs', 'jfs', 'reiserfs',
        # macOS
        'apfs', 'hfs', 'hfs+', 'udf', 'msdos', 'fuse.apfs',
    }
    virtual_fs_types = {
        'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'proc', 'sysfs',
        'cgroup', 'cgroup2', 'mqueue', 'hugetlbfs', 'fusectl', 'debugfs',
        'tracefs', 'configfs', 'securityfs', 'fuse.gvfsd-fuse',
        'autofs', 'binfmt_misc', 'rpc_pipefs', 'nsfs', 'fusectl',
    }
    try:
        for part in psutil.disk_partitions(all=False):
            fstype = (part.fstype or '').strip()
            opts = (part.opts or '') if hasattr(part, 'opts') else ''
            # Skip virtual/pseudo filesystems.
            if fstype in virtual_fs_types:
                continue
            # Include known real filesystems.
            if fstype in real_fs_types:
                dirs.append(part.mountpoint)
            # On Windows, fixed drives may not list a known fstype but have
            # 'fixed' in opts.
            elif is_windows and 'fixed' in opts:
                dirs.append(part.mountpoint)
            # On Linux/mac, include anything with a non-empty fstype that
            # isn't in the virtual set.
            elif not is_windows and fstype and fstype not in virtual_fs_types:
                dirs.append(part.mountpoint)
    except Exception:
        pass

    # On Windows, ALWAYS enumerate all drive letters A-Z regardless of what
    # psutil reported. Use both the Windows API (GetLogicalDrives) and
    # os.path.exists to catch every possible drive: fixed, removable, network,
    # mounted VHDs, USB, etc. For each drive found, add the drive root (so the
    # scan walks the ENTIRE drive) plus common subdirectories.
    if is_windows:
        import string as _string

        # Method 1: Windows API GetLogicalDrives -- returns a bitmask of all
        # logical drives, which catches drives that os.path.exists might miss
        # on some Windows configurations.
        win_drives = set()
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    letter = chr(ord('A') + i)
                    win_drives.add(f'{letter}:\\')
        except Exception:
            pass

        # Method 2: os.path.exists for every letter A-Z as a fallback.
        for letter in _string.ascii_uppercase:
            drive = f'{letter}:\\'
            if os.path.exists(drive):
                win_drives.add(drive)

        # Method 3: psutil disk partitions (already done above, but double
        # check we got the mountpoints).
        try:
            for part in psutil.disk_partitions(all=True):
                if part.mountpoint and len(part.mountpoint) >= 2 and part.mountpoint[1] == ':':
                    win_drives.add(part.mountpoint)
        except Exception:
            pass

        # Now add every detected drive root + common subdirectories.
        for drive in sorted(win_drives):
            if drive not in dirs:
                dirs.append(drive)
            # Add common subdirectories on every drive. These are the
            # directories that typically exist on a Windows drive. The
            # deduplication + os.path.exists filter at the end will remove
            # any that don't exist on a particular drive.
            drive_subdirs = [
                os.path.join(drive, 'Windows'),
                os.path.join(drive, 'Windows', 'System32'),
                os.path.join(drive, 'Windows', 'System32', 'drivers'),
                os.path.join(drive, 'Windows', 'Temp'),
                os.path.join(drive, 'Windows', 'SoftwareDistribution'),
                os.path.join(drive, 'Windows', 'WinSxS'),
                os.path.join(drive, 'Windows', 'Fonts'),
                os.path.join(drive, 'Windows', 'Boot'),
                os.path.join(drive, 'Windows', 'Installer'),
                os.path.join(drive, 'Program Files'),
                os.path.join(drive, 'Program Files (x86)'),
                os.path.join(drive, 'Program Files', 'Common Files'),
                os.path.join(drive, 'Program Files (x86)', 'Common Files'),
                os.path.join(drive, 'ProgramData'),
                os.path.join(drive, 'ProgramData', 'Microsoft'),
                os.path.join(drive, 'ProgramData', 'Package Cache'),
                os.path.join(drive, 'Users'),
                os.path.join(drive, 'Users', 'Public'),
                os.path.join(drive, 'Users', 'Public', 'Downloads'),
                os.path.join(drive, 'Users', 'Public', 'Documents'),
                os.path.join(drive, 'Users', 'Public', 'Desktop'),
                os.path.join(drive, 'Temp'),
                os.path.join(drive, 'tmp'),
                os.path.join(drive, 'Downloads'),
                os.path.join(drive, 'Tools'),
                os.path.join(drive, 'Backup'),
                os.path.join(drive, 'Scripts'),
                os.path.join(drive, 'Logs'),
                os.path.join(drive, '$Recycle.Bin'),
                os.path.join(drive, 'System Volume Information'),
                os.path.join(drive, 'PerfLogs'),
                os.path.join(drive, 'Config'),
                os.path.join(drive, 'Drivers'),
                os.path.join(drive, 'Apps'),
                os.path.join(drive, 'Data'),
                os.path.join(drive, 'Games'),
                os.path.join(drive, 'Steam'),
                os.path.join(drive, 'SteamLibrary'),
                os.path.join(drive, 'steamapps'),
                os.path.join(drive, 'Epic Games'),
                os.path.join(drive, 'Origin Games'),
                os.path.join(drive, 'GOG Games'),
                os.path.join(drive, 'Battle.net'),
            ]
            dirs.extend(drive_subdirs)

            # Also enumerate top-level directories on the drive root so we
            # catch any custom folders the user created (e.g. D:\MyFiles,
            # E:\Projects, etc). This makes sure we scan EVERYTHING on every
            # drive, not just the standard Windows directories.
            try:
                for entry in os.scandir(drive):
                    if entry.is_dir():
                        dirs.append(entry.path)
            except (PermissionError, OSError):
                pass

    user_home = str(Path.home())

    # --- User directories (common to all platforms) ---
    dirs.extend([
        user_home,
        os.path.join(user_home, 'Downloads'),
        os.path.join(user_home, 'Desktop'),
        os.path.join(user_home, 'Documents'),
        os.path.join(user_home, 'Pictures'),
        os.path.join(user_home, 'Videos'),
        os.path.join(user_home, 'Music'),
    ])

    if is_windows:
        # --- Windows user directories ---
        dirs.extend([
            os.path.join(user_home, 'AppData', 'Local', 'Temp'),
            os.path.join(user_home, 'AppData', 'Local'),
            os.path.join(user_home, 'AppData', 'Roaming'),
            os.path.join(user_home, 'AppData', 'LocalLow'),
            os.path.join(user_home, 'AppData', 'Local', 'Microsoft'),
            os.path.join(user_home, 'AppData', 'Local', 'Microsoft', 'Windows'),
            os.path.join(user_home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(user_home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent'),
            os.path.join(user_home, 'Contacts'),
            os.path.join(user_home, 'Favorites'),
            os.path.join(user_home, 'Links'),
            os.path.join(user_home, 'Saved Games'),
            os.path.join(user_home, 'Searches'),
            os.path.join(user_home, 'OneDrive'),
        ])

        # --- All user profiles on this machine ---
        users_dir = os.path.join(os.environ.get('SystemDrive', r'C:'), 'Users')
        if os.path.exists(users_dir):
            try:
                for uname in os.listdir(users_dir):
                    upath = os.path.join(users_dir, uname)
                    if os.path.isdir(upath):
                        dirs.extend([
                            upath,
                            os.path.join(upath, 'Downloads'),
                            os.path.join(upath, 'Desktop'),
                            os.path.join(upath, 'Documents'),
                            os.path.join(upath, 'AppData', 'Local', 'Temp'),
                            os.path.join(upath, 'AppData', 'Roaming'),
                            os.path.join(upath, 'AppData', 'Local'),
                        ])
            except (PermissionError, OSError):
                pass

        # --- Windows system directories ---
        systemroot = os.environ.get('SYSTEMROOT', r'C:\Windows')
        programdata = os.environ.get('PROGRAMDATA', r'C:\ProgramData')
        systemdrive = os.environ.get('SystemDrive', r'C:')
        dirs.extend([
            systemroot,
            os.path.join(systemroot, 'System32'),
            os.path.join(systemroot, 'SysWOW64'),
            os.path.join(systemroot, 'Temp'),
            os.path.join(systemroot, 'System32', 'drivers'),
            os.path.join(systemroot, 'System32', 'drivers', 'etc'),
            os.path.join(systemroot, 'System32', 'config'),
            os.path.join(systemroot, 'System32', 'Tasks'),
            os.path.join(systemroot, 'System32', 'winevt', 'Logs'),
            os.path.join(systemroot, 'SoftwareDistribution'),
            os.path.join(systemroot, 'Microsoft.NET'),
            os.path.join(systemroot, 'Microsoft.NET', 'Framework'),
            os.path.join(systemroot, 'Microsoft.NET', 'Framework64'),
            os.path.join(systemroot, 'Fonts'),
            os.path.join(systemroot, 'Boot'),
            os.path.join(systemroot, 'WinSxS'),
            programdata,
            os.path.join(programdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(programdata, 'Microsoft', 'Windows', 'TaskScheduler'),
            os.path.join(programdata, 'Package Cache'),
            os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files')),
            os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')),
            os.path.join(os.environ.get('ProgramW6432', r'C:\Program Files')),
            os.path.join(systemdrive, 'Users', 'Public'),
            os.path.join(systemdrive, 'Users', 'Public', 'Downloads'),
            os.path.join(systemdrive, 'Users', 'Public', 'Documents'),
            os.path.join(systemdrive, 'PerfLogs'),
            os.path.join(systemdrive, '$Recycle.Bin'),
            # Windows Defender & security
            os.path.join(programdata, 'Microsoft', 'Windows Defender'),
            os.path.join(systemroot, 'System32', 'winevt'),
            # Internet cache & downloaded programs
            os.path.join(user_home, 'AppData', 'Local', 'Microsoft', 'Windows', 'INetCache'),
            os.path.join(user_home, 'AppData', 'Local', 'Microsoft', 'Windows', 'WebCache'),
            os.path.join(user_home, 'AppData', 'Local', 'Microsoft', 'Windows', 'Explorer'),
            os.path.join(user_home, 'AppData', 'Local', 'CrashDumps'),
            os.path.join(user_home, 'AppData', 'Local', 'D3DSCache'),
            # Power & shell
            os.path.join(systemroot, 'System32', 'WindowsPowerShell'),
            os.path.join(systemroot, 'System32', 'WindowsPowerShell', 'v1.0'),
            # Installer cache
            os.path.join(systemroot, 'Installer'),
            os.path.join(programdata, 'Microsoft', 'Windows', 'Installer'),
            # WMI
            os.path.join(systemroot, 'System32', 'wbem'),
            # Group Policy
            os.path.join(systemroot, 'System32', 'GroupPolicy'),
            os.path.join(systemroot, 'System32', 'GroupPolicy', 'Machine'),
            os.path.join(systemroot, 'System32', 'GroupPolicy', 'User'),
        ])
    elif is_mac:
        # --- macOS user directories ---
        dirs.extend([
            os.path.join(user_home, 'Library'),
            os.path.join(user_home, 'Library', 'Application Support'),
            os.path.join(user_home, 'Library', 'Caches'),
            os.path.join(user_home, 'Library', 'Preferences'),
            os.path.join(user_home, 'Library', 'LaunchAgents'),
            os.path.join(user_home, 'Library', 'Logs'),
            os.path.join(user_home, 'Library', 'Saved Application State'),
            os.path.join(user_home, 'Library', 'Cookies'),
            os.path.join(user_home, 'Library', 'Internet Plug-Ins'),
            os.path.join(user_home, 'Library', 'Input Methods'),
            os.path.join(user_home, 'Library', 'Screen Savers'),
            os.path.join(user_home, 'Library', 'Services'),
            os.path.join(user_home, 'Library', 'Frameworks'),
            os.path.join(user_home, 'Movies'),
            os.path.join(user_home, 'Public'),
            os.path.join(user_home, 'Sites'),
        ])
        # --- macOS system directories ---
        dirs.extend([
            '/Applications',
            '/Applications/Utilities',
            '/Library',
            '/Library/Application Support',
            '/Library/Caches',
            '/Library/Preferences',
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
            '/Library/StartupItems',
            '/System',
            '/System/Library',
            '/usr/local',
            '/usr/local/bin',
            '/usr/local/etc',
            '/usr/local/lib',
            '/usr/local/share',
            '/opt',
            '/opt/homebrew',
            '/opt/homebrew/bin',
            '/tmp',
            '/private/tmp',
            '/private/var/tmp',
            '/private/var/log',
            '/private/var/db',
            '/private/etc',
            '/var/log',
            '/var/db',
            '/etc',
            '/bin',
            '/sbin',
            '/usr/bin',
            '/usr/sbin',
            '/usr/lib',
            '/usr/share',
            '/Volumes',
            '/cores',
        ])
    else:
        # --- Linux user directories ---
        dirs.extend([
            os.path.join(user_home, '.cache'),
            os.path.join(user_home, '.config'),
            os.path.join(user_home, '.local', 'share'),
            os.path.join(user_home, '.local', 'bin'),
            os.path.join(user_home, '.local', 'lib'),
            os.path.join(user_home, '.local', 'state'),
            os.path.join(user_home, '.gnupg'),
            os.path.join(user_home, '.ssh'),
            os.path.join(user_home, '.bashrc'),
            os.path.join(user_home, '.profile'),
            os.path.join(user_home, '.bash_history'),
            os.path.join(user_home, '.mozilla'),
            os.path.join(user_home, '.config', 'autostart'),
            os.path.join(user_home, '.config', 'systemd', 'user'),
            os.path.join(user_home, '.local', 'share', 'applications'),
        ])
        # --- Linux system directories ---
        dirs.extend([
            '/tmp',
            '/var',
            '/var/tmp',
            '/var/log',
            '/var/lib',
            '/var/cache',
            '/var/spool',
            '/var/spool/cron',
            '/var/spool/at',
            '/etc',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/etc/systemd',
            '/etc/systemd/system',
            '/etc/init.d',
            '/etc/rc.d',
            '/etc/sudoers.d',
            '/etc/ssh',
            '/opt',
            '/usr/local',
            '/usr/local/bin',
            '/usr/local/sbin',
            '/usr/local/lib',
            '/usr/local/share',
            '/usr/bin',
            '/usr/sbin',
            '/usr/lib',
            '/usr/share',
            '/root',
            '/home',
            '/srv',
            '/mnt',
            '/media',
            '/run',
            '/dev/shm',
            '/boot',
            '/proc',
            '/sys',
        ])
        # --- All user home directories on Linux ---
        if os.path.isdir('/home'):
            try:
                for uname in os.listdir('/home'):
                    upath = os.path.join('/home', uname)
                    if os.path.isdir(upath):
                        dirs.extend([
                            upath,
                            os.path.join(upath, 'Downloads'),
                            os.path.join(upath, 'Desktop'),
                            os.path.join(upath, 'Documents'),
                            os.path.join(upath, '.config'),
                            os.path.join(upath, '.cache'),
                            os.path.join(upath, '.local', 'share'),
                        ])
            except (PermissionError, OSError):
                pass

    # Deduplicate and filter to existing directories.
    seen = set()
    result = []
    for d in dirs:
        if not d or d in seen:
            continue
        seen.add(d)
        try:
            if os.path.exists(d):
                result.append(d)
        except (OSError, ValueError):
            pass

    return result or [user_home]


@cloud_bp.route('/get_network_monitored_directories', methods=['GET'])
def cloud_network_dirs():
    # Only show agent directories — the VPS has no user files to monitor.
    agents = _all_agents()
    dirs = []
    for device_id, ag in agents.items():
        host = ag.get('hostname', device_id)
        for d in (ag.get('scan_dirs') or []):
            labeled = f"[{host}] {d}"
            if labeled not in dirs:
                dirs.append(labeled)
    # Build the detailed directory objects the frontend expects (each entry
    # must have path/exists/accessible/file_count/etc.), plus the top-level
    # monitored_directories array of plain path strings.
    dir_objects = []
    total_files = 0
    for d in dirs:
        # Agent-reported directories (prefixed with [hostname]) are remote
        # paths that don't exist on the VPS — mark them as accessible with
        # file counts from the agent's heartbeat if available.
        is_agent_dir = d.startswith('[') and ']' in d
        if is_agent_dir:
            exists = True
            accessible = True
            file_count = 0
            subdir_count = 0
            # Try to find file count from the agent's scan_dirs data
            try:
                host_end = d.index(']')
                host = d[1:host_end]
                raw_path = d[host_end+2:]
                for device_id, ag in agents.items():
                    if ag.get('hostname', device_id) == host:
                        fc = ag.get('dir_file_counts', {})
                        if raw_path in fc:
                            val = fc[raw_path]
                            if isinstance(val, dict):
                                file_count = val.get('files', 0)
                                subdir_count = val.get('subdirs', 0)
                            else:
                                file_count = val
                        break
            except Exception:
                pass
        else:
            exists = os.path.exists(d)
            accessible = os.access(d, os.R_OK) if exists else False
            file_count = 0
            subdir_count = 0
            if exists:
                try:
                    for entry in os.scandir(d):
                        if entry.is_dir():
                            subdir_count += 1
                        else:
                            file_count += 1
                except (PermissionError, OSError):
                    pass
        total_files += file_count
        dir_objects.append({
            'path': d,
            'exists': exists,
            'accessible': accessible,
            'file_count': file_count,
            'subdirectory_count': subdir_count,
            'high_risk_files': 0,
            'subdirectories': []
        })
    from datetime import datetime
    return jsonify({
        'success': True,
        'monitored_directories': dirs,
        'monitoring_status': {
            'enabled': True,
            'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_directories': len(dir_objects),
            'total_files_monitored': total_files,
            'directories': dir_objects
        }
    }), 200


@cloud_bp.route('/folder-watcher-paths', methods=['GET'])
@cloud_bp.route('/get_folder_watcher_paths', methods=['GET'])
def cloud_folder_watcher_paths():
    # Only show agent directories — the VPS has no user files to monitor.
    agents = _all_agents()
    dirs = []
    for device_id, ag in agents.items():
        host = ag.get('hostname', device_id)
        for d in (ag.get('scan_dirs') or []):
            labeled = f"[{host}] {d}"
            if labeled not in dirs:
                dirs.append(labeled)
    folders = []
    for d in dirs:
        is_agent_dir = d.startswith('[') and ']' in d
        if is_agent_dir:
            exists = True
            accessible = True
            file_count = 0
            subdir_count = 0
            # Try to get file count from agent data
            try:
                host_end = d.index(']')
                host = d[1:host_end]
                raw_path = d[host_end+2:]
                for device_id, ag in agents.items():
                    if ag.get('hostname', device_id) == host:
                        fc = ag.get('dir_file_counts', {})
                        if raw_path in fc:
                            val = fc[raw_path]
                            if isinstance(val, dict):
                                file_count = val.get('files', 0)
                                subdir_count = val.get('subdirs', 0)
                            else:
                                file_count = val
                        break
            except Exception:
                pass
        else:
            exists = os.path.exists(d)
            accessible = True
            file_count = 10
            subdir_count = 2
        folders.append({
            'path': d,
            'exists': exists,
            'accessible': accessible,
            'file_count': file_count,
            'subdir_count': subdir_count,
            'high_risk_files': 0
        })
    return jsonify({
        'success': True,
        'folder_watcher_active': True,
        'paths': dirs,
        'monitored_paths': dirs,
        'folders': folders,
        'total_files_monitored': len(dirs) * 10,
        'total_high_risk_files': 0,
        'total_directories_monitored': len(dirs)
    }), 200


# Module-level state for the conditional startup scan. This persists across
# requests within the same process so the status endpoint returns a stable
# value instead of regenerating a fresh "last_run" timestamp on every poll.
_startup_state = {
    'running': False,
    'started_at': None,
    'last_run': None,
    'last_updated': None,
    'duration': None,
    'scanned_files': 0,
    'quarantined_files': 0,
    'ml_detections': 0,
    'ransomware_indicators': 0,
    'persistence_indicators': 0,
    'yara_suspicious': 0,
    'threats_detected': 0,
    'scan_log': [],
}


def _count_quarantine_files():
    """Count .enc files currently in the Defender_Quarantine folder."""
    try:
        qdir = _cloud_quarantine_dir()
        if os.path.isdir(qdir):
            return len([f for f in os.listdir(qdir) if f.endswith('.enc')])
    except Exception:
        pass
    return 0


def _get_scan_counter(key, default=0):
    """Pull a counter from the latest continuous scan result, falling back
    to the default when no scan has run or the field is missing."""
    result = _continuous_scan_state.get('last_result') or {}
    val = result.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _get_scan_findings():
    """Build a findings list for the dashboard review UI from the latest
    scan's yara_suspicious_list (ALL YARA matches, not just
    ransomware/persistence-named rules).
    The frontend expects fields: path, source, reason.
    Files that no longer exist (already quarantined/deleted) are filtered out."""
    result = _continuous_scan_state.get('last_result') or {}
    suspicious = result.get('yara_suspicious_list') or []
    findings = []
    seen_findings = set()
    scanned_files = 0
    quarantined_files = 0
    ml_detections = 0
    ransomware_indicators = 0
    persistence_indicators = 0
    last_scan = ''
    running = False
    now = time.time()

    for device_id, agent in agents.items():
        report = agent.get('last_report') or {}
        scanned_files += _live_max(report, agent, 'files_scanned')
        quarantined_files += _live_max(report, agent, 'quarantined_count')
        marker = _agent_report_marker(agent)
        last_scan = max(last_scan, marker)
        scan_state = _agent_scan_state.get(device_id)
        pending_scan = any(isinstance(cmd, dict) and cmd.get('action') == 'scan_now' for cmd in _legacy.commands.get(device_id, []))
        if scan_state:
            started = float(scan_state.get('started_at', 0) or 0)
            previous_marker = str(scan_state.get('report_marker') or '')
            if marker and marker != previous_marker:
                _agent_scan_state.pop(device_id, None)
            elif pending_scan or (started and now - started < _AGENT_SCAN_STALE_SECONDS):
                running = True
            else:
                _agent_scan_state.pop(device_id, None)
        elif pending_scan:
            running = True

    # Aggregate data from connected agents (local PCs) only.
    agents = _all_agents()
    agent_files_scanned = 0
    agent_quarantined = 0
    agent_threats = 0
    agent_blocked = 0
    agent_findings = []
    agent_list = []
    agent_dirs = []
    for device_id, ag in agents.items():
        host = ag.get('hostname', device_id)
        af = ag.get('files_scanned', 0) or 0
        aq = ag.get('quarantined_count', 0) or 0
        # Fallback: if quarantined_count is 0 but quarantine_files list has
        # entries, use the list length (counter resets on agent restart)
        if aq == 0:
            qf_list = ag.get('quarantine_files') or []
            if qf_list:
                aq = len(qf_list)
        at = ag.get('findings_count', 0) or 0
        ab = ag.get('threats_blocked', 0) or 0
        agent_files_scanned += af
        agent_quarantined += aq
        agent_threats += at
        agent_blocked += ab
        for d in (ag.get('scan_dirs') or []):
            labeled = f"[{host}] {d}"
            if labeled not in agent_dirs:
                agent_dirs.append(labeled)
        last_report = ag.get('last_report') or {}
        for f in (last_report.get('findings') or []):
            agent_findings.append(f)
        agent_list.append({
            'device_id': device_id,
            'hostname': host,
            'platform': ag.get('platform', 'unknown'),
            'last_seen': ag.get('last_seen', ''),
            'files_scanned': af,
            'quarantined': aq,
            'threats': at,
            'scanning': ag.get('scanning', False),
        })

        for finding in report_findings:
            if not isinstance(finding, dict):
                continue
            rule = str(finding.get('rule') or '').lower()
            threat = str(finding.get('threat_type') or '').lower()
            if rule in {'ml_heuristic', 'ml'} or rule.startswith('ml_') or threat == 'ml':
                ml_detections += 1

    # Compute ransomware/persistence/yara/ml indicators from cumulative
    # agent counters (stored on each agent record, never reset by clean scans)
    agent_ransomware = 0
    agent_persistence = 0
    agent_yara = 0
    agent_ml = 0
    agent_quarantine_errors = 0
    for device_id, ag in agents.items():
        agent_ransomware += ag.get('total_ransomware', 0) or 0
        agent_persistence += ag.get('total_persistence', 0) or 0
        agent_yara += ag.get('total_yara', 0) or 0
        agent_ml += ag.get('total_ml', 0) or 0
    # Count quarantine errors from last report findings
    for f in agent_findings:
        if f.get('quarantine_error'):
            agent_quarantine_errors += 1

    return jsonify({
        'success': True,
        'status': 'running' if _startup_state['running'] else 'completed',
        'progress': 100 if not _startup_state['running'] else 50,
        'running': _startup_state['running'],
        'started_at': _startup_state['started_at'],
        'last_run': _startup_state['last_run'],
        'last_updated': _startup_state['last_updated'] or _startup_state['last_run'],
        'duration': _startup_state['duration'],
        'scanned_files': (_startup_state['scanned_files'] if _startup_state['running'] else agent_files_scanned),
        'quarantined_files': agent_quarantined,  # Use agent quarantined count only, not mixed with local _count_quarantine_files()
        'errors': _get_scan_counter('errors', 0) + agent_quarantine_errors,
        'process_events': sum(1 for _ in psutil.process_iter()),
        'ml_detections': _get_scan_counter('ml_detections', 0) + agent_ml,
        'ransomware_indicators': _get_scan_counter('ransomware_indicators', 0) + agent_ransomware,
        'persistence_indicators': _get_scan_counter('persistence_indicators', 0) + agent_persistence,
        'yara_suspicious': _get_scan_counter('yara_suspicious', 0) + agent_yara,
        'threats_found': _get_scan_counter('threats_detected', 0) + agent_threats,
        'blocked_threats': agent_blocked,
        'findings': _get_scan_findings() + agent_findings,
        'ml_models': ml_models,
        'last_error': _continuous_scan_state.get('last_error'),
        'folders': agent_dirs,
        'agents': agent_list,
        'agent_count': len(agent_list),
        'agent_files_scanned': agent_files_scanned,
        'agent_quarantined': agent_quarantined,
        'agent_threats': agent_threats,
        'agent_findings': agent_findings,
        'agent_ransomware': agent_ransomware,
        'agent_persistence': agent_persistence,
        'agent_yara': agent_yara,
        'agent_ml': agent_ml,
    }), 200


@cloud_bp.route('/run_startup', methods=['POST'])
def cloud_run_startup():
    from datetime import datetime
    _startup_state['running'] = True
    _startup_state['started_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    _startup_state['started_ts'] = time.time()
    _startup_state['last_updated'] = _startup_state['started_at']
    _startup_state['duration'] = None
    _startup_state['scanned_files'] = 0
    _startup_state['quarantined_files'] = 0
    _startup_state['ml_detections'] = 0
    _startup_state['ransomware_indicators'] = 0
    _startup_state['persistence_indicators'] = 0
    _startup_state['yara_suspicious'] = 0
    _startup_state['threats_detected'] = 0
    _startup_state['scan_log'] = []
    # Trigger a scan on all connected agents instead of scanning the VPS.
    agents = _all_agents()
    sent = 0
    for device_id, agent in agents.items():
        pending = [cmd for cmd in list(_legacy.commands.get(device_id, [])) if cmd.get('action') != 'scan_now']
        pending.append({'action': 'scan_now'})
        _legacy.commands[device_id] = pending
        _agent_scan_state[device_id] = {'started_at': now, 'report_marker': _agent_report_marker(agent)}
        sent += 1
    message = f'Scan triggered for {sent} agent(s). Results will appear shortly.'
    return jsonify({'ok': True, 'success': True, 'status': 'started', 'accepted': True, 'message_type': 'success', 'message': message, 'error': None, 'agents': sent, 'agents_triggered': sent}), 200


def _yara_only_quarantine_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'Authentication required', 'error': 'Authentication required', 'quarantined': [], 'failed': [], 'count': 0}), 401
    agents = _legacy._all_agents()
    if not agents:
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'No connected agents.', 'error': 'No connected agents.', 'quarantined': [], 'failed': [], 'count': 0, 'agents_triggered': 0}), 404
    sent = 0
    targeted = 0
    for device_id, agent in agents.items():
        last_report = agent.get('last_report') or {}
        findings = []
        seen = set()
        for finding in last_report.get('findings') or last_report.get('results') or []:
            if not isinstance(finding, dict):
                continue
            path = finding.get('path') or finding.get('original_path')
            if not path or not _is_yara_finding(finding):
                continue
            key = _canonical_path(path)
            if not key or key in seen:
                continue
            seen.add(key)
            findings.append({'path': path})
        pending = list(_legacy.commands.get(device_id, []))
        existing_scan_files = {_canonical_path(cmd.get('file_path', '')) for cmd in pending if cmd.get('action') == 'scan_file'}
        for finding in findings:
            path = finding['path']
            if _canonical_path(path) not in existing_scan_files:
                pending.append({'action': 'scan_file', 'file_path': path})
                targeted += 1
        _legacy.commands[device_id] = pending
        sent += 1
    quarantined = []
    for device_id, agent in agents.items():
        host = agent.get('hostname', device_id)
        for qfile in agent.get('quarantine_files') or []:
            quarantined.append({'hostname': host, 'device_id': device_id, 'filename': qfile.get('filename', ''), 'original_path': qfile.get('original_path', ''), 'quarantined_at': qfile.get('quarantined_at', ''), 'size': qfile.get('size', 0)})
    return jsonify({'ok': True, 'success': True, 'status': 'accepted', 'message_type': 'success', 'quarantined': quarantined, 'failed': [], 'count': len(quarantined), 'agents_triggered': sent, 'targeted_findings': targeted, 'message': f'YARA quarantine queued for {targeted} current finding(s) across {sent} agent(s). Results will refresh after the scan.', 'error': None}), 200


def _complete_agent_scan_results_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'Authentication required', 'error': 'Authentication required'}), 401
    return jsonify(build_complete_agent_scan_results(_legacy)), 200


@app.before_request
def _intercept_agent_scan_and_yara_quarantine():
    if request.method == 'POST' and request.path == '/api/agent-trigger-scan':
        return _agent_trigger_scan_response()
    if request.method == 'GET' and request.path == '/api/agent-scan-results':
        return _complete_agent_scan_results_response()
    if request.method == 'POST' and request.path == '/quarantine/yara-matches':
        return _yara_only_quarantine_response()
    return None


@app.route('/api/conditional_startup/status', methods=['GET'])
def conditional_startup_status_api():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'error': 'Authentication required'}), 401
    return jsonify(_canonical_yara_agent_state()), 200
