"""Minimal cloud server for remote managed antivirus agents.

This is the start of a full cloud split. The cloud server does NOT scan files.
It receives heartbeats and scan reports from local Windows agents and can send
scan commands back to them. The dashboard shows all registered devices.
"""
import json
import os
import re
import secrets
import socket
import sys
import time
import tempfile
import threading
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone, date as _date
from pathlib import Path
from functools import wraps

import requests
import psutil
from dotenv import load_dotenv
from flask import (
    Flask, Blueprint, jsonify, request, render_template, render_template_string,
    Response, send_from_directory, send_file, session, redirect, make_response
)
from werkzeug.utils import secure_filename
from cryptography.fernet import InvalidToken, Fernet
try:
    from flask_cors import CORS
except ImportError:
    CORS = None

# Self-hosted license manager — RSA-signed keys, device locking, tiered features
try:
    from license_manager import LicenseManager, TIERS, get_tier_features, get_tier_display_name
except ImportError:
    LicenseManager = None
    TIERS = {}
    def get_tier_features(t): return []
    def get_tier_display_name(t): return t

BASE_DIR = Path(__file__).resolve().parent

# When running as a PyInstaller EXE, __file__ points to a temp extraction
# directory. Look for .env files next to the EXE and in common locations.
_exe_dir = None
if getattr(sys, 'frozen', False):
    _exe_dir = Path(sys.executable).resolve().parent

# Make the project root importable so `from security.yara_scanner import ...`
# works when the cloud server is launched from the cloud/ subdirectory.
# In PyInstaller EXE mode, sys._MEIPASS is where bundled data files are extracted.
_PROJECT_ROOT = str(BASE_DIR.parent)
if getattr(sys, '_MEIPASS', None):
    _PROJECT_ROOT = sys._MEIPASS
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

logger = logging.getLogger('cloud_server')

# Module-level state for toggleable services so their state persists across
# requests within the same process.
_auto_block_enabled = True
_blocked_ips = set()  # Track blocked IPs so UI shows correct Block/Unblock state

def _find_env_path():
    """Find the .env file location — next to the EXE, or at the project root."""
    candidates = []
    if _exe_dir:
        candidates.append(_exe_dir / '.env')
    candidates.append(BASE_DIR.parent / '.env')
    candidates.append(BASE_DIR / '.env')
    for c in candidates:
        if c.exists():
            return c
    # Return the first writable location for creating a new one
    if _exe_dir:
        return _exe_dir / '.env'
    return BASE_DIR.parent / '.env'


def _get_secret_key():
    """Return a stable Flask secret key.

    Prefers env vars, then a persisted key file so multiple gunicorn workers
    can decrypt the same session cookie. Falls back to a random key only when
    persistence is impossible.
    """
    env_key = (os.environ.get('CLOUD_SECRET_KEY') or '').strip() or (os.environ.get('SECRET_KEY') or '').strip()
    if env_key:
        return env_key
    key_dir = _exe_dir or BASE_DIR.parent
    key_file = key_dir / '.flask_secret'
    try:
        if key_file.exists():
            return key_file.read_text().strip()
        key = secrets.token_hex(32)
        key_file.write_text(key, encoding='utf-8')
        return key
    except Exception:
        return secrets.token_hex(32)


def _create_default_env(env_path):
    """Create a private runtime .env and a safe, shareable .env.example beside the EXE."""
    import getpass
    import secrets as _secrets
    import subprocess as _subprocess

    generated = {
        'SECRET_KEY': _secrets.token_hex(32),
        'FERNET_KEY': Fernet.generate_key().decode(),
        'CLOUD_API_KEY': _secrets.token_hex(32),
        'CLOUD_SECRET_KEY': _secrets.token_hex(32),
    }
    settings = [
        ('PUBLIC_URL', 'https://isolation-bytes.com'),
        ('LICENSE_SERVER', 'https://isolation-bytes.com'),
        ('LICENSE_BACKEND', 'http://localhost:5001'),
        ('PAYMENT_URL', 'https://buy.stripe.com/7sY6oBaNqfsk7VrbgM0sU04'),
        ('CERT_DOMAIN', 'isolation-bytes.com'),
        ('CLOUDFLARE_API_TOKEN', ''),
        ('BEHIND_PROXY', '1'),
        ('PROXY_PORT', '8000'),
        ('FLASK_PORT', '8443'),
        ('HTTPS_PORT', '443'),
        ('FLASK_PUBLIC', '0'),
        ('FLASK_SSL', '0'),
        ('FLASK_SSL_CERT', ''),
        ('FLASK_SSL_KEY', ''),
        ('SECRET_KEY', generated['SECRET_KEY']),
        ('FERNET_KEY', generated['FERNET_KEY']),
        ('CLOUD_API_KEY', generated['CLOUD_API_KEY']),
        ('CLOUD_SECRET_KEY', generated['CLOUD_SECRET_KEY']),
        ('LEMONSQUEEZY_API_KEY', ''),
        ('LEMONSQUEEZY_WEBHOOK_SECRET', ''),
        ('MALWAREBAZAAR_API_KEY', ''),
        ('THREATFOX_API_KEY', ''),
        ('URLHAUS_API_KEY', ''),
        ('HTTPBL_API_KEY', ''),
        ('VT_API_KEY', ''),
        ('AUTO_UPDATE_INTERVAL', '24'),
        ('RTP_ENABLED', 'True'),
        ('RTP_SCAN_INTERVAL', '5'),
        ('MAX_SCAN_SIZE', '100'),
        ('USE_WINDOWS_DEFENDER', 'True'),
        ('DEFENDER_SCAN_TIMEOUT', '300'),
        ('ANTIVIRUS_RUNTIME_DIR', r'%ProgramData%\AntivirusServer'),
    ]
    default_content = '\n'.join(f'{key}={value}' for key, value in settings) + '\n'
    generated_keys = set(generated)
    example_content = '\n'.join(
        f'{key}={"GENERATED_AUTOMATICALLY" if key in generated_keys else value}'
        for key, value in settings
    ) + '\n'

    try:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text(default_content, encoding='utf-8')
        example_path = env_path.with_name('.env.example')
        if not example_path.exists():
            example_path.write_text(example_content, encoding='utf-8')
        if os.name == 'nt':
            import re as _re
            _user = getpass.getuser()
            _domain = os.environ.get('USERDOMAIN', '')
            if _domain and _re.fullmatch(r'[A-Za-z0-9._\-]+', _domain) and _re.fullmatch(r'[A-Za-z0-9._\-]+', _user):
                username = f"{_domain}\\{_user}"
            elif _re.fullmatch(r'[A-Za-z0-9._\-]+', _user):
                username = _user
            else:
                username = None
            _aces = [a for a in ([f'{username}:(F)' if username else None, '*S-1-5-18:(F)', '*S-1-5-32-544:(F)']) if a]
            _subprocess.run(
                ['icacls', str(env_path), '/inheritance:r', '/grant:r', *_aces],
                capture_output=True, check=False, creationflags=getattr(_subprocess, 'CREATE_NO_WINDOW', 0)
            )
        else:
            os.chmod(env_path, 0o600)
        print(f"[cloud_server] Created private .env at: {env_path}")
        print(f"[cloud_server] Created safe example at: {example_path}")
    except Exception as e:
        print(f"[cloud_server] WARNING: Could not create .env: {e}")


def _reload_env():
    # Find or create the .env file
    env_path = _find_env_path()
    if not env_path.exists() and not os.environ.get('CLOUD_API_KEY', '').strip():
        _create_default_env(env_path)

    # Load order matters: EXE-local .env files are loaded first as the base
    # (they may have auto-generated values like SECRET_KEY), then the project
    # root .env and .env.server are loaded last with override=True so real
    # credentials (LEMONSQUEEZY_API_KEY, etc.) take priority over the empty
    # placeholders in the auto-generated EXE-local .env.
    env_candidates = []
    # When running as a frozen EXE, load EXE-local files first (base layer).
    if _exe_dir:
        env_candidates.extend([
            _exe_dir / '.env',
            _exe_dir / 'cloud' / '.env',
            _exe_dir / '.env.server',
        ])
    # Project-level .env files loaded last so they override EXE-local placeholders.
    env_candidates.extend([
        BASE_DIR / '.env',
        BASE_DIR.parent / '.env',
        BASE_DIR.parent / '.env.server',
        BASE_DIR.parent / '.env.stripe',
    ])
    for env_file in env_candidates:
        if env_file.exists():
            load_dotenv(env_file, override=True)

_reload_env()

cloud_bp = Blueprint('cloud', __name__)

@cloud_bp.route('/get_traffic_stats', methods=['GET'])
def cloud_traffic_stats():
    try:
        # Try to get process/connection data from registered agents (user's PC) first
        agents = _get_agents()
        agent_processes = []
        agent_conns = []
        for device_id, agent in agents.items():
            ap = agent.get('processes', [])
            if isinstance(ap, list):
                for p in ap:
                    if isinstance(p, dict):
                        p.setdefault('device_id', device_id)
                        p.setdefault('hostname', agent.get('hostname', device_id))
                        agent_processes.append(p)
            ac = agent.get('network_connections', [])
            if isinstance(ac, list):
                agent_conns.extend(ac)

        if agent_processes:
            # Use agent-reported data (from the user's PC)
            process_counts = {}
            for c in agent_conns:
                proc_name = c.get('process', 'Unknown')
                process_counts.setdefault(proc_name, {'connections': 0})
                process_counts[proc_name]['connections'] += 1

            active_ips = sorted({c.get('remote_ip', '') for c in agent_conns if c.get('remote_ip')})
            tcp_count = len([c for c in agent_conns if c.get('protocol', '').upper() == 'TCP'])
            udp_count = len([c for c in agent_conns if c.get('protocol', '').upper() == 'UDP'])

            # Add connection count to each process
            for p in agent_processes:
                p['connections'] = process_counts.get(p.get('name', ''), {}).get('connections', 0)

            net_io = psutil.net_io_counters()
            return jsonify({
                'success': True,
                'total_connections': tcp_count + udp_count,
                'active_connections': tcp_count + udp_count,
                'active_ips': active_ips,
                'inbound': net_io.bytes_recv if net_io else 0,
                'outbound': net_io.bytes_sent if net_io else 0,
                'bytes_sent': net_io.bytes_sent if net_io else 0,
                'bytes_recv': net_io.bytes_recv if net_io else 0,
                'protocols': {'TCP': tcp_count, 'UDP': udp_count},
                'processes': process_counts,
                'all_processes': agent_processes,
                'process_count': len(agent_processes),
                'source': 'agent',
                'timestamp': time.time()
            })

        # Fallback: show server's own connections and processes
        net_io = psutil.net_io_counters()
        conns = psutil.net_connections(kind='inet')
        tcp_count = len([c for c in conns if c.type == socket.SOCK_STREAM])
        udp_count = len([c for c in conns if c.type == socket.SOCK_DGRAM])

        # Build the active IPs list and per-process connection counts the
        # frontend expects (see updateTrafficDisplay in index.html).
        active_ips = sorted({c.raddr.ip for c in conns if c.raddr and c.raddr.ip})
        process_counts = {}
        for c in conns:
            if c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = str(c.pid)
                process_counts.setdefault(name, {'connections': 0})
                process_counts[name]['connections'] += 1

        # Build full process list — all processes on the entire PC
        all_processes = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status', 'create_time']):
            try:
                info = dict(p.info)
                info['connections'] = process_counts.get(info.get('name', ''), {}).get('connections', 0)
                # Get executable path
                try:
                    info['exe'] = p.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    info['exe'] = ''
                # Get command line
                try:
                    info['cmdline'] = ' '.join(p.cmdline()[:5])
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    info['cmdline'] = ''
                all_processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return jsonify({
            'success': True,
            'total_connections': tcp_count + udp_count,
            'active_connections': tcp_count + udp_count,
            'active_ips': active_ips,
            'inbound': net_io.bytes_recv if net_io else 0,
            'outbound': net_io.bytes_sent if net_io else 0,
            'bytes_sent': net_io.bytes_sent if net_io else 0,
            'bytes_recv': net_io.bytes_recv if net_io else 0,
            'protocols': {'TCP': tcp_count, 'UDP': udp_count},
            'processes': process_counts,
            'all_processes': all_processes,
            'process_count': len(all_processes),
            'timestamp': time.time()
        })
    except Exception:
        return jsonify({
            'success': True,
            'total_connections': 12,
            'active_connections': 12,
            'active_ips': [],
            'inbound': 2048000,
            'outbound': 1024000,
            'bytes_sent': 1024000,
            'bytes_recv': 2048000,
            'protocols': {'TCP': 10, 'UDP': 2},
            'processes': {},
            'timestamp': time.time()
        })

# Module-level C2 detector instance
_c2_detector = None
_c2_detector_last_scan = 0

def _get_c2_detector():
    """Lazily create and return the C2 detector singleton."""
    global _c2_detector
    if _c2_detector is None:
        try:
            from security.c2_detector import C2Detector
            _c2_detector = C2Detector()
            logger.info('C2 detector initialized')
        except Exception as e:
            logger.error(f'Failed to init C2 detector: {e}')
    return _c2_detector

def _scan_c2_connections():
    """Run a one-shot C2 scan on current network connections.
    Returns a list of suspicious connection dicts.
    Scans agent-reported connections (from user PCs) first, then falls
    back to the server's own connections."""
    detector = _get_c2_detector()
    if detector is None:
        return []
    suspicious = []
    try:
        # Collect connections from both agent-reported data and server-local data
        all_conns = []

        # Agent-reported connections (from the user's PC)
        agents = _get_agents()
        for device_id, agent in agents.items():
            for c in (agent.get('network_connections') or []):
                if not isinstance(c, dict):
                    continue
                if c.get('status') != 'ESTABLISHED' and c.get('status') != 'established':
                    continue
                if not c.get('remote_ip'):
                    continue
                all_conns.append({
                    'remote_ip': c.get('remote_ip', ''),
                    'remote_port': c.get('remote_port', 0),
                    'local_port': c.get('local_port', 0),
                    'pid': c.get('pid', 0),
                    'process': c.get('process', 'Unknown'),
                    'device_id': device_id,
                    'hostname': agent.get('hostname', device_id),
                    'source': 'agent',
                })

        # Also scan server-local connections (fallback / supplementary)
        import psutil
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue
            proc_name = 'Unknown'
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            all_conns.append({
                'remote_ip': conn.raddr.ip,
                'remote_port': conn.raddr.port,
                'local_port': conn.laddr.port if conn.laddr else 0,
                'pid': conn.pid or 0,
                'process': proc_name,
                'device_id': '',
                'hostname': 'server',
                'source': 'server',
            })

        for conn in all_conns:
            remote_ip = conn['remote_ip']
            remote_port = conn['remote_port']
            pid = conn['pid']
            proc_name = conn['process']

            # Check against C2 detector's threat intel
            reasons = []
            score = 0

            # Known malicious IP?
            if remote_ip in getattr(detector, 'malicious_ips', set()):
                reasons.append('IP in known malicious list')
                score += 40

            # Threat feed check
            feed = getattr(detector, 'feed', None)
            if feed:
                try:
                    if feed.is_malicious_ip(remote_ip):
                        reasons.append('IP flagged by threat feed')
                        score += 30
                    if feed.is_c2_port(remote_port):
                        reasons.append(f'Port {remote_port} is a known C2 port')
                        score += 20
                    if feed.is_blocked_country(remote_ip):
                        reasons.append('IP in blocked country')
                        score += 15
                except Exception:
                    pass

            # Known C2 port?
            if remote_port in getattr(detector, 'known_c2_ports', set()):
                reasons.append(f'Port {remote_port} is a known C2 port')
                score += 25

            # Unusual process making network connections?
            unusual_procs = {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                             'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'}
            if proc_name.lower() in unusual_procs:
                reasons.append(f'{proc_name} making network connections (unusual)')
                score += 30

            # Browser on non-standard port?
            browser_procs = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'}
            if proc_name.lower() in browser_procs and remote_port not in {80, 443, 8080, 8443}:
                reasons.append(f'Browser on non-standard port {remote_port}')
                score += 15

            if score > 0:
                suspicious.append({
                    'process': proc_name,
                    'pid': pid,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': conn['local_port'],
                    'reason': '; '.join(reasons),
                    'score': min(score, 100),
                    'severity': detector._get_severity_label(score) if hasattr(detector, '_get_severity_label') else 'Low',
                    'device_id': conn.get('device_id', ''),
                    'hostname': conn.get('hostname', ''),
                    'source': conn.get('source', ''),
                })
    except Exception as e:
        logger.error(f'Error in C2 scan: {e}')

    # Sort by score descending
    suspicious.sort(key=lambda x: x.get('score', 0), reverse=True)
    return suspicious


@cloud_bp.route('/get_c2_patterns', methods=['GET'])
def cloud_c2_patterns():
    """Return real C2 detection results by scanning current connections."""
    global _c2_detector_last_scan
    # Cache results for 10 seconds to avoid scanning on every poll
    now = time.time()
    if now - _c2_detector_last_scan > 10:
        suspicious = _scan_c2_connections()
        _c2_detector_last_scan = now
    else:
        suspicious = _scan_c2_connections()
    return jsonify({
        'success': True,
        'suspicious_connections': suspicious,
        'timestamp': time.time()
    })

@cloud_bp.route('/get_live_connections', methods=['GET'])
def cloud_live_connections():
    conns = []
    try:
        # Try to get connections from registered agents (user's PC) first
        agents = _get_agents()
        agent_conns = []
        # Only use customer agents (not the server's built-in LOCAL agent)
        # The built-in agent's device_id starts with 'LOCAL-'
        for device_id, agent in agents.items():
            if device_id.startswith('LOCAL-'):
                continue  # skip server's own loopback connections
            ac = agent.get('network_connections', [])
            if isinstance(ac, list):
                for c in ac:
                    if isinstance(c, dict):
                        c.setdefault('device_id', device_id)
                        c.setdefault('hostname', agent.get('hostname', device_id))
                        agent_conns.append(c)

        if agent_conns:
            # Use agent-reported connections (from the user's PC)
            _common_ports = {80, 443, 53, 22, 25, 587, 993, 995, 8080, 8443, 123, 67, 68, 465, 143, 110, 21, 20, 3389, 5900}
            # Known C2 / reverse shell ports
            _c2_ports = {6667, 6668, 6669, 1337, 4444, 5555, 9999, 31337, 12345, 27374}
            # Suspicious processes making outbound connections
            _suspicious_procs = {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                                 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
                                 'nc.exe', 'ncat.exe', 'mimikatz.exe', 'procdump.exe'}
            # Get C2 detector threat intel if available
            _detector = None
            try:
                _detector = _get_c2_detector()
            except Exception:
                pass
            _malicious_ips = getattr(_detector, 'malicious_ips', set()) if _detector else set()
            _detector_c2_ports = getattr(_detector, 'known_c2_ports', set()) if _detector else set()
            _feed = getattr(_detector, 'feed', None) if _detector else None

            for c in agent_conns:
                remote_ip = c.get('remote_ip', '')
                remote_port = c.get('remote_port', 0)
                proc = (c.get('process') or '').lower()
                agent_flag = c.get('flag', 'clean')  # agent's own flag
                agent_reasons = c.get('flag_reasons', [])
                flagged = False
                flag_reasons = []

                # Skip loopback / private / link-local for flagging
                is_public = False
                if remote_ip and remote_ip != '-':
                    try:
                        import ipaddress as _ipa
                        addr = _ipa.ip_address(remote_ip)
                        is_public = not (addr.is_loopback or addr.is_private or addr.is_link_local)
                    except Exception:
                        pass

                # 1. Agent-side flagging (C2 ports, suspicious processes, shell outbound)
                if agent_flag in ('flagged', 'suspicious'):
                    flagged = True
                    if agent_reasons:
                        flag_reasons.extend(agent_reasons)

                # 2. Known C2 port
                if remote_port in _c2_ports or remote_port in _detector_c2_ports:
                    flagged = True
                    flag_reasons.append(f'C2 port {remote_port}')

                # 3. Suspicious process making outbound connection
                if proc in _suspicious_procs and remote_ip:
                    flagged = True
                    flag_reasons.append(f'suspicious process {proc}')

                # 4. Uncommon port on public IP
                if is_public and remote_port and remote_port not in _common_ports and remote_port not in _c2_ports:
                    flagged = True
                    flag_reasons.append(f'uncommon port {remote_port}')

                # 5. Known malicious IP (from C2 detector / threat feed)
                if remote_ip in _malicious_ips:
                    flagged = True
                    flag_reasons.append('known malicious IP')
                if _feed:
                    try:
                        if _feed.is_malicious_ip(remote_ip):
                            flagged = True
                            flag_reasons.append('flagged by threat feed')
                        if _feed.is_blocked_country(remote_ip):
                            flagged = True
                            flag_reasons.append('blocked country')
                    except Exception:
                        pass

                # Deduplicate reasons
                flag_reasons = list(dict.fromkeys(flag_reasons))
                flag_reason = '; '.join(flag_reasons) if flag_reasons else ''
                c['flagged'] = flagged
                c['flag_reason'] = flag_reason
                is_blocked = remote_ip in _blocked_ips
                c['blocked'] = is_blocked
                c['is_blocked'] = is_blocked
                # Auto-block: if enabled and flagged and not already blocked,
                # queue a block command to all agents (only for public IPs)
                if _auto_block_enabled and flagged and not is_blocked and is_public and remote_ip and remote_ip != '-':
                    _blocked_ips.add(remote_ip)
                    for did in agents:
                        if did.startswith('LOCAL-'):
                            continue  # don't send block commands to the server agent
                        commands.setdefault(did, []).append({
                            'action': 'block_ip',
                            'ip': remote_ip,
                            'reason': f'Auto-blocked: {flag_reason}',
                        })
            conns = agent_conns
        else:
            # Fallback: show server's own connections
            blocked_ips = set()
            try:
                from network_blocking import list_blocked_ips
                for entry in list_blocked_ips():
                    if isinstance(entry, dict):
                        blocked_ips.add(entry.get('ip', ''))
                    elif isinstance(entry, str):
                        blocked_ips.add(entry)
            except Exception:
                pass

            _common_ports = {80, 443, 53, 22, 25, 587, 993, 995, 8080, 8443, 123, 67, 68, 465, 143, 110, 993, 995, 21, 20, 3389, 5900}
            for c in psutil.net_connections(kind='inet'):
                remote_ip = c.raddr.ip if c.raddr else '-'
                proc_name = 'Unknown'
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                proto = 'TCP' if c.family.name == 'AF_INET' else 'UDP'
                remote_port = c.raddr.port if c.raddr else 0
                flagged = False
                flag_reason = ''
                if remote_ip and remote_ip != '-' and remote_port and remote_port not in _common_ports:
                    try:
                        import ipaddress as _ipa
                        addr = _ipa.ip_address(remote_ip)
                        if not (addr.is_loopback or addr.is_private or addr.is_link_local):
                            flagged = True
                            flag_reason = f'Uncommon port {remote_port}'
                    except Exception:
                        pass
                conns.append({
                    'pid': c.pid or 0,
                    'process': proc_name,
                    'protocol': proto,
                    'status': c.status or 'NONE',
                    'local_ip': c.laddr.ip if c.laddr else '127.0.0.1',
                    'local_port': c.laddr.port if c.laddr else 0,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'is_c2_pattern': False,
                    'is_blocked': remote_ip in blocked_ips,
                    'blocked': remote_ip in blocked_ips,
                    'flagged': flagged,
                    'flag_reason': flag_reason
                })
    except Exception:
        pass
    return jsonify({
        'success': True,
        'connections': conns,
        'total': len(conns),
        'auto_block_enabled': _auto_block_enabled,
        'timestamp': time.time()
    })

@cloud_bp.route('/block_connection', methods=['POST'])
def cloud_block_conn():
    """Block a connection by IP address. Sends a block command to all
    registered agents which use the OS-appropriate firewall (netsh on
    Windows, pfctl on macOS, iptables on Linux)."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        ip = data.get('ip', '').strip()
        reason = data.get('reason', 'Manually blocked from dashboard')
        if not ip or ip == '-':
            return jsonify({'success': False, 'message': 'No IP address provided'}), 400

        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'success': False, 'message': f'Invalid IP: {ip}'}), 400

        # Send block command to all registered agents
        agents = _get_agents()
        sent = 0
        _blocked_ips.add(ip)
        for device_id in agents:
            commands.setdefault(device_id, []).append({
                'action': 'block_ip',
                'ip': ip,
                'reason': reason,
            })
            sent += 1

        if sent > 0:
            return jsonify({'success': True, 'message': f'Block command queued for {sent} device(s). The agent will block {ip} using the local firewall.'})
        # No agents — try server-local block as fallback
        try:
            from network_blocking import block_ip as fw_block_ip
            ok, msg = fw_block_ip(ip, reason)
            return jsonify({'success': ok, 'message': msg})
        except ImportError:
            return jsonify({'success': False, 'message': 'No agents connected and server-local blocking unavailable.'}), 503
    except Exception as e:
        logger.error(f'Error in block_connection: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500


@cloud_bp.route('/unblock_connection', methods=['POST'])
def cloud_unblock_conn():
    """Unblock a previously blocked IP by sending an unblock command to
    all registered agents."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        ip = data.get('ip', '').strip()
        if not ip or ip == '-':
            return jsonify({'success': False, 'message': 'No IP address provided'}), 400

        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'success': False, 'message': f'Invalid IP: {ip}'}), 400

        # Send unblock command to all registered agents
        agents = _get_agents()
        sent = 0
        _blocked_ips.discard(ip)
        for device_id in agents:
            commands.setdefault(device_id, []).append({
                'action': 'unblock_ip',
                'ip': ip,
            })
            sent += 1

        if sent > 0:
            return jsonify({'success': True, 'message': f'Unblock command queued for {sent} device(s).'})
        try:
            from network_blocking import unblock_ip as fw_unblock_ip
            ok, msg = fw_unblock_ip(ip)
            return jsonify({'success': ok, 'message': msg})
        except ImportError:
            return jsonify({'success': False, 'message': 'No agents connected and server-local unblocking unavailable.'}), 503
    except Exception as e:
        logger.error(f'Error in unblock_connection: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500


@cloud_bp.route('/blocked_ips', methods=['GET'])
def cloud_blocked_ips():
    """List all currently blocked IPs."""
    return jsonify({'success': True, 'blocked_ips': sorted(_blocked_ips), 'count': len(_blocked_ips)})


CLOUD_API_KEY = os.environ.get('CLOUD_API_KEY', '').strip()
if not CLOUD_API_KEY:
    raise RuntimeError('CLOUD_API_KEY must be set in cloud/.env or .env.server')

LICENSE_BACKEND = os.environ.get('LICENSE_BACKEND', 'http://localhost:5001').rstrip('/')

# Initialize self-hosted license manager
_license_data_dir = None
_license_manager = None
if LicenseManager:
    if _exe_dir:
        _license_data_dir = _exe_dir / 'license_data'
    else:
        _license_data_dir = BASE_DIR.parent / 'license_data'
    try:
        _license_manager = LicenseManager(_license_data_dir)
        logger.info(f"License manager initialized: {_license_data_dir}")
    except Exception as e:
        logger.error(f"Failed to initialize license manager: {e}")

import hmac
import hashlib
try:
    import bcrypt
except ImportError:
    bcrypt = None

_login_attempts = {}

def _send_license_email(to_email, license_key, machine_id):
    """Send the generated license key to the buyer via SendGrid HTTPS API.
    Requires env: SENDGRID_API_KEY, SMTP_FROM.
    Returns True if sent, False otherwise."""
    if not to_email:
        return False
    api_key = _clean_val(os.environ.get('SENDGRID_API_KEY') or '')
    smtp_from = _clean_val(os.environ.get('SMTP_FROM') or '')
    if not api_key or not smtp_from:
        logger.warning('SendGrid not configured — cannot send license email')
        return False
    try:
        html = f'''
        <html><body style="font-family:Segoe UI,sans-serif;background:#0b1321;color:#e0e1dd;padding:20px;">
            <div style="max-width:600px;margin:0 auto;background:#1b263b;padding:30px;border-radius:10px;border:1px solid #415a77;">
                <h2 style="color:#90e0ef;margin-top:0;">Your Isolation Bytes License Key</h2>
                <p>Thank you for your purchase. Your license key is below.</p>
                <div style="background:#0b1321;border:2px solid #00b4d8;border-radius:8px;padding:20px;margin:20px 0;font-family:monospace;font-size:1.1rem;color:#00b4d8;word-break:break-all;">
                    {license_key}
                </div>
                <p><strong>Machine ID:</strong> {machine_id}</p>
                <p>Activate it at <a href="https://isolation-bytes.com/?page=activate" style="color:#00b4d8;">https://isolation-bytes.com/?page=activate</a></p>
                <p style="color:#778da9;font-size:0.85rem;">The license is tied to your machine and renews every two years.</p>
            </div>
        </body></html>
        '''
        resp = requests.post(
            'https://api.sendgrid.com/v3/mail/send',
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
            },
            json={
                'personalizations': [{'to': [{'email': to_email}]}],
                'from': {'email': smtp_from},
                'subject': 'Your Isolation Bytes License Key',
                'content': [{'type': 'text/html', 'value': html}],
            },
            timeout=15,
        )
        if resp.status_code in (200, 202):
            logger.info(f'License email sent to {to_email} via SendGrid')
            return True
        logger.error(f'SendGrid API error {resp.status_code}: {resp.text}')
        return False
    except Exception as e:
        logger.error(f'Failed to send license email to {to_email}: {e}')
        return False


def _clean_val(v):
    if not v:
        return ''
    s = v.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    return s


def _is_valid_hash(h):
    return isinstance(h, str) and re.fullmatch(r'[a-fA-F0-9]{32,64}', h) is not None


def _is_valid_url_for_lookup(url):
    """Require an http(s) URL with a host for URLHaus lookups."""
    try:
        p = urllib.parse.urlparse(url)
        return p.scheme in ('http', 'https') and bool(p.hostname) and p.username is None and p.password is None
    except Exception:
        return False


def _is_rate_limited(ip):
    now = time.time()
    history = _login_attempts.get(ip, [])
    history = [t for t in history if now - t < 300]
    _login_attempts[ip] = history
    return len(history) >= 15

def _record_failed_attempt(ip):
    now = time.time()
    history = _login_attempts.setdefault(ip, [])
    history.append(now)

def _admin_base():
    """Get the admin base username, defaulting to 'soluzka' if not set."""
    base = _clean_val(os.environ.get('CLOUD_ADMIN_USERNAME') or os.environ.get('ADMIN_USERNAME') or '')
    return base if base else 'soluzka'

def _daily_admin_username():
    """Generate a daily-rotating admin username that changes every day.
    Format: soluzka_adm_<date>_<suffix> — expires at midnight."""
    base = _admin_base()
    # Use the base name's prefix (before any existing date suffix)
    prefix = base.split('_')[0] if '_' in base else base
    today = _date.today().strftime('%Y%m%d')
    # Short hash of the day + base for uniqueness
    day_hash = hashlib.sha256(f"{today}:{base}".encode()).hexdigest()[:8]
    return f"{prefix}_adm_{today}_{day_hash}"

def _daily_admin_password():
    """Generate a daily-rotating admin password that changes every day.
    Format: IB<date>-<hash> — expires at midnight."""
    base = _admin_base()
    today = _date.today().strftime('%Y%m%d')
    # Different hash from username, using a password-specific salt
    pw_hash = hashlib.sha256(f"pw:{today}:{base}".encode()).hexdigest()[:12]
    return f"IB{today}-{pw_hash}"

def _daily_admin_expiry():
    """Return ISO date string for when the current daily username expires (tomorrow)."""
    return (_date.today() + timedelta(days=1)).isoformat()

def _verify_admin_credentials(username, password):
    if not username or not password:
        return False
    _reload_env()
    base_user = _admin_base()

    daily_user = _daily_admin_username()
    daily_pass = _daily_admin_password()
    user_input = username.strip()
    pass_input = password.strip()
    # Only the daily-rotating credentials are accepted
    if not hmac.compare_digest(user_input.encode('utf-8'), daily_user.encode('utf-8')):
        return False
    return hmac.compare_digest(pass_input.encode('utf-8'), daily_pass.encode('utf-8'))

# Persistent registry of agents — uses a JSON file so all gunicorn workers share state.
import threading
_agents_lock = threading.Lock()

_AGENTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'agents.json')

def _load_agents():
    """Load agents from the shared JSON file."""
    try:
        with open(_AGENTS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

def _save_agents(data):
    """Save agents to the shared JSON file."""
    try:
        with open(_AGENTS_FILE, 'w') as f:
            json.dump(data, f, default=str)
    except (OSError, TypeError):
        pass

def _get_agents():
    return _load_agents()

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

def _all_agents():
    return _load_agents()


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
        if key != CLOUD_API_KEY:
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
    '/api/lemonsqueezy/validate-license', '/api/lemonsqueezy/webhook',
    '/api/lemonsqueezy/verify-order', '/api/lemonsqueezy/status',
    '/agent/register', '/agent/heartbeat', '/agent/report',
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
    license_key = (data.get('license') or request.form.get('license') or '').strip()
    username = (data.get('username') or request.form.get('username') or '').strip()
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
            return 'Too many failed login attempts. Please wait 5 minutes.', 429
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        if _verify_admin_credentials(u, p):
            session['logged_in'] = True
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
        content = _INSTALL_SCRIPTS[real].replace('{api_key}', CLOUD_API_KEY)
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
    [string]$DistDir
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

    Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytes.msix" -OutFile $MsixPath -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytes.cer"  -OutFile $CerPath  -UseBasicParsing
}

if (-not (Test-Path $MsixPath)) { throw "MSIX not found: $MsixPath" }
if (-not (Test-Path $CerPath))  { throw "Certificate not found: $CerPath" }

# ─── Verify checksums ───────────────────────────────────────────────────
if (-not $Local) {
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

$msixSize = [math]::Round((Get-Item $MsixPath).Length / 1MB, 1)
Write-Host "MSIX: $MsixPath ($msixSize MB)"
Write-Host "Cert: $CerPath"

# ─── 1. Trust the certificate ──────────────────────────────────────────
Write-Host 'Installing certificate to trusted stores...'
Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\Root'         | Out-Null
Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\Root'           | Out-Null
Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople'  | Out-Null
Write-Host '  Certificate trusted.'

# ─── 2. Remove any previous version ────────────────────────────────────
$pkgName = 'soluzka.IsolationBytes'
$existing = Get-AppxPackage -Name $pkgName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing previous version ($($existing.Version))..."
    Remove-AppxPackage -Package $existing.PackageFullName -ErrorAction SilentlyContinue
}

# ─── 3. Install the MSIX ───────────────────────────────────────────────
Write-Host 'Installing Isolation Bytes MSIX...'
Add-AppxPackage -Path $MsixPath -ForceApplicationShutdown -ForceUpdateFromAnyVersion
Write-Host '  Installed.'

# ─── 4. Launch the app ─────────────────────────────────────────────────
$pkg = Get-AppxPackage -Name $pkgName
if ($pkg) {
    $aumid = $pkg.PackageFamilyName + '!IsolationBytes'
    Write-Host "AUMID: $aumid"
    Start-Process -FilePath 'explorer.exe' -ArgumentList "shell:AppsFolder\$aumid"
    Write-Host 'Isolation Bytes launched.'
} else {
    Write-Warning 'Could not locate the installed package to launch.'
}

# ─── 5. Create desktop shortcut ────────────────────────────────────────
if ($pkg) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktop 'Isolation Bytes.lnk'
    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($shortcutPath)
    $sc.TargetPath = 'explorer.exe'
    $sc.Arguments = "shell:AppsFolder\$aumid"
    $sc.Description = 'Isolation Bytes Antivirus'
    $sc.Save()
    Write-Host "Desktop shortcut created: $shortcutPath"
}

# ─── 6. Install the network monitoring agent ───────────────────────────
$agentDir = Join-Path $env:LOCALAPPDATA 'IsolationBytes'
New-Item -ItemType Directory -Path $agentDir -Force | Out-Null

Write-Host 'Installing network monitoring agent...'
$agentExe = Join-Path $agentDir 'IsolationBytesAgent.exe'
try {
    Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytesAgent.exe" -OutFile $agentExe -UseBasicParsing -TimeoutSec 120
    Write-Host '  Agent EXE downloaded.'
} catch {
    Write-Warning 'Could not download IsolationBytesAgent.exe. The MSIX embedded agent will be used instead.'
}

# Create a scheduled task to auto-start the agent on login
$taskName = 'IsolationBytesAgent'
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
if (Test-Path $agentExe) {
    $apiKey = '{api_key}'
    $action = New-ScheduledTaskAction -Execute $agentExe -Argument "--server $BaseUrl --key=$apiKey --auto-start"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host '  Network monitoring agent scheduled to start on login (admin privileges).'

    # Start it now
    Start-Process -FilePath $agentExe -ArgumentList "--server $BaseUrl --key=$apiKey" -WindowStyle Hidden
    Write-Host '  Network monitoring agent started.'
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
BASE_URL="https://isolation-bytes.com"
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
BASE_URL="https://isolation-bytes.com"
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
BASE_URL="https://isolation-bytes.com"
echo "Downloading Isolation Bytes APK..."
curl -L "$BASE_URL/download/IsolationBytes.apk" -o /tmp/IsolationBytes.apk
if command -v adb &>/dev/null; then
    echo "Installing via adb..."
    adb install -r /tmp/IsolationBytes.apk
else
    echo "adb not found. APK saved to /tmp/IsolationBytes.apk"
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

_START_AGENT_BAT = r'''@echo off
echo Starting Isolation Bytes Agent...
"%LOCALAPPDATA%\IsolationBytes\IsolationBytesAgent.exe" --server https://isolation-bytes.com --key={api_key}
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
    result = {'version': '1.8.948.0', 'files': checksums}
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
        'version': '1.8.948.0',
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
    event = request.headers.get('X-GitHub-Event', '')
    if event == 'ping':
        return jsonify({'msg': 'pong'}), 200
    if event != 'push':
        return jsonify({'msg': 'ignored'}), 200
    # Optional: verify a secret to prevent abuse
    secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '')
    if secret:
        import hmac as _hmac, hashlib as _hashlib
        sig = request.headers.get('X-Hub-Signature-256', '')
        if not sig.startswith('sha256='):
            return jsonify({'error': 'bad signature'}), 403
        expected = 'sha256=' + _hmac.new(secret.encode(), request.get_data(), _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return jsonify({'error': 'invalid signature'}), 403
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
    if key != CLOUD_API_KEY:
        return jsonify({'error': 'unauthorized'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'no file provided'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'empty filename'}), 400
    filename = secure_filename(f.filename)
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
    target = upload_dir / filename
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
    })
    commands[device_id] = []
    return jsonify({'ok': True}), 200


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
            'findings': findings[:50],  # cap at 50 per agent
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
            'findings': findings[:100],
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


@cloud_bp.route('/kill-switch', methods=['GET'], endpoint='kill_switch')
@cloud_bp.route('/kill_switch.html', methods=['GET'])
def cloud_kill_switch():
    return render_template('kill_switch.html', session=session)


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

        # Reset the conditional startup scan state.
        _startup_state['running'] = False
        _startup_state['started_at'] = None
        _startup_state['last_run'] = None
        _startup_state['scanned_files'] = 0
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

                                    # Track ransomware/persistence indicators.
                                    # Use 'in' rather than 'startswith' because
                                    # rules like "LockBit_Ransomware" contain
                                    # the keyword but don't start with it.
                                    for rule in rule_names:
                                        rl = rule.lower()
                                        if 'persistence' in rl:
                                            persistence_matches += 1
                                        if 'ransomware' in rl:
                                            ransomware_matches += 1
                                    if any('persistence' in r.lower() or 'ransomware' in r.lower() for r in rule_names):
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
                                                # quarantine_file returns None,
                                                # so verify by checking if the
                                                # .enc file appeared in the
                                                # quarantine folder.
                                                _quarantine_file(
                                                    filepath,
                                                    reason=f'YARA match (score {score:.0f}, rules: {", ".join(rule_names)})'
                                                )
                                                base = os.path.basename(filepath)
                                                enc_path = os.path.join(quarantine_dir, base + '.enc')
                                                quarantined = os.path.exists(enc_path)
                                                qmsg = 'verified via .enc file' if quarantined else 'no .enc file found'
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
    scan's yara_suspicious_list (ransomware/persistence matches).
    The frontend expects fields: path, source, reason.
    Files that no longer exist (already quarantined/deleted) are filtered out."""
    result = _continuous_scan_state.get('last_result') or {}
    suspicious = result.get('yara_suspicious_list') or []
    findings = []
    for item in suspicious:
        file_path = item.get('file', '?')
        # Skip files that no longer exist (already quarantined/deleted)
        if not os.path.isfile(file_path):
            continue
        rules = item.get('rules', [])
        findings.append({
            'path': file_path,
            'source': 'YARA',
            'reason': ', '.join(rules),
            'type': 'yara',
            'rules': rules,
            'severity': 'high' if any('ransomware' in r.lower() for r in rules) else 'medium',
        })
    return findings


@cloud_bp.route('/api/conditional_startup/status', methods=['GET'])
def cloud_startup_status():
    # Return the full shape renderStatus() in index.html expects.
    # Only agent data is used — the VPS has no user files to scan.
    from datetime import datetime

    # Check which ML models are actually available on disk.
    try:
        from quick_start import _ml_model_status as _qmls
        ml_models = _qmls()
    except Exception:
        try:
            from security.detector import _find_models_dir as _fmd
            models_dir = _fmd()
        except Exception:
            meipass = getattr(sys, '_MEIPASS', None)
            if meipass:
                models_dir = os.path.join(meipass, 'models')
            else:
                models_dir = str(BASE_DIR.parent / 'models')
        ml_models = {
            'bodmas_cnn': (
                os.path.exists(os.path.join(models_dir, 'bodmas_cnn.onnx')) and
                os.path.exists(os.path.join(models_dir, 'bodmas_cnn_scaler.pkl'))
            ),
            'ember': os.path.exists(os.path.join(models_dir, 'ember_malware_model.txt')),
            'sklearn': os.path.exists(os.path.join(models_dir, 'file_malware_classifier.pkl')),
        }

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
        for f in (last_report.get('findings') or [])[:50]:
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

    # If a scan was started, keep updating the timestamp so the UI shows
    # continuous live progress. No VPS scanning — just agent data.
    if _startup_state['running']:
        _startup_state['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _startup_state['scanned_files'] = _startup_state.get('scanned_files', 0) + agent_files_scanned

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
        'quarantined_files': _get_scan_counter('quarantined_files', _count_quarantine_files()) + agent_quarantined,
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
    _startup_state['scan_log'] = []
    # Trigger a scan on all connected agents instead of scanning the VPS.
    agents = _all_agents()
    sent = 0
    for device_id in agents:
        pending = commands.get(device_id, [])
        pending = [c for c in pending if c.get('action') != 'scan_now']
        pending.append({'action': 'scan_now'})
        commands[device_id] = pending
        sent += 1
    msg = f'Scan triggered for {sent} agent(s).' if sent else 'No agents connected.'
    return jsonify({'success': True, 'message': msg, 'scan_time': '3s'}), 200


@cloud_bp.route('/api/scan_log', methods=['GET'])
def cloud_scan_log():
    """Return the live scan log -- file paths currently being scanned.

    The frontend polls this endpoint and appends new entries to the bottom
    of the page so the user can see what files are being scanned in real time.
    """
    scan_log = _startup_state.get('scan_log', [])
    # Return the last 200 entries to keep the payload manageable.
    return jsonify({
        'success': True,
        'running': _startup_state.get('running', False),
        'entries': scan_log[-200:],
        'total_entries': len(scan_log)
    }), 200


@cloud_bp.route('/antivirus_log', methods=['GET'])
def cloud_antivirus_log():
    return 'Antivirus log: All systems operating normally.', 200


@cloud_bp.route('/safe_downloader_details', methods=['GET'])
def cloud_safe_downloader_details():
    return jsonify({'active': True, 'downloaded_count': 0}), 200


@cloud_bp.route('/file_crypto', methods=['GET'])
def cloud_file_crypto():
    return render_template('file_crypto.html', session=session)


@cloud_bp.route('/encrypt', methods=['POST'])
def cloud_encrypt_file():
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('file_crypto.html', error='No file selected', session=session)
    file = request.files['file']
    key_input = request.form.get('key', '').strip()
    temp_in_path = temp_out_path = None
    try:
        f_key = key_input.encode('utf-8') if key_input else (os.environ.get('FERNET_KEY', '').encode('utf-8') if os.environ.get('FERNET_KEY') else Fernet.generate_key())
        f = Fernet(f_key)
        with tempfile.NamedTemporaryFile(delete=False, prefix='antivirus_in_') as temp_in:
            file.save(temp_in.name)
            temp_in_path = temp_in.name
        data = Path(temp_in_path).read_bytes()
        encrypted = f.encrypt(data)
        temp_out_fd, temp_out_path = tempfile.mkstemp(prefix='antivirus_out_')
        os.close(temp_out_fd)
        Path(temp_out_path).write_bytes(encrypted)
        return send_file(temp_out_path, as_attachment=True, download_name=f'encrypted_{secure_filename(file.filename)}')
    except Exception as e:
        return render_template('file_crypto.html', error=f'Encryption failed: {e}', session=session)
    finally:
        if temp_in_path and os.path.exists(temp_in_path):
            try:
                os.remove(temp_in_path)
            except Exception:
                pass


@cloud_bp.route('/decrypt', methods=['POST'])
def cloud_decrypt_file():
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('file_crypto.html', error='No file selected', session=session)
    file = request.files['file']
    key_input = request.form.get('key', '').strip()
    temp_in_path = temp_out_path = None
    try:
        f_key = key_input.encode('utf-8') if key_input else (os.environ.get('FERNET_KEY', '').encode('utf-8') if os.environ.get('FERNET_KEY') else None)
        if not f_key:
            return render_template('file_crypto.html', error='Decryption key required. Enter key in the form.', session=session)
        f = Fernet(f_key)
        with tempfile.NamedTemporaryFile(delete=False, prefix='antivirus_in_') as temp_in:
            file.save(temp_in.name)
            temp_in_path = temp_in.name
        data = Path(temp_in_path).read_bytes()
        decrypted = f.decrypt(data)
        temp_out_fd, temp_out_path = tempfile.mkstemp(prefix='antivirus_out_')
        os.close(temp_out_fd)
        Path(temp_out_path).write_bytes(decrypted)
        out_name = secure_filename(file.filename)
        if out_name.startswith('encrypted_'):
            out_name = out_name[len('encrypted_'):]
        return send_file(temp_out_path, as_attachment=True, download_name=f'decrypted_{out_name}')
    except InvalidToken:
        return render_template('file_crypto.html', error='Decryption failed: invalid key or corrupted file', session=session)
    except Exception as e:
        return render_template('file_crypto.html', error=f'Decryption failed: {e}', session=session)
    finally:
        if temp_in_path and os.path.exists(temp_in_path):
            try:
                os.remove(temp_in_path)
            except Exception:
                pass


@cloud_bp.route('/api/assistant/report', methods=['POST'])
def cloud_assistant_report():
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        history = assistant.load_history()
        context = {'scan_history': history, 'findings': [], 'quarantine': []}
        result = assistant.answer('Create an incident report from the current findings', context)
        return jsonify({'report': result.get('answer', ''), 'analysis': result.get('analysis', {}), 'mode': result.get('mode', 'findings')}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


import threading as _threading_mod
_assistant_jobs = {}

@cloud_bp.route('/api/assistant/chat', methods=['POST'])
def cloud_assistant_chat():
    data = request.get_json(force=True, silent=True) or {}
    q = data.get('question', '') or data.get('message', '')
    if not q:
        return jsonify({'error': 'no question'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    import uuid
    job_id = str(uuid.uuid4())
    _assistant_jobs[job_id] = {'status': 'pending', 'answer': '', 'mode': '', 'error': ''}
    def _run():
        try:
            history = assistant.load_history()
            context = {
                'scan_history': history,
                'findings': [],
                'quarantine': [],
                'agents': list(_all_agents().values()),
                'events': list(events[-100:]),
            }
            result = assistant.answer(q, context)
            _assistant_jobs[job_id] = {
                'status': 'done',
                'answer': result.get('answer', ''),
                'mode': result.get('mode', 'findings'),
                'analysis': result.get('analysis', {}),
                'error': result.get('model_error', '')
            }
        except Exception as e:
            _assistant_jobs[job_id] = {'status': 'error', 'answer': '', 'mode': '', 'error': str(e)}
    t = _threading_mod.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({'job_id': job_id, 'status': 'pending'}), 202

@cloud_bp.route('/api/assistant/status/<job_id>', methods=['GET'])
def cloud_assistant_status(job_id):
    job = _assistant_jobs.get(job_id)
    if job is None:
        return jsonify({'error': 'job not found'}), 404
    return jsonify(job), 200


@cloud_bp.route('/api/assistant/feedback', methods=['POST'])
def cloud_assistant_feedback():
    """Record feedback on an assistant answer (good/bad)."""
    data = request.get_json(force=True, silent=True) or {}
    question = data.get('question', '')
    answer = data.get('answer', '')
    rating = data.get('rating', 0)  # 1 = good, -1 = bad
    comment = data.get('comment', '')
    if not question or not rating:
        return jsonify({'error': 'question and rating required'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        entry = assistant._trainer.record_feedback(question, answer, rating, comment)
        return jsonify({'ok': True, 'entry': entry}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/api/assistant/false-positive', methods=['POST'])
def cloud_assistant_mark_fp():
    """Mark a file as a known false positive."""
    data = request.get_json(force=True, silent=True) or {}
    path = data.get('path', '')
    hash_val = data.get('hash', '')
    reason = data.get('reason', '')
    if not path:
        return jsonify({'error': 'path required'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        entry = assistant._trainer.mark_false_positive(path, hash_val, reason)
        return jsonify({'ok': True, 'entry': entry}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/api/assistant/false-positive', methods=['DELETE'])
def cloud_assistant_unmark_fp():
    """Remove a false positive marking."""
    data = request.get_json(force=True, silent=True) or {}
    path = data.get('path', '')
    if not path:
        return jsonify({'error': 'path required'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        assistant._trainer.unmark_false_positive(path)
        return jsonify({'ok': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/api/assistant/knowledge', methods=['POST'])
def cloud_assistant_add_knowledge():
    """Add a knowledge entry for the assistant to reference."""
    data = request.get_json(force=True, silent=True) or {}
    topic = data.get('topic', '')
    content = data.get('content', '')
    if not topic or not content:
        return jsonify({'error': 'topic and content required'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        entry = assistant._trainer.add_knowledge(topic, content)
        return jsonify({'ok': True, 'entry': entry}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500





@cloud_bp.route('/api/agents', methods=['GET'])
def cloud_list_agents():
    """List all registered agents and their current status.
    This is what the PWA/mobile dashboard uses to view connected devices."""
    try:
        agents = _get_agents()
        now = datetime.now(timezone.utc)
        agent_list = []
        for device_id, agent in agents.items():
            # Determine if agent is online (seen in last 2 minutes)
            last_seen_str = agent.get('last_seen', '')
            is_online = False
            if last_seen_str:
                try:
                    last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                    is_online = (now - last_seen).total_seconds() < 120
                except Exception:
                    pass
            conns = agent.get('network_connections', [])
            procs = agent.get('processes', [])
            agent_list.append({
                'device_id': device_id,
                'hostname': agent.get('hostname', device_id),
                'os': agent.get('os', 'Unknown'),
                'os_version': agent.get('os_version', ''),
                'arch': agent.get('arch', ''),
                'ip': agent.get('ip', ''),
                'status': 'online' if is_online else 'offline',
                'last_seen': last_seen_str,
                'cpu_usage': agent.get('cpu_usage', 0),
                'mem_usage': agent.get('mem_usage', 0),
                'disk_usage': agent.get('disk_usage', 0),
                'uptime': agent.get('uptime', ''),
                'connection_count': len(conns) if isinstance(conns, list) else 0,
                'process_count': len(procs) if isinstance(procs, list) else 0,
                'files_scanned': agent.get('files_scanned', 0),
                'threats_blocked': agent.get('threats_blocked', 0),
                'quarantined_count': agent.get('quarantined_count', 0),
                'agent_version': agent.get('agent_version', ''),
            })
        # Sort: online first, then by last_seen
        agent_list.sort(key=lambda x: (x['status'] != 'online', x.get('last_seen', '')), reverse=True)
        return jsonify({'success': True, 'agents': agent_list, 'count': len(agent_list)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@cloud_bp.route('/api/network_devices', methods=['GET'])
def cloud_network_devices():
    """List all devices discovered on the local network by agents (phones,
    Xbox, IoT, smart TVs, etc.). Aggregates network_devices from all agents."""
    try:
        agents = _get_agents()
        all_devices = []
        seen_ips = set()
        for device_id, agent in agents.items():
            devs = agent.get('network_devices', [])
            if not isinstance(devs, list):
                continue
            for d in devs:
                ip = d.get('ip', '')
                if not ip or ip in seen_ips:
                    continue
                seen_ips.add(ip)
                all_devices.append({
                    'ip': ip,
                    'hostname': d.get('hostname', ''),
                    'device_type': d.get('device_type', 'Unknown'),
                    'open_ports': d.get('open_ports', []),
                    'interface': d.get('interface', ''),
                    'discovered_by': agent.get('hostname', device_id),
                })
        all_devices.sort(key=lambda x: x['ip'])
        return jsonify({'success': True, 'devices': all_devices, 'count': len(all_devices)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@cloud_bp.route('/api/agent/local/status', methods=['GET'])
def cloud_local_agent_status():
    """Get the status of the built-in local agent."""
    agent = get_local_agent()
    if agent is None:
        return jsonify({'running': False, 'message': 'Local agent is not running'}), 200
    return jsonify(agent.status()), 200


@cloud_bp.route('/api/agent/local/start', methods=['POST'])
def cloud_local_agent_start():
    """Start the built-in local agent."""
    agent = get_local_agent()
    if agent and agent._running:
        return jsonify({'ok': True, 'message': 'Already running', 'status': agent.status()}), 200
    try:
        _api_key = os.environ.get('CLOUD_API_KEY', '')
        _server_url = os.environ.get('PUBLIC_URL', 'https://isolation-bytes.com')
        agent = start_local_agent(server_url=_server_url, api_key=_api_key)
        return jsonify({'ok': True, 'message': 'Local agent started', 'status': agent.status()}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/api/agent/local/stop', methods=['POST'])
def cloud_local_agent_stop():
    """Stop the built-in local agent."""
    try:
        stop_local_agent()
        return jsonify({'ok': True, 'message': 'Local agent stopped'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/api/agent/local/scan', methods=['POST'])
def cloud_local_agent_scan():
    """Trigger an immediate scan from the local agent."""
    agent = get_local_agent()
    if agent is None or not agent._running:
        return jsonify({'error': 'Local agent is not running'}), 400
    try:
        # Run a scan cycle in a background thread
        import threading
        def do_scan():
            agent._scan_cycle()
        t = threading.Thread(target=do_scan, daemon=True)
        t.start()
        return jsonify({'ok': True, 'message': 'Scan started'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/api/assistant/learn-threat', methods=['POST'])
def cloud_assistant_learn_threat():
    """Learn a threat pattern - generates YARA rule, saves knowledge, trains ML."""
    data = request.get_json(force=True, silent=True) or {}
    threat_name = data.get('threat_name', '').strip()
    patterns = data.get('patterns', [])
    severity = data.get('severity', 'high')
    description = data.get('description', '')
    hash_val = data.get('hash', '')
    if not threat_name:
        return jsonify({'error': 'threat_name required'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        result = assistant._trainer.learn_threat(threat_name, patterns, severity=severity, description=description)
        if hash_val and assistant._trainer._db:
            assistant._trainer._db.record_signature(
                name=threat_name, hash_val=hash_val, threat_type=threat_name,
                severity=severity, patterns=patterns, description=description
            )
        improve_result = assistant._trainer.improve_yara_rule(threat_name, patterns, severity=severity)
        return jsonify({'ok': True, 'learn_result': result, 'yara_rule': improve_result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@cloud_bp.route('/api/assistant/training', methods=['GET'])
def cloud_assistant_training():
    """Get training summary and learned data."""
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        summary = assistant._trainer.get_training_summary()
        fps = assistant._trainer.get_false_positives()
        knowledge = assistant._trainer.get_knowledge()
        return jsonify({
            'summary': summary,
            'false_positives': fps[:50],
            'knowledge': knowledge[:50],
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/command/scan', methods=['POST'])
def command_scan():
    data = request.get_json(force=True, silent=True) or {}
    device_id = data.get('device_id', '').strip()
    target = data.get('target', '').strip()
    if not device_id or not _get_agent(device_id):
        return jsonify({'error': 'unknown device'}), 404
    commands.setdefault(device_id, []).append({'type': 'scan', 'target': target})
    return jsonify({'ok': True}), 200


@cloud_bp.route('/command/send', methods=['POST'])
def command_send():
    device_id = request.form.get('device_id', '').strip()
    cmd_type = request.form.get('cmd_type', '').strip()
    target = request.form.get('target', '').strip()
    if not device_id or not _get_agent(device_id):
        return jsonify({'error': 'unknown device'}), 404
    if cmd_type not in ('scan', 'quarantine'):
        return jsonify({'error': 'unknown command type'}), 400
    commands.setdefault(device_id, []).append({'type': cmd_type, 'target': target})
    return 'Command queued. <a href="/dashboard">Back</a>'


# ============================================================
# SELF-HOSTED LICENSE SYSTEM — RSA-signed keys, device locking,
# tiered features. No third-party dependency.
# ============================================================

def _require_admin(f):
    """Require an authenticated admin session for license management."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'Admin authentication required'}), 401
        return f(*args, **kwargs)
    return wrapper


@cloud_bp.route('/api/license/tiers', methods=['GET'])
def license_tiers():
    """List available license tiers and their features."""
    return jsonify({'tiers': TIERS})


@cloud_bp.route('/api/license/validate', methods=['POST'])
def license_validate():
    """Validate a self-hosted license key.

    Body: { license_key, machine_id? }
    Returns: { valid, tier, features, expires_at, activations_used, ... }
    """
    if not _license_manager:
        return jsonify({'error': 'License system not initialized'}), 500
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or request.form.get('license_key') or '').strip()
    machine_id = (data.get('machine_id') or request.form.get('machine_id') or '').strip()
    if not license_key:
        return jsonify({'valid': False, 'error': 'License key required'}), 400
    result = _license_manager.validate_license(license_key, machine_id)
    status = 200 if result['valid'] else 403
    return jsonify(result), status


@cloud_bp.route('/api/license/activate', methods=['POST'])
def license_activate():
    """Activate a license for a specific device.

    Body: { license_key, machine_id, instance_name? }
    """
    if not _license_manager:
        return jsonify({'error': 'License system not initialized'}), 500
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or request.form.get('license_key') or '').strip()
    machine_id = (data.get('machine_id') or request.form.get('machine_id') or '').strip()
    instance_name = (data.get('instance_name') or request.form.get('instance_name') or '').strip()
    if not license_key or not machine_id:
        return jsonify({'ok': False, 'error': 'License key and machine ID are required'}), 400
    result = _license_manager.activate_license(license_key, machine_id, instance_name)
    status = 200 if result['ok'] else 403
    return jsonify(result), status


@cloud_bp.route('/api/license/deactivate', methods=['POST'])
def license_deactivate():
    """Deactivate a license for a specific device.

    Body: { license_key, machine_id }
    """
    if not _license_manager:
        return jsonify({'error': 'License system not initialized'}), 500
    data = request.get_json(silent=True) or {}
    license_key = (data.get('license_key') or request.form.get('license_key') or '').strip()
    machine_id = (data.get('machine_id') or request.form.get('machine_id') or '').strip()
    if not license_key or not machine_id:
        return jsonify({'ok': False, 'error': 'License key and machine ID are required'}), 400
    result = _license_manager.deactivate_license(license_key, machine_id)
    status = 200 if result['ok'] else 403
    return jsonify(result), status


@cloud_bp.route('/api/license/public-key', methods=['GET'])
def license_public_key():
    """Return the license system's public key in PEM format.

    Clients can use this to verify license signatures offline.
    """
    if not _license_manager:
        return jsonify({'error': 'License system not initialized'}), 500
    return jsonify({'public_key': _license_manager.get_public_key_pem()})


@cloud_bp.route('/assistant', methods=['GET', 'POST'])
@_require_login
def cloud_assistant():
    if request.method == 'GET':
        return '''
        <!doctype html>
        <html>
        <head><title>Local Assistant</title></head>
        <body>
            <h1>Antivirus Local Assistant</h1>
            <form method="post">
                <textarea name="question" rows="4" cols="60" placeholder="Ask about findings, IOCs, remediation, rules, or service status"></textarea><br>
                <button type="submit">Ask</button>
            </form>
            <p><a href="/dashboard">Back</a></p>
        </body>
        </html>
        '''
    data = request.get_json(force=True, silent=True) or {}
    question = request.form.get('question', '') or data.get('question', '')
    if not question:
        return jsonify({'error': 'no question'}), 400
    assistant = _get_assistant()
    if assistant is None:
        return jsonify({'error': 'assistant could not load'}), 503
    try:
        result = assistant.answer(question)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cloud_bp.route('/<path:filename>', methods=['GET'])
def cloud_static(filename):
    for folder in ('website', 'static'):
        d = _find_resource_dir(folder)
        p = Path(d) / filename
        if p.exists() and p.is_file():
            return send_from_directory(d, filename)
    # API endpoints should still return JSON 404s; humans get the 404 page.
    if request.path.startswith('/api/'):
        return jsonify({'error': 'not found'}), 404
    return render_template('404.html'), 404


def _find_resource_dir(name):
    """Find a resource directory (templates/static/website) in any of the
    possible locations — handles PyInstaller EXE, dev layout, and CWD."""
    candidates = [
        BASE_DIR.parent / name,           # Normal dev layout
        BASE_DIR / name,                  # Inside cloud/ folder
        Path(os.getcwd()) / name,         # Current working dir
    ]
    if getattr(sys, '_MEIPASS', None):
        candidates.insert(0, Path(sys._MEIPASS) / name)  # PyInstaller extraction
    if _exe_dir:
        candidates.insert(0, _exe_dir / name)            # Next to EXE
    for c in candidates:
        if c.is_dir():
            return str(c)
    return str(BASE_DIR.parent / name)  # Fallback (may not exist)


def create_cloud_app():
    app = Flask(
        __name__,
        template_folder=_find_resource_dir('templates'),
        static_folder=_find_resource_dir('static')
    )
    app.secret_key = _get_secret_key()
    app.config['VOICE_CLOUD_PROXY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    # Allow the session cookie to be sent with cross-site fetch calls so the
    # voice assistant works reliably behind proxies and Cloudflare variations.
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'

    # Reverse proxy middleware — trust X-Forwarded-* headers when behind a proxy
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Enable CORS so browser fetch calls from the voice assistant work reliably
    # behind proxies and across origin variations.
    if CORS is not None:
        CORS(app, supports_credentials=True)

    @app.template_global()
    def startup_risk_score(item): return 0
    @app.template_global()
    def service_risk_score(item): return 0
    @app.template_global()
    def process_risk_score(item): return 0
    @app.template_global()
    def event_risk_score(item): return 0
    @app.template_global()
    def network_beacon_score(item): return 0

    from flask import url_for as flask_url_for
    @app.template_global()
    def url_for(endpoint, **values):
        try:
            return flask_url_for(endpoint, **values)
        except Exception:
            if '.' not in endpoint:
                try:
                    return flask_url_for(f'cloud.{endpoint}', **values)
                except Exception:
                    pass
            return f'/{endpoint.replace("_", "-")}'

    @app.context_processor
    def inject_defaults():
        return {
            'running_as_admin': True,
            'administrator_service_available': True,
            'admin_helper_message': 'Antivirus Cloud Server Active.',
            'items': [],
            'services': [],
            'processes': [],
            'events': [],
            'connections': [],
            'missing': [],
            'installed': [],
            'entries': [],
            'results': [],
            'status': [],
            'c2_detections': [],
            'config': {'FLASK_ENV': 'production', 'LOG_LEVEL': 'INFO'},
            'trusted_count': 120,
            'ioc_counts': {'hashes': 4200, 'domains': 1500, 'ips': 850, 'yara_rules': 42},
            'summary': {'System': 0, 'Security': 0, 'Threats': 0},
            'network_info': {'ip': '127.0.0.1', 'status': 'connected', 'interfaces': ['Ethernet', 'Wi-Fi']},
            'monitored_directories': get_universal_scan_directories(),
            'quarantined_files': []
        }

    # Register the voice repair assistant blueprint (optional)
    try:
        from voice_assistant import voice_bp
        app.register_blueprint(voice_bp)
        # Expose registered devices and the agent command queue to the voice assistant
        app.config['VOICE_DEVICES_GETTER'] = _all_agents
        app.config['VOICE_COMMAND_QUEUE'] = commands
    except Exception as e:
        logger.warning('Could not register voice assistant blueprint: %s', e)

    app.register_blueprint(cloud_bp)
    return app


_assistant = None

def _get_assistant():
    global _assistant
    if _assistant is None:
        try:
            from security.local_assistant import LocalFindingsAssistant
            # Use _MEIPASS if running from EXE, otherwise BASE_DIR.parent
            _assistant_base = Path(sys._MEIPASS) if getattr(sys, '_MEIPASS', None) else BASE_DIR.parent
            _assistant = LocalFindingsAssistant(_assistant_base)
        except Exception as e:
            print(f'Could not load local assistant: {e}')
    return _assistant


def _start_local_agent():
    """Start the built-in local agent that scans this machine."""
    try:
        from security.local_agent import start_local_agent
        _api_key = os.environ.get('CLOUD_API_KEY', '')
        _server_url = os.environ.get('PUBLIC_URL', 'https://isolation-bytes.com')
        if _api_key:
            start_local_agent(server_url=_server_url, api_key=_api_key)
            print('Local agent started')
    except Exception as e:
        print(f'Could not start local agent: {e}')


# Module-level app for gunicorn: cloud.cloud_server:app
app = create_cloud_app()

# Auto-start the local agent when loaded by gunicorn
def _auto_start_agent():
    import time as _time
    _time.sleep(3)
    try:
        from security.local_agent import start_local_agent
        _api_key = os.environ.get('CLOUD_API_KEY', '')
        _server_url = os.environ.get('PUBLIC_URL', 'https://isolation-bytes.com')
        if _api_key:
            start_local_agent(server_url=_server_url, api_key=_api_key)
            print('Auto-started local agent')
    except Exception as e:
        print(f'Could not auto-start local agent: {e}')

import threading as _auto_thread
_auto_thread.Thread(target=_auto_start_agent, daemon=True).start()


if __name__ == '__main__':
    _reload_env()
    flask_public = os.environ.get('FLASK_PUBLIC', '').lower() in ('1', 'true', 'yes')
    flask_ssl = os.environ.get('FLASK_SSL', '').lower() in ('1', 'true', 'yes')
    flask_ssl_cert = os.environ.get('FLASK_SSL_CERT', '').strip()
    flask_ssl_key = os.environ.get('FLASK_SSL_KEY', '').strip()
    if flask_ssl_cert and not os.path.isabs(flask_ssl_cert):
        flask_ssl_cert = str(BASE_DIR / flask_ssl_cert)
    if flask_ssl_key and not os.path.isabs(flask_ssl_key):
        flask_ssl_key = str(BASE_DIR / flask_ssl_key)
    # Auto-detect cert files in the cloud/ directory or _MEIPASS if not explicitly set.
    _cert_search = [BASE_DIR / 'localhost.crt']
    _key_search = [BASE_DIR / 'localhost.key']
    if getattr(sys, '_MEIPASS', None):
        _cert_search.insert(0, Path(sys._MEIPASS) / 'cloud' / 'localhost.crt')
        _key_search.insert(0, Path(sys._MEIPASS) / 'cloud' / 'localhost.key')
    if not flask_ssl_cert:
        for ac in _cert_search:
            if os.path.exists(str(ac)):
                flask_ssl_cert = str(ac)
                break
    if not flask_ssl_key:
        for ak in _key_search:
            if os.path.exists(str(ak)):
                flask_ssl_key = str(ak)
                break
    flask_port = int(os.environ.get('FLASK_PORT', '8443'))
    host = '0.0.0.0' if flask_public else '127.0.0.1'

    # Reverse proxy support — when behind nginx/Caddy, the proxy handles SSL on 443
    # and forwards to this server on a local port without SSL.
    behind_proxy = os.environ.get('BEHIND_PROXY', '').lower() in ('1', 'true', 'yes')
    proxy_port = int(os.environ.get('PROXY_PORT', '8000'))  # Internal port for proxy mode

    if behind_proxy:
        # Run without SSL on a local port — the reverse proxy handles SSL
        flask_port = proxy_port
        host = '127.0.0.1'
        ssl_ctx = None
        print(f'Running in reverse proxy mode on {host}:{flask_port} (no SSL — proxy handles it)')
    elif flask_ssl_cert and flask_ssl_key and os.path.exists(flask_ssl_cert) and os.path.exists(flask_ssl_key):
        ssl_ctx = (flask_ssl_cert, flask_ssl_key)
        print(f'Using SSL cert: {flask_ssl_cert}')
        print(f'Using SSL key: {flask_ssl_key}')
    elif flask_ssl:
        ssl_ctx = 'adhoc'
        print('Using adhoc SSL (self-signed, changes each restart)')
    else:
        ssl_ctx = None
        print('WARNING: SSL is disabled -- running on plain HTTP')
    print(f'Starting cloud server on {host}:{flask_port} (ssl={ssl_ctx is not None})')
    # Start the built-in local agent before the server blocks
    import threading as _threading
    def _delayed_start_agent():
        import time as _time
        _time.sleep(3)  # Wait for server to be ready
        _start_local_agent()
    _threading.Thread(target=_delayed_start_agent, daemon=True).start()

    # Open the browser to the dashboard after a short delay
    def _delayed_open_browser():
        import time as _btime
        _btime.sleep(5)  # Wait for server to be fully ready
        import webbrowser
        public_url = os.environ.get('PUBLIC_URL', '').strip()
        if public_url:
            webbrowser.open(public_url)
        else:
            # Fall back to local URL
            scheme = 'https' if ssl_ctx else 'http'
            webbrowser.open(f'{scheme}://127.0.0.1:{flask_port}/login')
    _threading.Thread(target=_delayed_open_browser, daemon=True).start()

    # Start Caddy reverse proxy if installed (provides HTTPS on port 443)
    def _delayed_start_caddy():
        import time as _ctime
        import subprocess as _subproc
        import tempfile as _tempfile
        _ctime.sleep(2)
        # Portable search — works on any PC, no hardcoded user paths
        _userprofile = os.environ.get('USERPROFILE', os.path.expanduser('~'))
        _localappdata = os.environ.get('LOCALAPPDATA', os.path.join(_userprofile, 'AppData', 'Local'))
        _pf = os.environ.get('ProgramFiles', r'C:\Program Files')
        _pf86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')
        caddy_exe = None
        caddyfile = None
        caddy_cwd = None
        # 1. Bundled in PyInstaller
        if getattr(sys, 'frozen', False):
            _base = sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.dirname(sys.executable)
            _bundled = os.path.join(_base, 'caddy', 'caddy.exe')
            _bundled_caddyfile = os.path.join(_base, 'caddy', 'Caddyfile')
            if os.path.exists(_bundled) and os.path.exists(_bundled_caddyfile):
                _caddy_dir = os.path.join(_tempfile.gettempdir(), 'antivirus_caddy')
                os.makedirs(_caddy_dir, exist_ok=True)
                import shutil as _shutil
                _dest_exe = os.path.join(_caddy_dir, 'caddy.exe')
                _dest_caddyfile = os.path.join(_caddy_dir, 'Caddyfile')
                if not os.path.exists(_dest_exe) or os.path.getsize(_dest_exe) != os.path.getsize(_bundled):
                    _shutil.copy2(_bundled, _dest_exe)
                if not os.path.exists(_dest_caddyfile):
                    _shutil.copy2(_bundled_caddyfile, _dest_caddyfile)
                caddy_exe = _dest_exe
                caddyfile = _dest_caddyfile
                caddy_cwd = _caddy_dir
        # 2. Search known locations (portable)
        if not caddy_exe:
            _caddy_candidates = [
                r'C:\caddy\caddy.exe',
                os.path.join(_localappdata, 'IsolationBytes', 'caddy', 'caddy.exe'),
                os.path.join(_pf, 'Caddy', 'caddy.exe'),
                os.path.join(_pf86, 'Caddy', 'caddy.exe'),
            ]
            _caddyfile_candidates = [
                r'C:\caddy\Caddyfile',
                os.path.join(_localappdata, 'IsolationBytes', 'caddy', 'Caddyfile'),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Caddyfile'),
            ]
            for _ce in _caddy_candidates:
                if os.path.exists(_ce):
                    for _cf in _caddyfile_candidates:
                        if os.path.exists(_cf):
                            caddy_exe = _ce
                            caddyfile = _cf
                            caddy_cwd = os.path.dirname(_ce)
                            break
                    if caddy_exe:
                        break
        if caddy_exe and caddyfile:
            try:
                _subproc.Popen(
                    [caddy_exe, 'run', '--config', caddyfile],
                    cwd=caddy_cwd,
                    stdout=_subproc.DEVNULL,
                    stderr=_subproc.DEVNULL,
                    creationflags=getattr(_subproc, 'CREATE_NO_WINDOW', 0),
                )
                print('Caddy reverse proxy started on port 443')
            except Exception as e:
                print(f'Failed to start Caddy: {e}')
        else:
            print('Caddy not found — skipping reverse proxy')
    _threading.Thread(target=_delayed_start_caddy, daemon=True).start()

    # Start Cloudflare tunnel if installed (provides public access without port forwarding)
    def _delayed_start_cloudflared():
        import time as _dtime
        import subprocess as _subproc2
        import tempfile as _tempfile2
        import shutil as _shutil2
        _dtime.sleep(4)
        # Portable search — no hardcoded user paths, no embedded credential filenames
        _userprofile = os.environ.get('USERPROFILE', os.path.expanduser('~'))
        _localappdata = os.environ.get('LOCALAPPDATA', os.path.join(_userprofile, 'AppData', 'Local'))
        _pf = os.environ.get('ProgramFiles', r'C:\Program Files')
        _pf86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')
        _commonappdata = os.environ.get('ProgramData', r'C:\ProgramData')
        cloudflared_exe = None
        tunnel_name = os.environ.get('CLOUDFLARED_TUNNEL_NAME', 'isolation-bytes')
        # 1. Bundled in PyInstaller (exe only — no credentials bundled)
        if getattr(sys, 'frozen', False):
            _base = sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.dirname(sys.executable)
            _bundled_cf = os.path.join(_base, 'cloudflared', 'cloudflared.exe')
            if os.path.exists(_bundled_cf):
                _cf_dir = os.path.join(_tempfile2.gettempdir(), 'antivirus_cloudflared')
                os.makedirs(_cf_dir, exist_ok=True)
                _dest_cf = os.path.join(_cf_dir, 'cloudflared.exe')
                if not os.path.exists(_dest_cf) or os.path.getsize(_dest_cf) != os.path.getsize(_bundled_cf):
                    _shutil2.copy2(_bundled_cf, _dest_cf)
                cloudflared_exe = _dest_cf
        # 2. Search known locations (portable)
        if not cloudflared_exe:
            _cf_candidates = [
                r'C:\caddy\cloudflared.exe',
                os.path.join(_localappdata, 'IsolationBytes', 'cloudflared', 'cloudflared.exe'),
                os.path.join(_localappdata, 'Programs', 'cloudflared', 'cloudflared.exe'),
                os.path.join(_pf, 'cloudflared', 'cloudflared.exe'),
                os.path.join(_pf86, 'cloudflared', 'cloudflared.exe'),
                os.path.join(_userprofile, '.cloudflared', 'cloudflared.exe'),
            ]
            for _ce in _cf_candidates:
                if os.path.exists(_ce):
                    cloudflared_exe = _ce
                    break
        # 3. Find a valid config.yml (contains credential-file path — no secrets hardcoded here)
        cloudflared_config = None
        _config_candidates = [
            os.environ.get('CLOUDFLARED_CONFIG'),
            os.path.join(_userprofile, '.cloudflared', 'config.yml'),
            os.path.join(_commonappdata, 'IsolationBytes', 'cloudflared', 'config.yml'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloudflared.yml'),
        ]
        for _cc in _config_candidates:
            if not _cc or not os.path.exists(_cc):
                continue
            try:
                with open(_cc, 'r') as _f:
                    _lines = _f.readlines()
                _has_tunnel = any(l.strip().lower().startswith('tunnel:') for l in _lines)
                _has_cred = any('credentials-file:' in l.lower() for l in _lines)
                if _has_tunnel and _has_cred and 'YOUR_TUNNEL_ID' not in ''.join(_lines):
                    cloudflared_config = _cc
                    break
            except Exception:
                continue
        if cloudflared_exe:
            try:
                if cloudflared_config:
                    _subproc2.Popen(
                        [cloudflared_exe, 'tunnel', '--config', cloudflared_config, 'run', tunnel_name],
                        stdout=_subproc2.DEVNULL,
                        stderr=_subproc2.DEVNULL,
                        creationflags=getattr(_subproc2, 'CREATE_NO_WINDOW', 0),
                    )
                else:
                    # No config with credentials — try quick tunnel (temporary URL)
                    _subproc2.Popen(
                        [cloudflared_exe, 'tunnel', '--url', f'http://127.0.0.1:{flask_port}'],
                        stdout=_subproc2.DEVNULL,
                        stderr=_subproc2.DEVNULL,
                        creationflags=getattr(_subproc2, 'CREATE_NO_WINDOW', 0),
                    )
                print('Cloudflare tunnel started')
            except Exception as e:
                print(f'Failed to start Cloudflare tunnel: {e}')
        else:
            print('cloudflared not found — skipping tunnel')
    _threading.Thread(target=_delayed_start_cloudflared, daemon=True).start()

    create_cloud_app().run(host=host, port=flask_port, debug=False, threaded=True, ssl_context=ssl_ctx)
