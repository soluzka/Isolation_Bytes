"""Windows Firewall outbound/inbound IP blocking with safe validation.

Automatic blocking is deliberately gated on a *confirmed* C2 assessment rather
than a weak port-only heuristic. Manual calls to block_ip remain available.
"""
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Mapping, Optional

NETSH_PATH = shutil.which('netsh') or 'netsh'
logger = logging.getLogger('network_blocking')
_STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocked_ips.json')
_RULE_PREFIX = 'AV_Block_'


def _rule_name(ip):
    return f'{_RULE_PREFIX}{ip}'


def _load_state():
    if os.path.exists(_STATE_PATH):
        try:
            with open(_STATE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning('Could not read %s: %s', _STATE_PATH, exc)
    return {}


def _save_state(state):
    try:
        directory = os.path.dirname(_STATE_PATH)
        os.makedirs(directory, exist_ok=True)
        temp_path = _STATE_PATH + '.tmp'
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, sort_keys=True)
        os.replace(temp_path, _STATE_PATH)
        return True
    except OSError as exc:
        logger.error('Could not write %s: %s', _STATE_PATH, exc)
        return False


def _validate_blockable_ip(ip):
    """Return (valid, error), rejecting malformed and local/reserved addresses."""
    if not isinstance(ip, str) or not ip.strip():
        return False, 'IP address must be a non-empty string'
    value = ip.strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False, f'{value!r} is not a valid IP address'
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False, f'Refusing to block {value}: it is a local/reserved address'
    return True, None


def _run_netsh(args):
    try:
        result = subprocess.run(
            [NETSH_PATH, 'advfirewall', 'firewall'] + list(args),
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=0x08000000 if os.name == 'nt' else 0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f'Failed to run Windows Firewall command: {exc}'

    combined = f'{result.stdout}\n{result.stderr}'.strip()
    if result.returncode == 0:
        return True, combined or 'OK'
    lowered = combined.lower()
    if any(token in lowered for token in ('access is denied', 'elevation', 'requires elevation', 'requested operation requires elevation')):
        return False, 'Blocking requires the app to run as Administrator.'
    return False, f'netsh failed: {combined or "unknown error"}'


def block_ip(ip, reason=''):
    """Block outbound traffic to an externally routable IP."""
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    ip = ip.strip()
    state = _load_state()
    existing = state.get(ip)
    if existing and existing.get('outbound', True):
        return True, f'{ip} is already blocked'

    ok, msg = _run_netsh([
        'add', 'rule',
        f'name={_rule_name(ip)}',
        'dir=out', 'action=block', 'enable=yes',
        'profile=any', f'remoteip={ip}',
    ])
    if not ok:
        return False, msg

    state[ip] = {
        'reason': reason or 'manual block',
        'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'outbound': True,
        'inbound': bool(existing and existing.get('inbound')),
    }
    if not _save_state(state):
        # Do not claim a durable block-list state if persistence failed. The
        # firewall rule itself is still active, so report that accurately.
        return True, f'Blocked {ip}; warning: local block state could not be saved'
    logger.warning('Blocked outbound connections to %s (%s)', ip, reason or 'manual block')
    return True, f'Blocked {ip}'


def unblock_ip(ip):
    """Remove both inbound and outbound firewall rules for an IP."""
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    ip = ip.strip()
    errors = []
    for suffix in ('', '_in'):
        ok, msg = _run_netsh(['delete', 'rule', f'name={_rule_name(ip)}{suffix}'])
        if not ok and 'not found' not in msg.lower() and 'no rules match' not in msg.lower():
            errors.append(msg)
    if errors:
        return False, errors[0]
    state = _load_state()
    state.pop(ip, None)
    _save_state(state)
    return True, f'Unblocked {ip}'


def list_blocked_ips():
    return _load_state()


def block_ip_inbound(ip, reason=''):
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    ip = ip.strip()
    state = _load_state()
    if state.get(ip, {}).get('inbound'):
        return True, f'{ip} is already inbound-blocked'

    ok, msg = _run_netsh([
        'add', 'rule', f'name={_rule_name(ip)}_in',
        'dir=in', 'action=block', 'enable=yes', 'profile=any', f'remoteip={ip}',
    ])
    if not ok:
        return False, msg
    state.setdefault(ip, {'reason': reason or 'inbound block', 'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')})
    state[ip]['inbound'] = True
    state[ip]['outbound'] = bool(state[ip].get('outbound', False))
    _save_state(state)
    logger.warning('Blocked inbound traffic from %s (%s)', ip, reason or 'manual block')
    return True, f'Blocked inbound from {ip}'


def block_outbound_port(port, reason=''):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return False, f'Invalid port: {port!r}'
    rule = f'AV_BlockPort_{port}'
    state = _load_state()
    if state.get(rule):
        return True, f'Port {port} is already blocked'
    ok, msg = _run_netsh([
        'add', 'rule', f'name={rule}', 'dir=out', 'action=block',
        'enable=yes', 'profile=any', 'protocol=any', f'localport={port}',
    ])
    if not ok:
        return False, msg
    state[rule] = {'port': port, 'reason': reason or 'manual port block', 'blocked_at': time.strftime('%Y-%m-%d %H:%M:%S')}
    _save_state(state)
    return True, f'Blocked outbound port {port}'


def should_auto_block_ip(ip, *, threat_level=None, confirmed_c2=False, confidence=None, min_level='high'):
    """Return True only for a valid external IP with confirmed C2 evidence.

    A boolean ``confirmed_c2`` is required unless an assessment mapping is
    supplied. This prevents the old uncommon-port heuristic from becoming an
    automatic firewall action.
    """
    valid, _ = _validate_blockable_ip(ip)
    if not valid:
        return False
    if confirmed_c2:
        return True
    if isinstance(threat_level, Mapping):
        level = str(threat_level.get('level', '')).lower()
        score = float(threat_level.get('score', 0.0) or 0.0)
        return level in {'critical', 'high'} and score >= 0.65
    if confidence is not None:
        try:
            return float(confidence) >= 0.90
        except (TypeError, ValueError):
            return False
    return False


def auto_block_confirmed_c2(ip, *, threat_level=None, confidence=None, reason='confirmed C2'):
    """Convenience gate for the agent/network monitor."""
    if not should_auto_block_ip(ip, threat_level=threat_level, confidence=confidence, confirmed_c2=True):
        return False, 'C2 confirmation threshold not met'
    return block_ip(ip, reason=reason)
