"""
Manual and (opt-in) automatic blocking of outbound connections to specific
remote IPs, via Windows Firewall rules (netsh advfirewall).

Design notes:
- Requires the process to be running elevated (Administrator). netsh
  advfirewall rejects rule changes otherwise; block_ip()/unblock_ip() detect
  that specific failure and return a clear, actionable error rather than
  silently doing nothing.
- Blocks are persisted to a JSON state file (blocked_ips.json) so the block
  list survives server restarts and can be listed/reversed later.
- Never blocks loopback/private/link-local addresses -- those are either the
  local machine itself or LAN devices, and firewalling them out could cut off
  legitimate local services (or the user's own network) rather than an
  external threat.
- Auto-blocking (see should_auto_block_ip) is opt-in and off by default: the
  existing C2 heuristic this would drive from (uncommon remote port) is
  explicitly a weak proxy (see get_c2_patterns() in quick_start.py), so
  auto-blocking on it risks cutting off legitimate connections. Manual,
  human-initiated blocking from the dashboard doesn't have that risk since a
  person is making the call on a specific connection they're looking at.
"""
import ipaddress
import json
import logging
import os
import subprocess

logger = logging.getLogger('network_blocking')

_STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocked_ips.json')
_RULE_PREFIX = 'AV_Block_'


def _rule_name(ip):
    return f"{_RULE_PREFIX}{ip}"


def _load_state():
    if os.path.exists(_STATE_PATH):
        try:
            with open(_STATE_PATH, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read {_STATE_PATH}: {e}")
    return {}


def _save_state(state):
    try:
        with open(_STATE_PATH, 'w') as f:
            json.dump(state, f, indent=2)
    except OSError as e:
        logger.error(f"Could not write {_STATE_PATH}: {e}")


def _validate_blockable_ip(ip):
    """Returns (valid, error_message). Refuses to block loopback/private/
    link-local/reserved addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"{ip!r} is not a valid IP address"
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast:
        return False, f"Refusing to block {ip} -- it's loopback/private/link-local/reserved, not an external address"
    return True, None


def block_ip(ip, reason=""):
    """Add a Windows Firewall rule blocking outbound traffic to `ip`.
    Returns (success: bool, message: str)."""
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err

    state = _load_state()
    if ip in state:
        return True, f"{ip} is already blocked"

    try:
        result = subprocess.run(  # nosem; nosec B603
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name={_rule_name(ip)}', 'dir=out', 'action=block', f'remoteip={ip}'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            combined = (result.stdout + result.stderr).strip()
            if 'elevation' in combined.lower():
                return False, ("Blocking requires the app to run as Administrator "
                                "(Windows Firewall rule changes need elevation).")
            return False, f"netsh failed: {combined or 'unknown error'}"
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"Failed to run netsh: {e}"

    import time
    state[ip] = {"reason": reason, "blocked_at": time.strftime('%Y-%m-%d %H:%M:%S')}
    _save_state(state)
    logger.warning(f"Blocked outbound connections to {ip} ({reason})")
    return True, f"Blocked {ip}"


def unblock_ip(ip):
    """Remove the firewall rule blocking `ip`. Returns (success, message)."""
    try:
        result = subprocess.run(  # nosem; nosec B603
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={_rule_name(ip)}'],
            capture_output=True, text=True, timeout=15
        )
        combined = (result.stdout + result.stderr).strip()
        if result.returncode != 0 and 'elevation' in combined.lower():
            return False, "Unblocking requires the app to run as Administrator."
        # netsh returns non-zero if the rule doesn't exist, which is fine here --
        # we still want to drop it from our own state either way.
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"Failed to run netsh: {e}"

    state = _load_state()
    if ip in state:
        del state[ip]
        _save_state(state)
    return True, f"Unblocked {ip}"


def list_blocked_ips():
    """Returns {ip: {reason, blocked_at}} for all currently-tracked blocks."""
    return _load_state()


def should_auto_block_ip(ip):
    """Whether an IP is eligible for automatic blocking. Currently always
    False beyond the basic validity check -- auto-blocking is opt-in and,
    even when enabled (see the auto_block_enabled toggle in quick_start.py),
    should only ever act on signals stronger than the current C2 heuristic.
    Kept as a single choke point so that if/when a real threat-intel feed is
    integrated, this is the one place that needs to change."""
    valid, _ = _validate_blockable_ip(ip)
    return valid
