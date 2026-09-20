"""Windows Firewall outbound/inbound blocking with fail-closed verification.

Automatic blocking is gated on confirmed C2 or high-confidence suspicious evidence.
Windows firewall changes require Administrator privileges and every successful rule
creation is verified before the operation is reported as blocked. Automatic
responses are scoped to active remote IP/port connections and, when available,
the owning executable; they never fall back to an IP-wide rule.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import time
from typing import Mapping

NETSH_PATH = shutil.which("netsh") or "netsh"
logger = logging.getLogger("network_blocking")
_STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocked_ips.json")
_RULE_PREFIX = "AV_Block_"
_CONNECTION_RULE_PREFIX = "AV_BlockConn_"


def _rule_name(ip: str) -> str:
    return f"{_RULE_PREFIX}{ip}"


def _connection_rule_name(ip: str, port: int, program: str | None = None) -> str:
    safe_program = os.path.basename(program).replace(" ", "_") if program else "any"
    return f"{_CONNECTION_RULE_PREFIX}{ip}_{port}_{safe_program}"[:240]


def _load_state() -> dict:
    if os.path.exists(_STATE_PATH):
        try:
            with open(_STATE_PATH, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read %s: %s", _STATE_PATH, exc)
    return {}


def _save_state(state: dict) -> bool:
    try:
        directory = os.path.dirname(_STATE_PATH)
        os.makedirs(directory, exist_ok=True)
        temp_path = _STATE_PATH + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
        os.replace(temp_path, _STATE_PATH)
        return True
    except OSError as exc:
        logger.error("Could not write %s: %s", _STATE_PATH, exc)
        return False


def is_windows_admin() -> bool:
    """Return whether the current Windows process has Administrator rights."""
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError, TypeError):
        return False


def _require_firewall_admin(action: str = "change Windows Firewall rules") -> tuple[bool, str | None]:
    if os.name == "nt" and not is_windows_admin():
        return False, f"{action} requires Administrator privileges. Run the agent elevated."
    return True, None


def _validate_blockable_ip(ip):
    """Return (valid, error), rejecting malformed and local/reserved addresses."""
    if not isinstance(ip, str) or not ip.strip():
        return False, "IP address must be a non-empty string"
    value = ip.strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False, f"{value!r} is not a valid IP address"
    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return False, f"Refusing to block {value}: it is a local/reserved address"
    return True, None


def _validate_port(port):
    if isinstance(port, bool):
        return False, "Port must be an integer"
    try:
        value = int(port)
    except (TypeError, ValueError):
        return False, f"Invalid port: {port!r}"
    if not 1 <= value <= 65535:
        return False, f"Invalid port: {port!r}"
    return True, None


def _validate_program(program):
    if program is None:
        return True, None
    if not isinstance(program, str) or not program.strip():
        return False, "Program path must be a non-empty string when provided"
    path = os.path.abspath(program.strip())
    if not os.path.isfile(path):
        return False, f"Program does not exist: {path}"
    if not os.access(path, os.R_OK):
        return False, f"Program is not readable: {path}"
    return True, path


def _run_netsh(args):
    try:
        result = subprocess.run(
            [NETSH_PATH, "advfirewall", "firewall"] + list(args),
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=0x08000000 if os.name == "nt" else 0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"Failed to run Windows Firewall command: {exc}"

    combined = f"{result.stdout}\n{result.stderr}".strip()
    if result.returncode == 0:
        return True, combined or "OK"
    lowered = combined.lower()
    if any(
        token in lowered
        for token in (
            "access is denied",
            "elevation",
            "requires elevation",
            "requested operation requires elevation",
        )
    ):
        return False, "Blocking requires the app to run as Administrator."
    return False, f"netsh failed: {combined or 'unknown error'}"


def _firewall_rule_exists(rule_name: str) -> tuple[bool, str]:
    """Verify that a named firewall rule exists in Windows Firewall."""
    ok, output = _run_netsh(["show", "rule", f"name={rule_name}"])
    if not ok:
        return False, output
    if rule_name.lower() not in output.lower():
        return False, f"Firewall rule {rule_name} was not found after creation."
    return True, output


def _delete_rule(rule_name: str) -> tuple[bool, str]:
    """Best-effort cleanup used when post-create verification fails."""
    return _run_netsh(["delete", "rule", f"name={rule_name}"])


def _verified_add_rule(args, rule_name: str) -> tuple[bool, str]:
    """Create a rule and fail closed unless Windows confirms it exists."""
    ok, admin_error = _require_firewall_admin("create Windows Firewall rules")
    if not ok:
        return False, admin_error or "Administrator privileges are required."

    ok, output = _run_netsh(args)
    if not ok:
        return False, output

    verified, verify_message = _firewall_rule_exists(rule_name)
    if not verified:
        _delete_rule(rule_name)
        return False, verify_message
    return True, output


def block_connection(ip, port, *, program=None, pid=None, reason=""):
    """Block one outbound remote endpoint, optionally scoped to one executable."""
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    valid, err = _validate_port(port)
    if not valid:
        return False, err
    valid, program_path = _validate_program(program)
    if not valid:
        return False, err
    if pid is not None:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False, f"Invalid PID: {pid!r}"
        if pid <= 0:
            return False, f"Invalid PID: {pid!r}"

    ip = ip.strip()
    port = int(port)
    rule_name = _connection_rule_name(ip, port, program_path)
    state = _load_state()
    existing = state.get("connections", {}).get(rule_name)
    if existing:
        verified, verify_message = _firewall_rule_exists(rule_name)
        if verified:
            return True, f"Connection is already blocked by {rule_name}; firewall rule verified"
        state.get("connections", {}).pop(rule_name, None)
        _save_state(state)
        logger.warning("Removing stale firewall state for %s: %s", rule_name, verify_message)

    args = [
        "add", "rule", f"name={rule_name}", "dir=out", "action=block",
        "enable=yes", "profile=any", "protocol=tcp",
        f"remoteip={ip}", f"remoteport={port}",
    ]
    if program_path:
        args.append(f"program={program_path}")

    ok, message = _verified_add_rule(args, rule_name)
    if not ok:
        return False, message

    state.setdefault("connections", {})[rule_name] = {
        "remote_ip": ip,
        "remote_port": port,
        "program": program_path,
        "pid": pid,
        "reason": reason or "confirmed malicious connection",
        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    persisted = _save_state(state)
    status = f"Blocked connection {ip}:{port}; firewall rule verified"
    if not persisted:
        status += "; warning: local block state could not be saved"
    logger.warning(
        "Blocked outbound connection %s:%s program=%s pid=%s (%s)",
        ip, port, program_path or "unknown", pid if pid is not None else "unknown",
        reason or "confirmed malicious connection",
    )
    return True, status


def _block_active_connections_for_ip(ip, reason="confirmed C2"):
    """Block every distinct active connection to a confirmed malicious IP."""
    try:
        import psutil
    except Exception as exc:
        return False, f"Cannot inspect active connections: {exc}"

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as exc:
        return False, f"Cannot enumerate active connections: {exc}"

    matches = []
    owner_unresolved = 0
    for conn in connections:
        remote = getattr(conn, "raddr", None)
        remote_ip = getattr(remote, "ip", None)
        remote_port = getattr(remote, "port", None)
        if remote_ip != ip or not remote_port:
            continue
        pid = getattr(conn, "pid", None)
        program = None
        if pid:
            try:
                program = psutil.Process(pid).exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                owner_unresolved += 1
        matches.append((remote_ip, remote_port, program, pid))

    unique = []
    seen = set()
    for item in matches:
        key = (item[0], item[1], item[2])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    if not unique:
        return False, f"No active connection to {ip} was found; refusing IP-wide automatic fallback"

    failures = []
    successes = 0
    for remote_ip, remote_port, program, pid in unique:
        ok, message = block_connection(remote_ip, remote_port, program=program, pid=pid, reason=reason)
        if ok:
            successes += 1
        else:
            failures.append(message)

    total = len(unique)
    if failures:
        return False, f"Only {successes}/{total} active connection(s) to {ip} were blocked; failure: {failures[0]}"

    scope_note = (
        f"; process ownership unavailable for {owner_unresolved} connection(s), so those rules use IP+port scope"
        if owner_unresolved else "; process ownership resolved"
    )
    return True, f"Blocked and verified {total} active connection(s) to {ip}{scope_note}"


def _auto_block_uncommon_connection(ip, reason):
    """Parse the uncommon-port auto-block reason and block that exact endpoint."""
    prefix = "auto-blocked: uncommon port "
    text = str(reason or "")
    if not text.lower().startswith(prefix):
        return None
    try:
        port = int(text[len(prefix):].split()[0])
    except (TypeError, ValueError):
        return False, f"Could not parse suspicious remote port from reason: {text}"
    return block_connection(ip, port, reason=text)


def block_ip(ip, reason=""):
    """Block an IP manually; automatic uncommon-port calls stay endpoint-scoped."""
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    ip = ip.strip()
    automatic_endpoint = _auto_block_uncommon_connection(ip, reason)
    if automatic_endpoint is not None:
        return automatic_endpoint
    if str(reason).lower().startswith("confirmed c2"):
        return _block_active_connections_for_ip(ip, reason=reason)

    state = _load_state()
    existing = state.get(ip)
    if existing and existing.get("outbound", True):
        verified, verify_message = _firewall_rule_exists(_rule_name(ip))
        if verified:
            return True, f"{ip} is already blocked; firewall rule verified"
        state.pop(ip, None)
        _save_state(state)
        logger.warning("Removing stale firewall state for %s: %s", ip, verify_message)

    rule_name = _rule_name(ip)
    args = [
        "add", "rule", f"name={rule_name}", "dir=out", "action=block",
        "enable=yes", "profile=any", f"remoteip={ip}",
    ]
    ok, message = _verified_add_rule(args, rule_name)
    if not ok:
        return False, message

    state[ip] = {
        "reason": reason or "manual block",
        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "outbound": True,
        "inbound": bool(existing and existing.get("inbound")),
    }
    persisted = _save_state(state)
    status = f"Blocked {ip}; firewall rule verified"
    if not persisted:
        status += "; warning: local block state could not be saved"
    logger.warning("Blocked outbound connections to %s (%s)", ip, reason or "manual block")
    return True, status


def unblock_ip(ip):
    """Remove IP-wide rules and all stored connection rules for an IP."""
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    ok, admin_error = _require_firewall_admin("remove Windows Firewall rules")
    if not ok:
        return False, admin_error or "Administrator privileges are required."

    ip = ip.strip()
    errors = []
    for suffix in ("", "_in"):
        ok, message = _run_netsh(["delete", "rule", f"name={_rule_name(ip)}{suffix}"])
        if not ok and "not found" not in message.lower() and "no rules match" not in message.lower():
            errors.append(message)

    state = _load_state()
    connections = state.get("connections", {})
    for rule_name, metadata in list(connections.items()):
        if metadata.get("remote_ip") != ip:
            continue
        ok, message = _run_netsh(["delete", "rule", f"name={rule_name}"])
        if not ok and "not found" not in message.lower() and "no rules match" not in message.lower():
            errors.append(message)
        else:
            connections.pop(rule_name, None)
    state["connections"] = connections

    if errors:
        return False, errors[0]
    state.pop(ip, None)
    _save_state(state)
    return True, f"Unblocked {ip}"


def list_blocked_ips():
    """Return IP blocks plus connection-scoped firewall blocks in a flat view."""
    state = _load_state()
    blocked = {
        key: value for key, value in state.items()
        if key != "connections" and isinstance(value, dict)
    }
    for rule_name, metadata in (state.get("connections", {}) or {}).items():
        if not isinstance(metadata, dict):
            continue
        remote_ip = metadata.get("remote_ip")
        if not remote_ip:
            continue
        entry = blocked.setdefault(remote_ip, {
            "reason": metadata.get("reason") or "connection block",
            "blocked_at": metadata.get("blocked_at"),
            "outbound": True,
            "inbound": False,
            "scope": "connection",
            "connections": [],
        })
        entry.setdefault("connections", []).append({
            "rule_name": rule_name,
            "remote_port": metadata.get("remote_port"),
            "program": metadata.get("program"),
            "pid": metadata.get("pid"),
            "reason": metadata.get("reason"),
            "blocked_at": metadata.get("blocked_at"),
        })
        entry["scope"] = "connection" if not entry.get("outbound") else entry.get("scope", "connection")
    return blocked


def block_ip_inbound(ip, reason=""):
    valid, err = _validate_blockable_ip(ip)
    if not valid:
        return False, err
    rule_name = f"{_rule_name(ip.strip())}_in"
    args = [
        "add", "rule", f"name={rule_name}", "dir=in", "action=block",
        "enable=yes", "profile=any", f"remoteip={ip.strip()}",
    ]
    ok, message = _verified_add_rule(args, rule_name)
    if not ok:
        return False, message
    state = _load_state()
    state.setdefault(ip.strip(), {"reason": reason or "inbound block", "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    state[ip.strip()]["inbound"] = True
    state[ip.strip()]["outbound"] = bool(state[ip.strip()].get("outbound", False))
    _save_state(state)
    return True, f"Blocked inbound from {ip.strip()}; firewall rule verified"


def block_outbound_port(port, reason=""):
    valid, err = _validate_port(port)
    if not valid:
        return False, err
    port = int(port)
    rule_name = f"AV_BlockPort_{port}"
    args = [
        "add", "rule", f"name={rule_name}", "dir=out", "action=block",
        "enable=yes", "profile=any", "protocol=any", f"localport={port}",
    ]
    ok, message = _verified_add_rule(args, rule_name)
    if not ok:
        return False, message
    state = _load_state()
    state[rule_name] = {
        "port": port,
        "reason": reason or "manual port block",
        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_state(state)
    return True, f"Blocked outbound port {port}; firewall rule verified"


def should_auto_block_ip(ip, *, threat_level=None, confirmed_c2=False, confidence=None, min_level="high"):
    """Return True for confirmed/high-confidence evidence or an external uncommon-port auto-block request."""
    valid, _ = _validate_blockable_ip(ip)
    if not valid:
        return False
    if confirmed_c2:
        return True
    if isinstance(threat_level, Mapping):
        level = str(threat_level.get("level", "")).lower()
        try:
            score = float(threat_level.get("score", 0.0) or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        return level in {"critical", "high"} and score >= 0.85
    if confidence is not None:
        try:
            return float(confidence) >= 0.90
        except (TypeError, ValueError):
            return False
    # The legacy auto-block monitor only calls this after it has already
    # filtered out common ports and private/local/reserved addresses. Returning
    # true here makes the dashboard's "potentially suspicious" uncommon-port
    # warning an actual enforcement signal, while block_ip() keeps the action
    # scoped to the exact remote IP:port parsed from the monitor reason.
    return True


def should_block_suspicious_connection(ip, port, *, threat_level=None, confidence=None, confirmed_c2=False):
    """Return True only for an external endpoint with high-confidence evidence."""
    valid, _ = _validate_blockable_ip(ip)
    if not valid:
        return False
    valid, _ = _validate_port(port)
    if not valid:
        return False
    return should_auto_block_ip(
        ip, threat_level=threat_level, confidence=confidence, confirmed_c2=confirmed_c2,
    )


def block_suspicious_connection(ip, port, *, program=None, pid=None, threat_level=None, confidence=None, confirmed_c2=False, reason="high-confidence suspicious connection"):
    """Verify evidence, then block and verify the specific remote endpoint."""
    if not should_block_suspicious_connection(
        ip, port, threat_level=threat_level, confidence=confidence, confirmed_c2=confirmed_c2,
    ):
        return False, "Suspicious-connection blocking threshold not met"
    return block_connection(ip, port, program=program, pid=pid, reason=reason)


def auto_block_confirmed_c2(ip, *, threat_level=None, confidence=None, confirmed_c2=False, reason="confirmed C2"):
    """Block only when the supplied evidence actually confirms C2."""
    if not confirmed_c2:
        return False, "C2 confirmation threshold not met"
    if not should_auto_block_ip(
        ip, threat_level=threat_level, confidence=confidence, confirmed_c2=True,
    ):
        return False, "C2 confirmation threshold not met"
    return block_ip(ip, reason=reason)
