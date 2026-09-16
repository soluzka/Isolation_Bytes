"""Isolation Bytes startup enforcement hook.

The dashboard warning detector can flag a suspicious remote endpoint even when
that endpoint is on the local/private network. The normal manual firewall API
intentionally rejects private addresses, so warning enforcement uses the same
verified Windows Firewall primitives directly while remaining scoped to the
exact remote IP:port that triggered the warning.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import psutil
import threading
import time

logger = logging.getLogger("isolation_bytes.warning_enforcer")
_COMMON_REMOTE_PORTS = {80, 443, 53, 123, 22, 21, 25, 110, 143, 993, 995, 587, 3389, 8080, 8443}
_STARTED = False


def _warning_candidate(ip, port):
    """Accept public or LAN endpoints, but never loopback/link-local/reserved addresses."""
    if not ip or not port:
        return False
    try:
        port_value = int(port)
        addr = ipaddress.ip_address(str(ip))
    except (TypeError, ValueError):
        return False
    if port_value in _COMMON_REMOTE_PORTS:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _block_warning_connection(ip, port, program=None, pid=None, reason=""):
    """Create and verify an exact outbound firewall rule for a warned endpoint.

    This deliberately uses network_blocking's verified rule/state helpers rather
    than its general public-IP validator, because a detector-confirmed LAN
    endpoint such as 192.168.1.192:8009 must still be enforceable.
    """
    from network_blocking import (
        _connection_rule_name,
        _firewall_rule_exists,
        _load_state,
        _save_state,
        _verified_add_rule,
    )

    ip = str(ip).strip()
    port = int(port)
    program_path = None
    if program:
        program = str(program).strip()
        if program and os.path.isfile(os.path.abspath(program)):
            program_path = os.path.abspath(program)

    rule_name = _connection_rule_name(ip, port, program_path)
    state = _load_state()
    existing = state.get("connections", {}).get(rule_name)
    if existing:
        verified, verify_message = _firewall_rule_exists(rule_name)
        if verified:
            return True, f"Connection already blocked by verified firewall rule {rule_name}"
        state.get("connections", {}).pop(rule_name, None)
        _save_state(state)
        logger.warning("Removing stale warning-enforcement state for %s: %s", rule_name, verify_message)

    args = [
        "add", "rule", f"name={rule_name}", "dir=out", "action=block",
        "enable=yes", "profile=any", f"remoteip={ip}", f"remoteport={port}",
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
        "pid": int(pid) if pid is not None else None,
        "reason": reason or "dashboard suspicious connection warning",
        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if not _save_state(state):
        logger.error("Firewall rule %s is active but block state persistence failed", rule_name)
        return True, f"Firewall rule {rule_name} verified; local block state persistence failed"
    return True, f"Blocked and verified warning endpoint {ip}:{port}"


def _warning_enforcement_loop():
    while True:
        try:
            for conn in psutil.net_connections(kind="inet"):
                remote = getattr(conn, "raddr", None)
                ip = getattr(remote, "ip", None)
                port = getattr(remote, "port", None)
                if not _warning_candidate(ip, port):
                    continue

                pid = getattr(conn, "pid", None)
                program = None
                process_name = "unknown"
                if pid:
                    try:
                        process = psutil.Process(pid)
                        program = process.exe()
                        process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        pass

                ok, message = _block_warning_connection(
                    ip,
                    int(port),
                    program=program,
                    pid=pid,
                    reason=(
                        f"Dashboard warning: suspicious/non-standard remote endpoint "
                        f"{ip}:{int(port)} from {process_name}"
                    ),
                )
                if ok:
                    logger.warning("Dashboard warning enforced: %s:%s (%s)", ip, port, message)
                else:
                    logger.error("Dashboard warning could not be blocked: %s:%s (%s)", ip, port, message)
        except Exception as exc:
            logger.exception("Warning enforcement loop error: %s", exc)
        time.sleep(2)


def _start_warning_enforcement():
    global _STARTED
    if _STARTED:
        return
    _STARTED = True
    thread = threading.Thread(
        target=_warning_enforcement_loop,
        name="isolation-bytes-warning-enforcer",
        daemon=True,
    )
    thread.start()


_start_warning_enforcement()
