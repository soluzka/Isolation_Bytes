"""Runtime enforcement for dashboard network-suspicion warnings.

The normal manual firewall API rejects private/LAN addresses by design. A
connection already classified by the dashboard warning path is different: it
must be enforceable at the exact remote IP:port that produced the warning.
This module is explicitly started by the packaged standalone-agent entrypoint,
so enforcement does not depend on Python's optional ``sitecustomize`` startup
hook being loaded.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time

import psutil

logger = logging.getLogger("isolation_bytes.warning_enforcer")

_COMMON_REMOTE_PORTS = {
    80, 443, 53, 123, 22, 21, 25, 110, 143, 993, 995, 587, 3389, 8080, 8443
}
_BROWSER_PROCESSES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "brave.exe", "opera.exe"
}
_KNOWN_SUSPICIOUS_PORTS = {1024, 1080, 1337, 4444, 5555, 6666, 9001, 9030, 31337}
_STARTED = False


def is_warning_candidate(ip, port, process_name=None):
    """Return True for endpoints that match the dashboard warning heuristic."""
    if not ip or not port:
        return False
    try:
        port_value = int(port)
        addr = ipaddress.ip_address(str(ip))
    except (TypeError, ValueError):
        return False

    if addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False

    normalized_process = (str(process_name or "").strip().lower())
    if port_value in _KNOWN_SUSPICIOUS_PORTS:
        return True
    if port_value in _COMMON_REMOTE_PORTS:
        return False
    return normalized_process in _BROWSER_PROCESSES


def _block_warning_connection(ip, port, program=None, pid=None, reason=""):
    """Create and verify an exact outbound firewall rule for a warned endpoint."""
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
        candidate = os.path.abspath(str(program).strip())
        if os.path.isfile(candidate):
            program_path = candidate

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
                if not ip or not port:
                    continue

                pid = getattr(conn, "pid", None)
                program = None
                process_name = "unknown"
                if pid:
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name()
                        if process_name.lower() in _BROWSER_PROCESSES:
                            try:
                                program = process.exe()
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                                program = None
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        pass

                if not is_warning_candidate(ip, port, process_name):
                    continue

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


def start_warning_enforcement():
    """Start the detector-driven firewall enforcement loop once per process."""
    global _STARTED
    if _STARTED:
        return False
    _STARTED = True
    thread = threading.Thread(
        target=_warning_enforcement_loop,
        name="isolation-bytes-warning-enforcer",
        daemon=True,
    )
    thread.start()
    logger.info("Dashboard warning firewall enforcement started")
    return True
