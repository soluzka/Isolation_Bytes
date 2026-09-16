"""Isolation Bytes startup enforcement hook.

This module is loaded automatically by Python's ``site`` initialization when
this repository is the active Python environment. It closes the gap between
an uncommon external connection being reported by the dashboard warning and
the verified Windows Firewall enforcement path.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time

logger = logging.getLogger("isolation_bytes.warning_enforcer")
_COMMON_REMOTE_PORTS = {80, 443, 53, 123, 22, 21, 25, 110, 143, 993, 995, 587, 3389, 8080, 8443}
_STARTED = False


def _public_uncommon_connection(ip, port):
    if not ip or not port or int(port) in _COMMON_REMOTE_PORTS:
        return False
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _warning_enforcement_loop():
    try:
        import psutil
        from network_blocking import block_connection, list_blocked_ips
    except Exception as exc:
        logger.warning("Warning enforcement unavailable: %s", exc)
        return

    while True:
        try:
            blocked = list_blocked_ips()
            for conn in psutil.net_connections(kind="inet"):
                remote = getattr(conn, "raddr", None)
                ip = getattr(remote, "ip", None)
                port = getattr(remote, "port", None)
                if not _public_uncommon_connection(ip, port) or ip in blocked:
                    continue

                pid = getattr(conn, "pid", None)
                program = None
                if pid:
                    try:
                        program = psutil.Process(pid).exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        program = None

                ok, message = block_connection(
                    ip,
                    int(port),
                    program=program,
                    pid=pid,
                    reason=f"Dashboard warning: suspicious uncommon external connection {ip}:{int(port)}",
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
