"""Bridge cloud dashboard connection warnings into agent firewall commands.

The cloud C2 dashboard intentionally filtered private/LAN addresses out of its
legacy auto-block path. That prevented a warning such as
``msedge.exe -> 192.168.1.192:8009`` from ever reaching the Windows agent.
This bridge watches the same registered-agent heartbeat data and queues the
existing ``block_ip`` command for any dashboard-warning candidate, including
LAN addresses. The Windows agent performs the actual firewall enforcement.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time

logger = logging.getLogger("isolation_bytes.cloud_warning_bridge")

_COMMON_PORTS = {80, 443, 53, 123, 22, 21, 25, 110, 143, 993, 995, 587, 3389, 8080, 8443}
_BROWSER_PROCESSES = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "brave.exe", "opera.exe"}
_SUSPICIOUS_PORTS = {1024, 1080, 1337, 4444, 5555, 6666, 9001, 9030, 31337}
_STARTED = False


def _candidate(ip, port, process):
    if not ip or not port:
        return False
    try:
        addr = ipaddress.ip_address(str(ip))
        port = int(port)
    except (TypeError, ValueError):
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False
    name = str(process or "").strip().lower()
    if port in _SUSPICIOUS_PORTS:
        return True
    return port not in _COMMON_PORTS and name in _BROWSER_PROCESSES


def _run():
    while True:
        try:
            cloud = __import__("cloud.cloud_server_original", fromlist=["_get_agents", "commands"])
            agents = cloud._get_agents()
            commands = cloud.commands
            blocked = getattr(cloud, "_blocked_ips", set())
            auto_enabled = bool(getattr(cloud, "_auto_block_enabled", True))
            if not auto_enabled:
                time.sleep(2)
                continue

            for device_id, agent in agents.items():
                if str(device_id).startswith("LOCAL-"):
                    continue
                for conn in agent.get("network_connections", []) or []:
                    if not isinstance(conn, dict):
                        continue
                    ip = conn.get("remote_ip")
                    port = conn.get("remote_port")
                    process = conn.get("process") or conn.get("process_name")
                    if not _candidate(ip, port, process):
                        continue
                    if ip in blocked:
                        continue

                    reason = f"Auto-blocked: dashboard warning - Browser on non-standard port {port}" if str(process).lower() in _BROWSER_PROCESSES and int(port) not in _SUSPICIOUS_PORTS else f"Auto-blocked: dashboard suspicious endpoint {ip}:{port}"
                    pending = commands.setdefault(device_id, [])
                    duplicate = any(
                        isinstance(cmd, dict)
                        and cmd.get("action") == "block_ip"
                        and cmd.get("ip") == ip
                        for cmd in pending
                    )
                    if duplicate:
                        continue
                    pending.append({
                        "action": "block_ip",
                        "ip": str(ip),
                        "reason": reason,
                    })
                    try:
                        blocked.add(ip)
                    except Exception:
                        pass
                    logger.warning("Queued warning auto-block for %s: %s:%s (%s)", device_id, ip, port, process)
        except Exception:
            # Cloud module may not be fully imported yet; retry on next pass.
            logger.debug("Cloud warning bridge waiting for runtime agent state", exc_info=True)
        time.sleep(2)


def start():
    global _STARTED
    if _STARTED:
        return False
    _STARTED = True
    threading.Thread(target=_run, name="isolation-bytes-cloud-warning-bridge", daemon=True).start()
    return True
