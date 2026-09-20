"""Shared helper for the live agent/YARA scan results API.

This module is intentionally small and import-safe.  Historical findings stay
in the agent report; the API only limits the number serialized to the browser.
"""
import time

_LAST_COUNTERS = {}
_RESULTS_CACHE = {"at": 0.0, "payload": None}
_RESULTS_CACHE_TTL = 1.5


def _monotonic_counter(device_id, key, report_value, live_value, generation=None):
    try:
        current = max(int(report_value or 0), int(live_value or 0))
    except (TypeError, ValueError):
        current = 0

    state = _LAST_COUNTERS.setdefault(device_id, {})
    if generation and state.get("generation") != generation:
        state.clear()
        state["generation"] = generation

    previous = int(state.get(key, 0) or 0)
    value = max(previous, current)
    state[key] = value
    if generation:
        state["generation"] = generation
    return value


def build_complete_agent_scan_results(legacy, active_scan_state=None):
    """Build a bounded browser payload without deleting historical findings."""
    now = time.monotonic()
    cached = _RESULTS_CACHE.get("payload")
    if cached is not None and now - _RESULTS_CACHE.get("at", 0.0) < _RESULTS_CACHE_TTL:
        return cached

    agents = legacy._all_agents()
    results = []
    total_findings = 0

    for device_id, agent in agents.items():
        report = agent.get("last_report") or {}
        findings = report.get("findings") or report.get("results") or []
        if not isinstance(findings, list):
            findings = []

        scan_id = str(
            agent.get("scan_id")
            or report.get("scan_id")
            or agent.get("scan_started_at")
            or report.get("scan_started_at")
            or ""
        ).strip()

        # A newly active scan owns its own live counter. Never carry the
        # previous completed scan's count into the current scan display.
        if (str(agent.get("scan_status") or report.get("scan_status") or "").lower() == "scanning"):
            files_scanned = int(agent.get("files_scanned", report.get("files_scanned", 0)) or 0)
        else:
            files_scanned = _monotonic_counter(
                device_id,
                "files_scanned",
                report.get("files_scanned", 0),
                agent.get("files_scanned", 0),
                scan_id or None,
            )
        quarantined_count = _monotonic_counter(
            device_id,
            "quarantined_count",
            report.get("quarantined_count", 0),
            agent.get("quarantined_count", 0),
            scan_id or None,
        )

        # A cloud-side scan request is the authoritative start of a new
        # generation, even before the agent publishes its first progress report.
        active_state = (active_scan_state or {}).get(device_id) or {}
        pending_scan = any(
            isinstance(cmd, dict) and cmd.get("action") == "scan_now"
            for cmd in legacy.commands.get(device_id, [])
        )
        active_started = float(active_state.get("started_at", 0) or 0)
        agent_status = str(
            agent.get("scan_status") or report.get("scan_status") or "idle"
        ).lower()
        if active_state and (pending_scan or active_started):
            if agent_status == "idle":
                agent_status = "queued"
        if agent_status in {"queued", "scanning"} and active_started:
            from datetime import datetime, timezone
            live_last_scan = datetime.fromtimestamp(
                active_started, timezone.utc
            ).isoformat()
        else:
            live_last_scan = (
                agent.get("last_scan")
                or report.get("last_scan")
                or report.get("timestamp", "")
            )

        # Keep the normalized live counters available to other in-process
        # routes, while leaving the persisted report/history untouched.
        try:
            agent["files_scanned"] = files_scanned
            agent["quarantined_count"] = quarantined_count
        except Exception:
            pass

        results.append(
            {
                "hostname": agent.get("hostname", device_id),
                "device_id": device_id,
                "files_scanned": files_scanned,
                "finding_count": len(findings),
                "last_scan": live_last_scan,
                "findings": findings[:50],
                "quarantined_count": quarantined_count,
                "scan_id": scan_id,
                "scan_dirs": agent.get("scan_dirs") or report.get("scan_dirs") or [],
                "scan_status": agent_status,
                "scan_current_path": (
                    agent.get("scan_current_path")
                    or report.get("scan_current_path")
                    or ""
                ),
                "scan_started_at": (
                    agent.get("scan_started_at")
                    or report.get("scan_started_at")
                    or ""
                ),
            }
        )
        total_findings += len(findings)

    payload = {"agents": results, "total_findings": total_findings}
    _RESULTS_CACHE["at"] = now
    _RESULTS_CACHE["payload"] = payload
    return payload
