"""Current-generation agent/YARA scan results.

The dashboard intentionally shows the active/current scan generation rather than
replaying a previous completed scan. Historical findings are not used as the
live scan result.
"""
import time
from datetime import datetime, timezone

_RESULTS_CACHE = {"at": 0.0, "payload": None}
_RESULTS_CACHE_TTL = 1.0


def reset_agent_scan_results_cache():
    _RESULTS_CACHE["at"] = 0.0
    _RESULTS_CACHE["payload"] = None


def build_complete_agent_scan_results(legacy, active_scan_state=None):
    """Return only current-generation scan results for the dashboard."""
    now = time.monotonic()
    cached = _RESULTS_CACHE.get("payload")
    if cached is not None and now - _RESULTS_CACHE.get("at", 0.0) < _RESULTS_CACHE_TTL:
        return cached

    results = []
    total_findings = 0

    for device_id, agent in legacy._all_agents().items():
        report = agent.get("last_report") or {}
        active = (active_scan_state or {}).get(device_id) or {}
        active_started = float(active.get("started_at", 0) or 0)
        baseline_quarantined = int(active.get("baseline_quarantined", 0) or 0)

        current_scan_id = str(
            agent.get("scan_id") or report.get("scan_id") or ""
        )
        previous_scan_id = str(active.get("previous_scan_id") or "")
        # A new scan generation begins only when the agent publishes its new
        # scan_id. Timestamps cannot be used here because the cloud writes a
        # synthetic scan-start report before the agent consumes scan_now.
        generation_started = bool(
            active_started
            and current_scan_id
            and current_scan_id != previous_scan_id
        )

        if active_started and not generation_started:
            # New scan has been requested, but this agent has not published a
            # report belonging to it yet. Never leak the previous run here.
            files_scanned = 0
            quarantined_count = 0
            findings = []
            status = "queued"
            current_path = ""
            last_scan = datetime.fromtimestamp(active_started, timezone.utc).isoformat()
            scan_id = ""
            started_at = last_scan
        else:
            findings = report.get("findings") or report.get("results") or []
            if not isinstance(findings, list):
                findings = []
            files_scanned = int(
                agent.get("files_scanned", report.get("files_scanned", 0)) or 0
            )
            raw_quarantined = int(
                agent.get("quarantined_count", report.get("quarantined_count", 0)) or 0
            )
            quarantined_count = max(0, raw_quarantined - baseline_quarantined)
            status = str(
                agent.get("scan_status") or report.get("scan_status") or "idle"
            ).lower()
            current_path = (
                agent.get("scan_current_path")
                or report.get("scan_current_path")
                or ""
            )
            last_scan = (
                agent.get("last_scan")
                or report.get("last_scan")
                or report.get("timestamp", "")
            )
            scan_id = str(
                agent.get("scan_id")
                or report.get("scan_id")
                or ""
            )
            started_at = (
                agent.get("scan_started_at")
                or report.get("scan_started_at")
                or ""
            )

        results.append({
            "hostname": agent.get("hostname", device_id),
            "device_id": device_id,
            "files_scanned": files_scanned,
            "finding_count": len(findings),
            "last_scan": last_scan,
            "findings": findings[:50],
            "quarantined_count": quarantined_count,
            "scan_id": scan_id,
            "scan_dirs": agent.get("scan_dirs") or report.get("scan_dirs") or [],
            "scan_status": status,
            "scan_current_path": current_path,
            "scan_started_at": started_at,
        })
        total_findings += len(findings)

    payload = {"agents": results, "total_findings": total_findings}
    _RESULTS_CACHE["at"] = now
    _RESULTS_CACHE["payload"] = payload
    return payload
