""""Current-generation agent/YARA scan results.

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
        # The agent sends its LocalAppData scan_state.json as yara_scan_state.
        # Use it as the authoritative current-generation state.
        scan_state = report.get("yara_scan_state") or agent.get("yara_scan_state") or {}
        if not isinstance(scan_state, dict):
            scan_state = {}
        active = (active_scan_state or {}).get(device_id) or {}
        active_started = float(active.get("started_at", 0) or 0)

        current_scan_id = str(
            scan_state.get("scan_id") or agent.get("scan_id") or report.get("scan_id") or ""
        )
        current_status = str(
            scan_state.get("status")
            or agent.get("scan_status")
            or report.get("scan_status")
            or ""
        ).lower()

        # A cloud worker restart clears the in-memory generation map. If the
        # connected agent is demonstrably still in the same active scan, recover
        # that generation from the agent's own scan_id/status instead of
        # displaying a misleading 0/queued state. Completed historical reports
        # are deliberately not recovered.
        if (
            not active_started
            and current_scan_id
            and current_status in {"queued", "scanning"}
        ):
            recovered_started = (
                scan_state.get("started_at")
                or agent.get("scan_started_at")
                or report.get("scan_started_at")
                or report.get("timestamp")
            )
            try:
                active_started = datetime.fromisoformat(
                    str(recovered_started).replace("Z", "+00:00")
                ).timestamp()
            except (TypeError, ValueError, OSError):
                active_started = time.time()
            active = {
                "started_at": active_started,
                "previous_scan_id": "",
                "recovered_after_restart": True,
            }

        previous_scan_id = str(active.get("previous_scan_id") or "")
        generation_started = bool(
            active_started
            and current_scan_id
            and current_scan_id != previous_scan_id
        )

        if not active_started:
            files_scanned = 0
            quarantined_count = 0
            findings = []
            status = "idle"
            last_scan = ""
            scan_id = ""
            started_at = ""
        elif not generation_started:
            files_scanned = 0
            quarantined_count = 0
            findings = []
            status = "queued"
            last_scan = datetime.fromtimestamp(
                active_started, timezone.utc
            ).isoformat()
            scan_id = ""
            started_at = last_scan
        else:
            findings = report.get("findings") or report.get("results") or []
            if not isinstance(findings, list):
                findings = []

            # The current StandaloneAgent resets these counters to zero at
            # the start of every full scan. They are therefore already
            # per-generation values; never expose the agent's lifetime totals.
            files_scanned = max(
                0,
                int(
                    scan_state.get("files_scanned", agent.get("files_scanned", report.get("files_scanned", 0)))
                    or 0
                ),
            )
            quarantined_count = max(
                0,
                int(
                    scan_state.get("quarantined_count", agent.get("quarantined_count", report.get("quarantined_count", 0)))
                    or 0
                ),
            )
            status = str(
                scan_state.get("status")
                or agent.get("scan_status")
                or report.get("scan_status")
                or "idle"
            ).lower()

            last_scan = (
                scan_state.get("updated_at")
                or agent.get("last_scan")
                or report.get("last_scan")
                or report.get("timestamp", "")
            )
            scan_id = str(
                scan_state.get("scan_id")
                or agent.get("scan_id")
                or report.get("scan_id")
                or ""
            )
            started_at = (
                scan_state.get("started_at")
                or agent.get("scan_started_at")
                or report.get("scan_started_at")
                or ""
            )

        results.append(
            {
                "hostname": agent.get("hostname", device_id),
                "device_id": device_id,
                "files_scanned": files_scanned,
                "finding_count": len(findings),
                "last_scan": last_scan,
                "findings": findings[:50],
                "quarantined_count": quarantined_count,
                "scan_id": scan_id,
                "scan_dirs": scan_state.get("scan_dirs")
                or agent.get("scan_dirs")
                or report.get("scan_dirs")
                or [],
                "scan_status": status,
                "scan_started_at": started_at,
            }
        )
        total_findings += len(findings)

    payload = {"agents": results, "total_findings": total_findings}
    _RESULTS_CACHE["at"] = now
    _RESULTS_CACHE["payload"] = payload
    return payload
