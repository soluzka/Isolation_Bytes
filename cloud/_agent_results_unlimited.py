"""Shared helper for returning complete, live agent scan results.

The dashboard and YARA scanner must observe the same agent counters while a
scan is in progress. Completed reports and live heartbeats are normalized into
one monotonic snapshot so the UI cannot jump backward between polls.
"""

# Per-process monotonic counters. They are intentionally keyed by device so a
# delayed heartbeat/report can never make an active scan appear to go backward.
_LAST_COUNTERS = {}


def _monotonic_counter(device_id, key, report_value, live_value):
    try:
        current = max(int(report_value or 0), int(live_value or 0))
    except (TypeError, ValueError):
        current = 0
    state = _LAST_COUNTERS.setdefault(device_id, {})
    previous = int(state.get(key, 0) or 0)
    # A new agent registration may legitimately reset its counters. Without a
    # reliable restart marker, keep the active dashboard monotonic and let the
    # agent's cumulative counters remain authoritative for normal operation.
    value = max(previous, current)
    state[key] = value
    return value


def build_complete_agent_scan_results(legacy):
    agents = legacy._all_agents()
    results = []
    total_findings = 0
    for device_id, ag in agents.items():
        report = ag.get('last_report') or {}
        findings = report.get('findings') or report.get('results') or []
        if not isinstance(findings, list):
            findings = []

        files_scanned = _monotonic_counter(
            device_id, 'files_scanned',
            report.get('files_scanned', 0), ag.get('files_scanned', 0)
        )
        quarantined_count = _monotonic_counter(
            device_id, 'quarantined_count',
            report.get('quarantined_count', 0), ag.get('quarantined_count', 0)
        )

        # Publish the normalized counters back into the shared in-memory agent
        # record. The conditional-startup/index endpoint reads the same record,
        # so both pages converge on exactly the same progress values.
        try:
            ag['files_scanned'] = files_scanned
            ag['quarantined_count'] = quarantined_count
        except Exception:
            pass

        results.append({
            'hostname': ag.get('hostname', device_id),
            'device_id': device_id,
            'files_scanned': files_scanned,
            'finding_count': len(findings),
            'last_scan': ag.get('last_scan') or report.get('last_scan', ''),
            'findings': findings,
            'quarantined_count': quarantined_count,
            'scan_dirs': ag.get('scan_dirs') or report.get('scan_dirs') or [],
        })
        total_findings += len(findings)
    return {'agents': results, 'total_findings': total_findings}
