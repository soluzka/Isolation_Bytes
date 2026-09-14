"""Shared helper for returning complete, live agent scan results.

The dashboard and YARA scanner must observe the same agent counters while a
scan is in progress.  The completed report is still the source of findings,
but live heartbeat counters take precedence for progress/quarantine totals.
"""


def build_complete_agent_scan_results(legacy):
    agents = legacy._all_agents()
    results = []
    total_findings = 0
    for device_id, ag in agents.items():
        report = ag.get('last_report') or {}
        findings = report.get('findings') or report.get('results') or []
        if not isinstance(findings, list):
            findings = []

        # Heartbeats contain the live cumulative scan counter.  Do not let a
        # stale completed report pin the YARA page at the count from the last
        # finished scan while the current scan is still progressing.
        report_files = report.get('files_scanned', 0) or 0
        live_files = ag.get('files_scanned', 0) or 0
        try:
            files_scanned = max(int(report_files), int(live_files))
        except (TypeError, ValueError):
            files_scanned = live_files or report_files or 0

        report_quarantined = report.get('quarantined_count', 0) or 0
        live_quarantined = ag.get('quarantined_count', 0) or 0
        try:
            quarantined_count = max(int(report_quarantined), int(live_quarantined))
        except (TypeError, ValueError):
            quarantined_count = live_quarantined or report_quarantined or 0

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
