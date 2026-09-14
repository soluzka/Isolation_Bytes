"""Shared helper for returning complete agent scan findings without UI truncation."""

def build_complete_agent_scan_results(legacy):
    agents = legacy._all_agents()
    results = []
    total_findings = 0
    for device_id, ag in agents.items():
        report = ag.get('last_report') or {}
        findings = report.get('findings') or report.get('results') or []
        if not isinstance(findings, list):
            findings = []
        results.append({
            'hostname': ag.get('hostname', device_id),
            'device_id': device_id,
            'files_scanned': report.get('files_scanned', ag.get('files_scanned', 0)) or 0,
            'finding_count': len(findings),
            'last_scan': ag.get('last_scan', ''),
            'findings': findings,
            'quarantined_count': ag.get('quarantined_count', 0) or 0,
            'scan_dirs': ag.get('scan_dirs') or [],
        })
        total_findings += len(findings)
    return {'agents': results, 'total_findings': total_findings}
