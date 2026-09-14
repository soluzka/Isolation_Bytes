"""Compatibility wrapper for the cloud server with YARA-only dashboard quarantine."""

from flask import jsonify, request, session

from cloud import cloud_server_original as _legacy

# Preserve the original application and all routes, but correct the dashboard's
# YARA quarantine action so it cannot quarantine ML-only or unrelated blocked
# files.  The legacy route selected every blocked finding, including
# ``ml_suspicious`` findings and every entry in the blocked-files registry.
app = _legacy.app


def _is_yara_finding(finding):
    """Return True only for findings produced by the YARA scanner."""
    if not isinstance(finding, dict):
        return False
    rule = str(finding.get('rule') or '').strip().lower()
    threat_type = str(finding.get('threat_type') or '').strip().lower()
    # ML-only findings are explicitly excluded even when their threat type was
    # upgraded to ransomware/persistence by the ML heuristic.
    if rule in {'ml_heuristic', 'ml'} or rule.startswith('ml_'):
        return False
    return bool(rule) or threat_type in {'yara_match', 'ransomware', 'persistence'}


def _yara_only_quarantine_response():
    """Handle /quarantine/yara-matches using only current YARA findings."""
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'error': 'Authentication required'}), 401
    csrf = (
        request.form.get('csrf_token', '')
        or request.headers.get('X-CSRF-Token', '')
        or (request.get_json(silent=True) or {}).get('csrf_token', '')
    )
    if not csrf or csrf != session.get('csrf_token'):
        return jsonify({'error': 'CSRF token missing or invalid'}), 403

    agents = _legacy._all_agents()
    if not agents:
        return jsonify({
            'quarantined': [], 'failed': [], 'count': 0,
            'agents_triggered': 0,
            'message': 'No connected agents.'
        }), 404

    sent = 0
    for device_id, agent in agents.items():
        findings = []
        last_report = agent.get('last_report') or {}
        for finding in (last_report.get('findings') or []):
            if not finding.get('path') or not _is_yara_finding(finding):
                continue
            # Never quarantine a finding that was reported as a non-YARA ML
            # heuristic, even if it also has a ransomware/persistence label.
            findings.append({'path': finding['path']})

        pending = _legacy.commands.get(device_id, [])
        if findings:
            pending.append({
                'action': 'unblock_findings',
                'findings': findings,
                'quarantine_after': True,
            })
        else:
            # Refresh YARA findings only; do not fall back to the full blocked
            # file registry because it can contain ML-only detections.
            pending.append({'action': 'scan_now'})
        _legacy.commands[device_id] = pending
        sent += 1

    # Keep the existing agent polling contract: allow the scan/quarantine
    # command to complete before collecting the updated quarantine list.
    import time as _time
    _time.sleep(15)
    for device_id in agents:
        pending = _legacy.commands.get(device_id, [])
        pending = [c for c in pending if c.get('action') != 'list_quarantine']
        pending.append({'action': 'list_quarantine'})
        _legacy.commands[device_id] = pending
    _time.sleep(10)

    agents = _legacy._all_agents()
    quarantined = []
    for device_id, agent in agents.items():
        host = agent.get('hostname', device_id)
        for qfile in (agent.get('quarantine_files') or []):
            quarantined.append({
                'hostname': host,
                'device_id': device_id,
                'filename': qfile.get('filename', ''),
                'original_path': qfile.get('original_path', ''),
                'quarantined_at': qfile.get('quarantined_at', ''),
                'size': qfile.get('size', 0),
            })

    return jsonify({
        'quarantined': quarantined,
        'failed': [],
        'count': len(quarantined),
        'agents_triggered': sent,
        'message': (
            f'YARA-only quarantine sent to {sent} agent(s). '
            f'{len(quarantined)} file(s) currently quarantined.'
        ),
        'status': 'success',
        'success': True,
    }), 200


@app.before_request
def _intercept_yara_quarantine():
    if request.method == 'POST' and request.path == '/quarantine/yara-matches':
        return _yara_only_quarantine_response()
    return None
