"""Compatibility wrapper for the cloud server with consistent agent scan/quarantine semantics."""

import os
from flask import jsonify, request, session
from cloud import cloud_server_original as _legacy

app = _legacy.app


def _canonical_path(path):
    if not isinstance(path, str) or not path.strip():
        return ''
    try:
        return os.path.normcase(os.path.abspath(os.path.realpath(path)))
    except (OSError, TypeError, ValueError):
        return os.path.normcase(path.strip())


def _is_yara_finding(finding):
    if not isinstance(finding, dict):
        return False
    rule = str(finding.get('rule') or '').strip().lower()
    threat_type = str(finding.get('threat_type') or '').strip().lower()
    if rule in {'ml_heuristic', 'ml'} or rule.startswith('ml_'):
        return False
    return bool(rule) or threat_type in {'yara_match', 'ransomware', 'persistence'}


def _canonical_yara_agent_state():
    """Build one authoritative YARA state used by both dashboard pages."""
    agents = _legacy._all_agents()
    findings = []
    seen_findings = set()
    scanned_files = 0
    quarantined_files = 0
    ml_detections = 0
    ransomware_indicators = 0
    persistence_indicators = 0
    last_scan = ''

    for device_id, agent in agents.items():
        report = agent.get('last_report') or {}
        scanned_files += int(report.get('files_scanned') or agent.get('files_scanned') or 0)
        last_scan = max(last_scan, str(agent.get('last_scan') or report.get('timestamp') or ''))
        for finding in report.get('findings') or []:
            if not isinstance(finding, dict) or not _is_yara_finding(finding):
                continue
            path = finding.get('path') or finding.get('original_path') or ''
            key = (device_id, _canonical_path(path), str(finding.get('rule') or '').strip().lower())
            if key in seen_findings:
                continue
            seen_findings.add(key)
            item = dict(finding)
            item['path'] = path
            item['original_path'] = finding.get('original_path') or path
            item['device_id'] = device_id
            item['hostname'] = agent.get('hostname', device_id)
            item['quarantined'] = bool(finding.get('quarantined'))
            findings.append(item)
            if item['quarantined']:
                quarantined_files += 1
            threat = str(item.get('threat_type') or '').lower()
            rule = str(item.get('rule') or '').lower()
            if 'ransom' in threat or 'ransom' in rule:
                ransomware_indicators += 1
            if 'persist' in threat or 'persist' in rule:
                persistence_indicators += 1

        for finding in report.get('findings') or []:
            if not isinstance(finding, dict):
                continue
            rule = str(finding.get('rule') or '').lower()
            threat = str(finding.get('threat_type') or '').lower()
            if rule == 'ml_heuristic' or rule == 'ml' or rule.startswith('ml_') or threat == 'ml':
                ml_detections += 1

    return {
        'running': False,
        'last_run': last_scan,
        'last_updated': last_scan,
        'started_at': None,
        'duration': None,
        'scanned_files': scanned_files,
        'quarantined_files': quarantined_files,
        'blocked_threats': sum(1 for f in findings if f.get('blocked')),
        'errors': 0,
        'process_events': 0,
        'ml_detections': ml_detections,
        'ransomware_indicators': ransomware_indicators,
        'persistence_indicators': persistence_indicators,
        'yara_suspicious': len(findings),
        'findings': findings,
        'ml_models': {},
        'last_error': '',
    }


def _agent_trigger_scan_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message_type': 'error', 'message': 'Authentication required', 'error': 'Authentication required', 'agents': 0, 'agents_triggered': 0}), 401
    agents = _legacy._all_agents()
    if not agents:
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message_type': 'error', 'message': 'No connected agents to scan.', 'error': 'No connected agents to scan.', 'agents': 0, 'agents_triggered': 0}), 404
    sent = 0
    for device_id in agents:
        pending = list(_legacy.commands.get(device_id, []))
        pending = [cmd for cmd in pending if cmd.get('action') != 'scan_now']
        pending.append({'action': 'scan_now'})
        _legacy.commands[device_id] = pending
        sent += 1
    return jsonify({'ok': True, 'success': True, 'status': 'accepted', 'message_type': 'success', 'message': f'Scan triggered for {sent} agent(s). Results will appear shortly.', 'error': None, 'agents': sent, 'agents_triggered': sent}), 200


def _yara_only_quarantine_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'Authentication required', 'error': 'Authentication required', 'quarantined': [], 'failed': [], 'count': 0}), 401
    agents = _legacy._all_agents()
    if not agents:
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'No connected agents.', 'error': 'No connected agents.', 'quarantined': [], 'failed': [], 'count': 0, 'agents_triggered': 0}), 404
    sent = 0
    targeted = 0
    for device_id, agent in agents.items():
        report = agent.get('last_report') or {}
        findings = []
        seen = set()
        for finding in report.get('findings') or []:
            if not _is_yara_finding(finding):
                continue
            path = finding.get('path') or finding.get('original_path')
            key = _canonical_path(path)
            if not key or key in seen:
                continue
            seen.add(key)
            findings.append({'path': path})
        pending = list(_legacy.commands.get(device_id, []))
        existing = {_canonical_path(cmd.get('file_path', '')) for cmd in pending if cmd.get('action') == 'scan_file'}
        for finding in findings:
            if _canonical_path(finding['path']) not in existing:
                pending.append({'action': 'scan_file', 'file_path': finding['path']})
                targeted += 1
        _legacy.commands[device_id] = pending
        sent += 1
    state = _canonical_yara_agent_state()
    quarantined = []
    for device_id, agent in agents.items():
        for qfile in (agent.get('quarantine_files') or []):
            quarantined.append({'hostname': agent.get('hostname', device_id), 'device_id': device_id, 'filename': qfile.get('filename', ''), 'original_path': qfile.get('original_path', ''), 'quarantined_at': qfile.get('quarantined_at', ''), 'size': qfile.get('size', 0)})
    return jsonify({'ok': True, 'success': True, 'status': 'accepted', 'message_type': 'success', 'quarantined': quarantined, 'failed': [], 'count': len(quarantined), 'agents_triggered': sent, 'targeted_findings': targeted, 'message': f'YARA quarantine queued for {targeted} current finding(s) across {sent} agent(s).', 'state': state, 'error': None}), 200


@app.before_request
def _intercept_agent_scan_and_yara_quarantine():
    if request.method == 'POST' and request.path == '/api/agent-trigger-scan':
        return _agent_trigger_scan_response()
    if request.method == 'POST' and request.path == '/quarantine/yara-matches':
        return _yara_only_quarantine_response()
    if request.method == 'GET' and request.path == '/api/conditional_startup/status':
        if not (session.get('logged_in') or session.get('user_logged_in')):
            return jsonify({'error': 'Authentication required'}), 401
        # index.html now receives the same authoritative agent/YARA state as
        # yara_scanner.html: same scanned files, findings, paths and quarantine flags.
        return jsonify(_canonical_yara_agent_state()), 200
    return None
