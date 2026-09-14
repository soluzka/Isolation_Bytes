"""Compatibility wrapper for the cloud server with consistent agent scan/quarantine semantics."""

import os

from flask import jsonify, request, session

from cloud import cloud_server_original as _legacy

# Preserve the original application and all routes, but correct dashboard
# agent-scan/quarantine behavior so every frontend uses the same contract.
app = _legacy.app


def _canonical_path(path):
    """Normalize a local Windows/Unix path for comparisons."""
    if not isinstance(path, str) or not path.strip():
        return ''
    try:
        return os.path.normcase(os.path.abspath(os.path.realpath(path)))
    except (OSError, TypeError, ValueError):
        return os.path.normcase(path.strip())


def _is_yara_finding(finding):
    """Return True only for findings produced by the YARA scanner."""
    if not isinstance(finding, dict):
        return False
    rule = str(finding.get('rule') or '').strip().lower()
    threat_type = str(finding.get('threat_type') or '').strip().lower()
    if rule in {'ml_heuristic', 'ml'} or rule.startswith('ml_'):
        return False
    return bool(rule) or threat_type in {'yara_match', 'ransomware', 'persistence'}


def _agent_trigger_scan_response():
    """Queue the exact same scan command for every connected agent.

    Both index.html and yara_scanner.html call this endpoint.  Returning one
    canonical payload prevents one page from treating a successful scan as an
    error because it received a different success/status field.
    """
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({
            'ok': False,
            'success': False,
            'status': 'error',
            'message_type': 'error',
            'message': 'Authentication required',
            'error': 'Authentication required',
            'agents': 0,
            'agents_triggered': 0,
        }), 401

    agents = _legacy._all_agents()
    if not agents:
        return jsonify({
            'ok': False,
            'success': False,
            'status': 'error',
            'message_type': 'error',
            'message': 'No connected agents to scan.',
            'error': 'No connected agents to scan.',
            'agents': 0,
            'agents_triggered': 0,
        }), 404

    sent = 0
    for device_id in agents:
        pending = list(_legacy.commands.get(device_id, []))
        # Coalesce duplicate queued full scans so a double click cannot create
        # multiple scans with different result sets.
        pending = [cmd for cmd in pending if cmd.get('action') != 'scan_now']
        pending.append({'action': 'scan_now'})
        _legacy.commands[device_id] = pending
        sent += 1

    message = f'Scan triggered for {sent} agent(s). Results will appear shortly.'
    return jsonify({
        'ok': True,
        'success': True,
        'status': 'accepted',
        'message_type': 'success',
        'message': message,
        'error': None,
        'agents': sent,
        'agents_triggered': sent,
    }), 200


def _yara_only_quarantine_response():
    """Queue rescans only for current YARA findings.

    Quarantine is deliberately delegated back to the agent's normal YARA scan
    path.  This keeps detection and remediation in the same pipeline instead
    of using the persisted blocked-file registry, which may contain ML-only or
    stale entries from an earlier scan.
    """
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({
            'ok': False, 'success': False, 'status': 'error',
            'message': 'Authentication required', 'error': 'Authentication required',
            'quarantined': [], 'failed': [], 'count': 0,
        }), 401

    agents = _legacy._all_agents()
    if not agents:
        return jsonify({
            'ok': False, 'success': False, 'status': 'error',
            'message': 'No connected agents.', 'error': 'No connected agents.',
            'quarantined': [], 'failed': [], 'count': 0, 'agents_triggered': 0,
        }), 404

    sent = 0
    targeted = 0
    for device_id, agent in agents.items():
        last_report = agent.get('last_report') or {}
        findings = []
        seen = set()
        for finding in (last_report.get('findings') or []):
            path = finding.get('path') or finding.get('original_path')
            if not path or not _is_yara_finding(finding):
                continue
            key = _canonical_path(path)
            if not key or key in seen:
                continue
            seen.add(key)
            # Re-run the same scanner for the exact finding.  The agent's
            # scanner decides whether the match is actually quarantine-worthy.
            findings.append({'path': path})

        pending = list(_legacy.commands.get(device_id, []))
        if findings:
            # Do NOT use unblock_findings + quarantine_after here: that legacy
            # command also walks the entire persisted blocked-file registry.
            # That was the source of ML/YARA and stale-file mismatches.
            existing_scan_files = {
                _canonical_path(cmd.get('file_path', ''))
                for cmd in pending if cmd.get('action') == 'scan_file'
            }
            for finding in findings:
                path = finding['path']
                if _canonical_path(path) in existing_scan_files:
                    continue
                pending.append({'action': 'scan_file', 'file_path': path})
                targeted += 1
        else:
            # No current YARA findings means there is nothing to quarantine.
            # Never fall back to the blocked-file registry.
            pass
        _legacy.commands[device_id] = pending
        sent += 1

    # Return the current authoritative quarantine state.  The UI can poll the
    # normal agent-results endpoint for the post-scan state rather than being
    # given a fabricated count before the agent has finished.
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
        'ok': True,
        'success': True,
        'status': 'accepted',
        'message_type': 'success',
        'quarantined': quarantined,
        'failed': [],
        'count': len(quarantined),
        'agents_triggered': sent,
        'targeted_findings': targeted,
        'message': (
            f'YARA quarantine queued for {targeted} current finding(s) '
            f'across {sent} agent(s). Results will refresh after the scan.'
        ),
        'error': None,
    }), 200


@app.before_request
def _intercept_agent_scan_and_yara_quarantine():
    if request.method == 'POST' and request.path == '/api/agent-trigger-scan':
        return _agent_trigger_scan_response()
    if request.method == 'POST' and request.path == '/quarantine/yara-matches':
        return _yara_only_quarantine_response()
    return None
