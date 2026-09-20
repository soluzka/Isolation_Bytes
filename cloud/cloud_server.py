"""Compatibility wrapper for the cloud server with consistent agent scan/quarantine semantics."""

import os
import time
from datetime import datetime, timezone

from flask import jsonify, request, session

from cloud import cloud_server_original as _legacy
from cloud._agent_results_unlimited import build_complete_agent_scan_results, reset_agent_scan_results_cache

app = _legacy.app
_agent_scan_state = {}
_AGENT_SCAN_STALE_SECONDS = 30 * 60


def _patch_public_auth_security():
    """Allow public activation/login APIs without browser-session CSRF."""
    public_auth_paths = {
        '/api/user/login',
        '/api/license/activate',
        '/api/license/validate',
        '/api/license/deactivate',
    }
    for key, handlers in list(app.before_request_funcs.items()):
        patched = []
        for handler in handlers:
            if getattr(handler, '_public_auth_csrf_compat', False):
                patched.append(handler)
                continue
            if getattr(handler, '__name__', '') != 'enforce_web_security':
                patched.append(handler)
                continue

            def public_auth_security_wrapper(*args, _original=handler, **kwargs):
                if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and request.path in public_auth_paths:
                    return None
                return _original(*args, **kwargs)

            public_auth_security_wrapper._public_auth_csrf_compat = True
            patched.append(public_auth_security_wrapper)
        app.before_request_funcs[key] = patched


def _patch_license_input_length():
    """Do not truncate signed IB- license keys before RSA validation."""
    original = getattr(_legacy, 'sanitize_text', None)
    if not callable(original) or getattr(original, '_license_length_compat', False):
        return

    def license_safe_sanitize(value, *, max_length=512):
        if isinstance(value, str) and value.lstrip().startswith('IB-') and max_length == 256:
            return value.strip()
        return original(value, max_length=max_length)

    license_safe_sanitize._license_length_compat = True
    _legacy.sanitize_text = license_safe_sanitize


_patch_public_auth_security()
_patch_license_input_length()


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


def _agent_report_marker(agent):
    report = agent.get('last_report') or {}
    return str(agent.get('last_scan') or report.get('timestamp') or '')


def _live_max(report, agent, key):
    """Return the newest cumulative counter from report or live heartbeat."""
    try:
        return max(int(report.get(key) or 0), int(agent.get(key) or 0))
    except (TypeError, ValueError):
        return agent.get(key) or report.get(key) or 0


def _canonical_yara_agent_state():
    agents = _legacy._all_agents()
    findings = []
    seen_findings = set()
    scanned_files = 0
    quarantined_files = 0
    ml_detections = 0
    ransomware_indicators = 0
    persistence_indicators = 0
    last_scan = ''
    current_path = ''
    current_status = 'idle'
    current_started_at = ''
    running = False
    now = time.time()

    for device_id, agent in agents.items():
        report = agent.get('last_report') or {}
        scan_state = _agent_scan_state.get(device_id)
        if scan_state:
            scanned_files += max(0, int(agent.get('files_scanned', report.get('files_scanned', 0)) or 0))
            baseline_quarantined = int(scan_state.get('baseline_quarantined', 0) or 0)
            raw_quarantined = int(agent.get('quarantined_count', report.get('quarantined_count', 0)) or 0)
            quarantined_files += max(0, raw_quarantined - baseline_quarantined)
        else:
            scanned_files += _live_max(report, agent, 'files_scanned')
            quarantined_files += _live_max(report, agent, 'quarantined_count')
        marker = _agent_report_marker(agent)
        agent_path = agent.get('scan_current_path') or report.get('scan_current_path') or ''
        agent_status = agent.get('scan_status') or report.get('scan_status') or 'idle'
        agent_started = agent.get('scan_started_at') or report.get('scan_started_at') or ''
        if agent_path:
            current_path = agent_path
        if agent_status:
            current_status = agent_status
        if agent_started:
            current_started_at = agent_started
        last_scan = max(last_scan, marker)
        pending_scan = any(isinstance(cmd, dict) and cmd.get('action') == 'scan_now' for cmd in _legacy.commands.get(device_id, []))
        if scan_state:
            started = float(scan_state.get('started_at', 0) or 0)
            previous_marker = str(scan_state.get('report_marker') or '')
            if marker and marker != previous_marker:
                _agent_scan_state.pop(device_id, None)
            elif pending_scan or (started and now - started < _AGENT_SCAN_STALE_SECONDS):
                running = True
            else:
                _agent_scan_state.pop(device_id, None)
        elif pending_scan:
            running = True

        report_findings = report.get('findings') or report.get('results') or []
        for finding in report_findings:
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
            threat = str(item.get('threat_type') or '').lower()
            rule = str(item.get('rule') or '').lower()
            if 'ransom' in threat or 'ransom' in rule:
                ransomware_indicators += 1
            if 'persist' in threat or 'persist' in rule:
                persistence_indicators += 1

        for finding in report_findings:
            if not isinstance(finding, dict):
                continue
            rule = str(finding.get('rule') or '').lower()
            threat = str(finding.get('threat_type') or '').lower()
            if rule in {'ml_heuristic', 'ml'} or rule.startswith('ml_') or threat == 'ml':
                ml_detections += 1

    active_started = max(
        (str(v.get('started_at') or '') for v in _agent_scan_state.values()
         if v.get('started_at')),
        default=''
    )
    # Never report contradictory "Running + idle". If the cloud has an
    # active scan request but the agent has not published its first scanning
    # report yet, expose the state as queued until that report arrives.
    if running and current_status == 'idle':
        current_status = 'queued'
    scan_generation = active_started or last_scan

    # During an active run, "last scan" means this newly-started run.
    # Historical completion timestamps remain available in the agent report,
    # but must not replace the active scan's start time in the live dashboard.
    live_last_scan = active_started or last_scan
    return {
        'running': running,
        'last_run': live_last_scan,
        'last_updated': live_last_scan,
        'started_at': active_started or None,
        'scan_generation': scan_generation,
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
        'scan_current_path': current_path,
        'scan_status': current_status,
        'scan_started_at': current_started_at,
    }


def _agent_trigger_scan_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message_type': 'error', 'message': 'Authentication required', 'error': 'Authentication required', 'agents': 0, 'agents_triggered': 0}), 401
    agents = _legacy._all_agents()
    if not agents:
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message_type': 'error', 'message': 'No connected agents to scan.', 'error': 'No connected agents to scan.', 'agents': 0, 'agents_triggered': 0}), 404

    now = time.time()
    sent = 0
    for device_id, agent in agents.items():
        pending = [
            cmd for cmd in list(_legacy.commands.get(device_id, []))
            if cmd.get('action') != 'scan_now'
        ]
        pending.append({'action': 'scan_now'})
        _legacy.commands[device_id] = pending

        baseline_quarantined = int(agent.get('quarantined_count', 0) or 0)
        _agent_scan_state[device_id] = {
            'started_at': now,
            'report_marker': _agent_report_marker(agent),
            'baseline_quarantined': baseline_quarantined,
        }

        # Reset the live scan result immediately. The next agent report will
        # populate this record with the new generation's findings/progress.
        agent['last_report'] = {
            'device_id': device_id,
            'hostname': agent.get('hostname', device_id),
            'findings': [],
            'results': [],
            'files_scanned': 0,
            'quarantined_count': baseline_quarantined,
            'scan_status': 'queued',
            'scan_current_path': '',
            'scan_started_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
            'scan_id': '',
            'last_scan': datetime.fromtimestamp(now, timezone.utc).isoformat(),
            'type': 'scan_start',
        }
        agent['files_scanned'] = 0
        agent['scan_status'] = 'queued'
        agent['scan_current_path'] = ''
        agent['scan_started_at'] = agent['last_report']['scan_started_at']
        agent['scan_id'] = ''
        sent += 1

    reset_agent_scan_results_cache()
    return jsonify({
        'ok': True,
        'success': True,
        'status': 'started',
        'accepted': True,
        'message_type': 'success',
        'message': 'Scan request accepted. Current-generation results were reset and will update as agents report progress.',
        'error': None,
        'agents': sent,
        'agents_triggered': sent,
    }), 200

