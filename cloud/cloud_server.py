"""Compatibility wrapper for the cloud server with consistent agent scan/quarantine semantics."""

import os
import time
import logging
from datetime import datetime, timezone

from flask import jsonify, request, session

logger = logging.getLogger("cloud_server")

from cloud import cloud_server_original as _legacy
from cloud._agent_results_unlimited import build_complete_agent_scan_results, reset_agent_scan_results_cache

app = _legacy.app


def create_cloud_app():
    """Return the already-configured cloud Flask app for WSGI servers.

    The compatibility layer patches the legacy app at module import time, so
    WSGI entry points must return this same instance rather than constructing
    a second unpatched Flask application.
    """
    return app


# Export the legacy blueprint for callers that historically imported it from
# cloud.cloud_server rather than cloud.cloud_server_original.
cloud_bp = getattr(_legacy, 'cloud_bp', None)

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




@app.route('/api/scan-directories', methods=['GET', 'PUT', 'POST'])
def api_scan_directories_cloud():
    """Read or save the application-owned scan_directories.txt on the cloud dashboard."""
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'success': False, 'error': 'Authentication required'}), 401

    runtime_dir = os.environ.get(
        'ANTIVIRUS_RUNTIME_DIR',
        os.path.join(os.path.expanduser('~'), 'IsolationBytes')
    )
    os.makedirs(runtime_dir, exist_ok=True)
    runtime_file = os.path.join(runtime_dir, 'scan_directories.txt')

    if request.method == 'GET':
        try:
            if os.path.isfile(runtime_file):
                with open(runtime_file, 'r', encoding='utf-8') as handle:
                    content = handle.read()
            else:
                content = ''
            return jsonify({
                'success': True,
                'content': content,
                'path': runtime_file,
                'message': 'Scan directories loaded.'
            }), 200
        except OSError as exc:
            logger.exception('Failed to load scan directories: %s', exc)
            return jsonify({'success': False, 'error': str(exc)}), 500

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get('content'), str):
        return jsonify({
            'success': False,
            'error': 'Request must contain JSON with a string "content" field.'
        }), 400

    content = payload['content'].replace('\r\n', '\n').replace('\r', '\n')
    try:
        tmp_file = runtime_file + '.tmp'
        with open(tmp_file, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(content)
        os.replace(tmp_file, runtime_file)
        return jsonify({
            'success': True,
            'content': content,
            'path': runtime_file,
            'message': 'Scan directories saved to the writable Isolation Bytes runtime directory.'
        }), 200
    except OSError as exc:
        try:
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
        except OSError:
            pass
        logger.exception('Failed to save scan directories: %s', exc)
        return jsonify({'success': False, 'error': str(exc)}), 500

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
    blocked_threats = 0
    errors = 0
    process_events = 0
    last_scan = ''
    current_status = 'idle'
    current_started_at = ''
    running = False
    now = time.time()

    for device_id, agent in agents.items():
        report = agent.get('last_report') or {}
        current_scan_id = str(agent.get('scan_id') or report.get('scan_id') or '')
        scan_state = _agent_scan_state.get(device_id)
        # Recover an active generation after a cloud worker restart. The
        # generation state is intentionally in-memory, so a gunicorn restart
        # (including one caused by an origin outage/502) used to make an
        # already-running agent scan appear as 0 files / 0 quarantined.
        # Only reconstruct state when the agent itself proves that a scan is
        # currently queued or running and has a real scan_id; completed
        # historical reports are never resurrected as a new scan.
        if scan_state is None:
            recovered_status = str(
                agent.get('scan_status')
                or report.get('scan_status')
                or ''
            ).lower()
            recovered_scan_id = str(
                agent.get('scan_id')
                or report.get('scan_id')
                or ''
            )
            if recovered_scan_id and recovered_status in {'queued', 'scanning'}:
                recovered_started = agent.get('scan_started_at') or report.get('scan_started_at')
                try:
                    recovered_epoch = datetime.fromisoformat(
                        str(recovered_started).replace('Z', '+00:00')
                    ).timestamp()
                except (TypeError, ValueError, OSError):
                    recovered_epoch = now
                scan_state = {
                    'started_at': recovered_epoch,
                    'report_marker': _agent_report_marker(agent),
                    'previous_scan_id': '',
                    'baseline_files_scanned': 0,
                    'baseline_quarantined': 0,
                    'recovered_after_restart': True,
                }
                _agent_scan_state[device_id] = scan_state
        if scan_state:
            # Only counters carrying the current scan generation may reach the
            # dashboard. Heartbeats can contain lifetime values from an older
            # scan; those must never be mistaken for the new generation.
            previous_scan_id = str(scan_state.get('previous_scan_id') or '')
            generation_started = bool(
                current_scan_id and (
                    not previous_scan_id or current_scan_id != previous_scan_id
                )
            )
            if generation_started:
                current_files = max(0, int(
                    agent.get('files_scanned', report.get('files_scanned', 0)) or 0
                ))
                scanned_files += current_files
                current_quarantined = max(0, int(
                    agent.get('quarantined_count', report.get('quarantined_count', 0)) or 0
                ))
                quarantined_files += current_quarantined
                blocked_threats += max(0, int(
                    agent.get('threats_blocked', report.get('threats_blocked', 0)) or 0
                ))
                counters = report.get('scanner_counters') or agent.get('scanner_counters') or {}
                errors += max(0, int(counters.get('errors', 0) or 0))
                process_events += max(0, int(counters.get('process_events', 0) or 0))
                # Prefer authoritative agent counters for the current generation.
                ml_detections += max(0, int(
                    agent.get('total_ml', report.get('total_ml', counters.get('ml_detections', 0))) or 0
                ))
                ransomware_indicators += max(0, int(
                    agent.get('total_ransomware', report.get('total_ransomware', counters.get('ransomware_indicators', 0))) or 0
                ))
                persistence_indicators += max(0, int(
                    agent.get('total_persistence', report.get('total_persistence', counters.get('persistence_indicators', 0))) or 0
                ))
            # If the agent has not published this generation's scan_id yet,
            # keep the dashboard at zero/queued rather than showing history.
        else:
            # No server-owned scan generation exists for this agent. Do not
            # display its lifetime heartbeat counters as a new scan.
            pass
        marker = _agent_report_marker(agent)
        agent_status = agent.get('scan_status') or report.get('scan_status') or 'idle'
        agent_started = agent.get('scan_started_at') or report.get('scan_started_at') or ''
        if agent_status:
            current_status = agent_status
        if agent_started:
            current_started_at = agent_started
        last_scan = max(last_scan, marker)
        pending_scan = any(isinstance(cmd, dict) and cmd.get('action') == 'scan_now' for cmd in _legacy.commands.get(device_id, []))
        current_scan_id = str(agent.get('scan_id') or report.get('scan_id') or '')
        if scan_state:
            started = float(scan_state.get('started_at', 0) or 0)
            previous_scan_id = str(scan_state.get('previous_scan_id') or '')
            # Do not use last_scan/timestamp as the generation boundary.
            # The server publishes a synthetic scan-start report immediately,
            # so its timestamp changes before the agent actually begins.
            generation_started = bool(current_scan_id and current_scan_id != previous_scan_id)
            if generation_started:
                running = agent_status in {'scanning', 'queued'}
                # Keep the generation baseline after completion so the dashboard
                # continues to expose only this run's counters. The next explicit
                # scan trigger replaces this state with a fresh baseline.
            elif pending_scan or started:
                # A scan generation is persistent. Do not turn it idle merely
                # because two minutes have elapsed or because the agent has not
                # published its scan_id yet. The Windows normal scan is intended
                # to remain active indefinitely until the process itself exits.
                running = True
            else:
                running = False
        elif pending_scan:
            running = True

        # Never expose a heartbeat/report as a current scan unless this
        # process owns an explicit scan generation for the agent. This prevents
        # stale findings from a previous process/restart from becoming a new
        # scan generation.
        report_findings = []
        if scan_state:
            previous_scan_id = str(scan_state.get('previous_scan_id') or '')
            generation_started = bool(current_scan_id and current_scan_id != previous_scan_id)
            if generation_started:
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
            # Threat counters are taken from the authoritative generation totals above.
            # Do not increment them again from the latest report's findings.

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
        'started_at': _format_scan_timestamp(active_started),
        'scan_generation': scan_generation,
        'duration': None,
        'scanned_files': scanned_files,
        'quarantined_files': quarantined_files,
        'blocked_threats': blocked_threats,
        'errors': errors,
        'process_events': process_events,
        'ml_detections': ml_detections,
        'ransomware_indicators': ransomware_indicators,
        'persistence_indicators': persistence_indicators,
        'yara_suspicious': len(findings),
        'findings': findings,
        'ml_models': {},
        'last_error': '',
        'scan_status': current_status,
        'scan_started_at': current_started_at,
    }


def _format_scan_timestamp(value):
    """Return dashboard timestamps as ISO-8601, never raw Unix epoch floats."""
    if value in (None, ''):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        text_value = str(value)
        # Numeric strings are also treated as Unix timestamps.
        if text_value.replace('.', '', 1).isdigit():
            return datetime.fromtimestamp(float(text_value), timezone.utc).isoformat()
        return text_value
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _conditional_startup_status_response():
    """Return only the current server-owned scan generation.
    
    The legacy cloud route aggregates lifetime agent counters after a scan,
    which makes a fresh dashboard run start with historical totals. The
    cloud wrapper is the canonical dashboard API, so it must never fall back
    to those lifetime values.
    """
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error',
                        'message': 'Authentication required',
                        'error': 'Authentication required'}), 401

    state = _canonical_yara_agent_state()
    return jsonify({
        'ok': True,
        'success': True,
        'status': 'running' if state.get('running') else 'idle',
        'running': bool(state.get('running')),
        'started_at': _format_scan_timestamp(state.get('started_at')),
        'last_run': _format_scan_timestamp(state.get('last_run')),
        'last_updated': _format_scan_timestamp(state.get('last_updated')),
        'duration': state.get('duration'),
        'scanned_files': int(state.get('scanned_files') or 0),
        'quarantined_files': int(state.get('quarantined_files') or 0),
        'errors': int(state.get('errors') or 0),
        'process_events': int(state.get('process_events') or 0),
        'ml_detections': int(state.get('ml_detections') or 0),
        'ransomware_indicators': int(state.get('ransomware_indicators') or 0),
        'persistence_indicators': int(state.get('persistence_indicators') or 0),
        'yara_suspicious': int(state.get('yara_suspicious') or 0),
        'blocked_threats': int(state.get('blocked_threats') or 0),
        'findings': state.get('findings') or [],
        'ml_models': state.get('ml_models') or {},
        'last_error': state.get('last_error') or '',
        'scan_status': state.get('scan_status') or 'idle',
        'scan_started_at': state.get('scan_started_at') or '',
        'scan_generation': state.get('scan_generation') or '',
        'agents': [],
        'agent_count': 0,
        'folders': [],
    }), 200


def _agent_trigger_scan_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message_type': 'error', 'message': 'Authentication required', 'error': 'Authentication required', 'agents': 0, 'agents_triggered': 0}), 401
    agents = _legacy._all_agents()
    if not agents:
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message_type': 'error', 'message': 'No connected agents to scan.', 'error': 'No connected agents to scan.', 'agents': 0, 'agents_triggered': 0}), 404
    now = time.time()

    # /run_startup and /api/agent-trigger-scan may be issued together by
    # different dashboard surfaces. Treat a just-created generation as
    # idempotent so the second request cannot reset its counters or scan_id
    # while the agent is already consuming the first command.
    for device_id in agents:
        existing = _agent_scan_state.get(device_id)
        if existing:
            try:
                age = max(0.0, now - float(existing.get('started_at', 0) or 0))
            except (TypeError, ValueError):
                age = 999.0
            pending = any(
                isinstance(cmd, dict) and cmd.get('action') == 'scan_now'
                for cmd in _legacy.commands.get(device_id, [])
            )
            current_id = str(
                agents[device_id].get('scan_id')
                or (agents[device_id].get('last_report') or {}).get('scan_id')
                or ''
            )
            if age < 10 and pending and not current_id:
                reset_agent_scan_results_cache()
                return jsonify({
                    'ok': True, 'success': True, 'status': 'started',
                    'accepted': True, 'message_type': 'success',
                    'message': 'The current scan generation is already queued.',
                    'error': None, 'agents': len(agents),
                    'agents_triggered': len(agents),
                    'scan_generation': 'connected-agent',
                }), 200

    sent = 0
    for device_id, agent in agents.items():
        pending = [cmd for cmd in list(_legacy.commands.get(device_id, [])) if cmd.get('action') != 'scan_now']
        pending.append({'action': 'scan_now'})
        _legacy.commands[device_id] = pending
        # Start every server-side scan generation with its own counters.
        # Do not seed counters from previous quarantine history.
        # StandaloneAgent resets files_scanned at the beginning of every
        # full scan, so the live value is already a per-scan counter.
        # Do not subtract the lifetime total from the current generation.
        baseline_quarantined = 0
        baseline_files_scanned = 0
        previous_scan_id = str(agent.get('scan_id') or (agent.get('last_report') or {}).get('scan_id') or '')
        _agent_scan_state[device_id] = {
            'started_at': now,
            'report_marker': _agent_report_marker(agent),
            'previous_scan_id': previous_scan_id,
            'baseline_files_scanned': baseline_files_scanned,
            'baseline_quarantined': baseline_quarantined,
        }
        agent['last_report'] = {'device_id': device_id, 'hostname': agent.get('hostname', device_id), 'findings': [], 'results': [], 'files_scanned': 0, 'quarantined_count': baseline_quarantined, 'scan_status': 'queued', 'scan_started_at': datetime.fromtimestamp(now, timezone.utc).isoformat(), 'scan_id': '', 'last_scan': datetime.fromtimestamp(now, timezone.utc).isoformat(), 'type': 'scan_start'}
        agent['files_scanned'] = 0
        agent['threats_blocked'] = 0
        agent['quarantined_count'] = 0
        agent['quarantine_files'] = []
        agent['scan_status'] = 'queued'
        agent['scan_started_at'] = agent['last_report']['scan_started_at']
        agent['scan_id'] = ''
        sent += 1
    reset_agent_scan_results_cache()
    return jsonify({'ok': True, 'success': True, 'status': 'started', 'accepted': True, 'message_type': 'success', 'message': 'Scan request accepted. Current-generation results were reset and will update as agents report progress.', 'error': None, 'agents': sent, 'agents_triggered': sent}), 200


def _yara_only_quarantine_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'Authentication required', 'error': 'Authentication required', 'quarantined': [], 'failed': [], 'count': 0}), 401
    agents = _legacy._all_agents()
    if not agents:
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'No connected agents.', 'error': 'No connected agents.', 'quarantined': [], 'failed': [], 'count': 0, 'agents_triggered': 0}), 404
    sent = 0
    targeted = 0
    for device_id, agent in agents.items():
        last_report = agent.get('last_report') or {}
        findings = []
        seen = set()
        for finding in last_report.get('findings') or last_report.get('results') or []:
            if not isinstance(finding, dict):
                continue
            path = finding.get('path') or finding.get('original_path')
            if not path or not _is_yara_finding(finding):
                continue
            key = _canonical_path(path)
            if not key or key in seen:
                continue
            seen.add(key)
            findings.append({'path': path})
        pending = list(_legacy.commands.get(device_id, []))
        existing_scan_files = {_canonical_path(cmd.get('file_path', '')) for cmd in pending if cmd.get('action') == 'scan_file'}
        for finding in findings:
            path = finding['path']
            if _canonical_path(path) not in existing_scan_files:
                pending.append({'action': 'scan_file', 'file_path': path})
                targeted += 1
        _legacy.commands[device_id] = pending
        sent += 1
    quarantined = []
    for device_id, agent in agents.items():
        host = agent.get('hostname', device_id)
        for qfile in agent.get('quarantine_files') or []:
            quarantined.append({'hostname': host, 'device_id': device_id, 'filename': qfile.get('filename', ''), 'original_path': qfile.get('original_path', ''), 'quarantined_at': qfile.get('quarantined_at', ''), 'size': qfile.get('size', 0)})
    return jsonify({'ok': True, 'success': True, 'status': 'accepted', 'message_type': 'success', 'quarantined': quarantined, 'failed': [], 'count': len(quarantined), 'agents_triggered': sent, 'targeted_findings': targeted, 'message': f'YARA quarantine queued for {targeted} current finding(s) across {sent} agent(s). Results will refresh after the scan.', 'error': None}), 200


def _conditional_startup_state():
    """Return the current app-owned Conditional Startup generation.

    Refresh the persisted state before every read so a request handled by a
    different worker sees the live counters written by the scan worker.
    """
    # The cloud service runs on Linux; the Windows quick_start launcher is not
    # a cloud worker and must never be imported here. Connected agents own the
    # cloud scan generation on non-Windows deployments.
    if os.name != 'nt':
        return None
    try:
        import quick_start
        refresh = getattr(quick_start, '_refresh_conditional_startup_state', None)
        if callable(refresh):
            refresh()
        state = getattr(quick_start, 'conditional_startup_state', None)
        if isinstance(state, dict):
            return dict(state)
    except Exception:
        pass
    return None


def _start_conditional_startup_response():
    """Start the actual current scan generation.

    On the Linux cloud deployment there is no local Windows Conditional
    Startup worker.  The connected Windows agent is the scanner, so /run_startup
    must queue the agent scan instead of returning a false "started" response.
    On Windows, quick_start owns the real Conditional Startup worker.
    """
    if os.name != 'nt':
        # Make /run_startup the canonical cloud scan trigger.  This prevents
        # the dashboard from marking a generation running before an agent has
        # actually received the command.
        response = _agent_trigger_scan_response()
        if isinstance(response, tuple):
            payload, status = response
            if status >= 400:
                return response
            try:
                data = payload.get_json() or {}
            except Exception:
                data = {}
            data['cloud_mode'] = True
            data['scan_generation'] = 'connected-agent'
            return jsonify(data), status
        return response

    try:
        import quick_start
        starter = getattr(quick_start, 'start_conditional_startup_scan', None)
        if not callable(starter):
            return jsonify({
                'ok': False, 'success': False, 'status': 'error',
                'message': 'Conditional Startup starter is unavailable',
                'error': 'Conditional Startup starter is unavailable',
            }), 503
        return jsonify(starter()), 200
    except Exception as exc:
        logger.exception('Failed to start local Conditional Startup: %s', exc)
        return jsonify({
            'ok': False, 'success': False, 'status': 'error',
            'message': str(exc), 'error': str(exc),
        }), 500


def _active_conditional_startup_state():
    """Return the current Conditional Startup state only while it is running."""
    state = _conditional_startup_state()
    if not state or not state.get('running'):
        return None
    return state

def _complete_agent_scan_results_response():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'ok': False, 'success': False, 'status': 'error', 'message': 'Authentication required', 'error': 'Authentication required'}), 401

    # The dashboard's synchronized scan generation is owned by Conditional
    # Startup. While a run exists (active or just completed), expose that
    # generation instead of replaying an older agent heartbeat/report.
    conditional = _conditional_startup_state()
    if conditional is not None and conditional.get('run_id'):
        started = str(conditional.get('started_at') or '')
        findings = conditional.get('findings') or []
        scanned = int(conditional.get('scanned_files') or 0)
        quarantined = int(conditional.get('quarantined_files') or 0)
        running = bool(conditional.get('running'))
        return jsonify({
            'ok': True, 'success': True,
            'agents': [{
                'device_id': 'conditional-startup',
                'hostname': 'Conditional Startup',
                'files_scanned': scanned,
                'finding_count': len(findings),
                'findings': findings[:50],
                'quarantined_count': quarantined,
                'scan_id': str(conditional.get('run_id') or ''),
                'scan_dirs': [],
                'scan_status': 'scanning' if running else 'idle',
                'scan_started_at': started,
                'last_scan': str(conditional.get('last_run') or started),
            }],
            'total_files_scanned': scanned,
            'total_findings': len(findings),
            'total_quarantined': quarantined,
            'status': 'running' if running else 'idle',
            'message': 'Conditional Startup is the current dashboard scan generation.',
        }), 200

    # Cloud deployments do not run the Windows Conditional Startup worker.
    # Fall back to the server-owned connected-agent generation instead of
    # returning a false empty scan.
    state = _canonical_yara_agent_state()
    findings = state.get('findings') or []
    scanned = int(state.get('scanned_files') or 0)
    quarantined = int(state.get('quarantined_files') or 0)
    running = bool(state.get('running'))
    return jsonify({
        'ok': True,
        'success': True,
        'agents': [{
            'device_id': 'cloud-agent-generation',
            'hostname': 'Connected Agent Scan',
            'files_scanned': scanned,
            'finding_count': len(findings),
            'findings': findings[:50],
            'quarantined_count': quarantined,
            'scan_id': str(state.get('scan_generation') or ''),
            'scan_dirs': [],
            'scan_status': state.get('scan_status') or ('scanning' if running else 'idle'),
            'scan_started_at': str(state.get('scan_started_at') or ''),
            'last_scan': str(state.get('last_run') or ''),
        }] if (running or state.get('scan_generation')) else [],
        'total_files_scanned': scanned,
        'total_findings': len(findings),
        'total_quarantined': quarantined,
        'status': 'running' if running else 'idle',
        'message': 'Connected-agent scan is the current dashboard scan generation.' if (running or state.get('scan_generation')) else 'No current scan generation.',
    }), 200


@app.before_request
def _intercept_agent_scan_and_yara_quarantine():
    # /run_startup starts the actual Conditional Startup worker. The agent
    # trigger remains separate because the dashboard intentionally starts both
    # paths together.
    if request.method == 'POST' and request.path == '/run_startup':
        return _start_conditional_startup_response()
    if request.method == 'POST' and request.path == '/api/agent-trigger-scan':
        return _agent_trigger_scan_response()
    if request.method == 'GET' and request.path == '/api/agent-scan-results':
        return _complete_agent_scan_results_response()
    if request.method == 'GET' and request.path == '/api/conditional_startup/status':
        return _conditional_startup_status_response()
    if request.method == 'POST' and request.path == '/quarantine/yara-matches':
        return _yara_only_quarantine_response()
    return None


@app.route('/api/conditional_startup/status', methods=['GET'])
def conditional_startup_status_api():
    if not (session.get('logged_in') or session.get('user_logged_in')):
        return jsonify({'error': 'Authentication required'}), 401

    # Conditional Startup has its own generation and counters. Always
    # return that state when available, including after completion. Do not
    # fall back to the agent aggregate, which may contain historical files,
    # quarantine events, or blocks from a previous generation.
    conditional = _conditional_startup_state()
    if conditional is not None:
        payload = dict(conditional)
        payload.setdefault('status', 'RUNNING' if payload.get('running') else 'IDLE')
        payload.setdefault('running', False)
        payload.setdefault('scanned_files', 0)
        payload.setdefault('quarantined_files', 0)
        payload.setdefault('blocked_threats', 0)
        payload.setdefault('errors', 0)
        payload.setdefault('scan_phase', 'scanning' if payload.get('running') else 'idle')
    else:
        # On the Linux/cloud deployment Conditional Startup is unavailable.
        # Report the connected-agent generation rather than an unconditional
        # zero/idle state, which made the scan panel appear stale.
        state = _canonical_yara_agent_state()
        payload = {
            'status': 'RUNNING' if state.get('running') else 'IDLE',
            'running': bool(state.get('running')),
            'run_id': str(state.get('scan_generation') or ''),
            'last_run': state.get('last_run'),
            'started_at': state.get('started_at'),
            'last_updated': state.get('last_updated'),
            'duration': state.get('duration'),
            'scanned_files': int(state.get('scanned_files') or 0),
            'quarantined_files': int(state.get('quarantined_files') or 0),
            'blocked_threats': int(state.get('blocked_threats') or 0),
            'errors': int(state.get('errors') or 0),
            'process_events': int(state.get('process_events') or 0),
            'ml_detections': int(state.get('ml_detections') or 0),
            'ransomware_indicators': int(state.get('ransomware_indicators') or 0),
            'persistence_indicators': int(state.get('persistence_indicators') or 0),
            'yara_suspicious': int(state.get('yara_suspicious') or 0),
            'scan_phase': 'scanning' if state.get('running') else 'idle',
            'last_error': state.get('last_error') or None,
        }
        response = jsonify(payload)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response, 200

    response = jsonify(payload)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response, 200
