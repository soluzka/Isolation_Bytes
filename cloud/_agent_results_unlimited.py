"""Shared helper for returning complete, live agent scan results.

The dashboard and YARA scanner must observe the same agent counters while a
scan is in progress. Completed reports and live heartbeats are normalized into
one monotonic snapshot so the UI cannot jump backward between polls.
"""

# Per-process monotonic counters. They are intentionally keyed by device so a
# delayed heartbeat/report can never make an active scan appear to go backward.
_LAST_COUNTERS = {}


def _monotonic_counter(device_id, key, report_value, live_value, generation=None):
    try:
        current = max(int(report_value or 0), int(live_value or 0))
    except (TypeError, ValueError):
        current = 0

    state = _LAST_COUNTERS.setdefault(device_id, {})
    if generation and state.get('generation') != generation:
        # A new scan must start from zero.  The old implementation kept the
        # previous run's 8,204-style value and then added the new run on top.
        state.clear()
        state['generation'] = generation

    previous = int(state.get(key, 0) or 0)
    value = max(previous, current)
    state[key] = value
    if generation:
        state['generation'] = generation
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

        scan_id = str(
            ag.get('scan_id') or report.get('scan_id') or
            ag.get('scan_started_at') or report.get('scan_started_at') or ''
        ).strip()

        files_scanned = _monotonic_counter(
            device_id, 'files_scanned',
            report.get('files_scanned', 0), ag.get('files_scanned', 0),
            scan_id or None
        )
        quarantined_count = _monotonic_counter(
            device_id, 'quarantined_count',
            report.get('quarantined_count', 0), ag.get('quarantined_count', 0),
            scan_id or None
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
            'last_scan': ag.get('last_scan') or report.get('last_scan') or report.get('timestamp', ''),
            'findings': findings,
            'quarantined_count': quarantined_count,
            'scan_id': scan_id,
            'scan_dirs': ag.get('scan_dirs') or report.get('scan_dirs') or [],
            'scan_status': ag.get('scan_status') or report.get('scan_status') or 'idle',
            'scan_current_path': ag.get('scan_current_path') or report.get('scan_current_path') or '',
            'scan_started_at': ag.get('scan_started_at') or report.get('scan_started_at') or '',
        })
        total_findings += len(findings)
    return {'agents': results, 'total_findings': total_findings}


def _json_payload(response):
    """Extract a Flask JSON payload from a view response."""
    try:
        if isinstance(response, tuple):
            response = response[0]
        return response.get_json(silent=True), response
    except Exception:
        return None, response


def _wrap_conditional_startup_routes(legacy):
    """Fix the legacy cloud routes that the Index page actually resolves to.

    The compatibility cloud wrapper's duplicate routes do not necessarily win
    Flask's URL-rule ordering. Wrap the already-registered legacy view
    functions instead, so the deployed Index path gets the canonical contract.
    """
    app = getattr(legacy, 'app', None)
    if app is None:
        return

    for rule in list(app.url_map.iter_rules()):
        endpoint = rule.endpoint
        original = app.view_functions.get(endpoint)
        if not original or getattr(original, '_conditional_startup_contract', False):
            continue

        if rule.rule == '/run_startup' and 'POST' in rule.methods:
            def run_startup_wrapped(*args, _original=original, **kwargs):
                response = _original(*args, **kwargs)
                data, _ = _json_payload(response)
                if not isinstance(data, dict):
                    return response

                message = str(data.get('message') or '')
                successful = data.get('success') is True and (
                    message.lower().startswith('scan triggered for ')
                    or data.get('status') in {'success', 'started', 'already_running'}
                )
                if successful:
                    agents = data.get('agents') or data.get('agents_triggered')
                    return {
                        'ok': True,
                        'success': True,
                        'status': 'started',
                        'accepted': True,
                        'message_type': 'success',
                        'message': 'Conditional startup scan started on connected agent(s).',
                        'error': None,
                        'agents': agents if isinstance(agents, int) else 0,
                        'agents_triggered': agents if isinstance(agents, int) else 0,
                    }, 200
                return response

            run_startup_wrapped._conditional_startup_contract = True
            app.view_functions[endpoint] = run_startup_wrapped

        elif rule.rule == '/api/conditional_startup/status' and 'GET' in rule.methods:
            def startup_status_wrapped(*args, _original=original, **kwargs):
                response = _original(*args, **kwargs)
                data, _ = _json_payload(response)
                if isinstance(data, dict):
                    error = data.get('last_error')
                    if isinstance(error, str) and error.strip().lower().startswith('scan triggered for '):
                        data['last_error'] = None
                        from flask import jsonify
                        return jsonify(data)
                return response

            startup_status_wrapped._conditional_startup_contract = True
            app.view_functions[endpoint] = startup_status_wrapped


def _fix_license_input_and_login_csrf(legacy):
    """Keep generated IB license keys intact and allow the public login API.

    RSA signatures make generated license keys substantially longer than the
    old 256-character sanitizer limit. The login page is also a public API
    client, so requiring a browser-session CSRF token on its first login POST
    causes the request to fail before credentials/license validation runs.
    """
    try:
        from security import web_hardening as _web_hardening

        original_sanitize = getattr(legacy, 'sanitize_text', None)
        if callable(original_sanitize):
            def license_safe_sanitize(value, *, max_length=512):
                raw = str(value or '').strip()
                if raw.startswith('IB-'):
                    return _web_hardening._CONTROL_CHARS.sub('', raw).strip()
                return original_sanitize(value, max_length=max_length)

            legacy.sanitize_text = license_safe_sanitize
    except Exception:
        pass

    # init_web_security stores its exempt-path set in the closure of the
    # already-registered before_request function. Add the public login API to
    # that set without replacing the security middleware itself.
    try:
        for funcs in getattr(app, 'before_request_funcs', {}).values():
            for func in funcs:
                if getattr(func, '__name__', '') != 'enforce_web_security':
                    continue
                freevars = getattr(func.__code__, 'co_freevars', ())
                closure = getattr(func, '__closure__', ()) or ()
                for name, cell in zip(freevars, closure):
                    if name == 'exempt_paths':
                        value = cell.cell_contents
                        if isinstance(value, set):
                            value.update({'/api/user/login'})
    except Exception:
        pass


# cloud_server.py imports this helper immediately after importing the legacy
# cloud app, so the legacy view functions are already registered here.
try:
    from cloud import cloud_server_original as _legacy_app
    _wrap_conditional_startup_routes(_legacy_app)
    _fix_license_input_and_login_csrf(_legacy_app)
except Exception:
    # The result helper remains usable independently in tests and tooling.
    pass
