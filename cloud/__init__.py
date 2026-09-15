"""Cloud package privacy boundary.

The legacy cloud server keeps a shared agent registry for agent-to-server
operations. Browser users must only receive telemetry belonging to the machine
bound to their authenticated session.
"""

import re

from flask import has_request_context, request, session


_TELEMETRY_PATHS = frozenset({
    '/get_traffic_stats',
    '/get_c2_patterns',
    '/get_live_connections',
    '/api/network_devices',
    '/api/agents',
})


def _machine_key(value):
    """Normalize a machine/device identifier for exact comparison."""
    if not isinstance(value, str):
        return ''
    return re.sub(r'[^a-z0-9._:-]', '', value.strip().lower())


def _user_machine_id():
    if not has_request_context():
        return ''
    return _machine_key(session.get('user_machine_id'))


def _is_user_session():
    return has_request_context() and bool(session.get('user_logged_in'))


def _user_is_admin():
    return has_request_context() and bool(session.get('logged_in'))


def _agent_belongs_to_user(device_id, info):
    """Return True only when an agent is explicitly bound to this session."""
    machine_id = _user_machine_id()
    if not machine_id or not isinstance(info, dict):
        return False

    identifiers = (
        info.get('machine_id'),
        info.get('device_id'),
        info.get('agent_id'),
        info.get('owner_machine_id'),
        info.get('bound_machine_id'),
        device_id,
    )
    return machine_id in {_machine_key(value) for value in identifiers if value}


def _scope_agents(agents):
    """Filter a registry to the machine bound to the current user."""
    if not isinstance(agents, dict):
        return {}
    return {
        device_id: info
        for device_id, info in agents.items()
        if _agent_belongs_to_user(device_id, info)
    }


def _safe_telemetry(path, original):
    """Return an empty, schema-compatible response for an unbound user."""
    timestamp = original.get('timestamp') if isinstance(original, dict) else None
    if path == '/get_traffic_stats':
        return {
            'success': True,
            'total_connections': 0,
            'active_connections': 0,
            'connections_observed': 0,
            'inbound': 0,
            'outbound': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
            'protocols': {'TCP': 0, 'UDP': 0},
            'processes': {},
            'all_processes': [],
            'process_count': 0,
            'source': 'user_agent',
        }
    if path == '/get_c2_patterns':
        return {'success': True, 'total': 0, 'timestamp': timestamp,
                'suspicious_connections': []}
    if path == '/get_live_connections':
        return {'success': True, 'total': 0, 'timestamp': timestamp,
                'connections': []}
    if path == '/api/network_devices':
        return {'success': True, 'devices': [], 'count': 0}
    return {'success': True, 'agents': [], 'count': 0}


def _scrub_traffic_stats(response):
    """Replace browser-visible remote IPs with an aggregate observation count."""
    payload = response.get_json(silent=True)
    if not isinstance(payload, dict):
        return response

    active_ips = payload.pop('active_ips', None)
    if isinstance(active_ips, list):
        payload['connections_observed'] = len(active_ips)
    elif 'connections_observed' not in payload:
        try:
            payload['connections_observed'] = max(
                0, int(payload.get('active_connections') or 0)
            )
        except (TypeError, ValueError):
            payload['connections_observed'] = 0
    response.set_json(payload)
    return response


def _install_privacy_boundary(legacy):
    """Install machine-scoped access around the legacy cloud registry."""
    if getattr(legacy, '_user_device_privacy_installed', False):
        return

    original_get_agents = legacy._get_agents
    original_get_agent = getattr(legacy, '_get_agent', None)
    original_load_agents = getattr(legacy, '_load_agents', None)

    def scoped_get_agents():
        agents = original_get_agents()
        if not _is_user_session() or _user_is_admin():
            return agents
        return _scope_agents(agents)

    def scoped_get_agent(device_id):
        agent = original_get_agent(device_id) if callable(original_get_agent) else None
        if not _is_user_session() or _user_is_admin():
            return agent
        if not _agent_belongs_to_user(device_id, agent):
            return None
        return agent

    def scoped_load_agents():
        agents = original_load_agents() if callable(original_load_agents) else {}
        if not _is_user_session() or _user_is_admin():
            return agents
        return _scope_agents(agents)

    legacy._get_agents = scoped_get_agents
    if callable(original_get_agent):
        legacy._get_agent = scoped_get_agent
    if callable(original_load_agents):
        legacy._load_agents = scoped_load_agents

    @legacy.app.after_request
    def _privacy_after_request(response):
        """Bind login sessions and prevent cross-machine telemetry leakage."""
        _bind_machine_after_login(response)
        if not _is_user_session() or _user_is_admin():
            return response
        if request.path not in _TELEMETRY_PATHS:
            return response

        payload = response.get_json(silent=True)
        if not isinstance(payload, dict):
            return response
        if not _scope_agents(original_get_agents()):
            response.set_json(_safe_telemetry(request.path, payload))
            return response
        if request.path == '/get_traffic_stats':
            return _scrub_traffic_stats(response)
        return response

    legacy._user_device_privacy_installed = True


def _bind_machine_after_login(response):
    """Bind the machine ID supplied to a successful user login."""
    if request.path != '/api/user/login' or response.status_code != 200:
        return
    payload = response.get_json(silent=True)
    body = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or not payload.get('ok'):
        return
    machine_id = body.get('machine_id') or request.form.get('machine_id')
    normalized = _machine_key(machine_id)
    if normalized:
        session['user_machine_id'] = normalized


from . import cloud_server_original as _legacy_cloud
_install_privacy_boundary(_legacy_cloud)
