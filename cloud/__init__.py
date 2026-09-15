"""Cloud package privacy boundary.

The legacy cloud server keeps a shared agent registry for agent-to-server
operations. Browser users, however, must only receive telemetry belonging to
the machine bound to their authenticated license. This module installs that
request-time boundary before the compatibility wrapper is used.
"""

import json
import re

from flask import has_request_context, request, session


def _machine_key(value):
    """Normalize a machine/device identifier for safe exact comparison."""
    if not isinstance(value, str):
        return ''
    return re.sub(r'[^a-z0-9._:-]', '', value.strip().lower())


def _user_machine_id():
    if not has_request_context():
        return ''
    return _machine_key(session.get('user_machine_id', ''))


def _user_is_admin():
    return has_request_context() and bool(session.get('logged_in'))


def _agent_belongs_to_user(device_id, info):
    """Return True only when an agent is explicitly bound to this session."""
    machine_id = _user_machine_id()
    if not machine_id or not isinstance(info, dict):
        return False

    candidates = (
        info.get('machine_id'),
        info.get('device_id'),
        info.get('agent_id'),
        info.get('owner_machine_id'),
        info.get('bound_machine_id'),
    )
    normalized = {_machine_key(value) for value in candidates if value}
    return machine_id in normalized or machine_id == _machine_key(device_id)


def _install_privacy_boundary(legacy):
    """Scope legacy agent access and browser telemetry to the logged-in user."""
    if getattr(legacy, '_user_device_privacy_installed', False):
        return

    original_get_agents = legacy._get_agents
    original_get_agent = getattr(legacy, '_get_agent', None)
    original_load_agents = getattr(legacy, '_load_agents', None)

    def scoped_get_agents():
        agents = original_get_agents()
        if not has_request_context() or _user_is_admin() or not session.get('user_logged_in'):
            return agents
        return {
            device_id: info
            for device_id, info in agents.items()
            if _agent_belongs_to_user(device_id, info)
        }

    def scoped_get_agent(device_id):
        agent = original_get_agent(device_id) if callable(original_get_agent) else None
        if not has_request_context() or _user_is_admin() or not session.get('user_logged_in'):
            return agent
        return agent if _agent_belongs_to_user(device_id, agent or {}) else None

    def scoped_load_agents():
        agents = original_load_agents() if callable(original_load_agents) else {}
        if not has_request_context() or _user_is_admin() or not session.get('user_logged_in'):
            return agents
        return {
            device_id: info
            for device_id, info in agents.items()
            if _agent_belongs_to_user(device_id, info)
        }

    legacy._get_agents = scoped_get_agents
    if callable(original_get_agent):
        legacy._get_agent = scoped_get_agent
    if callable(original_load_agents):
        legacy._load_agents = scoped_load_agents

    @legacy.app.after_request
    def _bind_machine_and_scrub_fallbacks(response):
        """Bind successful web login and prevent cross-machine telemetry leaks."""
        if request.path == '/api/user/login' and response.status_code == 200:
            try:
                payload = response.get_json(silent=True) or {}
                body = request.get_json(silent=True) or {}
                machine_id = body.get('machine_id') or request.form.get('machine_id')
                if payload.get('ok') and machine_id:
                    session['user_machine_id'] = str(machine_id).strip()
            except (TypeError, ValueError):
                pass

        if not session.get('user_logged_in') or _user_is_admin():
            return response

        if request.path not in {
            '/get_traffic_stats',
            '/get_c2_patterns',
            '/get_live_connections',
            '/api/network_devices',
            '/api/agents',
        }:
            return response

        try:
            payload = response.get_json(silent=True)
        except (TypeError, ValueError):
            payload = None
        if not isinstance(payload, dict):
            return response

        owned_agents = scoped_get_agents()
        if owned_agents:
            # Network IP addresses are retained for security analysis on the
            # server, but the browser receives only an aggregate observation.
            if request.path == '/get_traffic_stats':
                active_ips = payload.pop('active_ips', [])
                if isinstance(active_ips, list):
                    payload['connections_observed'] = len(active_ips)
                else:
                    payload['connections_observed'] = int(payload.get('active_connections') or 0)
                response.set_data(json.dumps(payload))
                response.content_type = 'application/json'
            return response

        # A licensed user with no bound agent must never receive the server's
        # own process/network telemetry as a fallback.
        if request.path == '/get_traffic_stats':
            safe = {
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
        elif request.path in {'/get_c2_patterns', '/get_live_connections'}:
            safe = {
                'success': True,
                'total': 0,
                'timestamp': payload.get('timestamp'),
            }
            if request.path.endswith('patterns'):
                safe['suspicious_connections'] = []
            else:
                safe['connections'] = []
        elif request.path == '/api/network_devices':
            safe = {'success': True, 'devices': [], 'count': 0}
        else:
            safe = {'success': True, 'agents': [], 'count': 0}

        response.set_data(json.dumps(safe))
        response.content_type = 'application/json'
        return response

    legacy._user_device_privacy_installed = True


try:
    from . import cloud_server_original as _legacy_cloud
    _install_privacy_boundary(_legacy_cloud)
except Exception:
    # The compatibility wrapper imports the legacy module explicitly; if the
    # package is imported during an unusual bootstrap path, it can still load.
    pass
