"""Cloud server entry point.

This module intentionally keeps the legacy Flask application as the single
application owner and adds only the agent-scan compatibility endpoints needed
by the dashboard.  Do not duplicate the legacy server implementation here:
doing so can execute partial merged code during import and take the origin
offline.
"""

import os
import sys
import time
from functools import wraps

from flask import jsonify, request, session

from cloud import cloud_server_original as _legacy
from cloud._agent_results_unlimited import build_complete_agent_scan_results

app = _legacy.app
create_cloud_app = getattr(_legacy, 'create_cloud_app', lambda: app)
_agent_scan_state = {}
_STARTUP_RUNNING = False
_STARTUP_STARTED_AT = None


def _logged_in():
    return bool(session.get("logged_in") or session.get("user_logged_in"))


def _agent_report_marker(agent):
    report = agent.get("last_report") or {}
    return str(agent.get("last_scan") or report.get("timestamp") or "")


def _pending_scan(agent_id):
    try:
        return any(
            isinstance(cmd, dict) and cmd.get("action") == "scan_now"
            for cmd in _legacy.commands.get(agent_id, [])
        )
    except Exception:
        return False


def _scan_still_running(agents):
    """A triggered scan ends once every agent reports newer data or it times out."""
    global _STARTUP_RUNNING
    if not _STARTUP_RUNNING:
        return False
    now = time.time()
    for device_id, agent in agents.items():
        state = _agent_scan_state.get(device_id)
        if not state:
            continue
        if now - state["started_at"] > 3600:
            continue
        if _pending_scan(device_id) or agent.get("scanning"):
            return True
        if _agent_report_marker(agent) == state["report_marker"]:
            return True
    _STARTUP_RUNNING = False
    return False


def _canonical_yara_agent_state():
    """Return the one dashboard scan state, using agent data as authority."""
    agents = _legacy._all_agents()
    complete = build_complete_agent_scan_results(_legacy)
    normalized = {item["device_id"]: item for item in complete.get("agents", [])}

    scanned_files = 0
    quarantined = 0
    threats = 0
    blocked = 0
    ransomware = 0
    persistence = 0
    yara = 0
    ml = 0
    findings = []
    folders = []
    agent_rows = []
    running = _scan_still_running(agents)

    for device_id, agent in agents.items():
        row = normalized.get(device_id, {})
        report = agent.get("last_report") or {}

        files_scanned = int(row.get("files_scanned") or 0)
        quarantined_count = int(row.get("quarantined_count") or 0)
        agent_findings = _legacy._agent_findings_list(agent)

        scanned_files += files_scanned
        quarantined += quarantined_count
        threats += int(agent.get("findings_count") or len(agent_findings) or 0)
        blocked += int(agent.get("threats_blocked") or report.get("threats_blocked") or 0)
        ransomware += int(agent.get("total_ransomware") or 0)
        persistence += int(agent.get("total_persistence") or 0)
        yara += int(agent.get("total_yara") or 0)
        ml += int(agent.get("total_ml") or 0)

        if agent.get("scanning") or _pending_scan(device_id):
            running = True

        for finding in agent_findings:
            if isinstance(finding, dict):
                findings.append(finding)

        host = agent.get("hostname", device_id)
        for directory in agent.get("scan_dirs") or []:
            labeled = f"[{host}] {directory}"
            if labeled not in folders:
                folders.append(labeled)

        agent_rows.append({
            "device_id": device_id,
            "hostname": host,
            "platform": agent.get("platform", "unknown"),
            "last_seen": agent.get("last_seen", ""),
            "files_scanned": files_scanned,
            "quarantined": quarantined_count,
            "threats": int(agent.get("findings_count") or len(agent_findings) or 0),
            "scanning": bool(agent.get("scanning") or _pending_scan(device_id)),
        })

    return {
        "success": True,
        "status": "running" if running else "completed",
        "running": running,
        "progress": 50 if running else 100,
        "started_at": _STARTUP_STARTED_AT,
        "last_run": max(
            [str(a.get("last_scan") or "") for a in agents.values()] or [""]
        ),
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanned_files": scanned_files,
        "quarantined_files": quarantined,
        "errors": 0,
        "process_events": 0,
        "ml_detections": ml,
        "ransomware_indicators": ransomware,
        "persistence_indicators": persistence,
        "yara_suspicious": yara,
        "threats_found": threats,
        "blocked_threats": blocked,
        "findings": findings,
        "folders": folders,
        "agents": agent_rows,
        "agent_count": len(agent_rows),
        "agent_files_scanned": scanned_files,
        "agent_quarantined": quarantined,
        "agent_threats": threats,
        "agent_findings": findings,
        "agent_ransomware": ransomware,
        "agent_persistence": persistence,
        "agent_yara": yara,
        "agent_ml": ml,
    }


def _agent_trigger_scan_response():
    if not _logged_in():
        return jsonify({
            "ok": False,
            "success": False,
            "status": "error",
            "message_type": "error",
            "message": "Authentication required",
            "error": "Authentication required",
            "agents": 0,
            "agents_triggered": 0,
        }), 401

    agents = _legacy._all_agents()
    if not agents:
        return jsonify({
            "ok": False,
            "success": False,
            "status": "error",
            "message_type": "error",
            "message": "No connected agents to scan.",
            "error": "No connected agents to scan.",
            "agents": 0,
            "agents_triggered": 0,
        }), 404

    global _STARTUP_RUNNING, _STARTUP_STARTED_AT
    _STARTUP_RUNNING = True
    _STARTUP_STARTED_AT = time.strftime("%Y-%m-%d %H:%M:%S")
    now = time.time()
    sent = 0

    for device_id, agent in agents.items():
        try:
            pending = [
                cmd for cmd in list(_legacy.commands.get(device_id, []))
                if not (isinstance(cmd, dict) and cmd.get("action") == "scan_now")
            ]
            pending.append({"action": "scan_now"})
            _legacy.commands[device_id] = pending
            _agent_scan_state[device_id] = {
                "started_at": now,
                "report_marker": _agent_report_marker(agent),
            }
            sent += 1
        except Exception:
            continue

    if sent == 0:
        return jsonify({
            "ok": False,
            "success": False,
            "status": "error",
            "message_type": "error",
            "message": "No connected agents accepted the scan request.",
            "error": "No connected agents accepted the scan request.",
            "agents": 0,
            "agents_triggered": 0,
        }), 503

    return jsonify({
        "ok": True,
        "success": True,
        "status": "started",
        "accepted": True,
        "message_type": "success",
        "message": "Conditional startup scan started on connected agent(s).",
        "error": None,
        "agents": sent,
        "agents_triggered": sent,
    }), 200


def _yara_only_quarantine_response():
    if not _logged_in():
        return jsonify({
            "ok": False, "success": False, "status": "error",
            "message": "Authentication required",
            "error": "Authentication required",
            "quarantined": [], "failed": [], "count": 0,
        }), 401

    agents = _legacy._all_agents()
    if not agents:
        return jsonify({
            "ok": False, "success": False, "status": "error",
            "message": "No connected agents.",
            "error": "No connected agents.",
            "quarantined": [], "failed": [], "count": 0,
        }), 404

    targeted = 0
    for device_id, agent in agents.items():
        report = agent.get("last_report") or {}
        pending = list(_legacy.commands.get(device_id, []))
        existing = {
            os.path.normcase(os.path.abspath(str(cmd.get("file_path"))))
            for cmd in pending
            if isinstance(cmd, dict) and cmd.get("action") == "scan_file"
            and cmd.get("file_path")
        }

        for finding in _legacy._agent_findings_list(agent):
            if not isinstance(finding, dict):
                continue
            if finding.get("quarantined"):
                continue
            if not _legacy._is_yara_finding(finding):
                continue
            path = finding.get("path") or finding.get("original_path")
            if not path:
                continue
            key = os.path.normcase(os.path.abspath(str(path)))
            if key not in existing:
                pending.append({"action": "scan_file", "file_path": path})
                existing.add(key)
                targeted += 1

        _legacy.commands[device_id] = pending

    return jsonify({
        "ok": True,
        "success": True,
        "status": "accepted",
        "message_type": "success",
        "quarantined": [],
        "failed": [],
        "count": 0,
        "agents_triggered": len(agents),
        "targeted_findings": targeted,
        "message": "YARA quarantine queued for current findings.",
        "error": None,
    }), 200


def _complete_agent_scan_results_response():
    if not _logged_in():
        return jsonify({
            "ok": False,
            "success": False,
            "status": "error",
            "message": "Authentication required",
            "error": "Authentication required",
        }), 401
    return jsonify(build_complete_agent_scan_results(_legacy)), 200


@app.before_request
def _intercept_agent_scan_and_yara_quarantine():
    path = request.path
    if request.method == "POST" and path in {"/run_startup", "/api/agent-trigger-scan"}:
        return _agent_trigger_scan_response()
    if request.method == "GET" and path == "/api/agent-scan-results":
        return _complete_agent_scan_results_response()
    if request.method == "GET" and path == "/api/conditional_startup/status":
        return conditional_startup_status_api()
    if request.method == "POST" and path == "/quarantine/yara-matches":
        return _yara_only_quarantine_response()
    return None


@app.route("/api/conditional_startup/status", methods=["GET"])
def conditional_startup_status_api():
    if not _logged_in():
        return jsonify({"error": "Authentication required"}), 401
    state = _canonical_yara_agent_state()
    state["ml_models"] = _ml_models_status()
    return jsonify(state), 200


def _ml_models_status():
    """Report which ML model files exist, without importing quick_start."""
    try:
        from security.detector import _find_models_dir as _fmd
        models_dir = _fmd()
    except BaseException:
        meipass = getattr(sys, "_MEIPASS", None)
        models_dir = (
            os.path.join(meipass, "models") if meipass
            else str(_legacy.BASE_DIR.parent / "models")
        )
    exists = lambda name: os.path.exists(os.path.join(models_dir, name))
    return {
        "bodmas_cnn": exists("bodmas_cnn.onnx") and exists("bodmas_cnn_scaler.pkl"),
        "ember": exists("ember_malware_model.txt"),
        "sklearn": exists("file_malware_classifier.pkl"),
    }


# Delegate compatibility attributes that older imports may still access.
def __getattr__(name):
    return getattr(_legacy, name)
