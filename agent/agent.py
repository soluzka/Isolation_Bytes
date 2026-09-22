"""Minimal Windows security agent with dynamic process/network scoring."""
import hashlib
import ipaddress
import json
import os
import platform
import socket
import threading
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

try:
    import psutil
except Exception:
    psutil = None

try:
    import scan_utils
except Exception as exc:
    scan_utils = None
    print(f'Could not load scan_utils: {exc}')

try:
    from security.yara_scanner import scan_file_with_yara
except Exception as exc:
    scan_file_with_yara = None
    print(f'Could not load yara_scanner: {exc}')

try:
    from security.hardened_scan_pipeline import scan_target as hardened_scan_target
except Exception as exc:
    hardened_scan_target = None
    print(f'Could not load hardened scan pipeline: {exc}')

try:
    from threat_level_engine import threat_level_engine
except Exception as exc:
    threat_level_engine = None
    print(f'Could not load threat_level_engine: {exc}')

try:
    from network_blocking import (
        block_ip,
        block_suspicious_connection,
        is_windows_admin,
        should_auto_block_ip,
        should_block_suspicious_connection,
    )
except Exception as exc:
    block_ip = None
    block_suspicious_connection = None
    is_windows_admin = None
    should_auto_block_ip = None
    should_block_suspicious_connection = None
    print(f'Could not load network_blocking: {exc}')

try:
    import quarantine_utils
except Exception as exc:
    quarantine_utils = None
    print(f'Could not load quarantine_utils: {exc}')

try:
    from agent.prompt_learning import learn_from_prompt, recall_prompt_lessons
except Exception as exc:
    learn_from_prompt = None
    recall_prompt_lessons = lambda prompt, limit=5: []
    print(f'Prompt learning unavailable: {exc}')

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')
CLOUD_URL = os.environ.get('CLOUD_URL', 'http://localhost:5002').rstrip('/')
CLOUD_API_KEY = os.environ.get('CLOUD_API_KEY', '').strip()


def _get_device_id():
    default = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'AntivirusServer')
    runtime_dir = os.path.expandvars(os.environ.get('ANTIVIRUS_RUNTIME_DIR', default))
    lic_path = Path(runtime_dir) / 'credentials.lic'
    if lic_path.exists():
        try:
            lic = json.loads(lic_path.read_text(encoding='utf-8'))
            mid = lic.get('machine_id', '').strip()
            if mid:
                return mid
        except Exception:
            pass
    return os.environ.get('DEVICE_ID', '').strip() or hashlib.sha256(platform.node().encode()).hexdigest()[:16]


DEVICE_ID = _get_device_id()

_AGENT_START_LOCK = threading.Lock()
_AGENT_RUNTIME_STARTED = False
_AGENT_RUNTIME_THREADS = []


def ensure_agent_runtime():
    """Start the detector runtime once and reuse it for subsequent detections."""
    global _AGENT_RUNTIME_STARTED
    with _AGENT_START_LOCK:
        if _AGENT_RUNTIME_STARTED:
            return True
        if not CLOUD_API_KEY:
            # Local code scanning can still run without cloud credentials.
            return False
        try:
            register()
            targets = [
                (process_scan_loop, 'CodeScannerProcessMonitor'),
                (network_monitor_loop, 'CodeScannerNetworkMonitor'),
                (voice_command_loop, 'CodeScannerVoiceCommands'),
            ]
            for target, name in targets:
                thread = threading.Thread(target=target, name=name, daemon=True)
                thread.start()
                _AGENT_RUNTIME_THREADS.append(thread)
            _AGENT_RUNTIME_STARTED = True
            return True
        except Exception as exc:
            print(f'Could not start detector agent runtime: {exc}')
            return False


def _post(endpoint, payload):
    try:
        return requests.post(f'{CLOUD_URL}{endpoint}', json=payload,
                             headers={'X-Api-Key': CLOUD_API_KEY}, timeout=15, verify=True)
    except Exception as exc:
        print(f'Cloud connection failed: {exc}')
        return None


def register():
    _post('/agent/register', {'device_id': DEVICE_ID, 'hostname': platform.node()})


def send_heartbeat():
    resp = _post('/agent/heartbeat', {'device_id': DEVICE_ID})
    if not resp:
        return []
    try:
        return resp.json().get('commands', [])
    except Exception:
        return []


def report_scan(target, findings):
    _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'scan', 'target': target, 'findings': findings})


def _safe_yara_severity(matches):
    if not matches:
        return 0.0
    if isinstance(matches, str):
        return 0.85
    severities = []
    for match in matches if isinstance(matches, (list, tuple, set)) else [matches]:
        if isinstance(match, dict):
            value = match.get('severity', 0)
        else:
            value = getattr(match, 'severity', 0)
        if isinstance(value, str):
            severities.append({'critical': 1.0, 'high': 0.85, 'medium': 0.55, 'low': 0.25}.get(value.lower(), 0.0))
        else:
            try:
                severities.append(float(value))
            except (TypeError, ValueError):
                severities.append(0.85)
    return max(severities, default=0.0)


def _scan_ml_confidence(path, yara_matches=None):
    try:
        from ml_security import security_ml
        if not os.path.isfile(path) or not security_ml._is_fitted():
            return 0.0
        features = security_ml.get_features({'path': path, 'filename': os.path.basename(path)})
        _, scores = security_ml.predict(features)
        if scores is None:
            return 0.0
        return max(0.0, min(1.0, 0.5 - float(scores[0])))
    except Exception:
        return 0.0


def _assess(entity_id, *, yara_matches=None, ml_confidence=0.0, behavioral_signals=None):
    if threat_level_engine is None:
        return {'entity_id': entity_id, 'score': 0.0, 'level': 'clean'}
    return threat_level_engine.update(
        entity_id,
        yara_severity=_safe_yara_severity(yara_matches),
        ml_confidence=ml_confidence,
        behavioral_signals=behavioral_signals or {},
    )


def scan_target(target):
    """Route scans through the hardened pipeline and ensure detector runtime availability."""
    # A code-scanner invocation may happen before the long-running agent was
    # explicitly launched. Start the shared detector runtime once, then reuse
    # those same threads for later detections instead of spawning duplicates.
    ensure_agent_runtime()
    if not target or not os.path.exists(target):
        return [{'error': f'target not found: {target}'}]
    if hardened_scan_target is None:
        return [{'error': 'hardened scan pipeline unavailable', 'target': target}]
    try:
        return hardened_scan_target(target, quarantine=True)
    except Exception as exc:
        return [{'error': f'hardened scan failed: {exc}', 'target': target}]


def handle_command(cmd):
    target = cmd.get('target', '')
    if cmd.get('type') == 'scan':
        findings = scan_target(target)
        report_scan(target, findings)
    elif cmd.get('type') == 'quarantine':
        if quarantine_utils is not None and target and os.path.exists(target):
            try:
                quarantine_utils.quarantine_file(target, reason='cloud quarantine command')
                _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': target, 'ok': True})
            except Exception as exc:
                _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': target, 'error': str(exc)})
    else:
        print(f'Unknown command: {cmd}')


def _cloud_event_callback(event):
    _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'event', 'event': event})
    if quarantine_utils is not None and event.get('type') == 'malware_found' and event.get('exe'):
        try:
            quarantine_utils.quarantine_file(event['exe'], reason='malware found in running process')
            _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': event['exe']})
        except Exception as exc:
            print(f'Quarantine error: {exc}')


def _load_blocklists():
    repo = BASE_DIR.parent
    try:
        blocked = set(json.loads((repo / 'blocklists' / 'blocked_ips.json').read_text('utf-8')))
    except Exception:
        blocked = set()
    try:
        c2_ports = set(json.loads((repo / 'c2_ports.json').read_text('utf-8')))
    except Exception:
        c2_ports = set()
    return blocked, c2_ports


def _terminate_process(pid):
    if psutil is None or not pid:
        return False, 'process information unavailable'
    try:
        proc = psutil.Process(int(pid))
        if proc.pid == os.getpid():
            return False, 'refusing to terminate the monitoring agent itself'
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
        return True, 'terminated'
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as exc:
        return False, str(exc)


def network_monitor_loop():
    if psutil is None:
        print('psutil is unavailable; network monitoring disabled')
        return
    blocked_ips, c2_ports = _load_blocklists()
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr:
                    continue
                ip = getattr(conn.raddr, 'ip', None)
                port = getattr(conn.raddr, 'port', None)
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue

                port_signal = port in c2_ports
                known_blocked = ip in blocked_ips
                pid = getattr(conn, 'pid', None)
                owner = None
                owner_error = None
                if pid:
                    try:
                        owner = psutil.Process(pid).exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError) as exc:
                        owner_error = str(exc)

                assessment = _assess(
                    f'network:{ip}:{port}',
                    behavioral_signals={
                        'known_blocked_ip': 1.0 if known_blocked else 0.0,
                        'known_c2_port': 0.75 if port_signal else 0.0,
                        'repeated_remote_connection': 0.25 if getattr(conn, 'status', '') == 'ESTABLISHED' else 0.0,
                    },
                )
                confirmed_c2 = known_blocked or (port_signal and assessment.get('score', 0.0) >= 0.85)
                suspicious_connection = (
                    assessment.get('level') in ('high', 'critical')
                    and assessment.get('score', 0.0) >= 0.85
                ) or confirmed_c2
                firewall_blocked = False
                firewall_result = 'not_attempted'
                admin = is_windows_admin() if is_windows_admin is not None else False

                if suspicious_connection:
                    if block_suspicious_connection is None or should_block_suspicious_connection is None:
                        firewall_result = 'network_blocking suspicious-endpoint path unavailable'
                    elif not admin:
                        firewall_result = 'Windows Firewall blocking requires Administrator privileges'
                    elif should_block_suspicious_connection(
                        ip,
                        port,
                        threat_level=assessment,
                        confirmed_c2=confirmed_c2,
                    ):
                        firewall_blocked, firewall_result = block_suspicious_connection(
                            ip,
                            port,
                            program=owner,
                            pid=pid,
                            threat_level=assessment,
                            confirmed_c2=confirmed_c2,
                            reason=(
                                f"confirmed C2; threat={assessment.get('score', 0):.2f}"
                                if confirmed_c2
                                else f"high-confidence suspicious connection; threat={assessment.get('score', 0):.2f}"
                            ),
                        )
                        if firewall_blocked:
                            blocked_ips.add(ip)

                if known_blocked or port_signal or assessment.get('level') in ('high', 'critical') or suspicious_connection:
                    _post('/agent/report', {
                        'device_id': DEVICE_ID,
                        'type': 'network_alert',
                        'remote_ip': ip,
                        'remote_port': port,
                        'pid': pid,
                        'process_owner': owner,
                        'process_owner_error': owner_error,
                        'confirmed_c2': confirmed_c2,
                        'suspicious_connection': suspicious_connection,
                        'firewall_blocked': firewall_blocked,
                        'firewall_result': firewall_result,
                        'administrator': admin,
                        'reason': (
                            'confirmed C2' if confirmed_c2
                            else ('high-confidence suspicious connection' if suspicious_connection
                                  else ('blocked ip' if known_blocked else f'c2 port {port}'))
                        ),
                        'threat_assessment': assessment,
                    })
        except Exception as exc:
            print(f'Network monitor error: {exc}')
        time.sleep(30)


def process_scan_loop():
    try:
        from security import process_monitor
        def scan_func(path):
            if hardened_scan_target is not None:
                try:
                    result = hardened_scan_target(path, quarantine=False)
                    if not result:
                        return True, False, 'no result'
                    first = result[0]
                    suspicious = first.get('status') in ('suspicious_review_or_corroboration', 'quarantined')
                    return True, suspicious, first.get('status', 'scanned')
                except Exception as exc:
                    return False, False, str(exc)
            if scan_utils is None:
                return True, False, 'scan_utils not loaded'
            return scan_utils.scan_file_for_viruses(path)

        while True:
            try:
                process_monitor.scan_running_processes(
                    scan_func=scan_func,
                    terminate_on_malware=False,
                    block_connections=False,
                    event_callback=_cloud_event_callback,
                )
                if psutil is not None:
                    for proc in psutil.process_iter(['pid', 'name', 'exe']):
                        try:
                            pid = proc.info['pid']
                            exe = proc.info.get('exe')
                            if not exe or not os.path.isfile(exe):
                                continue
                            yara_matches = None
                            if scan_file_with_yara is not None:
                                try:
                                    yara_matches = scan_file_with_yara(exe)
                                except Exception:
                                    yara_matches = None
                            ml_confidence = _scan_ml_confidence(exe, yara_matches)
                            assessment = _assess(
                                f'process:{pid}', yara_matches=yara_matches,
                                ml_confidence=ml_confidence,
                                behavioral_signals={'running_executable': 0.25},
                            )
                            if assessment.get('level') == 'critical' or (assessment.get('level') == 'high' and yara_matches):
                                ok, reason = _terminate_process(pid)
                                _post('/agent/report', {
                                    'device_id': DEVICE_ID, 'type': 'process_response',
                                    'pid': pid, 'exe': exe, 'terminated': ok,
                                    'reason': reason, 'threat_assessment': assessment,
                                })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception as exc:
                print(f'Process scan error: {exc}')
            time.sleep(60)
    except Exception as exc:
        print(f'Could not start process monitor: {exc}')


def _post_voice_result(job_id, status, result):
    _post('/api/voice/agent/result', {'device_id': DEVICE_ID, 'job_id': job_id, 'status': status, 'result': result})


def _execute_voice_command(cmd):
    job_id = cmd.get('job_id')
    raw = cmd.get('command', '')
    apply_fix = bool(cmd.get('apply_fix', False))
    try:
        # Prior lessons are context only. They are never executed as commands.
        lessons = recall_prompt_lessons(raw, limit=3)
        import voice_assistant
        result = voice_assistant.run_command(
            voice_assistant.parse_intent(raw),
            raw_command=raw,
            apply_fix=apply_fix,
        )
        if learn_from_prompt is not None:
            learn_from_prompt(
                raw,
                str(result),
                outcome='completed',
                feedback=0,
            )
        _post_voice_result(job_id, 'completed', {
            'result': result,
            'learned_context': lessons,
        })
    except ImportError:
        if learn_from_prompt is not None:
            learn_from_prompt(raw, 'voice assistant unavailable', outcome='error', feedback=-1)
        _post_voice_result(job_id, 'error', 'This agent build does not support voice commands yet.')
    except Exception as exc:
        if learn_from_prompt is not None:
            learn_from_prompt(raw, str(exc), outcome='error', feedback=-1)
        _post_voice_result(job_id, 'error', str(exc))


def voice_command_loop():
    while True:
        try:
            resp = _post('/api/voice/agent/pending', {'device_id': DEVICE_ID})
            if resp is not None and resp.status_code == 200:
                for cmd in resp.json().get('commands', []):
                    threading.Thread(target=_execute_voice_command, args=(cmd,), daemon=True).start()
        except Exception:
            pass
        time.sleep(5)


def monitoring_snapshot():
    if psutil is None:
        return
    try:
        procs = [{'pid': p.pid, 'name': p.name()} for p in psutil.process_iter(['pid', 'name'])]
        conns = [{'laddr': c.laddr, 'raddr': c.raddr, 'status': c.status} for c in psutil.net_connections()]
        _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'monitoring', 'processes': procs[:50], 'connections': conns[:50]})
    except Exception as exc:
        print(f'Monitoring error: {exc}')


def main():
    if not CLOUD_API_KEY:
        raise RuntimeError('CLOUD_API_KEY not set in agent/.env')
    ensure_agent_runtime()
    while True:
        try:
            for cmd in send_heartbeat():
                handle_command(cmd)
            monitoring_snapshot()
        except Exception as exc:
            print(f'Agent error: {exc}')
        time.sleep(30)


if __name__ == '__main__':
    main()
