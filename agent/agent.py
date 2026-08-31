"""Minimal Windows agent for the cloud antivirus split.

This runs on the customer PC. It sends heartbeats and scan reports to the
cloud server and receives commands (scan, update, quarantine) from it.

Full integration with the local security modules is still needed.
"""
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
    import scan_utils
except Exception as e:
    scan_utils = None
    print(f'Could not load scan_utils: {e}')

try:
    from security.yara_scanner import scan_file_with_yara
except Exception as e:
    scan_file_with_yara = None
    print(f'Could not load yara_scanner: {e}')

try:
    import quarantine_utils
except Exception as e:
    quarantine_utils = None
    print(f'Could not load quarantine_utils: {e}')


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

CLOUD_URL = os.environ.get('CLOUD_URL', 'http://localhost:5002').rstrip('/')
CLOUD_API_KEY = os.environ.get('CLOUD_API_KEY', '').strip()


def _get_device_id():
    # Use the same machine ID from the launcher's license if it exists.
    default = os.path.join(os.environ.get('ProgramData', r'C:\\ProgramData'), 'AntivirusServer')
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


def _post(endpoint, payload):
    try:
        return requests.post(
            f'{CLOUD_URL}{endpoint}',
            json=payload,
            headers={'X-Api-Key': CLOUD_API_KEY},
            timeout=15,
            verify=True
        )
    except Exception as e:
        print(f'Cloud connection failed: {e}')
        return None


def register():
    print(f'Registering agent {DEVICE_ID} with cloud')
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


def scan_target(target):
    findings = []
    if not target or not os.path.exists(target):
        return [{'error': f'target not found: {target}'}]
    if os.path.isfile(target):
        if scan_utils is not None:
            success, found, msg = scan_utils.scan_file_for_viruses(target)
            findings.append({'path': target, 'success': success, 'malware_found': found, 'message': msg})
        if scan_file_with_yara is not None:
            try:
                yara_matches = scan_file_with_yara(target)
                if yara_matches:
                    findings.append({'path': target, 'yara_matches': yara_matches})
            except Exception as e:
                findings.append({'path': target, 'yara_error': str(e)})
    elif os.path.isdir(target):
        if scan_utils is not None:
            try:
                results = scan_utils.scan_all_folders_with_yara([target])
                findings.extend([{'message': r} for r in results])
            except Exception as e:
                findings.append({'error': str(e)})
    return findings


def handle_command(cmd):
    target = cmd.get('target', '')
    if cmd.get('type') == 'scan':
        print(f'Cloud requested scan of: {target}')
        findings = scan_target(target)
        report_scan(target, findings)
    elif cmd.get('type') == 'quarantine':
        print(f'Cloud requested quarantine of: {target}')
        if quarantine_utils is not None and target and os.path.exists(target):
            try:
                quarantine_utils.quarantine_file(target, reason='cloud quarantine command')
                _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': target, 'ok': True})
            except Exception as e:
                _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': target, 'error': str(e)})
        else:
            _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': target, 'error': 'target not found or quarantine not loaded'})
    else:
        print(f'Unknown command: {cmd}')


def _cloud_event_callback(event):
    try:
        _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'event', 'event': event})
    except Exception as e:
        print(f'Failed to send event: {e}')
    if quarantine_utils is not None and event.get('type') == 'malware_found' and event.get('exe'):
        try:
            quarantine_utils.quarantine_file(event['exe'], reason='malware found in running process')
            _post('/agent/report', {'device_id': DEVICE_ID, 'type': 'quarantine', 'path': event['exe']})
        except Exception as e:
            print(f'Quarantine error: {e}')


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


def network_monitor_loop():
    try:
        import psutil
        blocked_ips, c2_ports = _load_blocklists()
    except Exception as e:
        print(f'Could not load network blocklists: {e}')
        return
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr:
                    continue
                remote = conn.raddr
                ip = remote.ip
                port = remote.port
                reason = None
                if ip in blocked_ips:
                    reason = f'blocked ip {ip}'
                elif port in c2_ports:
                    reason = f'c2 port {port}'
                if reason:
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    _post('/agent/report', {
                        'device_id': DEVICE_ID,
                        'type': 'network_alert',
                        'remote_ip': ip,
                        'remote_port': port,
                        'pid': conn.pid,
                        'reason': reason
                    })
        except Exception as e:
            print(f'Network monitor error: {e}')
        time.sleep(30)


def process_scan_loop():
    try:
        from security import process_monitor
        if scan_utils is not None:
            def scan_func(path):
                return scan_utils.scan_file_for_viruses(path)
        else:
            def scan_func(path):
                return (True, False, 'scan_utils not loaded')
        while True:
            try:
                process_monitor.scan_running_processes(
                    scan_func=scan_func,
                    terminate_on_malware=True,
                    block_connections=False,
                    event_callback=_cloud_event_callback
                )
            except Exception as e:
                print(f'Process scan error: {e}')
            time.sleep(60)
    except Exception as e:
        print(f'Could not start process monitor: {e}')


def _post_voice_result(job_id, status, result):
    """Report a voice command result back to the cloud queue."""
    _post('/api/voice/agent/result', {
        'device_id': DEVICE_ID,
        'job_id': job_id,
        'status': status,
        'result': result,
    })


def _execute_voice_command(cmd):
    """Execute a queued voice command on this PC and post back the result."""
    job_id = cmd.get('job_id')
    raw = cmd.get('command', '')
    apply_fix = bool(cmd.get('apply_fix', False))
    try:
        import voice_assistant
        intent = voice_assistant.parse_intent(raw)
        result = voice_assistant.run_command(intent, raw_command=raw, apply_fix=apply_fix)
        _post_voice_result(job_id, 'completed', result)
    except ImportError:
        _post_voice_result(job_id, 'error',
                           'This agent build does not support voice commands yet.')
    except Exception as e:
        _post_voice_result(job_id, 'error', str(e))


def voice_command_loop():
    """Poll the cloud for queued voice commands and execute them locally."""
    while True:
        try:
            resp = _post('/api/voice/agent/pending', {'device_id': DEVICE_ID})
            if resp is not None and resp.status_code == 200:
                for cmd in resp.json().get('commands', []):
                    threading.Thread(target=_execute_voice_command,
                                     args=(cmd,), daemon=True).start()
        except Exception:
            pass
        time.sleep(5)


def monitoring_snapshot():
    try:
        import psutil
        procs = [{'pid': p.pid, 'name': p.name()} for p in psutil.process_iter(['pid', 'name'])]
        conns = [{'laddr': c.laddr, 'raddr': c.raddr, 'status': c.status} for c in psutil.net_connections()]
        _post('/agent/report', {
            'device_id': DEVICE_ID,
            'type': 'monitoring',
            'processes': procs[:50],
            'connections': conns[:50]
        })
    except Exception as e:
        print(f'Monitoring error: {e}')


def main():
    if not CLOUD_API_KEY:
        raise RuntimeError('CLOUD_API_KEY not set in agent/.env')
    register()
    threading.Thread(target=process_scan_loop, daemon=True).start()
    threading.Thread(target=network_monitor_loop, daemon=True).start()
    threading.Thread(target=voice_command_loop, daemon=True).start()
    while True:
        try:
            commands = send_heartbeat()
            for cmd in commands:
                handle_command(cmd)
            monitoring_snapshot()
        except Exception as e:
            print(f'Agent error: {e}')
        time.sleep(30)


if __name__ == '__main__':
    main()
