"""Built-in local agent that runs on the server machine.

This agent:
- Registers with the cloud server
- Sends heartbeats with live system stats
- Scans files using YARA rules (including AI-learned rules)
- Reports findings to the server
- Works with the assistant's training system
- Runs in a background thread

No separate machine needed — it scans the local machine.
"""
import datetime
import hashlib
import os
import platform
import psutil
import socket
import threading
import time
import json
import requests
import urllib.parse
from datetime import timezone


def _is_valid_server_url(url):
    """Require http(s) with a host and no embedded credentials."""
    try:
        p = urllib.parse.urlparse(url)
        return p.scheme in ('http', 'https') and bool(p.hostname) and p.username is None and p.password is None
    except Exception:
        return False


class LocalAgent:
    """A built-in agent that scans the local machine and reports to the cloud server."""

    def __init__(self, server_url='https://isolation-bytes.com', api_key='',
                 device_id=None, scan_interval=300, scan_dirs=None):
        if not _is_valid_server_url(server_url):
            raise ValueError(f'Invalid server URL: {server_url}')
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        env_id = (os.environ.get('DEVICE_ID') or '').strip().strip('"').strip("'")
        self.device_id = (device_id or env_id) or f'LOCAL-{socket.gethostname().upper()[:12]}'
        self.hostname = socket.gethostname()
        self.scan_interval = scan_interval
        self.scan_dirs = scan_dirs or [
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop'),
            os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp')),
        ]
        self._thread = None
        self._running = False
        self._registered = False
        self._files_scanned = 0
        self._threats_blocked = 0
        self._quarantined_count = 0
        self._last_findings = []
        self._headers = {'X-Api-Key': api_key, 'Content-Type': 'application/json'}

    def _get_system_info(self):
        """Collect system information for registration."""
        try:
            vm = psutil.virtual_memory()
            return {
                'device_id': self.device_id,
                'hostname': self.hostname,
                'os': f'{platform.system()} {platform.release()}',
                'os_version': platform.version(),
                'arch': platform.machine(),
                'cpu': platform.processor() or 'Unknown',
                'ram_mb': int(vm.total / 1024 / 1024),
                'ip': self._get_local_ip(),
                'agent_version': '2.1.0-local',
            }
        except Exception:
            return {'device_id': self.device_id, 'hostname': self.hostname}

    def _get_live_stats(self):
        """Collect live system stats for heartbeat."""
        try:
            vm = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network_connections = []
            try:
                for c in psutil.net_connections(kind='inet'):
                    proc_name = 'Unknown'
                    if c.pid:
                        try:
                            proc_name = psutil.Process(c.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    network_connections.append({
                        'pid': c.pid or 0,
                        'process': proc_name,
                        'protocol': 'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                        'status': c.status or 'NONE',
                        'local_ip': c.laddr.ip if c.laddr else '',
                        'local_port': c.laddr.port if c.laddr else 0,
                        'remote_ip': c.raddr.ip if c.raddr else '',
                        'remote_port': c.raddr.port if c.raddr else 0,
                    })
            except Exception:
                pass
            all_processes = []
            try:
                for p in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'status']):
                    try:
                        info = dict(p.info)
                        try:
                            info['exe'] = p.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            info['exe'] = ''
                        all_processes.append(info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass
            return {
                'device_id': self.device_id,
                'cpu_usage': int(psutil.cpu_percent(interval=1)),
                'mem_usage': int(vm.percent),
                'disk_usage': int(disk.percent),
                'uptime': self._get_uptime(),
                'files_scanned': self._files_scanned,
                'threats_blocked': self._threats_blocked,
                'quarantined_count': self._quarantined_count,
                'network_connections': network_connections,
                'processes': all_processes,
                'process_count': len(all_processes),
                'connection_count': len(network_connections),
            }
        except Exception:
            return {'device_id': self.device_id}

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def _get_uptime(self):
        try:
            boot_time = psutil.boot_time()
            uptime_sec = int(time.time() - boot_time)
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            mins = (uptime_sec % 3600) // 60
            return f'{days}d {hours}h {mins}m'
        except Exception:
            return 'unknown'

    def _register(self):
        """Register with the cloud server."""
        try:
            info = self._get_system_info()
            r = requests.post(f'{self.server_url}/agent/register',
                              json=info, headers=self._headers,
                              verify=True, timeout=10)
            if r.status_code == 200:
                self._registered = True
                return True
        except Exception:
            pass
        return False

    def _heartbeat(self):
        """Send a heartbeat with live stats."""
        try:
            stats = self._get_live_stats()
            r = requests.post(f'{self.server_url}/agent/heartbeat',
                              json=stats, headers=self._headers,
                              verify=True, timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def _execute_voice_command(self, cmd):
        """Execute a voice command from the cloud queue and post back the result."""
        job_id = cmd.get('job_id')
        raw = cmd.get('command', '')
        apply_fix = bool(cmd.get('apply_fix', False))
        try:
            import voice_assistant
            intent = voice_assistant.parse_intent(raw)
            result = voice_assistant.run_command(intent, raw_command=raw, apply_fix=apply_fix)
            self._post_voice_result(job_id, 'completed', result)
        except Exception as e:
            self._post_voice_result(job_id, 'error', str(e))

    def _post_voice_result(self, job_id, status, result):
        """Report a voice command result back to the cloud queue."""
        try:
            requests.post(f'{self.server_url}/api/voice/agent/result',
                          json={'device_id': self.device_id, 'job_id': job_id,
                                'status': status, 'result': result},
                          headers=self._headers,
                          verify=True, timeout=15)
        except Exception:
            pass

    def _voice_poll(self):
        """Poll the cloud for queued voice commands and execute them locally."""
        try:
            r = requests.post(f'{self.server_url}/api/voice/agent/pending',
                              json={'device_id': self.device_id},
                              headers=self._headers,
                              verify=True, timeout=15)
            if r.status_code != 200:
                return
            commands = r.json().get('commands', [])
            for cmd in commands:
                threading.Thread(target=self._execute_voice_command,
                                 args=(cmd,), daemon=True).start()
        except Exception:
            pass

    def _scan_file_yara(self, filepath):
        """Scan a single file with YARA rules."""
        try:
            import sys
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if str(base_dir) not in sys.path:
                sys.path.insert(0, str(base_dir))
            from security.yara_scanner import scan_file_with_yara
            return scan_file_with_yara(filepath)
        except Exception:
            return []

    def _hash_file(self, filepath):
        """Calculate SHA256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def _quarantine_record(self, filepath):
        """Return the verified quarantine record for an original path, if any.

        YARA may quarantine a critical file during scan_file_with_yara().  The
        scan result must not claim quarantine merely because a match occurred;
        it is only considered quarantined when the quarantine subsystem has a
        corresponding encrypted artifact and log entry for this exact path.
        """
        try:
            from quarantine_utils import list_quarantine_files
            canonical = os.path.normcase(os.path.abspath(os.path.realpath(filepath)))
            for item in list_quarantine_files():
                original = item.get('original_path') or ''
                if os.path.normcase(os.path.abspath(os.path.realpath(original))) == canonical:
                    quarantine_path = item.get('path') or ''
                    if quarantine_path and os.path.isfile(quarantine_path):
                        return {
                            'quarantined': True,
                            'quarantine_path': quarantine_path,
                            'quarantine_error': '',
                        }
        except Exception:
            pass
        return {
            'quarantined': False,
            'quarantine_path': '',
            'quarantine_error': 'Quarantine artifact not found or could not be verified',
        }

    def _scan_directory(self, dirpath, max_files=100):
        """Scan a directory and return canonical, deduplicated findings."""
        findings = []
        if not os.path.isdir(dirpath):
            return findings

        scanned = 0
        seen_files = set()
        seen_findings = set()
        for root, dirs, files in os.walk(dirpath):
            for filename in files:
                if scanned >= max_files or not self._running:
                    break
                filepath = os.path.normcase(os.path.abspath(os.path.realpath(os.path.join(root, filename))))
                if filepath in seen_files:
                    continue
                seen_files.add(filepath)
                try:
                    if os.path.getsize(filepath) > 50 * 1024 * 1024:
                        continue

                    # Hash before YARA runs. Critical YARA matches may quarantine
                    # or remove the original before control returns here.
                    file_hash = self._hash_file(filepath)
                    matches = self._scan_file_yara(filepath)
                    self._files_scanned += 1

                    if matches:
                        quarantine = self._quarantine_record(filepath)
                        for m in matches:
                            rule = str(getattr(m, 'rule', '') or '')
                            finding_key = (filepath, rule)
                            if finding_key in seen_findings:
                                continue
                            seen_findings.add(finding_key)

                            sev = 'medium'
                            tags = list(getattr(m, 'tags', []) or [])
                            if any(str(t).lower() in ('critical', 'high') for t in tags):
                                sev = 'high'
                            if 'ransomware' in rule.lower() or 'ransom' in rule.lower():
                                sev = 'critical'

                            findings.append({
                                'path': filepath,
                                'original_path': filepath,
                                'severity': sev,
                                'threat_type': 'YARA',
                                'reason': f'YARA rule matched: {rule}',
                                'hash': file_hash,
                                'sha256': file_hash,
                                'rule': rule,
                                'tags': tags,
                                'quarantined': quarantine['quarantined'],
                                'quarantine_path': quarantine['quarantine_path'],
                                'quarantine_error': '' if quarantine['quarantined'] else quarantine['quarantine_error'],
                            })
                            self._threats_blocked += 1

                        if quarantine['quarantined']:
                            self._quarantined_count += 1
                    scanned += 1
                except Exception:
                    continue
            if scanned >= max_files:
                break
        return findings

    def _report(self, findings, report_type='scan'):
        """Send a report to the cloud server."""
        try:
            data = {
                'device_id': self.device_id,
                'type': report_type,
                'timestamp': datetime.datetime.now(timezone.utc).isoformat(),
                'files_scanned': self._files_scanned,
                'quarantined_count': self._quarantined_count,
                'findings': findings,
            }
            r = requests.post(f'{self.server_url}/cloud/agent/report',
                              json=data, headers=self._headers,
                              verify=True, timeout=15)
            return r.status_code == 200
        except Exception:
            return False

    def _scan_cycle(self):
        """Run one full scan cycle across all scan directories."""
        all_findings = []
        for dirpath in self.scan_dirs:
            if not self._running:
                break
            if os.path.isdir(dirpath):
                all_findings.extend(self._scan_directory(dirpath))

        if all_findings:
            self._last_findings = all_findings
            self._report(all_findings)
        else:
            self._report([], report_type='heartbeat_scan')

    def _run(self):
        """Main agent loop — runs in a background thread."""
        for _ in range(30):
            if not self._running:
                return
            try:
                r = requests.get(self.server_url, verify=True, timeout=5)
                if r.status_code < 500:
                    break
            except Exception:
                pass
            time.sleep(2)

        for attempt in range(5):
            if not self._running:
                return
            if self._register():
                break
            time.sleep(3)

        if not self._registered:
            return

        while self._running:
            try:
                self._heartbeat()
                self._scan_cycle()
            except Exception:
                pass

            for i in range(self.scan_interval):
                if not self._running:
                    break
                if i % 5 == 0:
                    self._voice_poll()
                time.sleep(1)

    def start(self):
        """Start the agent in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name='LocalAgent')
        self._thread.start()

    def stop(self):
        """Stop the agent."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def status(self):
        """Return current agent status."""
        return {
            'device_id': self.device_id,
            'hostname': self.hostname,
            'registered': self._registered,
            'running': self._running,
            'files_scanned': self._files_scanned,
            'threats_blocked': self._threats_blocked,
            'quarantined': self._quarantined_count,
            'last_findings_count': len(self._last_findings),
            'scan_dirs': self.scan_dirs,
        }


_local_agent = None


def get_local_agent():
    """Get the global local agent instance."""
    return _local_agent


def start_local_agent(server_url='https://isolation-bytes.com', api_key=''):
    """Start the built-in local agent."""
    global _local_agent
    if _local_agent and _local_agent._running:
        return _local_agent
    _local_agent = LocalAgent(server_url=server_url, api_key=api_key)
    _local_agent.start()
    return _local_agent


def stop_local_agent():
    """Stop the built-in local agent."""
    global _local_agent
    if _local_agent:
        _local_agent.stop()
        _local_agent = None
