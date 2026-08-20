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
import urllib3
import requests
from datetime import timezone

urllib3.disable_warnings()


class LocalAgent:
    """A built-in agent that scans the local machine and reports to the cloud server."""

    def __init__(self, server_url='https://127.0.0.1:8443', api_key='',
                 device_id=None, scan_interval=300, scan_dirs=None):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.device_id = device_id or f'LOCAL-{socket.gethostname().upper()[:12]}'
        self.hostname = socket.gethostname()
        self.scan_interval = scan_interval  # seconds between scans
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
            return {
                'device_id': self.device_id,
                'cpu_usage': int(psutil.cpu_percent(interval=1)),
                'mem_usage': int(vm.percent),
                'disk_usage': int(disk.percent),
                'uptime': self._get_uptime(),
                'files_scanned': self._files_scanned,
                'threats_blocked': self._threats_blocked,
                'quarantined_count': self._quarantined_count,
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
                              verify=False, timeout=10)
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
                              verify=False, timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def _scan_file_yara(self, filepath):
        """Scan a single file with YARA rules."""
        try:
            import sys
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if str(base_dir) not in sys.path:
                sys.path.insert(0, str(base_dir))
            from security.yara_scanner import scan_file_with_yara
            matches = scan_file_with_yara(filepath)
            return matches
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

    def _scan_directory(self, dirpath, max_files=100):
        """Scan a directory and return findings."""
        findings = []
        if not os.path.isdir(dirpath):
            return findings

        scanned = 0
        for root, dirs, files in os.walk(dirpath):
            for filename in files:
                if scanned >= max_files or not self._running:
                    break
                filepath = os.path.join(root, filename)
                try:
                    # Skip very large files (>50MB)
                    if os.path.getsize(filepath) > 50 * 1024 * 1024:
                        continue
                    matches = self._scan_file_yara(filepath)
                    self._files_scanned += 1
                    if matches:
                        h = self._hash_file(filepath)
                        for m in matches:
                            sev = 'medium'
                            tags = list(m.tags) if m.tags else []
                            if any(t in ('critical', 'high') for t in tags):
                                sev = 'high'
                            if 'ransomware' in m.rule.lower() or 'ransom' in m.rule.lower():
                                sev = 'critical'
                            findings.append({
                                'path': filepath,
                                'severity': sev,
                                'reason': f'YARA rule matched: {m.rule}',
                                'hash': h,
                                'rule': m.rule,
                                'tags': tags,
                            })
                            self._threats_blocked += 1
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
            r = requests.post(f'{self.server_url}/agent/report',
                              json=data, headers=self._headers,
                              verify=False, timeout=15)
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
                findings = self._scan_directory(dirpath)
                all_findings.extend(findings)

        if all_findings:
            self._last_findings = all_findings
            self._report(all_findings)
        else:
            # Send a clean report so the server knows we're alive
            self._report([], report_type='heartbeat_scan')

    def _run(self):
        """Main agent loop — runs in a background thread."""
        # Wait for server to be ready
        for _ in range(30):
            if not self._running:
                return
            try:
                r = requests.get(self.server_url, verify=False, timeout=5)
                if r.status_code < 500:
                    break
            except Exception:
                pass
            time.sleep(2)

        # Register
        for attempt in range(5):
            if not self._running:
                return
            if self._register():
                break
            time.sleep(3)

        if not self._registered:
            return

        # Main loop
        while self._running:
            try:
                # Heartbeat
                self._heartbeat()

                # Scan cycle
                self._scan_cycle()

            except Exception:
                pass

            # Wait for next cycle
            for _ in range(self.scan_interval):
                if not self._running:
                    break
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


# Global instance
_local_agent = None


def get_local_agent():
    """Get the global local agent instance."""
    return _local_agent


def start_local_agent(server_url='https://127.0.0.1:8443', api_key=''):
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
