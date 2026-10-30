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

HEARTBEAT_INTERVAL = 5       # seconds between heartbeats (cloud treats 90s as offline)
DEFAULT_SCAN_INTERVAL = 300  # seconds between automatic sweeps


def _is_runtime_cache_path(filepath):
    """True for toolchain/package caches whose DLLs must not be quarantined."""
    try:
        path = os.path.abspath(str(filepath)).replace('\\', '/').lower()
    except (TypeError, ValueError, OSError):
        return False
    for marker in ('.nuget', '.dotnet', 'node_modules', 'site-packages',
                   '.gradle', '.m2'):
        if f'/{marker}/' in path or path.endswith('/' + marker):
            return True
    for marker in ('/program files/dotnet', '/program files (x86)/dotnet'):
        if marker in path:
            return True
    return False


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
                 device_id=None, scan_interval=DEFAULT_SCAN_INTERVAL, scan_dirs=None):
        if not _is_valid_server_url(server_url):
            raise ValueError(f'Invalid server URL: {server_url}')
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        env_id = (os.environ.get('DEVICE_ID') or '').strip().strip('"').strip("'")
        self.device_id = (device_id or env_id) or f'LOCAL-{socket.gethostname().upper()[:12]}'
        self.hostname = socket.gethostname()
        self.scan_interval = scan_interval
        self.scan_dirs = self._normalize_scan_dirs(
            scan_dirs or self._discover_default_scan_dirs())
        self._thread = None
        self._running = False
        self._registered = False
        self._files_scanned = 0
        self._threats_blocked = 0
        self._quarantined_count = 0
        self._last_findings = []
        self._counted_threat_files = set()
        self._last_progress_report = 0.0
        self._scan_lock = threading.Lock()
        self._scan_requested = threading.Event()
        self._headers = {'X-Api-Key': api_key, 'Content-Type': 'application/json'}

    @staticmethod
    def _normalize_scan_dirs(directories):
        """Expand, absolutize and de-duplicate monitored directories."""
        result = []
        seen = set()
        for directory in directories or []:
            try:
                path = os.path.abspath(os.path.expanduser(str(directory)))
            except (TypeError, ValueError, OSError):
                continue
            key = os.path.normcase(path)
            if key in seen:
                continue
            seen.add(key)
            result.append(path)
        return result

    @staticmethod
    def _discover_default_scan_dirs():
        """Return full-system scan roots, not just the user's common folders.

        The built-in agent is what the dashboard starts when no external
        agent is connected; scanning only Downloads/Desktop/Temp made a
        "full system scan" miss most of the machine.
        """
        try:
            from folder_watcher import discover_all_drives_and_important_folders
            discovered = discover_all_drives_and_important_folders()
            if discovered:
                return discovered
        except Exception:
            pass
        # Inline fallback (frozen EXE where folder_watcher may be unavailable).
        import platform as _platform
        import string as _string
        roots = []
        if _platform.system() == 'Windows':
            for letter in _string.ascii_uppercase:
                drive = f'{letter}:\\'
                if os.path.exists(drive):
                    roots.append(drive)
        else:
            roots.append('/')
        home = os.path.expanduser('~')
        roots.extend([os.path.join(home, 'Downloads'), os.path.join(home, 'Desktop')])
        return roots

    def _effective_scan_dirs(self):
        """Collapse overlapping roots so no file is traversed twice."""
        normalized = sorted(
            self._normalize_scan_dirs(self.scan_dirs),
            key=lambda p: (len(os.path.normcase(p)), os.path.normcase(p)),
        )
        roots = []
        root_keys = []
        for path in normalized:
            key = os.path.normcase(path)
            if any(key == kept or key.startswith(kept.rstrip(os.sep) + os.sep)
                   for kept in root_keys):
                continue
            roots.append(path)
            root_keys.append(key)
        return roots

    def _get_dir_file_counts(self):
        """Count direct children of each monitored directory for the heartbeat."""
        counts = {}
        for directory in self._effective_scan_dirs():
            try:
                files = 0
                subdirs = 0
                for entry in os.scandir(directory):
                    if entry.is_dir():
                        subdirs += 1
                    else:
                        files += 1
                counts[directory] = {'files': files, 'subdirs': subdirs}
            except (PermissionError, OSError):
                counts[directory] = {'files': 0, 'subdirs': 0}
        return counts

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
                'scan_dirs': self._effective_scan_dirs(),
            }
        except Exception:
            return {'device_id': self.device_id, 'hostname': self.hostname,
                    'scan_dirs': self._effective_scan_dirs()}

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
                'scanning': self._scan_lock.locked(),
                'scan_dirs': self._effective_scan_dirs(),
                'dir_file_counts': self._get_dir_file_counts(),
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
        """Send a heartbeat and execute any commands returned by the server."""
        try:
            stats = self._get_live_stats()
            r = requests.post(f'{self.server_url}/agent/heartbeat',
                              json=stats, headers=self._headers,
                              verify=True, timeout=10)
            if r.status_code == 404:
                # The server lost its agent registry (restart/redeploy);
                # re-register so scanning and triggers keep working.
                self._registered = False
                self._register()
                return False
            if r.status_code != 200:
                return False
            try:
                for cmd in (r.json() or {}).get('commands', []) or []:
                    if isinstance(cmd, dict):
                        self._handle_command(cmd)
            except Exception:
                pass
            return True
        except Exception:
            return False

    def _handle_command(self, cmd):
        """Handle a command queued by the cloud dashboard."""
        action = str(cmd.get('action') or '')
        if action == 'scan_now':
            print('[CMD] Full scan requested from cloud dashboard')
            if not self.request_scan():
                # A sweep is already traversing; publish its live progress
                # instead of queueing a redundant second full sweep.
                threading.Thread(target=self._report, args=([], 'scan_progress'),
                                 daemon=True).start()
            return
        if action == 'scan_file':
            filepath = cmd.get('file_path') or ''
            if filepath and os.path.isfile(filepath):
                threading.Thread(target=self._scan_single_file,
                                 args=(filepath,), daemon=True).start()
            else:
                print(f'[CMD] Scan file skipped (not a file): {filepath}')
            return
        if action == 'add_folder':
            folder = cmd.get('folder_path') or ''
            try:
                folder = os.path.abspath(os.path.expanduser(str(folder)))
            except (TypeError, ValueError, OSError):
                folder = ''
            if folder and os.path.isdir(folder) and os.path.normcase(folder) not in {
                os.path.normcase(d) for d in self.scan_dirs
            }:
                self.scan_dirs.append(folder)
                print(f'[CMD] Added scan folder: {folder}')
                self.request_scan()
            else:
                print(f'[CMD] Add folder skipped (not a directory or already monitored): {folder}')
            return
        if action == 'remove_folder':
            folder = cmd.get('folder_path') or ''
            target = os.path.normcase(os.path.abspath(os.path.expanduser(str(folder)))) if folder else ''
            remaining = [d for d in self.scan_dirs if os.path.normcase(d) != target]
            if folder and len(remaining) != len(self.scan_dirs):
                self.scan_dirs = remaining
                print(f'[CMD] Removed scan folder: {folder}')
            else:
                print(f'[CMD] Remove folder not found: {folder}')
            return

    def request_scan(self):
        """Ask the scan worker to start a sweep; False if one is already running."""
        if self._scan_lock.locked():
            return False
        self._scan_requested.set()
        return True

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

    def _count_blocked_threat(self, filepath):
        """Count a blocked threat once per file across repeated sweeps."""
        try:
            key = os.path.normcase(os.path.abspath(str(filepath)))
        except Exception:
            key = str(filepath)
        if key in self._counted_threat_files:
            return
        self._counted_threat_files.add(key)
        self._threats_blocked += 1

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

    @staticmethod
    def _match_severity(match):
        """Return the canonical severity for a YARA match (meta/tags fallback)."""
        try:
            from security.yara_scanner import get_match_severity
            severity = str(get_match_severity(match) or '').lower()
            if severity in ('low', 'medium', 'high', 'critical'):
                return severity
        except Exception:
            pass
        meta = getattr(match, 'meta', None) or {}
        severity = str(meta.get('severity', '') or '').lower()
        if severity in ('low', 'medium', 'high', 'critical'):
            return severity
        tags = {str(tag).lower() for tag in (getattr(match, 'tags', None) or [])}
        for level in ('critical', 'high', 'medium', 'low'):
            if level in tags:
                return level
        return 'medium'

    @staticmethod
    def _match_threat_type(match):
        """Classify a YARA match for the dashboard's threat-type counters."""
        meta = getattr(match, 'meta', None) or {}
        blob = ' '.join([
            str(getattr(match, 'rule', '') or ''),
            ' '.join(str(tag) for tag in (getattr(match, 'tags', None) or [])),
            str(meta.get('description', '') or meta.get('Description', '') or ''),
        ]).lower()
        if any(token in blob for token in (
                'ransom', 'vss_delete', 'shadow_copy', 'wbadmin',
                'recovery_disabl', 'backup_delete', 'ransomnote')):
            return 'ransomware'
        if any(token in blob for token in (
                'persist', 'startup', 'autorun', 'scheduled', 'rootkit',
                'keylog', 'backdoor', 'trojan', 'implant', 'beacon', 'botnet',
                'worm', 'miner', 'stealer', 'dropper', 'shellcode', 'exploit',
                'webshell', 'web_shell', 'spyware', 'adware', 'process_inject',
                'process_hollow', 'dll_hijack', 'api_hook', 'reflective_load',
                'amsi_bypass', 'etw_bypass', 'defender_bypass', 'uac_bypass',
                'privilege_escal', 'privesc', 'lateral_movement',
                'credsteal', 'exfil')):
            return 'persistence'
        return 'yara_match'

    def _scan_directory(self, dirpath, seen_files=None):
        """Scan a directory tree and return canonical, deduplicated findings.

        There is deliberately no file-count cap: a full scan must traverse the
        whole monitored folder. Quarantine artifacts are skipped because the
        original file is already contained under a different location.
        """
        findings = []
        if not os.path.isdir(dirpath):
            return findings

        try:
            from quarantine_utils import QUARANTINE_FOLDER
            quarantine_root = os.path.normcase(os.path.abspath(QUARANTINE_FOLDER))
        except Exception:
            quarantine_root = ''

        if seen_files is None:
            seen_files = set()
        seen_findings = set()
        for root, dirs, files in os.walk(dirpath):
            if not self._running:
                break
            root_key = os.path.normcase(os.path.abspath(root))
            if quarantine_root and (
                    root_key == quarantine_root
                    or root_key.startswith(quarantine_root + os.sep)):
                dirs[:] = []
                continue
            if _is_runtime_cache_path(root):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs
                       if not _is_runtime_cache_path(os.path.join(root, d))]
            for filename in files:
                if not self._running:
                    break
                filepath = os.path.abspath(os.path.realpath(os.path.join(root, filename)))
                if _is_runtime_cache_path(filepath):
                    continue
                file_key = os.path.normcase(filepath)
                if file_key in seen_files:
                    continue
                seen_files.add(file_key)
                try:
                    # Hash before YARA runs. Critical YARA matches may quarantine
                    # or remove the original before control returns here.
                    file_hash = self._hash_file(filepath)
                    matches = self._scan_file_yara(filepath)
                    self._files_scanned += 1
                    now = time.time()
                    if now - self._last_progress_report >= 5:
                        self._last_progress_report = now
                        self._report([], report_type='scan_progress')

                    if matches:
                        quarantine = self._quarantine_record(filepath)
                        for m in matches:
                            rule = str(getattr(m, 'rule', '') or '')
                            finding_key = (filepath, rule)
                            if finding_key in seen_findings:
                                continue
                            seen_findings.add(finding_key)

                            sev = self._match_severity(m)
                            tags = list(getattr(m, 'tags', []) or [])

                            findings.append({
                                'path': filepath,
                                'original_path': filepath,
                                'severity': sev,
                                'threat_type': self._match_threat_type(m),
                                'reason': f'YARA rule matched: {rule}',
                                'hash': file_hash,
                                'sha256': file_hash,
                                'rule': rule,
                                'tags': tags,
                                'quarantined': quarantine['quarantined'],
                                'quarantine_path': quarantine['quarantine_path'],
                            })
                            self._count_blocked_threat(filepath)

                        if quarantine['quarantined']:
                            self._quarantined_count += 1
                except Exception:
                    continue
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
                'threats_blocked': self._threats_blocked,
                'scan_dirs': self._effective_scan_dirs(),
                'scanning': self._scan_lock.locked(),
                'findings': findings,
            }
            r = requests.post(f'{self.server_url}/agent/report',
                              json=data, headers=self._headers,
                              verify=True, timeout=120)
            return r.status_code == 200
        except Exception:
            return False

    def _scan_cycle(self):
        """Run one full sweep across all monitored directories."""
        if not self._scan_lock.acquire(blocking=False):
            return
        all_findings = []
        seen_files = set()
        try:
            for dirpath in self._effective_scan_dirs():
                if not self._running:
                    break
                if not os.path.isdir(dirpath):
                    continue
                findings = self._scan_directory(dirpath, seen_files=seen_files)
                all_findings.extend(findings)
                # Report after each directory so the dashboard fills in while
                # the sweep is still running instead of only at the very end.
                self._report(findings, report_type='scan' if findings else 'scan_progress')
            if all_findings:
                self._last_findings = all_findings
                print(f'[SCAN] Sweep found {len(all_findings)} finding(s)')
        finally:
            # Release first so the report carries scanning=False and the
            # dashboard can stop polling as soon as the sweep ends.
            # The complete snapshot lets the cloud replace stale findings.
            self._scan_lock.release()
            self._report(all_findings, report_type='scan_complete')

    def _scan_single_file(self, filepath):
        """Scan one file requested from the dashboard and report it."""
        findings = []
        try:
            print(f'[SCAN] Scanning single file: {filepath}')
            file_hash = self._hash_file(filepath)
            matches = self._scan_file_yara(filepath)
            self._files_scanned += 1
            quarantine = self._quarantine_record(filepath)
            for match in matches:
                rule = str(getattr(match, 'rule', '') or '')
                tags = list(getattr(match, 'tags', []) or [])
                findings.append({
                    'path': filepath,
                    'original_path': filepath,
                    'severity': self._match_severity(match),
                    'threat_type': self._match_threat_type(match),
                    'reason': f'YARA rule matched: {rule}',
                    'hash': file_hash,
                    'sha256': file_hash,
                    'rule': rule,
                    'tags': tags,
                    'quarantined': quarantine['quarantined'],
                    'quarantine_path': quarantine['quarantine_path'],
                })
                self._count_blocked_threat(filepath)
            if quarantine['quarantined']:
                self._quarantined_count += 1
            self._report(findings, report_type='single_file_scan')
        except Exception as exc:
            print(f'[SCAN] Single file scan failed: {exc}')
            self._report([], report_type='single_file_scan')

    def _heartbeat_loop(self):
        """Heartbeat independently so the agent never looks offline mid-scan."""
        beats = 0
        while self._running:
            try:
                self._heartbeat()
                beats += 1
                if beats % 3 == 0:
                    self._voice_poll()
            except Exception:
                pass
            for _ in range(HEARTBEAT_INTERVAL):
                if not self._running:
                    break
                time.sleep(1)

    def _scan_loop(self):
        """Run automatic sweeps, waking early when a scan is requested."""
        while self._running:
            try:
                self._scan_requested.wait(timeout=self.scan_interval)
                self._scan_requested.clear()
                if not self._running:
                    break
                self._scan_cycle()
            except Exception as exc:
                print(f'[SCAN] Sweep failed: {exc}')
                time.sleep(1)

    def _run(self):
        """Register, then run heartbeat and scan workers in the background."""
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
            # Allow a later dashboard trigger to start a fresh agent instead of
            # handing back a dead instance whose scan worker was never created.
            self._running = False
            return

        threading.Thread(target=self._heartbeat_loop, daemon=True,
                         name='LocalAgentHeartbeat').start()
        # The first automatic sweep starts right away, then every scan_interval.
        self._scan_requested.set()
        threading.Thread(target=self._scan_loop, daemon=True,
                         name='LocalAgentScanner').start()

        while self._running:
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
        self._scan_requested.set()
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
            'scanning': self._scan_lock.locked(),
            'scan_dirs': self._effective_scan_dirs(),
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
