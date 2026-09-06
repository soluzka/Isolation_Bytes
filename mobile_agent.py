"""Isolation Bytes Mobile Agent — runs on Android via Termux.

Usage on Android:
    1. Install Termux from F-Droid (not Play Store — Play Store version is outdated)
    2. In Termux:
       pkg install python
       pip install psutil requests
       python mobile_agent.py --server https://isolation-bytes.com --key YOUR_API_KEY

This script:
- Registers the phone with the cloud server
- Sends heartbeats with battery, CPU, memory, and process stats
- Scans Download/Music/Pictures folders for threats
- Reports running processes and network connections
- Works without root (limited process visibility on Android)
"""
import argparse
import datetime
import hashlib
import os
import platform
import socket
import sys
import time
import threading
import json
import subprocess
import urllib.parse

from utils.subprocess_safe import safe_run

try:
    import psutil
except ImportError:
    print("Installing psutil...")
    safe_run([sys.executable, '-m', 'pip', 'install', 'psutil'],
                   capture_output=True, check=False,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    import psutil

try:
    import requests
except ImportError:
    print("Installing requests...")
    safe_run([sys.executable, '-m', 'pip', 'install', 'requests'],
                   capture_output=True, check=False,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    import requests

DEFAULT_SERVER = "https://isolation-bytes.com"
HEARTBEAT_INTERVAL = 30
SCAN_INTERVAL = 300
MAX_FILES_PER_SCAN = 100
MAX_FILE_SIZE = 30 * 1024 * 1024  # 30 MB


def _get_android_property(name):
    """Read an Android system property via getprop."""
    try:
        result = safe_run(
            ['getprop', name], capture_output=True, text=True, timeout=3
        )
        return result.stdout.strip()
    except Exception:
        return ''


def _get_battery_level():
    """Get battery percentage on Android."""
    try:
        with open('/sys/class/power_supply/battery/capacity', 'r') as f:
            return int(f.read().strip())
    except Exception:
        return -1


def _get_battery_charging():
    """Check if battery is charging."""
    try:
        with open('/sys/class/power_supply/battery/status', 'r') as f:
            status = f.read().strip().lower()
            return 'charging' in status
    except Exception:
        return False


def _get_android_scan_dirs():
    """Get scan directories on Android (Termux-accessible paths)."""
    dirs = []
    home = os.path.expanduser('~')
    # Termux home-based storage
    storage = os.path.join(home, 'storage')
    if os.path.isdir(storage):
        for sub in ['shared', 'downloads', 'music', 'pictures', 'dcim', 'movies', 'documents']:
            p = os.path.join(storage, sub)
            if os.path.isdir(p):
                dirs.append(p)
    # Direct paths
    for p in ['/sdcard/Download', '/sdcard/Documents', '/sdcard/Music',
              '/sdcard/Pictures', '/sdcard/DCIM', '/sdcard/Movies']:
        if os.path.isdir(p) and p not in dirs:
            dirs.append(p)
    # Fallback to home
    if not dirs:
        dirs.append(home)
    return dirs


def _is_valid_server_url(url):
    """Require http(s) with a host and no embedded credentials."""
    try:
        p = urllib.parse.urlparse(url)
        return p.scheme in ('http', 'https') and bool(p.hostname) and p.username is None and p.password is None
    except Exception:
        return False


class MobileAgent:
    def __init__(self, server_url, api_key, device_id=None):
        if not _is_valid_server_url(server_url):
            raise ValueError(f'Invalid server URL: {server_url}')
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        # Android device ID from getprop
        if not device_id:
            android_id = ''
            try:
                android_id = safe_run(
                    ['settings', 'get', 'secure', 'android_id'],
                    capture_output=True, text=True, timeout=3
                ).stdout.strip()
            except Exception:
                pass
            if not android_id:
                android_id = _get_android_property('ro.serialno') or 'unknown'
            model = _get_android_property('ro.product.model') or 'Android'
            self.device_id = f'ANDROID-{model[:10].upper()}-{android_id[:8]}'
        else:
            self.device_id = device_id
        self.hostname = _get_android_property('ro.product.model') or platform.node()
        self._running = False
        self._registered = False
        self._files_scanned = 0
        self._threats_blocked = 0
        self._quarantined_count = 0
        self._cached_network_devices = []
        self._headers = {'X-Api-Key': api_key, 'Content-Type': 'application/json'}
        self._scan_dirs = _get_android_scan_dirs()
        self._skipped_files = set()

    def _get_system_info(self):
        """Get system info for registration."""
        model = _get_android_property('ro.product.model') or 'Unknown'
        brand = _get_android_property('ro.product.brand') or ''
        manufacturer = _get_android_property('ro.product.manufacturer') or ''
        android_ver = _get_android_property('ro.build.version.release') or ''
        sdk = _get_android_property('ro.build.version.sdk') or ''
        serial = _get_android_property('ro.serialno') or ''
        return {
            'device_id': self.device_id,
            'hostname': self.hostname,
            'os': f'Android {android_ver}',
            'os_version': f'Android {android_ver} (SDK {sdk})',
            'arch': _get_android_property('ro.product.cpu.abi') or platform.machine(),
            'ip': self._get_local_ip(),
            'agent_version': 'mobile-1.0',
            'device_model': f'{manufacturer} {brand} {model}'.strip(),
            'serial': serial,
        }

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return ''

    def _get_live_stats(self):
        """Collect live system stats for heartbeat."""
        try:
            vm = psutil.virtual_memory()
            # CPU - Android may not support per-core on all devices
            try:
                cpu = int(psutil.cpu_percent(interval=1))
            except Exception:
                cpu = 0
            # Disk usage
            try:
                disk = psutil.disk_usage('/sdcard' if os.path.isdir('/sdcard') else '/')
            except Exception:
                disk = psutil.disk_usage('/')
            # Uptime
            boot_time = psutil.boot_time()
            uptime_sec = int(time.time() - boot_time)
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            mins = (uptime_sec % 3600) // 60
            # Battery
            battery = _get_battery_level()
            charging = _get_battery_charging()
            # Network connections
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
            # Processes (limited on Android without root)
            all_processes = []
            try:
                for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                    try:
                        info = p.info
                        all_processes.append({
                            'pid': info.get('pid', 0),
                            'name': info.get('name', 'Unknown'),
                            'user': info.get('username', 'unknown'),
                            'cpu': float(info.get('cpu_percent', 0) or 0),
                            'mem': float(info.get('memory_percent', 0) or 0),
                            'status': info.get('status', 'running'),
                            'connections': 0,
                            'exe': '',
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass
            return {
                'device_id': self.device_id,
                'cpu_usage': cpu,
                'mem_usage': int(vm.percent),
                'disk_usage': int(disk.percent),
                'uptime': f'{days}d {hours}h {mins}m',
                'files_scanned': self._files_scanned,
                'threats_blocked': self._threats_blocked,
                'quarantined_count': self._quarantined_count,
                'network_connections': network_connections,
                'network_devices': self._cached_network_devices,
                'processes': all_processes,
                'process_count': len(all_processes),
                'connection_count': len(network_connections),
                'battery': battery,
                'charging': charging,
            }
        except Exception:
            return {'device_id': self.device_id}

    def _register(self):
        try:
            info = self._get_system_info()
            r = requests.post(f'{self.server_url}/agent/register',
                              json=info, headers=self._headers,
                              verify=True, timeout=10)
            if r.status_code == 200:
                self._registered = True
                print(f"[OK] Registered with {self.server_url} as {self.device_id}")
                return True
            else:
                print(f"[ERROR] Registration failed: HTTP {r.status_code} {r.text}")
                return False
        except Exception as e:
            print(f"[ERROR] Registration failed: {e}")
            return False

    def _heartbeat(self):
        try:
            stats = self._get_live_stats()
            r = requests.post(f'{self.server_url}/agent/heartbeat',
                              json=stats, headers=self._headers,
                              verify=True, timeout=10)
            if r.status_code == 200:
                try:
                    resp = r.json()
                    cmds = resp.get('commands', [])
                    for cmd in cmds:
                        self._handle_command(cmd)
                except Exception:
                    pass
                return True
            return False
        except Exception:
            return False

    def _handle_command(self, cmd):
        """Handle a command from the cloud server."""
        action = cmd.get('action', '')
        ip = cmd.get('ip', '')
        if action == 'block_ip' and ip:
            print(f"[CMD] Block {ip} — not supported on mobile without root")
        elif action == 'unblock_ip' and ip:
            print(f"[CMD] Unblock {ip} — not supported on mobile without root")
        elif action == 'scan':
            target = cmd.get('target', '')
            if target:
                print(f"[CMD] Scan requested: {target}")

    def _scan_file_yara(self, filepath):
        """Scan a file with YARA rules if available."""
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            if base_dir not in sys.path:
                sys.path.insert(0, base_dir)
            from security.yara_scanner import scan_file_with_yara
            return scan_file_with_yara(filepath)
        except Exception:
            return []

    def _hash_file(self, filepath):
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def _scan_directory(self, dirpath, max_files=MAX_FILES_PER_SCAN):
        findings = []
        scanned = 0
        try:
            for root, dirs, files in os.walk(dirpath):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if filepath in self._skipped_files:
                        continue
                    try:
                        if os.path.getsize(filepath) > MAX_FILE_SIZE:
                            continue
                        if not os.access(filepath, os.R_OK):
                            self._skipped_files.add(filepath)
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
                                    'file': filepath,
                                    'rule': m.rule,
                                    'tags': tags,
                                    'severity': sev,
                                    'hash': h,
                                })
                    except Exception:
                        pass
                    scanned += 1
                    if scanned >= max_files:
                        break
                if scanned >= max_files:
                    break
        except Exception:
            pass
        return findings

    def _scan_cycle(self):
        all_findings = []
        for dirpath in self._scan_dirs:
            if os.path.isdir(dirpath):
                findings = self._scan_directory(dirpath)
                all_findings.extend(findings)
        if all_findings:
            print(f"[ALERT] Found {len(all_findings)} threat(s)!")
            self._report(all_findings)
        else:
            self._report([], report_type='heartbeat_scan')

    def _report(self, findings, report_type='scan'):
        try:
            data = {
                'device_id': self.device_id,
                'type': report_type,
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'files_scanned': self._files_scanned,
                'quarantined_count': self._quarantined_count,
                'findings': findings,
            }
            r = requests.post(f'{self.server_url}/agent/report',
                              json=data, headers=self._headers,
                              verify=True, timeout=15)
            return r.status_code == 200
        except Exception:
            return False

    def _heartbeat_loop(self):
        while self._running:
            try:
                ok = self._heartbeat()
                if not ok:
                    print("[WARN] Heartbeat failed — will retry")
            except Exception:
                pass
            for _ in range(HEARTBEAT_INTERVAL):
                if not self._running:
                    break
                time.sleep(1)

    def _network_scan_loop(self):
        """Background network device scanner."""
        while self._running:
            try:
                from security.network_devices import scan_network_devices
                devices = scan_network_devices()
                if devices:
                    self._cached_network_devices = devices
                    print(f"[NET] Found {len(devices)} device(s) on network")
            except Exception as e:
                print(f"[NET] Scan error: {e}")
            for _ in range(60):
                if not self._running:
                    break
                time.sleep(1)

    def _scan_loop(self):
        while self._running:
            try:
                self._scan_cycle()
            except Exception:
                pass
            for _ in range(SCAN_INTERVAL):
                if not self._running:
                    break
                time.sleep(1)

    def start(self):
        self._running = True
        print(f"Starting Isolation Bytes Mobile Agent")
        print(f"  Server:  {self.server_url}")
        print(f"  Device:  {self.device_id}")
        print(f"  Model:   {self.hostname}")
        print(f"  Battery: {_get_battery_level()}% ({'charging' if _get_battery_charging() else 'discharging'})")
        print()

        # Wait for server to be reachable
        print("Connecting to server...")
        for i in range(15):
            if not self._running:
                return
            try:
                r = requests.get(self.server_url, verify=True, timeout=5)
                if r.status_code < 500:
                    print("[OK] Server is reachable")
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            print("[ERROR] Could not reach server. Check your internet connection.")
            return

        # Register
        for attempt in range(5):
            if not self._running:
                return
            if self._register():
                break
            time.sleep(3)
        if not self._registered:
            print("[ERROR] Failed to register. Check your API key.")
            return

        # Start heartbeat thread
        hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True, name='Heartbeat')
        hb_thread.start()

        # Start network device scan thread
        net_thread = threading.Thread(target=self._network_scan_loop, daemon=True, name='NetScan')
        net_thread.start()

        # Start scan thread
        scan_thread = threading.Thread(target=self._scan_loop, daemon=True, name='Scanner')
        scan_thread.start()

        print()
        print("Mobile agent is running. Press Ctrl+C to stop.")
        print(f"  Heartbeats: every {HEARTBEAT_INTERVAL}s")
        print(f"  Scans:      every {SCAN_INTERVAL}s")
        print(f"  Directories: {', '.join(self._scan_dirs)}")
        print()

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping agent...")
            self._running = False


def main():
    parser = argparse.ArgumentParser(description='Isolation Bytes Mobile Agent')
    parser.add_argument('--server', default=DEFAULT_SERVER, help='Cloud server URL')
    parser.add_argument('--key', required=True, help='Cloud API key')
    parser.add_argument('--device-id', default=None, help='Custom device ID')
    parser.add_argument('--auto-start', action='store_true',
                        help='Register the agent to start automatically on boot (requires Termux:Boot on Android)')
    args = parser.parse_args()

    agent = MobileAgent(args.server, args.key, args.device_id)

    if args.auto_start:
        # Create Termux:Boot script for Android auto-start
        import os
        boot_dir = os.path.expanduser('~/.termux/boot')
        try:
            os.makedirs(boot_dir, exist_ok=True)
            boot_script = os.path.join(boot_dir, 'isolationbytes')
            exe = sys.executable
            script = os.path.abspath(__file__)
            content = f'''#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
{exe} {script} --server {args.server} --key={args.key}
'''
            with open(boot_script, 'w') as f:
                f.write(content)
            os.chmod(boot_script, 0o755)
            print(f"[STARTUP] Boot script created at {boot_script}")
            print("[STARTUP] Install Termux:Boot from F-Droid and open it once to activate auto-start")
        except Exception as e:
            print(f"[STARTUP] Failed to create boot script: {e}")

    agent.start()


if __name__ == '__main__':
    main()
