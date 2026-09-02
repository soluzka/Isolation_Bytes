import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import timedelta

from flask import Blueprint, jsonify, redirect, render_template, request, session

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

voice_bp = Blueprint('voice_assistant', __name__, template_folder='templates')
logger = logging.getLogger('voice_assistant')


def _safe_run(cmd, timeout=15, shell=False):
    """Run a subprocess and return stripped stdout, or an error string."""
    try:
        kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'timeout': timeout,
            'shell': shell,
        }
        if sys.platform == 'win32':
            kwargs.setdefault('creationflags', 0x08000000)  # CREATE_NO_WINDOW
        proc = subprocess.run(cmd, **kwargs)
        out = proc.stdout.decode('utf-8', errors='replace').strip()
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', errors='replace').strip()
            return f"exit {proc.returncode}: {err or out}"
        return out
    except FileNotFoundError:
        return f"command not found: {cmd[0] if isinstance(cmd, list) else cmd}"
    except Exception as e:
        logger.exception('subprocess failed')
        return str(e)


# ---------------------------------------------------------------------------
# Command intent catalogue
# ---------------------------------------------------------------------------
COMMANDS = {
    'status': {
        'keywords': ['status', 'health', 'overview', 'summary', 'how is my pc',
                     'system health', 'check my computer', 'pc health'],
        'description': 'overall system health summary',
    },
    'cpu': {
        'keywords': ['cpu', 'processor', 'slow computer', 'high cpu',
                     'cpu usage', 'processor load'],
        'description': 'CPU usage and core information',
    },
    'memory': {
        'keywords': ['memory', 'ram', 'out of memory', 'memory usage', 'high ram',
                     'low memory'],
        'description': 'RAM and swap usage',
    },
    'disk': {
        'keywords': ['disk', 'drive', 'storage', 'hard drive', 'ssd', 'full disk',
                     'disk space', 'disk usage', 'low space'],
        'description': 'disk space and health',
    },
    'network': {
        'keywords': ['network', 'internet', 'wifi', 'connection', 'ping',
                     'no internet', 'slow internet', 'connectivity'],
        'description': 'network connectivity diagnostics',
    },
    'hardware': {
        'keywords': ['hardware', 'specs', 'specifications', 'motherboard', 'gpu',
                     'graphics', 'device', 'components'],
        'description': 'hardware component details',
    },
    'temperatures': {
        'keywords': ['temperature', 'overheating', 'hot', 'thermal', 'fan',
                     'cooling'],
        'description': 'thermal sensor readings',
    },
    'processes': {
        'keywords': ['processes', 'apps', 'programs', 'running', 'slow apps',
                     'top processes'],
        'description': 'top processes by resource usage',
    },
    'services': {
        'keywords': ['services', 'background services', 'system services'],
        'description': 'running system services',
    },
    'temp_files': {
        'keywords': ['temp files', 'temporary files', 'junk', 'cleanup',
                     'disk cleanup', 'free space', 'clear cache'],
        'description': 'temporary file cleanup',
    },
    'drivers': {
        'keywords': ['drivers', 'device driver', 'missing driver', 'update driver'],
        'description': 'installed hardware drivers',
    },
    'updates': {
        'keywords': ['updates', 'patches', 'windows update', 'system update',
                     'security update', 'patch status'],
        'description': 'available system and security updates',
    },
    'dns': {
        'keywords': ['dns', 'flush dns', 'domain name', 'resolve'],
        'description': 'DNS cache and resolution',
    },
    'ip': {
        'keywords': ['ip', 'ip address', 'renew ip', 'dhcp', 'release ip'],
        'description': 'IP configuration and DHCP renewal',
    },
    'checkdisk': {
        'keywords': ['check disk', 'chkdsk', 'fsck', 'disk errors', 'bad sectors',
                     'scan drive'],
        'description': 'disk error checking',
    },
    'restart_service': {
        'keywords': ['restart service', 'restart', 'start service', 'stop service'],
        'description': 'restart a named service',
    },
    'help': {
        'keywords': ['help', 'what can you do', 'commands', 'assist'],
        'description': 'list available voice commands',
    },
    'virus_scan': {
        'keywords': ['scan for virus', 'run antivirus scan', 'scan my computer',
                     'check for malware', 'find virus', 'remove virus', 'virus scan',
                     'virus', 'malware', 'infected'],
        'description': 'scan high-risk files for malware with YARA',
    },
    'miner_check': {
        'keywords': ['miner', 'crypto miner', 'mining virus', 'xmrig', 'high cpu virus',
                     'virus using my cpu', 'bitcoin miner', 'mining', 'mine',
                     'cryptominer', 'rig'],
        'description': 'detect cryptocurrency-mining malware',
    },
    'hardware_virus': {
        'keywords': ['hardware virus', 'virus overheating', 'computer hot virus',
                     'virus using hardware', 'fan loud virus', 'pc hot virus',
                     'hot virus', 'virus overheating', 'virus making hot'],
        'description': 'check if viruses or miners are stressing hardware',
    },
}

# Known crypto-miner and hardware-abuse signatures.
MINER_SIGNATURES = {
    'names': {'xmrig', 'minerd', 'nanominer', 't-rex', 'trex', 'nbminer',
              'gminer', 'lolminer', 'teamredminer', 'phoenixminer',
              'excavator', 'ccminer', 'cgminer', 'sgminer', 'bfgminer',
              'nicehash', 'miner', 'mining', 'stratum', 'pool', 'hashrate'},
    'pools': {'stratum+tcp', 'stratum+ssl', 'xmrig', 'minexmr', 'supportxmr',
              'nanopool', 'ethermine', 'f2pool', 'poolin', 'antpool',
              'nicehash.com', 'miningpoolhub'},
    'ports': {3333, 4444, 5555, 7777, 45700, 45701, 80, 443, 8080},
}


class SemanticRouter:
    """Optional ML-based command classifier using sentence-transformers."""

    def __init__(self):
        self._model = None
        self._corpus = None
        self._labels = None
        self._available = self._probe()

    @staticmethod
    def _probe():
        try:
            import sentence_transformers  # noqa: F401
            return True
        except Exception:
            return False

    def _load(self):
        if self._model is not None:
            return True
        if not self._available:
            return False
        try:
            from sentence_transformers import SentenceTransformer, util
            model_name = os.environ.get('VOICE_EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
            self._model = SentenceTransformer(model_name)
            self._util = util
            # Build corpus from keyword examples and descriptions.
            corpus = []
            labels = []
            for intent, meta in COMMANDS.items():
                examples = meta['keywords']
                if meta['description'] not in examples:
                    examples = examples + [meta['description']]
                for ex in examples:
                    corpus.append(ex)
                    labels.append(intent)
            self._corpus = corpus
            self._labels = labels
            self._embeddings = self._model.encode(corpus, convert_to_tensor=True)
            logger.info('Voice assistant semantic router loaded with %s examples', len(corpus))
            return True
        except Exception as e:
            logger.warning('Could not load sentence-transformers voice model: %s', e)
            self._available = False
            return False

    def classify(self, command):
        if not self._load():
            return None
        try:
            embedding = self._model.encode(command, convert_to_tensor=True)
            scores = self._util.cos_sim(embedding, self._embeddings)[0]
            best_idx = int(scores.argmax())
            best_score = float(scores[best_idx])
            if best_score >= 0.45:
                return self._labels[best_idx], best_score
        except Exception as e:
            logger.warning('Semantic classification failed: %s', e)
        return None


_semantic_router = SemanticRouter()


def _split_service_name(raw_command):
    """Try to extract a service name after a restart/start/stop keyword."""
    text = raw_command.lower()
    for prefix in ('restart service', 'start service', 'stop service', 'restart'):
        if text.startswith(prefix):
            return raw_command[len(prefix):].strip().strip('"').strip("'")
    return None


def parse_intent(raw_command):
    text = raw_command.lower()
    best = None
    best_score = 0
    for intent, meta in COMMANDS.items():
        score = 0
        for kw in meta['keywords']:
            if kw in text:
                score += len(kw.split())  # weight multi-word matches higher
        if score > best_score:
            best_score = score
            best = intent

    # Prefer the hardware-virus intent when the user mentions virus/malware/miner
    # alongside a thermal, CPU, or fan symptom.
    if best in ('cpu', 'memory', 'temperatures', 'disk', 'processes', None):
        if any(w in text for w in ('virus', 'malware', 'miner', 'mining', 'infected')):
            if any(w in text for w in ('hot', 'overheat', 'heat', 'fan', 'loud', 'temperature', 'burning')):
                best = 'hardware_virus'

    semantic = _semantic_router.classify(raw_command)
    if semantic:
        sem_intent, sem_score = semantic
        # Allow semantic match to override keyword when the score is strong
        # or when keyword matching returned nothing.
        if best is None or sem_score >= 0.6:
            return sem_intent
    return best


# ---------------------------------------------------------------------------
# Diagnostic implementations
# ---------------------------------------------------------------------------
def _bytes_to_gb(n):
    return round(n / (1024 ** 3), 2)


def _uptime():
    if psutil is None:
        return None
    return str(timedelta(seconds=int(time.time() - psutil.boot_time())))


def get_status():
    if psutil is None:
        return _make_response('status', 'psutil is not available; cannot run diagnostics.', success=False)
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot = _uptime()
    summary = (
        f"System has been up for {boot}. CPU is at {cpu}% usage, "
        f"memory is {mem.percent}% used, and the root drive has "
        f"{_bytes_to_gb(disk.free)} GB free out of {_bytes_to_gb(disk.total)} GB."
    )
    details = {
        'platform': platform.platform(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor(),
        'uptime': boot,
        'cpu_percent': cpu,
        'memory_percent': mem.percent,
        'memory_free_gb': _bytes_to_gb(mem.available),
        'disk_free_gb': _bytes_to_gb(disk.free),
        'disk_total_gb': _bytes_to_gb(disk.total),
    }
    return _make_response('status', summary, details)


def get_cpu():
    if psutil is None:
        return _make_response('cpu', 'psutil is not available.', success=False)
    per_cpu = psutil.cpu_percent(interval=0.5, percpu=True)
    freq = getattr(psutil, 'cpu_freq', lambda: None)()
    summary = (
        f"CPU usage per core is {per_cpu}. The system has {psutil.cpu_count(logical=False)} "
        f"physical cores and {psutil.cpu_count(logical=True)} logical cores."
    )
    if freq:
        summary += f" Current frequency is {freq.current:.0f} MHz."
    details = {
        'percent_per_core': per_cpu,
        'physical_cores': psutil.cpu_count(logical=False),
        'logical_cores': psutil.cpu_count(logical=True),
        'frequency_mhz': freq.current if freq else None,
    }
    return _make_response('cpu', summary, details)


def get_memory():
    if psutil is None:
        return _make_response('memory', 'psutil is not available.', success=False)
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    summary = (
        f"Memory is {mem.percent}% used ({_bytes_to_gb(mem.used)} GB of "
        f"{_bytes_to_gb(mem.total)} GB). Swap is {swap.percent}% used."
    )
    details = {
        'percent': mem.percent,
        'total_gb': _bytes_to_gb(mem.total),
        'used_gb': _bytes_to_gb(mem.used),
        'available_gb': _bytes_to_gb(mem.available),
        'swap_percent': swap.percent,
        'swap_total_gb': _bytes_to_gb(swap.total),
        'swap_used_gb': _bytes_to_gb(swap.used),
    }
    return _make_response('memory', summary, details)


def get_disk():
    if psutil is None:
        return _make_response('disk', 'psutil is not available.', success=False)
    partitions = []
    summary_parts = []
    for p in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(p.mountpoint)
            partitions.append({
                'device': p.device,
                'mountpoint': p.mountpoint,
                'fstype': p.fstype,
                'total_gb': _bytes_to_gb(usage.total),
                'used_gb': _bytes_to_gb(usage.used),
                'free_gb': _bytes_to_gb(usage.free),
                'percent': usage.percent,
            })
            summary_parts.append(
                f"{p.mountpoint} is {usage.percent}% full ({_bytes_to_gb(usage.free)} GB free)"
            )
        except (PermissionError, OSError):
            continue
    summary = 'Disk usage: ' + '; '.join(summary_parts) if summary_parts else 'No accessible disk partitions found.'
    suggestion = None
    high = [p for p in partitions if p['percent'] >= 90]
    if high:
        suggestion = 'One or more drives are over 90% full. Run a cleanup or delete unneeded files.'
    return _make_response('disk', summary, {'partitions': partitions}, suggested_fix=suggestion)


def _ping_host(host, count=2):
    if sys.platform == 'win32':
        cmd = ['ping', '-n', str(count), host]
    else:
        cmd = ['ping', '-c', str(count), '-W', '2', host]
    return _safe_run(cmd, timeout=10)


def get_network():
    dns_ok = False
    public_ip = 'unknown'
    try:
        if sys.platform != 'win32':
            gateway_info = _safe_run(['ip', 'route'], timeout=5)
        else:
            gateway_info = _safe_run(
                ['netsh', 'interface', 'ip', 'show', 'route'], timeout=5)
    except Exception as e:
        gateway_info = str(e)

    ping_local = _ping_host('127.0.0.1', count=1)
    ping_inet = _ping_host('8.8.8.8', count=2)
    try:
        socket.gethostbyname('cloudflare.com')
        dns_ok = True
    except Exception:
        dns_ok = False

    try:
        public_ip = _safe_run(
            ['curl', '-s', '--max-time', '5', 'https://api.ipify.org'],
            timeout=8, shell=False)
        if public_ip.startswith('exit') or public_ip.startswith('command'):
            public_ip = 'unavailable'
    except Exception:
        public_ip = 'unavailable'

    summary = (
        f"Local loopback ping: {ping_local.splitlines()[0] if ping_local else 'failed'}. "
        f"Internet ping to 8.8.8.8: {ping_inet.splitlines()[0] if ping_inet else 'failed'}. "
        f"DNS resolution is {'working' if dns_ok else 'failing'}. "
        f"Public IP is {public_ip}."
    )
    details = {
        'loopback': ping_local.splitlines()[0] if ping_local else 'failed',
        'internet': ping_inet.splitlines()[0] if ping_inet else 'failed',
        'dns_ok': dns_ok,
        'public_ip': public_ip,
        'gateway_info': gateway_info,
    }
    suggestion = None
    if 'failed' in summary.lower() and not dns_ok:
        suggestion = 'Try flushing DNS or renewing your IP address.'
    return _make_response('network', summary, details, suggested_fix=suggestion)


def get_hardware():
    info = {
        'platform': platform.platform(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor() or 'unknown',
    }
    try:
        if psutil is not None:
            info['memory_total_gb'] = _bytes_to_gb(psutil.virtual_memory().total)
    except Exception:
        info['memory_total_gb'] = None

    if sys.platform == 'win32':
        info['cpu_name'] = _safe_run(['wmic', 'cpu', 'get', 'Name', '/VALUE'], timeout=10)
        info['gpu'] = _safe_run(['wmic', 'path', 'win32_VideoController', 'get', 'Name', '/VALUE'], timeout=10)
    elif sys.platform == 'linux':
        cpuinfo = _safe_run(['grep', '-m1', 'model name', '/proc/cpuinfo'], timeout=5)
        if 'model name' in cpuinfo:
            info['cpu_name'] = cpuinfo.split(':', 1)[-1].strip()
        else:
            info['cpu_name'] = info['processor']
        info['gpu'] = _safe_run(['lspci'], timeout=8)
        info['usb'] = _safe_run(['lsusb'], timeout=8)
    elif sys.platform == 'darwin':
        info['cpu_name'] = _safe_run(['sysctl', '-n', 'machdep.cpu.brand_string'], timeout=5)
        info['gpu'] = _safe_run(['system_profiler', 'SPDisplaysDataType'], timeout=15)

    summary = (
        f"You are running {info['platform']} on {info.get('cpu_name', info['processor'])} "
        f"with {info.get('memory_total_gb', 'unknown')} GB of RAM."
    )
    return _make_response('hardware', summary, info)


def get_temperatures():
    if psutil is None or not hasattr(psutil, 'sensors_temperatures'):
        return _make_response('temperatures', 'Thermal sensors are not available.', {})
    try:
        sensors = psutil.sensors_temperatures()
    except Exception as e:
        return _make_response('temperatures', f'Could not read sensors: {e}', {}, success=False)
    if not sensors:
        return _make_response('temperatures', 'No thermal sensors detected.', {})
    summary_parts = []
    for chip, entries in sensors.items():
        for entry in entries:
            summary_parts.append(f"{chip} {entry.label}: {entry.current}C")
    summary = 'Thermal readings: ' + '; '.join(summary_parts)
    return _make_response('temperatures', summary, sensors)


def get_processes():
    if psutil is None:
        return _make_response('processes', 'psutil is not available.', success=False)
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    top_cpu = sorted(procs, key=lambda x: x.get('cpu_percent') or 0, reverse=True)[:5]
    top_mem = sorted(procs, key=lambda x: x.get('memory_percent') or 0, reverse=True)[:5]
    summary = (
        f"Top CPU process is {top_cpu[0]['name']} (PID {top_cpu[0]['pid']}) at "
        f"{top_cpu[0]['cpu_percent']}% CPU. Top memory process is {top_mem[0]['name']} "
        f"at {round(top_mem[0].get('memory_percent', 0), 1)}% RAM."
    )
    return _make_response('processes', summary, {'top_cpu': top_cpu, 'top_memory': top_mem},
                          suggested_fix='Close unused applications if memory or CPU usage is high.')


def get_services():
    services = []
    if sys.platform == 'win32':
        out = _safe_run(['sc', 'query', 'type=', 'service', 'state=', 'all'], timeout=15)
        for line in out.splitlines():
            if line.strip().startswith('SERVICE_NAME:'):
                services.append(line.split(':', 1)[-1].strip())
    else:
        out = _safe_run(
            ['systemctl', 'list-units', '--type=service', '--state=running',
             '--no-pager', '--no-legend'], timeout=10)
        for line in out.splitlines():
            services.append(line.split()[0])
    summary = f"Found {len(services)} running services." if services else 'Could not enumerate services.'
    return _make_response('services', summary, {'count': len(services), 'sample': services[:20]})


def _dir_size(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except (OSError, FileNotFoundError):
                pass
    return _bytes_to_gb(total)


def clean_temp_files(apply_fix=False):
    import tempfile
    dirs = [d for d in [tempfile.gettempdir()] if os.path.isdir(d)]
    if sys.platform != 'win32':
        dirs += ['/tmp', '/var/tmp']
    dirs = list(dict.fromkeys(dirs))
    sizes = {d: _dir_size(d) for d in dirs}
    summary = 'Temporary directories: ' + '; '.join(f"{d} is {sizes.get(d, 0)} GB" for d in sizes)
    if not apply_fix:
        return _make_response('temp_files', summary, {'sizes_gb': sizes},
                              suggested_fix='Say "clean temp files now" to remove old temporary files.')
    removed = 0
    skipped = 0
    cutoff = time.time() - (24 * 3600)
    for d in dirs:
        for dirpath, dirnames, filenames in os.walk(d, topdown=False):
            for name in filenames:
                fpath = os.path.join(dirpath, name)
                try:
                    if os.path.getmtime(fpath) < cutoff:
                        os.remove(fpath)
                        removed += 1
                except (PermissionError, OSError, FileNotFoundError):
                    skipped += 1
            for name in dirnames:
                dpath = os.path.join(dirpath, name)
                try:
                    if not os.listdir(dpath):
                        os.rmdir(dpath)
                except (PermissionError, OSError, FileNotFoundError):
                    pass
    summary = f"Cleaned {removed} temporary files older than 24 hours; {skipped} could not be removed."
    return _make_response('temp_files', summary, {'sizes_gb': sizes, 'removed': removed, 'skipped': skipped},
                          action_taken=True)


def get_drivers():
    if sys.platform == 'win32':
        out = _safe_run(
            ['wmic', 'path', 'Win32_PnPSignedDriver',
             'get', 'DeviceName,DriverVersion', '/FORMAT:CSV'], timeout=15)
    elif sys.platform == 'linux':
        out = _safe_run(['lspci', '-k'], timeout=10)
    elif sys.platform == 'darwin':
        out = _safe_run(['system_profiler', 'SPUSBDataType', 'SPAudioDataType', 'SPDisplaysDataType'], timeout=20)
    else:
        out = 'Unsupported platform for driver enumeration.'
    summary = 'Driver and device information retrieved.'
    return _make_response('drivers', summary, {'drivers': out[:2000]})


def get_updates():
    available = []
    if sys.platform == 'win32':
        # Use a fast PowerShell command if available; otherwise suggest Windows Update.
        out = _safe_run([
            'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
            'if (Get-Module -ListAvailable PSWindowsUpdate) '
            '{ Get-WUList | Select-Object Title,KB } '
            'else { Write-Output "PSWindowsUpdate not installed" }'
        ], timeout=20)
        available.append(out)
    elif sys.platform == 'linux':
        apt = shutil.which('apt')
        if apt:
            out = _safe_run(['apt', 'list', '--upgradable'], timeout=25)
            available.append(out)
        dnf = shutil.which('dnf')
        if dnf:
            out = _safe_run(['dnf', 'check-update'], timeout=25)
            available.append(out)
        pacman = shutil.which('pacman')
        if pacman:
            out = _safe_run(['pacman', '-Qu'], timeout=15)
            available.append(out)
    elif sys.platform == 'darwin':
        available.append(_safe_run(['softwareupdate', '-l'], timeout=20))
    summary = (
        f"Found {len(available)} update source(s)."
        if available else 'No update checker is available for this platform.')
    return _make_response('updates', summary, {'updates': available},
                          suggested_fix='Apply pending updates to fix known security and hardware issues.')


def flush_dns(apply_fix=False):
    if sys.platform == 'win32':
        cmd = ['ipconfig', '/flushdns']
    else:
        # Prefer resolvectl; fall back to systemd-resolved restart.
        if shutil.which('resolvectl'):
            cmd = ['resolvectl', 'flush-caches']
        else:
            cmd = ['systemctl', 'restart', 'systemd-resolved']
    if apply_fix:
        out = _safe_run(cmd, timeout=10)
        return _make_response('dns', f"Flushed DNS cache: {out}", {}, action_taken=True)
    return _make_response('dns', 'I can flush the DNS cache for you.', {},
                          suggested_fix=f"Run the command {' '.join(cmd)} or say 'flush dns now'.")


def renew_ip(apply_fix=False):
    if sys.platform == 'win32':
        cmd = ['ipconfig', '/release', '&&', 'ipconfig', '/renew']
        shell = True
    else:
        cmd = ['dhclient', '-r', '&&', 'dhclient']
        shell = True
    if apply_fix:
        out = _safe_run(cmd, timeout=20, shell=shell)
        return _make_response('ip', f"Renewed IP configuration: {out}", {}, action_taken=True)
    return _make_response('ip', 'I can renew your DHCP lease.', {},
                          suggested_fix='Say "renew my IP now" to release and renew.')


def check_disk(apply_fix=False):
    drive = 'C:' if sys.platform == 'win32' else '/'
    if sys.platform == 'win32':
        if apply_fix:
            # Non-destructive scan only; /f would require reboot.
            out = _safe_run(['chkdsk', drive], timeout=30)
        else:
            out = _safe_run(['chkdsk', drive], timeout=30)
            suggestion = f"Schedule a repair with chkdsk {drive} /f (requires reboot)."
            return _make_response('checkdisk', out, {}, suggested_fix=suggestion)
    else:
        # Use fsck in read-only mode by default to avoid data loss.
        root_dev = _safe_run(['findmnt', '-no', 'SOURCE', '/'], timeout=5)
        if not root_dev or root_dev.startswith('exit'):
            root_dev = '/dev/sda1'
        if apply_fix:
            out = _safe_run(['fsck', '-n', root_dev], timeout=30)
        else:
            out = _safe_run(['fsck', '-n', root_dev], timeout=30)
            return _make_response('checkdisk', out, {},
                                  suggested_fix=f'Schedule a repair: sudo fsck -y {root_dev} (unmount first).')
    return _make_response('checkdisk', out, {}, action_taken=apply_fix)


def restart_service(apply_fix=False, service_name=None):
    if not service_name:
        summary = (
            'Please say the name of the service to restart, '
            'for example "restart service MyService".')
        return _make_response('restart_service', summary, {},
                              suggested_fix='Include the service name in your command.')
    if sys.platform == 'win32':
        if apply_fix:
            out = _safe_run(['net', 'stop', service_name], timeout=10)
            out2 = _safe_run(['net', 'start', service_name], timeout=10)
            return _make_response('restart_service', f"Stopped: {out}. Started: {out2}",
                                  {'service': service_name}, action_taken=True)
        return _make_response('restart_service', f"I can restart the Windows service '{service_name}'.",
                              {'service': service_name},
                              suggested_fix=(
                                  f'Run: net stop {service_name} && net start {service_name} '
                                  f'or say "restart service {service_name} now".'))
    else:
        if apply_fix:
            out = _safe_run(['systemctl', 'restart', service_name], timeout=15)
            return _make_response('restart_service', f"Restarted {service_name}: {out}",
                                  {'service': service_name}, action_taken=True)
        return _make_response('restart_service', f"I can restart the Linux service '{service_name}'.",
                              {'service': service_name},
                              suggested_fix=(
                                  f'Run: sudo systemctl restart {service_name} '
                                  f'or say "restart service {service_name} now".'))


def get_help():
    lines = [f"{intent} - {meta['description']}" for intent, meta in COMMANDS.items()]
    summary = (
        'I can run diagnostics and repairs. Try commands like: '
        '"check my system status", "disk space", "network connection", "clean temp files".')
    return _make_response('help', summary, {'commands': lines})


def _yara_scanner_available():
    try:
        from security import yara_scanner
        return yara_scanner
    except Exception:
        return None


def _collect_scan_targets(max_files=40):
    """Build a small, high-value target list for a voice-triggered malware scan."""
    targets = []
    # Running executables are a prime target.
    if psutil is not None:
        seen = set()
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                exe = (p.info.get('exe') or '')
                if exe and os.path.isfile(exe) and exe not in seen:
                    seen.add(exe)
                    targets.append(exe)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
    # Common download and temp locations.
    candidates = []
    home = os.path.expanduser('~')
    if sys.platform == 'win32':
        candidates += [
            os.path.join(home, 'Downloads'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
            os.path.join(os.environ.get('WINDIR', r'C:\Windows'), 'Temp'),
        ]
    else:
        candidates += [os.path.join(home, 'Downloads'), '/tmp', '/var/tmp']
    for d in candidates:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.scandir(d):
                if entry.is_file(follow_symlinks=False):
                    targets.append(entry.path)
                if len(targets) >= max_files:
                    break
        except (PermissionError, OSError):
            continue
        if len(targets) >= max_files:
            break
    return list(dict.fromkeys(targets))[:max_files]


def _scan_targets_with_yara(targets):
    ys = _yara_scanner_available()
    if ys is None:
        return None, 'YARA scanner is not available. The antivirus engine may need to be installed.'
    results = []
    total = 0
    for path in targets:
        try:
            matches = ys.scan_file_with_yara(path)
            total += 1
            if matches:
                rule_names = [getattr(m, 'rule', 'unknown') for m in matches]
                results.append({'file': path, 'rules': rule_names})
        except Exception as e:
            logger.debug('YARA scan failed for %s: %s', path, e)
    return total, results


def scan_for_viruses():
    targets = _collect_scan_targets(max_files=40)
    total, results = _scan_targets_with_yara(targets)
    if total is None:
        return _make_response('virus_scan', results, {}, success=False,
                              suggested_fix='Open the YARA scanner page to run a full scan.')
    if results:
        rules = set()
        for r in results:
            rules.update(r.get('rules', []))
        summary = (
            f"Scanned {total} high-risk files and found {len(results)} suspicious file(s) "
            f"matching YARA rule(s): {', '.join(sorted(rules))}. "
            f"These should be quarantined or investigated."
        )
        return _make_response(
            'virus_scan', summary,
            {'scanned': total, 'matches': results},
            suggested_fix=('Use the YARA scanner to scan the full system and '
                           'quarantine matched files.'))
    return _make_response('virus_scan', f"Scanned {total} high-risk files. No malware signatures were detected.",
                          {'scanned': total, 'matches': []})


def check_miners():
    if psutil is None:
        return _make_response('miner_check', 'psutil is not available.', {}, success=False)
    flagged = []
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            name = (info.get('name') or '').lower()
            exe = (info.get('exe') or '').lower()
            cmd = ' '.join(info.get('cmdline') or []).lower()
            combined = f"{name} {exe} {cmd}"
            hits = []
            for sig in MINER_SIGNATURES['names']:
                if sig in combined:
                    hits.append(sig)
            for pool in MINER_SIGNATURES['pools']:
                if pool in cmd:
                    hits.append(pool)
            if hits:
                flagged.append({
                    'pid': info.get('pid'),
                    'name': info.get('name'),
                    'exe': info.get('exe'),
                    'cpu_percent': info.get('cpu_percent'),
                    'memory_percent': info.get('memory_percent'),
                    'indicators': list(set(hits)),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Also inspect active network connections for known mining ports.
    suspicious_conns = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                port = conn.raddr.port
                if port in MINER_SIGNATURES['ports']:
                    try:
                        proc = psutil.Process(conn.pid)
                        suspicious_conns.append({
                            'pid': conn.pid,
                            'name': proc.name(),
                            'remote': f"{conn.raddr.ip}:{port}",
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
    except Exception:
        pass

    if flagged or suspicious_conns:
        detail = {'processes': flagged, 'connections': suspicious_conns}
        summary = (
            f"Found {len(flagged)} suspicious process(es) and {len(suspicious_conns)} "
            "connection(s) matching crypto-mining patterns. This could explain high CPU, heat, or fan noise."
        )
        return _make_response('miner_check', summary, detail,
                              suggested_fix=('Investigate these processes, terminate them, '
                                             'and run a full YARA scan.'))
    return _make_response('miner_check', 'No crypto-miner signatures were found in running processes or connections.',
                          {'processes': [], 'connections': []})


def hardware_virus_check():
    if psutil is None:
        return _make_response('hardware_virus', 'psutil is not available.', {}, success=False)
    cpu = get_cpu()
    temps = get_temperatures()
    miner = check_miners()
    top = get_processes()
    high_cpu = cpu['details'].get('percent_per_core', [])
    avg_cpu = sum(high_cpu) / len(high_cpu) if high_cpu else 0
    hot = False
    if temps['success']:
        for chip, entries in temps['details'].items():
            for entry in entries:
                current = getattr(entry, 'current', getattr(entry, 'value', None))
                if current and current > 75:
                    hot = True

    if miner['success'] and (miner['details'].get('processes') or miner['details'].get('connections')):
        summary = (
            f"Hardware stress detected: CPU average {avg_cpu:.1f}%, high temperature {hot}, "
            "and crypto-miner indicators are present. This malware is likely causing your hardware issues."
        )
        return _make_response(
            'hardware_virus', summary,
            {'cpu': cpu['details'], 'temperatures': temps['details'],
             'top_processes': top['details'], 'miners': miner['details']},
            suggested_fix=('Kill the flagged miner processes and run a full virus scan '
                           'from the YARA scanner.'))

    if avg_cpu > 70 or hot:
        summary = (
            f"High hardware load detected: CPU average {avg_cpu:.1f}% and sensors show overheating: {hot}. "
            "A virus or runaway process may be the cause."
        )
        return _make_response(
            'hardware_virus', summary,
            {'cpu': cpu['details'], 'temperatures': temps['details'],
             'top_processes': top['details']},
            suggested_fix=('Review the top processes, terminate unknown high-CPU tasks, '
                           'and run a virus scan.'))

    return _make_response('hardware_virus',
                          'No unusual hardware stress or mining signatures detected. Your hardware looks normal.',
                          {'cpu': cpu['details'], 'temperatures': temps['details'],
                           'top_processes': top['details'], 'miners': miner['details']})


def _make_response(intent, response, details=None, success=True, action_taken=False, suggested_fix=None):
    return {
        'intent': intent,
        'response': response,
        'details': details or {},
        'success': success,
        'action_taken': action_taken,
        'suggested_fix': suggested_fix,
    }


def run_command(intent, raw_command=None, apply_fix=False):
    if not intent or intent == 'unknown':
        return _make_response(
            'unknown',
            "I'm not sure what you need. Try saying 'help' for a list of voice commands.",
            {'command': raw_command}, success=False)
    service_name = _split_service_name(raw_command or '') if intent == 'restart_service' else None
    handlers = {
        'status': get_status,
        'cpu': get_cpu,
        'memory': get_memory,
        'disk': get_disk,
        'network': get_network,
        'hardware': get_hardware,
        'temperatures': get_temperatures,
        'processes': get_processes,
        'services': get_services,
        'temp_files': lambda: clean_temp_files(apply_fix=apply_fix),
        'drivers': get_drivers,
        'updates': get_updates,
        'dns': lambda: flush_dns(apply_fix=apply_fix),
        'ip': lambda: renew_ip(apply_fix=apply_fix),
        'checkdisk': lambda: check_disk(apply_fix=apply_fix),
        'restart_service': lambda: restart_service(apply_fix=apply_fix, service_name=service_name),
        'virus_scan': scan_for_viruses,
        'miner_check': check_miners,
        'hardware_virus': hardware_virus_check,
        'help': get_help,
    }
    fn = handlers.get(intent)
    if not fn:
        return _make_response('unknown', 'Command not implemented yet.', {}, success=False)
    try:
        return fn()
    except Exception as e:
        logger.exception('voice handler failed')
        return _make_response(intent, f'Sorry, that command failed: {e}', {}, success=False)


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@voice_bp.route('/voice-assistant')
def voice_assistant_page():
    if not session.get('logged_in'):
        return redirect('/login')
    return render_template('voice_assistant.html')


@voice_bp.route('/api/voice/command', methods=['POST'])
def voice_command():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'login required'}), 401
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') or request.args.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'status': 'error', 'message': 'Invalid or missing CSRF token'}), 403
    data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict()
    raw = (data.get('command') or '').strip()
    if not raw:
        return jsonify({'status': 'error', 'message': 'No voice command received'}), 400
    apply_fix = str(data.get('apply_fix', '')).lower() in ('true', '1', 'yes', 'on')
    intent = parse_intent(raw)
    result = run_command(intent, raw_command=raw, apply_fix=apply_fix)
    return jsonify({'status': 'ok', 'command': raw, **result})


@voice_bp.route('/api/voice/intents', methods=['GET'])
def voice_intents():
    return jsonify({
        'intents': [
            {'name': k, 'description': v['description'], 'examples': v['keywords'][:3]}
            for k, v in COMMANDS.items()
        ]
    })
