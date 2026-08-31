import concurrent.futures
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import timedelta

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

voice_bp = Blueprint('voice_assistant', __name__, template_folder='templates')
logger = logging.getLogger('voice_assistant')


_SHELL_METACHARS = re.compile(r'[;&|`$\\<>\n\r\x00]')


def _is_safe_arg(arg):
    return isinstance(arg, str) and not _SHELL_METACHARS.search(arg)


def _safe_run(cmd, timeout=15):
    """Run a subprocess and return stripped stdout, or an error string.

    Only a list of static or sanitized arguments is accepted; shell=False is
    enforced and any shell metacharacters in an argument will raise.
    """
    if not isinstance(cmd, (list, tuple)):
        raise ValueError('cmd must be a list of strings')
    if not cmd:
        raise ValueError('cmd must not be empty')
    exe = shutil.which(cmd[0]) if not os.path.isabs(cmd[0]) else cmd[0]
    if not exe:
        return f"command not found: {cmd[0]}"
    safe_cmd = [exe if not os.path.isabs(cmd[0]) else cmd[0]]
    for arg in cmd[1:]:
        if not _is_safe_arg(arg):
            raise ValueError(f'unsafe argument: {arg!r}')
        safe_cmd.append(arg)
    try:
        kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'timeout': timeout,
            'shell': False,
        }
        if sys.platform == 'win32':
            kwargs.setdefault('creationflags', 0x08000000)  # CREATE_NO_WINDOW
        proc = subprocess.run(safe_cmd, **kwargs)
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


def _call_with_timeout(func, args=(), kwargs=None, timeout=5):
    """Call a function with a timeout. Uses SIGALRM on Linux when in the main thread,
    otherwise falls back to a thread-based timeout (which may not interrupt C code)."""
    if kwargs is None:
        kwargs = {}
    main = threading.current_thread() is threading.main_thread()
    if main and hasattr(signal, 'SIGALRM'):
        def _handler(signum, frame):
            raise TimeoutError(f'Operation timed out after {timeout}s')
        old_handler = signal.signal(signal.SIGALRM, _handler)
        try:
            remaining = signal.alarm(int(max(1, timeout)))
            return func(*args, **kwargs)
        finally:
            signal.alarm(0)
            if remaining:
                signal.alarm(int(max(1, remaining)))
            signal.signal(signal.SIGALRM, old_handler)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        return future.result(timeout=timeout)


_VOICE_JOBS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'voice_jobs')


def _job_file(job_id):
    os.makedirs(_VOICE_JOBS_DIR, exist_ok=True)
    return os.path.join(_VOICE_JOBS_DIR, f'voice_job_{job_id}.json')


def _save_job(job_id, state):
    try:
        with open(_job_file(job_id), 'w') as f:
            json.dump(state, f)
    except Exception as e:
        logger.error('save job %s failed: %s', job_id, e)


def _load_job(job_id):
    try:
        with open(_job_file(job_id), 'r') as f:
            return json.load(f)
    except Exception:
        return None


def _run_voice_job(job_id, intent, raw_command, apply_fix):
    """Worker that runs in a separate process and writes the result to a job file."""
    _save_job(job_id, {'status': 'running', 'command': raw_command, 'started': time.strftime('%Y-%m-%d %H:%M:%S')})
    try:
        result = run_command(intent, raw_command=raw_command, apply_fix=apply_fix)
        _save_job(job_id, {'status': 'completed', 'command': raw_command, 'result': result, 'finished': time.strftime('%Y-%m-%d %H:%M:%S')})
    except Exception as e:
        logger.exception('voice job %s failed', job_id)
        _save_job(job_id, {'status': 'error', 'command': raw_command, 'error': str(e), 'finished': time.strftime('%Y-%m-%d %H:%M:%S')})


_VOICE_JOB_SCRIPT = """
import json, os, sys
sys.path.insert(0, os.getcwd())
from voice_assistant import _run_voice_job
data = json.load(sys.stdin)
_run_voice_job(data['job_id'], data['intent'], data.get('raw_command', ''), data.get('apply_fix', False))
"""


def _quarantine_path(path, reason=''):
    """Quarantine or remove a file. Returns True if the original path no longer exists."""
    if not os.path.exists(path):
        return True
    try:
        from quarantine_utils import quarantine_file
        quarantine_file(path, reason=reason)
        return not os.path.exists(path)
    except Exception:
        pass
    try:
        from security.scan_cache import safe_quarantine
        qdir = os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')), 'AppData', 'Local', 'Temp', 'Defender_Quarantine')
        if sys.platform != 'win32':
            qdir = os.path.join(os.path.expanduser('~'), 'Defender_Quarantine')
        def _encrypt(src, dst):
            try:
                from cryptography.fernet import Fernet
                key = os.environ.get('FERNET_KEY', '').strip().encode('utf-8')
                if not key or len(key) != 44:
                    return False
                f = Fernet(key)
                with open(src, 'rb') as fh:
                    data = fh.read()
                with open(dst, 'wb') as oh:
                    oh.write(f.encrypt(data))
                return True
            except Exception:
                return False
        ok, _ = safe_quarantine(path, qdir, _encrypt, force=True)
        return ok and not os.path.exists(path)
    except Exception:
        pass
    try:
        qdir = os.path.join(os.path.expanduser('~'), 'voice_quarantine')
        os.makedirs(qdir, exist_ok=True)
        dst = os.path.join(qdir, os.path.basename(path) + '.quarantined')
        if os.path.exists(dst):
            dst = os.path.join(qdir, f'{os.path.basename(path)}.{int(time.time())}.quarantined')
        shutil.move(path, dst)
        return True
    except Exception:
        return False


_VOICE_SCAN_STATUS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'voice_scan_status.json')


def _load_scan_status():
    default = {'active': False, 'result': None, 'error': None, 'started': None}
    if not os.path.exists(_VOICE_SCAN_STATUS_FILE):
        return default
    try:
        with open(_VOICE_SCAN_STATUS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {**default, 'error': f'Could not load scan status: {e}'}


def _save_scan_status(state):
    try:
        with open(_VOICE_SCAN_STATUS_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        logger.error('save scan status failed: %s', e)


# ---------------------------------------------------------------------------
# Cloud voice command queue
# Used when the voice assistant is registered on the cloud server so commands
# are executed on the local agent instead of the VPS. The queue is persisted
# to a JSON file under an OS-level file lock because gunicorn runs multiple
# worker processes — an in-memory dict would lose commands whenever a request
# landed on a different worker than the one that queued it.
# ---------------------------------------------------------------------------
_VOICE_QUEUE_FILE = os.path.join(_VOICE_JOBS_DIR, 'voice_queue.json')
_VOICE_QUEUE_LOCK = _VOICE_QUEUE_FILE + '.lock'


class _queue_locked:
    """Cross-process lock for read-modify-write on the voice queue file."""

    def __enter__(self):
        os.makedirs(_VOICE_JOBS_DIR, exist_ok=True)
        self._lf = open(_VOICE_QUEUE_LOCK, 'a+b')
        try:
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.locking(self._lf.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lf.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass
        return self

    def __exit__(self, *exc):
        try:
            self._lf.seek(0)
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.locking(self._lf.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lf.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        self._lf.close()


def _load_voice_queue():
    try:
        with open(_VOICE_QUEUE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_voice_queue(queue):
    tmp = _VOICE_QUEUE_FILE + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(queue, f)
        os.replace(tmp, _VOICE_QUEUE_FILE)
    except Exception as e:
        logger.error('save voice queue failed: %s', e)


def _enqueue_voice_command(device_id, command, apply_fix):
    """Queue a voice command for a specific local agent/device."""
    job_id = secrets.token_urlsafe(16)
    record = {
        'command': command,
        'apply_fix': apply_fix,
        'status': 'pending',
        'result': None,
        'created': time.time(),
    }
    with _queue_locked():
        queue = _load_voice_queue()
        queue.setdefault(device_id, {})[job_id] = record
        _save_voice_queue(queue)
    return job_id


def _get_voice_command_result(device_id, job_id):
    """Return the current state of a queued command."""
    return _load_voice_queue().get(device_id, {}).get(job_id)


def _poll_voice_commands(device_id):
    """Return all pending commands for a device and mark them dispatched."""
    with _queue_locked():
        queue = _load_voice_queue()
        device_queue = queue.get(device_id, {})
        pending = []
        for job_id, record in list(device_queue.items()):
            # Re-dispatch commands stuck in 'dispatched' for over 60s —
            # the agent may have restarted or crashed before reporting back.
            if record.get('status') == 'dispatched' and record.get('dispatched_at', 0) + 60 < time.time():
                record['status'] = 'pending'
            if record.get('status') == 'pending':
                record['dispatched_at'] = time.time()
                record['status'] = 'dispatched'
                pending.append({
                    'job_id': job_id,
                    'command': record['command'],
                    'apply_fix': record['apply_fix'],
                })
        if pending:
            _save_voice_queue(queue)
    return pending


def _complete_voice_command(device_id, job_id, status, result):
    """Mark a queued command as completed or errored."""
    with _queue_locked():
        queue = _load_voice_queue()
        record = queue.get(device_id, {}).get(job_id)
        if not record:
            return False
        record['status'] = status
        record['result'] = result
        record['finished'] = time.time()
        _save_voice_queue(queue)
    return True


def _server_device_ids():
    """Device IDs that belong to the server machine itself.

    The cloud server auto-starts a LocalAgent on its own host (the VPS), which
    registers as ``LOCAL-<hostname>`` (or the DEVICE_ID env var). Voice commands
    must never be routed there — they are meant for the user's own device.
    """
    ids = set()
    env_id = (os.environ.get('DEVICE_ID') or '').strip().strip('"').strip("'")
    if env_id:
        ids.add(env_id)
    ids.add(f'LOCAL-{socket.gethostname().upper()[:12]}')
    try:
        from security.local_agent import get_local_agent
        agent = get_local_agent()
        if agent is not None and getattr(agent, 'device_id', None):
            ids.add(agent.device_id)
    except Exception:
        pass
    return ids


def _prune_voice_command_queue(max_age=300):
    """Remove completed records older than max_age seconds."""
    now = time.time()
    with _queue_locked():
        queue = _load_voice_queue()
        changed = False
        for device_id in list(queue.keys()):
            device_queue = queue[device_id]
            for job_id in list(device_queue.keys()):
                record = device_queue[job_id]
                if record.get('status') in ('completed', 'error'):
                    if record.get('finished', 0) + max_age < now:
                        del device_queue[job_id]
                        changed = True
            if not device_queue:
                del queue[device_id]
                changed = True
        if changed:
            _save_voice_queue(queue)


def _voice_scan_worker(intent, raw_command, apply_fix):
    started = time.strftime('%Y-%m-%d %H:%M:%S')
    _save_scan_status({'active': True, 'result': None, 'error': None, 'started': started})
    try:
        if intent == 'virus_scan':
            result = scan_for_viruses(apply_fix=apply_fix)
        else:
            result = run_command(intent, raw_command=raw_command, apply_fix=apply_fix)
        _save_scan_status({'active': False, 'result': result, 'error': None, 'started': started})
    except Exception as e:
        _save_scan_status({'active': False, 'result': None, 'error': str(e), 'started': started})
        logger.exception('background voice scan failed')


_VOICE_SCAN_SUBPROCESS_SCRIPT = """
import json, os, sys
sys.path.insert(0, os.getcwd())
from voice_assistant import _voice_scan_worker
data = json.load(sys.stdin)
_voice_scan_worker(data.get('intent', 'virus_scan'), data.get('raw_command', ''), data.get('apply_fix', False))
"""


def start_voice_scan(intent, raw_command, apply_fix):
    state = _load_scan_status()
    if state.get('active'):
        return _make_response(
            'virus_scan',
            f"A scan is already running (started {state.get('started')}). Say 'scan status' for progress.",
            {'status': 'running', 'started': state.get('started')}
        )
    _save_scan_status({'active': True, 'result': None, 'error': None, 'started': time.strftime('%Y-%m-%d %H:%M:%S')})
    try:
        threading.Thread(target=_voice_scan_worker, args=(intent, raw_command, apply_fix), daemon=True).start()
    except Exception as e:
        _save_scan_status({'active': False, 'result': None, 'error': str(e), 'started': None})
        return _make_response('virus_scan', f'Could not start background scan: {e}', {}, success=False)
    msg = 'Started a virus scan in the background. Say "scan status" for results.'
    if apply_fix:
        msg = 'Started a virus scan and quarantine in the background. Say "scan status" for results.'
    return _make_response('virus_scan', msg, {'status': 'started'}, action_taken=apply_fix)


def get_voice_scan_status():
    state = _load_scan_status()
    if state.get('active'):
        return _make_response(
            'scan_status',
            f"Scan started at {state.get('started')} is still running.",
            {'status': 'running', 'started': state.get('started')}
        )
    if state.get('error'):
        return _make_response('scan_status', f"Last scan failed: {state['error']}",
                              {'status': 'error', 'error': state['error']}, success=False)
    if state.get('result'):
        r = state['result']
        return _make_response('scan_status', r.get('response', 'Scan complete.'), r.get('details', {}), success=r.get('success', True))
    return _make_response('scan_status', 'No scan has been run yet.', {'status': 'idle'})


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
    'scan_status': {
        'keywords': ['scan status', 'scan progress', 'scan results', 'scan done',
                     'scan finished', 'is the scan done'],
        'description': 'get the status of a background virus scan',
    },
    'full_diagnostic': {
        'keywords': ['full diagnostic', 'run diagnostics', 'diagnostic', 'health check',
                     'pc checkup', 'system diagnostic', 'troubleshoot', 'what is wrong',
                     'repair diagnostics', 'system check', 'computer check'],
        'description': 'run a full system diagnostic covering CPU, memory, disk, network, temperature, miners, and processes',
    },
    'system_services': {
        'keywords': ['startup', 'scheduled tasks', 'services', 'event logs', 'system services',
                     'startup programs', 'autostart', 'failed services', 'error logs'],
        'description': 'list startup items, scheduled tasks, services, and recent error logs',
    },
}

# Known crypto-miner and hardware-abuse signatures.
# Known crypto-miner and hardware-abuse signatures.
# NOTE: ports must NOT include common web ports (80/443/8080) — those would
# flag and kill ordinary browsers and services.
MINER_SIGNATURES = {
    'names': {'xmrig', 'minerd', 'nanominer', 't-rex', 'trex', 'nbminer',
              'gminer', 'lolminer', 'teamredminer', 'phoenixminer',
              'excavator', 'ccminer', 'cgminer', 'sgminer', 'bfgminer',
              'nicehash'},
    'pools': {'stratum+tcp', 'stratum+ssl', 'minexmr', 'supportxmr',
              'nanopool', 'ethermine', 'f2pool', 'poolin', 'antpool',
              'nicehash.com', 'miningpoolhub'},
    'ports': {3333, 4444, 5555, 7777, 45700, 45701},
}
# Only terminate a process if it matches a high-confidence kill signature.
# Connection to a suspicious port alone is not enough to kill.
_KILL_SIGNATURES = set(MINER_SIGNATURES['names']) | set(MINER_SIGNATURES['pools'])


class SemanticRouter:
    """Optional ML-based command classifier using sentence-transformers."""

    def __init__(self):
        self._model = None
        self._corpus = None
        self._labels = None
        self._available = self._probe()

    @staticmethod
    def _probe():
        if os.environ.get('VOICE_USE_SEMANTIC', '0') != '1':
            return False
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


def _word_overlap_score(text, phrase):
    text_tokens = set(text.lower().split())
    phrase_tokens = set(phrase.lower().split())
    if not phrase_tokens:
        return 0
    return len(text_tokens & phrase_tokens) / len(phrase_tokens)


def parse_intent(raw_command):
    text = raw_command.lower()
    best = None
    best_score = 0
    for intent, meta in COMMANDS.items():
        for kw in meta['keywords']:
            if kw in text:
                score = len(kw.split()) * 1.5
            else:
                from difflib import SequenceMatcher
                ratio = SequenceMatcher(None, text, kw).ratio()
                overlap = _word_overlap_score(text, kw)
                score = max(ratio, overlap) * 2
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


_HOST_RE = re.compile(r'^[A-Za-z0-9._:-]{1,253}$')
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,80}$")


def _ping_host(host, count=2):
    if not _HOST_RE.match(host):
        return 'Invalid host: only hostnames and IP addresses are allowed.'
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
    serializable = {}
    for chip, entries in sensors.items():
        serializable[chip] = []
        for entry in entries:
            summary_parts.append(f"{chip} {entry.label}: {entry.current}C")
            serializable[chip].append(entry._asdict())
    summary = 'Thermal readings: ' + '; '.join(summary_parts)
    return _make_response('temperatures', summary, serializable)


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
    if not top_cpu or not top_mem:
        return _make_response('processes', 'No running processes could be enumerated.', {}, success=False)
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
            parts = line.split()
            if parts:
                services.append(parts[0])
    summary = f"Found {len(services)} running services." if services else 'Could not enumerate services.'
    return _make_response('services', summary, {'count': len(services), 'sample': services[:20]})


def _dir_size(path, time_budget=5):
    total = 0
    start = time.time()
    for dirpath, dirnames, filenames in os.walk(path):
        if time.time() - start > time_budget:
            break
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except (OSError, FileNotFoundError):
                pass
    return _bytes_to_gb(total)


def clean_temp_files(apply_fix=False, time_budget=15):
    import tempfile
    start = time.time()
    dirs = [d for d in [tempfile.gettempdir()] if os.path.isdir(d)]
    if sys.platform != 'win32':
        dirs += ['/tmp', '/var/tmp']
    dirs = list(dict.fromkeys(dirs))
    sizes = {d: _dir_size(d, time_budget=5) for d in dirs}
    summary = 'Temporary directories: ' + '; '.join(f"{d} is {sizes.get(d, 0)} GB" for d in sizes)
    if not apply_fix:
        return _make_response('temp_files', summary, {'sizes_gb': sizes},
                              suggested_fix='Say "clean temp files now" to remove old temporary files.')
    removed = 0
    skipped = 0
    cutoff = time.time() - (24 * 3600)
    for d in dirs:
        for dirpath, dirnames, filenames in os.walk(d, topdown=False):
            if time.time() - start > time_budget:
                return _make_response('temp_files', 'Temporary file cleanup took too long; stopped early.',
                                      {'sizes_gb': sizes, 'removed': removed, 'skipped': skipped},
                                      action_taken=True, success=False)
            for name in filenames:
                if time.time() - start > time_budget:
                    break
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
            out = _safe_run(['apt', 'list', '--upgradable'], timeout=10)
            available.append(out)
        dnf = shutil.which('dnf')
        if dnf:
            out = _safe_run(['dnf', 'check-update'], timeout=10)
            available.append(out)
        pacman = shutil.which('pacman')
        if pacman:
            out = _safe_run(['pacman', '-Qu'], timeout=10)
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
        release_cmd = ['ipconfig', '/release']
        renew_cmd = ['ipconfig', '/renew']
    else:
        release_cmd = ['dhclient', '-r']
        renew_cmd = ['dhclient']
    if apply_fix:
        out1 = _safe_run(release_cmd, timeout=20)
        out2 = _safe_run(renew_cmd, timeout=20)
        return _make_response('ip', f"Renewed IP configuration: {out1}; {out2}", {}, action_taken=True)
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
            out = _safe_run(['fsck', '-n', root_dev], timeout=15)
        else:
            out = _safe_run(['fsck', '-n', root_dev], timeout=15)
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
    if not _SERVICE_NAME_RE.match(service_name.strip()):
        return _make_response('restart_service', 'Invalid service name. Only letters, numbers, dots, underscores, hyphens and spaces are allowed.', {})
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


def _scan_targets_with_yara(targets, per_file_timeout=5, total_budget=25):
    ys = _yara_scanner_available()
    if ys is None:
        return None, 'YARA scanner is not available. The antivirus engine may need to be installed.'
    results = []
    total = 0
    start = time.time()
    for path in targets:
        if time.time() - start > total_budget:
            break
        try:
            matches = _call_with_timeout(ys.scan_file_with_yara, args=(path,), timeout=per_file_timeout)
            total += 1
            if matches:
                rule_names = [getattr(m, 'rule', 'unknown') for m in matches]
                results.append({'file': path, 'rules': rule_names})
        except (TimeoutError, concurrent.futures.TimeoutError):
            logger.debug('YARA scan timed out for %s', path)
        except Exception as e:
            logger.debug('YARA scan failed for %s: %s', path, e)
    return total, results


def scan_for_viruses(apply_fix=False):
    targets = _collect_scan_targets(max_files=5)
    total, results = _scan_targets_with_yara(targets)
    if total is None:
        return _make_response('virus_scan', results, {}, success=False,
                              suggested_fix='Open the YARA scanner page to run a full scan.')
    quarantined = 0
    failed = 0
    if apply_fix and results:
        for r in results:
            path = r.get('file')
            if not path:
                continue
            if _quarantine_path(path, reason=f"Voice YARA match: {', '.join(r.get('rules', []))}"):
                quarantined += 1
            else:
                failed += 1
    if results:
        rules = set()
        for r in results:
            rules.update(r.get('rules', []))
        if apply_fix:
            summary = (
                f"Scanned {total} high-risk files and found {len(results)} suspicious file(s). "
                f"Quarantined {quarantined} file(s); {failed} could not be quarantined. "
                f"Matching rules: {', '.join(sorted(rules))}."
            )
        else:
            summary = (
                f"Scanned {total} high-risk files and found {len(results)} suspicious file(s) "
                f"matching YARA rule(s): {', '.join(sorted(rules))}. "
                f"Quarantining was not requested; turn on 'Apply repair/cleanup' to remove them automatically."
            )
        return _make_response(
            'virus_scan', summary,
            {'scanned': total, 'matches': results, 'quarantined': quarantined, 'failed': failed},
            action_taken=apply_fix and quarantined > 0,
            suggested_fix=('Turn on "Apply repair/cleanup" and say "scan and remove viruses" '
                           'to quarantine matched files automatically.'))
    return _make_response('virus_scan', f"Scanned {total} high-risk files. No malware signatures were detected.",
                          {'scanned': total, 'matches': [], 'quarantined': 0, 'failed': 0})


def check_miners(apply_fix=False):
    if psutil is None:
        return _make_response('miner_check', 'psutil is not available.', {}, success=False)
    flagged = []
    pids_to_kill = set()
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
                # Only kill if a high-confidence signature matched; generic
                # terms or ports alone are not enough to terminate a process.
                if apply_fix and any(h in _KILL_SIGNATURES for h in hits):
                    pids_to_kill.add(info.get('pid'))
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
                        pname = (proc.name() or '').lower()
                        pcmd = ' '.join(proc.cmdline() or []).lower()
                        combined = f"{pname} {pcmd}"
                        # A suspicious port alone is not enough to kill; the
                        # process must also look like a miner binary or contain
                        # a mining pool address.
                        killable = apply_fix and any(
                            sig in combined for sig in _KILL_SIGNATURES
                        )
                        suspicious_conns.append({
                            'pid': conn.pid,
                            'name': proc.name(),
                            'remote': f"{conn.raddr.ip}:{port}",
                        })
                        if killable:
                            pids_to_kill.add(conn.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
    except Exception:
        pass

    killed = []
    if apply_fix and pids_to_kill:
        for pid in pids_to_kill:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
                killed.append(pid)
            except Exception:
                try:
                    proc = psutil.Process(pid)
                    proc.kill()
                    killed.append(pid)
                except Exception:
                    pass

    if flagged or suspicious_conns:
        detail = {'processes': flagged, 'connections': suspicious_conns, 'killed': killed}
        if apply_fix:
            summary = (
                f"Found {len(flagged)} suspicious process(es) and {len(suspicious_conns)} "
                f"connection(s). Terminated {len(killed)} miner process(es)."
            )
        else:
            summary = (
                f"Found {len(flagged)} suspicious process(es) and {len(suspicious_conns)} "
                "connection(s) matching crypto-mining patterns. This could explain high CPU, heat, or fan noise."
            )
        return _make_response('miner_check', summary, detail,
                              action_taken=apply_fix and len(killed) > 0,
                              suggested_fix=('Turn on "Apply repair/cleanup" and say "stop miners" '
                                             'to terminate them automatically.'))
    return _make_response('miner_check', 'No crypto-miner signatures were found in running processes or connections.',
                          {'processes': [], 'connections': [], 'killed': []})


def hardware_virus_check(apply_fix=False):
    if psutil is None:
        return _make_response('hardware_virus', 'psutil is not available.', {}, success=False)
    cpu = get_cpu()
    temps = get_temperatures()
    miner = check_miners(apply_fix=apply_fix)
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


def get_system_services():
    """Collect startup items, scheduled tasks, services, and recent error logs."""
    startup = []
    scheduled = []
    services_running = []
    services_failed = []
    logs = []
    try:
        if sys.platform == 'win32':
            out = _safe_run(['wmic', 'startup', 'get', 'Caption,Command'], timeout=8)
            for line in out.splitlines()[1:]:
                if line.strip():
                    startup.append(line.strip())
            out = _safe_run(['schtasks', '/query', '/fo', 'csv', '/nh'], timeout=8)
            for line in out.splitlines()[1:]:
                if line.strip():
                    scheduled.append(line.split(',')[0].strip('"'))
            out = _safe_run(['sc', 'query', 'type=', 'service', 'state=', 'all'], timeout=10)
            for line in out.splitlines():
                if line.strip().startswith('SERVICE_NAME:'):
                    services_running.append(line.split(':', 1)[-1].strip())
            out = _safe_run(['wevtutil', 'qe', 'System', '/q:"*[System[(Level=1 or Level=2)]]"', '/f:text', '/c:10'], timeout=8)
            logs = [line.strip() for line in out.splitlines() if line.strip()]
        else:
            for d in ['/etc/xdg/autostart', os.path.expanduser('~/.config/autostart')]:
                if os.path.isdir(d):
                    for f in sorted(os.listdir(d))[:20]:
                        if f.endswith('.desktop'):
                            startup.append(os.path.join(d, f))
            out = _safe_run(['systemctl', 'list-timers', '--all', '--no-pager', '--no-legend'], timeout=5)
            scheduled = [line.split()[0] for line in out.splitlines() if line.strip()]
            out = _safe_run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'], timeout=5)
            services_running = [line.split()[0] for line in out.splitlines() if line.strip()]
            out = _safe_run(['systemctl', 'list-units', '--failed', '--no-pager', '--no-legend'], timeout=5)
            services_failed = [line.split()[0] for line in out.splitlines() if line.strip()]
            out = _safe_run(['journalctl', '-p', 'err', '--since', '1 hour ago', '--no-pager', '-n', '20'], timeout=5)
            logs = [line.strip() for line in out.splitlines() if line.strip()]
    except Exception as e:
        return _make_response('system_services', f'Could not collect system services info: {e}', {}, success=False)
    summary = (
        f"Found {len(startup)} startup item(s), {len(scheduled)} scheduled task(s), "
        f"{len(services_running)} running service(s), {len(services_failed)} failed service(s), "
        f"and {len(logs)} recent error log line(s)."
    )
    return _make_response(
        'system_services', summary,
        {'startup': startup, 'scheduled': scheduled, 'services_running': services_running,
         'services_failed': services_failed, 'logs': logs},
        suggested_fix='Review failed services, unknown startup items, and scheduled tasks for malware persistence.'
    )


def run_full_diagnostic(apply_fix=False):
    if psutil is None:
        return _make_response('full_diagnostic', 'psutil is not available.', {}, success=False)
    try:
        diagnostics = {}
        def _collect(name, fn, *args):
            try:
                diagnostics[name] = fn(*args)
            except Exception as e:
                logger.debug('full_diagnostic component %s failed: %s', name, e)
                diagnostics[name] = _make_response(name, f'{name} check failed: {e}', {}, success=False)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        futures = {
            executor.submit(_collect, 'cpu', get_cpu): 'cpu',
            executor.submit(_collect, 'memory', get_memory): 'memory',
            executor.submit(_collect, 'disk', get_disk): 'disk',
            executor.submit(_collect, 'network', get_network): 'network',
            executor.submit(_collect, 'temperatures', get_temperatures): 'temperatures',
            executor.submit(_collect, 'miners', check_miners, apply_fix): 'miners',
            executor.submit(_collect, 'processes', get_processes): 'processes',
            executor.submit(_collect, 'system_services', get_system_services): 'system_services',
        }
        try:
            for _ in concurrent.futures.as_completed(futures, timeout=10):
                pass
        except concurrent.futures.TimeoutError:
            pass
        finally:
            executor.shutdown(wait=False)

        cpu = diagnostics.get('cpu', {})
        mem = diagnostics.get('memory', {})
        disk = diagnostics.get('disk', {})
        net = diagnostics.get('network', {})
        temps = diagnostics.get('temperatures', {})
        miners = diagnostics.get('miners', {})
        procs = diagnostics.get('processes', {})
        system = diagnostics.get('system_services', {})

        issues = []
        if system.get('details', {}).get('services_failed'):
            issues.append(f"{len(system['details']['services_failed'])} failed service(s)")
        actions = []
        repairs = []

        if cpu.get('details', {}).get('percent_per_core'):
            avg = sum(cpu['details']['percent_per_core']) / len(cpu['details']['percent_per_core'])
            if avg > 70:
                issues.append(f'high CPU ({avg:.0f}%)')
        if mem.get('details', {}).get('percent', 0) > 85:
            issues.append(f'high memory ({mem["details"]["percent"]:.0f}%)')
        if disk.get('success') and disk.get('details', {}).get('percent', 0) > 80:
            issues.append(f'low disk space ({disk["details"]["percent"]:.0f}% used)')
            if apply_fix:
                repairs.append(('cleanup temporary files', lambda: clean_temp_files(apply_fix=True)))
        if not net.get('success'):
            issues.append('network issue')
            if apply_fix:
                repairs.append(('flush DNS', lambda: flush_dns(apply_fix=True)))
                repairs.append(('renew IP', lambda: renew_ip(apply_fix=True)))
        if temps.get('details'):
            hot = False
            for chip, entries in temps['details'].items():
                for entry in entries:
                    if isinstance(entry, dict) and entry.get('current', 0) > 75:
                        hot = True
                    elif getattr(entry, 'current', getattr(entry, 'value', 0)) > 75:
                        hot = True
            if hot:
                issues.append('high temperature')
        if miners.get('success') and (miners.get('details', {}).get('processes') or miners.get('details', {}).get('connections')):
            issues.append('possible miner/malware')
            if apply_fix and miners.get('details', {}).get('killed'):
                actions.append(f"terminated {len(miners['details']['killed'])} miner process(es)")

        scan_result = None
        if apply_fix:
            repair_threads = []
            for label, fn in repairs:
                t = threading.Thread(target=fn, daemon=True)
                t.start()
                repair_threads.append(t)
                actions.append(f'started {label}')
            scan_result = start_voice_scan('virus_scan', 'full diagnostic auto scan', apply_fix=True)
            if scan_result.get('success'):
                actions.append('started a background virus scan and quarantine')

        summary = 'Full diagnostic complete.'
        if issues:
            summary += ' Issues detected: ' + ', '.join(issues) + '.'
        else:
            summary += ' No major issues detected.'
        if actions:
            summary += ' Actions taken: ' + ', '.join(actions) + '.'
        return _make_response(
            'full_diagnostic', summary,
            {'cpu': cpu, 'memory': mem, 'disk': disk, 'network': net,
             'temperatures': temps, 'miners': miners, 'processes': procs,
             'system_services': system, 'scan': scan_result},
            action_taken=bool(actions),
            suggested_fix='Review the details above or say "scan status" to see background scan results.')
    except Exception as e:
        logger.exception('full_diagnostic failed')
        return _make_response('full_diagnostic', f'Diagnostic failed: {e}', {}, success=False)


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
        'virus_scan': lambda: start_voice_scan('virus_scan', raw_command, apply_fix),
        'scan_status': get_voice_scan_status,
        'full_diagnostic': lambda: run_full_diagnostic(apply_fix=apply_fix),
        'system_services': get_system_services,
        'miner_check': lambda: check_miners(apply_fix=apply_fix),
        'hardware_virus': lambda: hardware_virus_check(apply_fix=apply_fix),
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


def _is_authenticated():
    """Accept admin, licensed user, or flask_login sessions."""
    if session.get('logged_in') or session.get('user_logged_in'):
        return True
    try:
        from flask_login import current_user
        return current_user.is_authenticated
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@voice_bp.route('/voice-assistant')
def voice_assistant_page():
    if not _is_authenticated():
        return redirect('/login')
    session.setdefault('csrf_token', secrets.token_urlsafe(32))
    device_id = request.args.get('device_id', '')
    devices = []

    # Cloud proxy mode: list the user's registered devices and default to the
    # most recently seen one. The server's own agent (running on the VPS) is
    # always excluded so commands can never execute on the server by default.
    if current_app.config.get('VOICE_CLOUD_PROXY'):
        try:
            getter = current_app.config.get('VOICE_DEVICES_GETTER')
            if getter:
                server_ids = _server_device_ids()
                devices = sorted(
                    (d for d in getter().values()
                     if d.get('device_id', '') and d.get('device_id', '') not in server_ids),
                    key=lambda x: x.get('last_seen', ''), reverse=True)
                if not device_id and devices:
                    device_id = devices[0].get('device_id', '')
        except Exception as e:
            logger.warning('Could not select default voice device: %s', e)

    return render_template('voice_assistant.html', device_id=device_id, devices=devices)


@voice_bp.route('/api/voice/command', methods=['POST'])
def voice_command():
    try:
        if not _is_authenticated():
            return jsonify({'status': 'error', 'message': 'login required'}), 401
        session.setdefault('csrf_token', secrets.token_urlsafe(32))
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

        # Cloud proxy mode: queue the command for a local agent to execute.
        if current_app.config.get('VOICE_CLOUD_PROXY'):
            device_id = (data.get('device_id') or request.args.get('device_id') or '').strip()
            if not device_id:
                return jsonify({'status': 'error', 'message': 'No target device selected. Pick a device, or make sure the agent is running on your PC.'}), 400
            if device_id in _server_device_ids():
                return jsonify({'status': 'error', 'message': 'Voice commands cannot run on the server itself. Select your own device.'}), 400
            intent = parse_intent(raw)
            job_id = _enqueue_voice_command(device_id, raw, apply_fix)
            return jsonify({
                'status': 'pending',
                'job_id': job_id,
                'command': raw,
                'intent': intent,
                'message': 'Command queued for local agent...',
            })

        # Local mode: run directly on this machine in a background thread.
        intent = parse_intent(raw)
        job_id = secrets.token_urlsafe(16)
        _save_job(job_id, {'status': 'pending', 'command': raw, 'started': time.strftime('%Y-%m-%d %H:%M:%S')})
        threading.Thread(target=_run_voice_job, args=(job_id, intent, raw, apply_fix), daemon=True).start()
        return jsonify({'status': 'pending', 'job_id': job_id, 'command': raw, 'message': 'Processing command...'})
    except (TimeoutError, concurrent.futures.TimeoutError):
        logger.warning('voice_command timed out')
        return jsonify({'status': 'error', 'message': 'Command timed out. Try a more specific command or run a full scan from the scanner page.'}), 504
    except Exception as e:
        logger.exception('voice_command failed')
        return jsonify({'status': 'error', 'message': f'Command failed: {e}'}), 500


@voice_bp.route('/api/voice/intents', methods=['GET'])
def voice_intents():
    return jsonify({
        'intents': [
            {'name': k, 'description': v['description'], 'examples': v['keywords'][:3]}
            for k, v in COMMANDS.items()
        ]
    })


@voice_bp.route('/api/voice/result', methods=['GET'])
def voice_result():
    if not _is_authenticated():
        return jsonify({'status': 'error', 'message': 'login required'}), 401
    token = request.args.get('csrf_token') or request.headers.get('X-CSRF-Token') or ''
    if not token or token != session.get('csrf_token'):
        return jsonify({'status': 'error', 'message': 'Invalid or missing CSRF token'}), 403
    job_id = (request.args.get('job_id') or '').strip()
    if not job_id:
        return jsonify({'status': 'error', 'message': 'Missing job_id'}), 400

    if current_app.config.get('VOICE_CLOUD_PROXY'):
        device_id = (request.args.get('device_id') or '').strip()
        if not device_id:
            return jsonify({'status': 'error', 'message': 'device_id is required'}), 400
        record = _get_voice_command_result(device_id, job_id)
        if not record:
            return jsonify({'status': 'error', 'message': 'Job not found'}), 404
        if record.get('status') == 'completed':
            result = record.get('result') or {}
            return jsonify({'status': 'ok', 'command': record.get('command', ''), **result})
        if record.get('status') == 'error':
            return jsonify({'status': 'error', 'message': record.get('result') or 'Job failed'}), 500
        return jsonify({'status': 'pending', 'message': 'Still processing...', 'command': record.get('command', '')})

    job = _load_job(job_id)
    if not job:
        return jsonify({'status': 'error', 'message': 'Job not found'}), 404
    if job.get('status') == 'completed':
        result = job.get('result') or {}
        return jsonify({'status': 'ok', 'command': job.get('command', ''), **result})
    if job.get('status') == 'error':
        return jsonify({'status': 'error', 'message': job.get('error', 'Job failed')}), 500
    return jsonify({'status': 'pending', 'message': 'Still processing...', 'command': job.get('command', '')})


def _check_voice_api_key():
    expected = os.environ.get('CLOUD_API_KEY', '')
    if not expected:
        return False
    return request.headers.get('X-Api-Key', '').strip() == expected


@voice_bp.route('/api/voice/agent/pending', methods=['POST'])
def voice_agent_pending():
    """Local agents poll this endpoint to receive queued voice commands."""
    if not _check_voice_api_key():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    device_id = (data.get('device_id') or '').strip()
    if not device_id:
        return jsonify({'error': 'device_id is required'}), 400
    _prune_voice_command_queue()
    commands = _poll_voice_commands(device_id)
    return jsonify({'device_id': device_id, 'commands': commands})


@voice_bp.route('/api/voice/agent/result', methods=['POST'])
def voice_agent_result():
    """Local agents post command results back to this endpoint."""
    if not _check_voice_api_key():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    device_id = (data.get('device_id') or '').strip()
    job_id = (data.get('job_id') or '').strip()
    status = data.get('status')
    result = data.get('result')
    if not device_id or not job_id or status not in ('completed', 'error'):
        return jsonify({'error': 'invalid payload'}), 400
    if not _complete_voice_command(device_id, job_id, status, result):
        return jsonify({'error': 'job not found'}), 404
    return jsonify({'ok': True})
