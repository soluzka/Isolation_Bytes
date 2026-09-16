import hashlib
import os
import sys
import time
import logging
import subprocess
import shutil
import threading
import re

import psutil

from utils.subprocess_safe import safe_run

NETSH_PATH = shutil.which('netsh') or 'netsh'

if sys.platform == 'win32':
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
else:
    DETACHED_PROCESS = 0
    CREATE_NO_WINDOW = 0

_TELEMETRY_STARTED = False
_TELEMETRY_LOCK = threading.Lock()


def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _normalize(path):
    try:
        return os.path.normcase(os.path.abspath(path))
    except (OSError, TypeError, ValueError):
        return ''


def _is_windows_system_binary(path):
    if not path:
        return False
    p = _normalize(path)
    system_root = os.environ.get('SystemRoot', r'C:\Windows')
    for root in (
        os.path.join(system_root, 'System32'),
        os.path.join(system_root, 'SysWOW64'),
        os.path.join(system_root, 'WinSxS'),
    ):
        r = _normalize(root)
        if r and (p == r or p.startswith(r + os.sep)):
            return True
    return False


def _command_line(proc):
    try:
        return ' '.join(proc.cmdline() or [])
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return ''


def _parent_details(proc):
    try:
        parent = proc.parent()
        if parent is None:
            return {}
        return {
            'parent_pid': parent.pid,
            'parent_name': parent.name(),
            'parent_exe': parent.exe(),
            'parent_cmdline': _command_line(parent),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return {}


def _sha256(path):
    """Hash a file without executing or modifying it."""
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def _suspicious_command_line(command_line):
    value = (command_line or '').lower()
    patterns = (
        r'\\icacls(?:\.exe)?\s+.*\\windows\\system32\\(?:advapi32|kernel32|ntdll)\.dll.*?/grant\s+administrators:\(f\)',
        r'\\windows\\system32\\(?:advapi32|kernel32|ntdll)\.dll.*?/grant\s+administrators:\(f\)',
        r'(?:powershell|pwsh)(?:\.exe)?[^\r\n]*(?:-enc|-encodedcommand|downloadstring|invoke-expression|\biex\b)',
        r'(?:rundll32|regsvr32|mshta|wscript|cscript|installutil|wmic|msiexec|certutil|bitsadmin)(?:\.exe)?[^\r\n]*(?:http|https|\\\\|/urlcache|/transfer|/decode|/i\s)',
        r'(?:schtasks|sc)(?:\.exe)?[^\r\n]*(?:create|create\s+service)',
        r'(?:reg|reg\.exe)\s+(?:add|import)\s+.*(?:\\run(?:once)?(?:\\|$)|\\services\\)',
        r'(?:cmd|cmd\.exe)[^\r\n]*/c[^\r\n]*(?:powershell|certutil|bitsadmin|rundll32|regsvr32|mshta)',
    )
    return [pattern for pattern in patterns if re.search(pattern, value)]


def _enable_process_auditing():
    if sys.platform != 'win32':
        return False, 'not_windows'
    try:
        result = safe_run(
            ['auditpol', '/set', '/subcategory:Process Creation', '/success:enable'],
            check=False,
            creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True, 'enabled'
        return False, (result.stderr or result.stdout or f'rc={result.returncode}').strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def _event4688_loop(event_callback):
    """Poll Windows Security 4688 events and correlate child/parent context."""
    if sys.platform != 'win32':
        return
    try:
        import win32evtlog
    except ImportError:
        logging.warning('pywin32 unavailable; Windows 4688 telemetry disabled')
        return

    ok, audit_status = _enable_process_auditing()
    emit = event_callback or (lambda event: None)
    last_record = 0
    try:
        handle = win32evtlog.OpenEventLog(None, 'Security')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0) or []
        if events:
            last_record = max(int(getattr(e, 'RecordNumber', 0)) for e in events)
        win32evtlog.CloseEventLog(handle)
    except Exception as exc:
        logging.warning('Unable to initialize Windows 4688 telemetry: %s', exc)
        return

    logging.info('Windows process telemetry started (audit=%s, status=%s)', ok, audit_status)
    while True:
        try:
            handle = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0) or []
            win32evtlog.CloseEventLog(handle)
            for event in events:
                record = int(getattr(event, 'RecordNumber', 0))
                if record <= last_record:
                    continue
                last_record = max(last_record, record)
                if int(getattr(event, 'EventID', 0)) & 0xFFFF != 4688:
                    continue
                strings = list(getattr(event, 'StringInserts', ()) or ())
                data = {
                    'event_id': 4688,
                    'record_number': record,
                    'time_created': str(getattr(event, 'TimeGenerated', '')),
                    'subject_user': strings[1] if len(strings) > 1 else None,
                    'new_process_id': strings[4] if len(strings) > 4 else None,
                    'new_process_name': strings[5] if len(strings) > 5 else None,
                    'creator_process_id': strings[7] if len(strings) > 7 else None,
                    'creator_process_name': strings[8] if len(strings) > 8 else None,
                    'command_line': strings[9] if len(strings) > 9 else (strings[-1] if strings else None),
                    'audit_status': audit_status,
                }
                command_hits = _suspicious_command_line(data['command_line'])
                if not command_hits:
                    continue
                data['suspicious_command_indicators'] = command_hits
                data['severity_hint'] = 'high'
                try:
                    pid = int(str(data.get('new_process_id') or ''), 0)
                    proc = psutil.Process(pid)
                    data['exe'] = proc.exe()
                    data['pid'] = pid
                    data['sha256'] = _sha256(data['exe'])
                    data.update(_parent_details(proc))
                    modules = []
                    try:
                        for mapping in proc.memory_maps(grouped=True):
                            module = getattr(mapping, 'path', '')
                            if module and os.path.isfile(module):
                                modules.append(module)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        pass
                    data['loaded_modules'] = modules[:256]
                except (ValueError, psutil.Error, OSError):
                    pass
                try:
                    emit({'type': 'process_creation_suspicious', **data})
                except Exception:
                    logging.exception('Process telemetry callback failed')
        except Exception as exc:
            logging.warning('Windows process telemetry error: %s', exc)
        time.sleep(3)


def _host_snapshot_loop(event_callback):
    """Periodically collect read-only persistence and boot-state inventory."""
    try:
        from security.host_telemetry import collect_persistence_snapshot
    except Exception as exc:
        logging.warning('Host telemetry unavailable: %s', exc)
        return
    while True:
        try:
            snapshot = collect_persistence_snapshot()
            if event_callback:
                event_callback(snapshot)
        except Exception as exc:
            logging.warning('Persistence telemetry error: %s', exc)
        time.sleep(300)


def start_process_creation_telemetry(event_callback=None):
    global _TELEMETRY_STARTED
    with _TELEMETRY_LOCK:
        if _TELEMETRY_STARTED:
            return
        _TELEMETRY_STARTED = True
    if sys.platform == 'win32':
        threading.Thread(target=_event4688_loop, args=(event_callback,), name='process-creation-telemetry', daemon=True).start()
    threading.Thread(target=_host_snapshot_loop, args=(event_callback,), name='host-persistence-telemetry', daemon=True).start()


def scan_running_processes(scan_func, terminate_on_malware=True, block_connections=True, event_callback=None):
    """Scan accessible running processes, including privileged/system processes."""
    start_process_creation_telemetry(event_callback)

    def emit(event_type, **details):
        if event_callback:
            try:
                event_callback({'type': event_type, **details})
            except Exception as e:
                logging.debug(f'event_callback raised for event {event_type!r}: {e}')

    scanned = set()
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            exe = proc.info.get('exe')
            pid = proc.info.get('pid')
            name = proc.info.get('name')
            username = proc.info.get('username')
            if not exe or not os.path.isfile(exe) or pid in scanned:
                continue
            scanned.add(pid)
            parent = _parent_details(proc)
            cmdline = _command_line(proc)
            indicators = _suspicious_command_line(cmdline)
            sha256 = _sha256(exe)
            emit('process_scanned', pid=pid, name=name, exe=exe, username=username,
                 command_line=cmdline, system_binary=_is_windows_system_binary(exe),
                 sha256=sha256, suspicious_command_indicators=indicators, **parent)
            result = scan_func(exe)
            if not result or len(result) < 3:
                logging.error(f'Unexpected scan result format for {exe}: {result}')
                continue
            scan_success, malware_found, msg = result
            if indicators and not malware_found:
                # Behavioral evidence is useful even when static/YARA/ML scans
                # have no signature for the payload. Do not claim it is malware.
                emit('behavioral_suspicion', pid=pid, name=name, exe=exe,
                     username=username, command_line=cmdline,
                     suspicious_command_indicators=indicators, sha256=sha256, **parent)
            if not scan_success:
                logging.warning(f'Scan failed for {exe}: {msg}')
                emit('process_scan_error', pid=pid, name=name, exe=exe, message=msg)
                continue
            if malware_found:
                logging.warning(f'Malware found in process {name} (PID: {pid}), exe: {exe}. {msg}')
                emit('malware_found', pid=pid, name=name, exe=exe, username=username,
                     command_line=cmdline, sha256=sha256, message=msg, **parent)
                if terminate_on_malware:
                    try:
                        p = psutil.Process(pid)
                        p.terminate()
                        p.wait(timeout=5)
                        logging.warning(f'Terminated process {name} (PID: {pid}) due to malware.')
                        emit('process_terminated', pid=pid, name=name, exe=exe)
                    except Exception as e:
                        logging.error(f'Failed to terminate process {pid}: {e}')
                if block_connections:
                    try:
                        p = psutil.Process(pid)
                        for conn in psutil.net_connections(kind='inet'):
                            if conn.pid == pid and conn.raddr:
                                remote_ip = conn.raddr.ip
                                block_ip(remote_ip)
                                logging.warning(f'Blocked IP {remote_ip} for process {name} (PID: {pid})')
                                emit('connection_blocked', pid=pid, name=name, remote_ip=remote_ip)
                    except Exception as e:
                        logging.error(f'Failed to block connections for process {pid}: {e}')
            else:
                logging.info(f'Process {name} (PID: {pid}) is clean.')

            try:
                from security.yara_scanner import scan_file_with_yara
                matches = scan_file_with_yara(exe)
                if matches:
                    logging.warning(f'[RTP][PROC] YARA match detected in process EXE: {exe} (PID: {pid}, Name: {name})')
                    emit('yara_match', pid=pid, name=name, exe=exe, username=username,
                         command_line=cmdline, sha256=sha256, yara_matches=matches, **parent)
            except Exception as e:
                logging.error(f'[RTP][PROC] Error running YARA scan on process EXE {exe}: {e}')

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            logging.debug('Process scan error: %s', e)


def block_ip(ip):
    """Block an IP using Windows Firewall (netsh advfirewall)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        logging.error(f'Refusing to block invalid IP: {ip!r}')
        return
    try:
        for direction in ('out', 'in'):
            safe_run(
                [
                    NETSH_PATH, 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=Block_{ip}', f'dir={direction}', 'action=block', f'remoteip={ip}'
                ], check=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    except Exception as e:
        logging.error(f'Failed to block IP {ip}: {e}')
