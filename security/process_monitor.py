import psutil
import os
import logging
import sys
import subprocess

# --- Windows subprocess window suppression ---
import sys
if sys.platform == 'win32':
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
else:
    DETACHED_PROCESS = 0
    CREATE_NO_WINDOW = 0

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def scan_running_processes(scan_func, terminate_on_malware=True, block_connections=True, event_callback=None):
    """
    Scan all running processes owned by the current user and running from user-created folders (not Windows defaults/system).

    event_callback: optional callable invoked with a dict for each notable
    event (process scanned, malware found, process terminated, connection
    blocked, YARA match). Callers that don't need this can omit it -- this
    is purely additive so existing callers are unaffected.
    """
    def emit(event_type, **details):
        if event_callback:
            try:
                event_callback({'type': event_type, **details})
            except Exception as e:
                # A misbehaving callback shouldn't abort the process scan, but
                # silently swallowing the error makes such bugs invisible.
                logging.debug(f'event_callback raised for event {event_type!r}: {e}')

    import getpass
    current_user = getpass.getuser()
    import pathlib
    import re

    # Define Windows default/system folders to exclude
    SYSTEM_FOLDERS = [
        r"C:\\Windows",
        r"C:\\Program Files",
        r"C:\\Program Files (x86)",
        r"C:\\ProgramData",
        r"C:\\Users\\Default",
        r"C:\\Users\\Public",
        r"C:\\Users\\All Users",
        r"C:\\Users\\defaultuser0",
    ]
    SYSTEM_FOLDERS = [os.path.normcase(f) for f in SYSTEM_FOLDERS]

    # Helper to check if a path is under any system folder
    def is_system_folder(path):
        np = os.path.normcase(os.path.abspath(path))
        return any(np.startswith(sf) for sf in SYSTEM_FOLDERS)

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            exe = proc.info.get('exe', None)
            pid = proc.info.get('pid', None)
            name = proc.info.get('name', None)
            username = proc.info.get('username', None)
            if exe and os.path.isfile(exe):
                if username is None or (current_user.lower() not in username.lower()):
                    continue  # Not the current user's process
                if is_system_folder(exe):
                    continue  # Skip system/Windows default folders
                # Only scan user processes from user-created folders
                emit('process_scanned', pid=pid, name=name, exe=exe, malware_found=False)
                result = scan_func(exe)
                if result and len(result) >= 3:  # Ensure result tuple has enough elements
                    if isinstance(result, (tuple, list)) and len(result) >= 3:
                        scan_success, malware_found, msg = result
                    else:
                        logging.error(f'Unexpected scan result format for {exe}: {result}')
                        continue
                    if not scan_success:
                        logging.warning(f'Scan failed for {exe}: {msg}')
                    elif malware_found:
                        logging.warning(f'Malware found in process {name} (PID: {pid}), exe: {exe}. {msg}')
                        emit('malware_found', pid=pid, name=name, exe=exe, message=msg)
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
                                # Find all connections for this process and block remote IPs
                                p = psutil.Process(pid)
                                for conn in psutil.net_connections(kind='inet'):
                                    if conn.pid == pid:
                                        if conn.raddr:
                                            remote_ip = conn.raddr.ip
                                            block_ip(remote_ip)
                                            logging.warning(f'Blocked IP {remote_ip} for process {name} (PID: {pid})')
                                            emit('connection_blocked', pid=pid, name=name, remote_ip=remote_ip)
                            except Exception as e:
                                logging.error(f'Failed to block connections for process {pid}: {e}')
                    else:
                        logging.info(f'Process {name} (PID: {pid}) is clean.')
                    # YARA scan
                    try:
                        from security.yara_scanner import scan_file_with_yara
                        if scan_file_with_yara(exe):
                            logging.warning(f'[RTP][PROC] YARA match detected in process EXE: {exe} (PID: {pid}, Name: {name})')
                            emit('yara_match', pid=pid, name=name, exe=exe)
                    except Exception as e:
                        logging.error(f'[RTP][PROC] Error running YARA scan on process EXE {exe}: {e}')

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def block_ip(ip):
    """
    Block the given IP using Windows Firewall (netsh advfirewall). Only works with admin privileges.
    """
    try:
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=Block_{ip}', 'dir=out', 'action=block', f'remoteip={ip}'
        ], check=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=Block_{ip}', 'dir=in', 'action=block', f'remoteip={ip}'
        ], check=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logging.error(f'Failed to block IP {ip}: {e}')
