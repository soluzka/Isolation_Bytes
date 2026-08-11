import os
import psutil
import hashlib
import math
import logging
import tempfile
from typing import Dict, List, Optional, Tuple


def _shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy (0-8 for bytes) of a byte string."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    size = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / size
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _file_hashes(path: str) -> Dict[str, str]:
    """Return md5/sha1/sha256 hex hashes for a file."""
    hashes = {'md5': None, 'sha1': None, 'sha256': None}
    try:
        with open(path, 'rb') as f:
            data = f.read()
        hashes = {
            'md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
            'sha1': hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'entropy': round(_shannon_entropy(data), 2)
        }
    except Exception as e:
        logging.warning(f'Could not hash {path}: {e}')
    return hashes


def _yara_scan(path: str) -> List[str]:
    """Run the project's YARA scanner against a file if available."""
    try:
        from security.yara_scanner import scan_file_with_yara
        result = scan_file_with_yara(path)
        if result:
            return [str(result)]
    except Exception as e:
        logging.debug(f'YARA scan unavailable for {path}: {e}')
    return []


def _memory_regions(pid: int, max_bytes: int = 8192) -> List[Dict]:
    """Snapshot readable memory region names/sizes for a process (no full read)."""
    try:
        proc = psutil.Process(pid)
        regions = []
        for m in proc.memory_maps():
            regions.append({
                'path': m.path,
                'rss': m.rss,
                'size': m.size,
                'private': getattr(m, 'private', 0)
            })
        return regions
    except Exception as e:
        logging.debug(f'Memory map read failed for PID {pid}: {e}')
        return []


def _is_signed_windows(path: str) -> bool:
    """Best-effort check for a Windows Authenticode signature using PowerShell."""
    import platform
    import os
    if platform.system() != 'Windows':
        return False
    try:
        import subprocess
        env = os.environ.copy()
        env['TARGET_EXE'] = path
        # nosem; nosec B603: path is passed via env var, command list is static
        out = subprocess.run(
            [
                'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
                'Get-AuthenticodeSignature -Path $env:TARGET_EXE | Select-Object -ExpandProperty Status -ErrorAction Stop'
            ],
            capture_output=True, text=True, check=False,
            creationflags=0x08000000, env=env
        ).stdout.strip()
        return 'Valid' in out
    except Exception:
        return False


def scan_processes_with_hardening(
    scan_all_users: bool = False,
    terminate_on_malware: bool = True,
    block_connections: bool = False,
    entropy_threshold: float = 7.5,
    event_callback=None
) -> List[Dict]:
    """
    Scan every running process executable for:
      - file hashes (md5, sha1, sha256)
      - Shannon entropy
      - YARA rule matches
      - memory region snapshots
      - missing/invalid code signature (Windows)

    Optionally terminate high-risk processes (YARA match or very high entropy).
    Returns a list of result dicts.
    """
    import getpass
    from security.process_monitor import scan_running_processes

    current_user = getpass.getuser()
    results: List[Dict] = []

    def _default_scan(exe: str) -> Tuple[bool, bool, str]:
        findings: List[str] = []
        hashes = _file_hashes(exe)
        yara = _yara_scan(exe)
        if yara:
            findings.extend(yara)
        if hashes.get('entropy', 0) > entropy_threshold:
            findings.append(f'high entropy ({hashes["entropy"]})')
        if not _is_signed_windows(exe) and not exe.startswith('C:\\Windows'):
            findings.append('not signed')
        msg = '; '.join(findings) if findings else 'clean'
        return True, bool(findings), msg

    def _on_event(event: Dict):
        if event['type'] == 'process_scanned' and event_callback:
            # Enrich with extra metadata once per process
            pid = event.get('pid')
            exe = event.get('exe')
            if pid and exe and os.path.isfile(exe):
                event['hashes'] = _file_hashes(exe)
                event['yara'] = _yara_scan(exe)
                event['memory_regions'] = _memory_regions(pid)
                event['signed'] = _is_signed_windows(exe)
                results.append(event)
            if event_callback:
                event_callback(event)
        elif event_callback:
            event_callback(event)

    scan_running_processes(
        scan_func=_default_scan,
        terminate_on_malware=terminate_on_malware,
        block_connections=block_connections,
        event_callback=_on_event
    )
    return results


def scan_specific_process(pid: int, entropy_threshold: float = 7.5) -> Optional[Dict]:
    """Scan a single process by PID: hashes, YARA, signature, memory regions."""
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        if not exe or not os.path.isfile(exe):
            return None

        findings = []
        yara = _yara_scan(exe)
        if yara:
            findings.extend(yara)

        hashes = _file_hashes(exe)
        if hashes.get('entropy', 0) > entropy_threshold:
            findings.append(f'high entropy ({hashes["entropy"]})')

        if not _is_signed_windows(exe) and not exe.startswith('C:\\Windows'):
            findings.append('not signed')

        return {
            'pid': pid,
            'name': proc.name(),
            'exe': exe,
            'hashes': hashes,
            'yara': yara,
            'signed': _is_signed_windows(exe),
            'memory_regions': _memory_regions(pid),
            'findings': findings,
            'malware_found': bool(findings)
        }
    except Exception as e:
        logging.warning(f'Could not scan process {pid}: {e}')
        return None
