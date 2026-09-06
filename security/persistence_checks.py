"""
Static/lightweight checks for common malware persistence and execution
patterns: processes running from unusual locations, registry autostart
entries pointing at unusual locations, and autorun.inf on removable drives.

These replace the substring-matching spyware/trojan/worm/adware checks in
conditional_startup.py's routine_maintenance_and_system_recovery(), which
flagged process/file names containing generic English words like 'shell',
'access', 'remote', 'monitor', 'log', or 'capture' -- catching PowerShell,
Microsoft Access, Remote Desktop/TeamViewer, display monitors, event logs,
and screen-capture software as "malware indicators". Location-based checks
(is this running from/persisting from a place legitimate installed software
doesn't normally live) are a much narrower, lower-false-positive signal.

All of this is report-only, same rationale as the ML/ransomware checks in
security/detector.py: these are weak proxies, not proof of malware, so they
should surface as dashboard counters rather than auto-quarantine triggers.
"""
import os
import logging

logger = logging.getLogger('persistence_checks')

# Directories legitimate installed software essentially never runs from or
# persists from; malware commonly does, since it doesn't go through a normal
# installer that would put it in Program Files/AppData\Local\Programs/etc.
_SUSPICIOUS_LOCATION_FRAGMENTS = (
    os.path.join('appdata', 'local', 'temp'),
    os.path.join('windows', 'temp'),
    os.path.join('users', 'public'),
    '\\temp\\',
    '\\downloads\\',
    '\\recycle.bin\\',
    '$recycle.bin',
)


def _is_suspicious_location(path):
    if not path:
        return False
    lowered = path.lower()
    return any(fragment in lowered for fragment in _SUSPICIOUS_LOCATION_FRAGMENTS)


def check_suspicious_processes():
    """Running processes whose executable lives in a location legitimate
    software doesn't normally run from. Returns a list of finding dicts."""
    findings = []
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not available, skipping suspicious process check")
        return findings

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info.get('exe')
            if exe and _is_suspicious_location(exe):
                findings.append({
                    "process": proc.info.get('name'),
                    "pid": proc.info.get('pid'),
                    "exe": exe,
                    "indicator": "process_running_from_unusual_location",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def check_registry_persistence():
    """Windows Run/RunOnce autostart entries (HKCU and HKLM) pointing at
    executables in an unusual location. Returns a list of finding dicts.
    No-ops (returns []) on non-Windows."""
    findings = []
    try:
        import winreg
    except ImportError:
        return findings  # Not on Windows

    run_key_paths = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, subkey in run_key_paths:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if isinstance(value, str) and _is_suspicious_location(value):
                        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                        findings.append({
                            "registry_key": f"{hive_name}\\{subkey}",
                            "value_name": name,
                            "command": value,
                            "indicator": "autostart_entry_in_unusual_location",
                        })
        except OSError:
            continue  # Key doesn't exist or isn't accessible
    return findings


def check_removable_drive_autorun():
    """autorun.inf on removable drives -- a real, specific worm/USB-malware
    propagation technique (unlike the generic filename substring matching
    this replaces), so this stays a straightforward exact-filename check.
    Returns a list of finding dicts. No-ops (returns []) on non-Windows."""
    findings = []
    try:
        import psutil
    except ImportError:
        return findings

    try:
        for part in psutil.disk_partitions():
            if 'removable' not in part.opts.lower():
                continue
            autorun_path = os.path.join(part.mountpoint, 'autorun.inf')
            if os.path.exists(autorun_path):
                findings.append({
                    "path": autorun_path,
                    "drive": part.mountpoint,
                    "indicator": "autorun_inf_on_removable_drive",
                })
    except Exception as e:
        logger.debug(f"Error checking removable drive autorun: {e}")
    return findings


def run_all_checks():
    """Run all persistence/process checks and return a combined dict."""
    return {
        "suspicious_processes": check_suspicious_processes(),
        "registry_persistence": check_registry_persistence(),
        "removable_autorun": check_removable_drive_autorun(),
    }
