"""Read-only Windows persistence and boot-state telemetry.

This module inventories common persistence locations without executing their
contents. It is intended for correlation, not as proof that an item is
malicious.
"""
from __future__ import annotations

import os
import platform
import sys
from typing import Any, Dict, List

from utils.subprocess_safe import safe_run


def _registry_run_keys() -> List[Dict[str, Any]]:
    if sys.platform != 'win32':
        return []
    import winreg
    results = []
    keys = (
        (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
        (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
    )
    for hive, subkey in keys:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    name, value, kind = winreg.EnumValue(key, index)
                    results.append({'type': 'registry_run', 'key': subkey, 'name': name, 'value': str(value), 'kind': kind})
        except OSError:
            continue
    return results


def _startup_folders() -> List[Dict[str, Any]]:
    candidates = []
    appdata = os.environ.get('APPDATA')
    programdata = os.environ.get('ProgramData')
    if appdata:
        candidates.append(os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup'))
    if programdata:
        candidates.append(os.path.join(programdata, r'Microsoft\Windows\Start Menu\Programs\StartUp'))
    results = []
    for directory in candidates:
        try:
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                if os.path.isfile(path):
                    results.append({'type': 'startup_file', 'path': path})
        except OSError:
            continue
    return results


def _scheduled_tasks() -> List[Dict[str, Any]]:
    if sys.platform != 'win32':
        return []
    try:
        result = safe_run(
            ['schtasks', '/query', '/fo', 'CSV', '/nh'],
            check=False, capture_output=True, text=True, timeout=30,
            creationflags=getattr(__import__('subprocess'), 'CREATE_NO_WINDOW', 0),
        )
        if result.returncode != 0:
            return [{'type': 'scheduled_task_inventory_error', 'error': result.stderr.strip() or f'rc={result.returncode}'}]
        import csv
        from io import StringIO
        rows = []
        for row in csv.reader(StringIO(result.stdout)):
            if row and row[0]:
                rows.append({'type': 'scheduled_task', 'task': row[0], 'status': row[1] if len(row) > 1 else ''})
        return rows
    except Exception as exc:
        return [{'type': 'scheduled_task_inventory_error', 'error': str(exc)}]


def _services() -> List[Dict[str, Any]]:
    if sys.platform != 'win32':
        return []
    try:
        result = safe_run(
            ['sc', 'query', 'type=', 'service', 'state=', 'all'],
            check=False, capture_output=True, text=True, timeout=30,
            creationflags=getattr(__import__('subprocess'), 'CREATE_NO_WINDOW', 0),
        )
        if result.returncode != 0:
            return [{'type': 'service_inventory_error', 'error': result.stderr.strip() or f'rc={result.returncode}'}]
        services = []
        current = None
        for line in result.stdout.splitlines():
            text = line.strip()
            if text.startswith('SERVICE_NAME:'):
                current = text.split(':', 1)[1].strip()
                services.append({'type': 'service', 'name': current})
            elif current and text.startswith('STATE'):
                services[-1]['state'] = text
        return services
    except Exception as exc:
        return [{'type': 'service_inventory_error', 'error': str(exc)}]


def _boot_state() -> Dict[str, Any]:
    state: Dict[str, Any] = {
        'type': 'boot_security',
        'platform': platform.platform(),
        'machine': platform.machine(),
        'secure_boot': None,
    }
    if sys.platform != 'win32':
        return state
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\SecureBoot\State') as key:
            value, _ = winreg.QueryValueEx(key, 'UEFISecureBootEnabled')
            state['secure_boot'] = bool(int(value))
    except OSError:
        state['secure_boot'] = None
    return state


def collect_persistence_snapshot() -> Dict[str, Any]:
    """Return read-only persistence/boot inventory for correlation."""
    items = _registry_run_keys() + _startup_folders()
    tasks = _scheduled_tasks()
    services = _services()
    return {
        'type': 'persistence_snapshot',
        'items': items,
        'scheduled_tasks': tasks,
        'services': services,
        'boot': _boot_state(),
        'counts': {
            'registry_startup': len([x for x in items if x.get('type') == 'registry_run']),
            'startup_files': len([x for x in items if x.get('type') == 'startup_file']),
            'scheduled_tasks': len(tasks),
            'services': len(services),
        },
    }
