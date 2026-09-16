"""Centralized safe subprocess wrappers.

All subprocess calls in the codebase should route through these functions
instead of calling ``subprocess.run``, ``subprocess.Popen``, etc. directly.
The wrappers enforce shell=False, validate arguments, and refuse automatic
ACL changes to critical Windows system DLLs.
"""

import os
import re
import subprocess
import logging

logger = logging.getLogger(__name__)

_CORE_SYSTEM_DLL_RE = re.compile(
    r"^(?:[A-Za-z]:)?[\\/]Windows[\\/]System32[\\/](?:advapi32|kernel32|ntdll)\.dll$",
    re.IGNORECASE,
)


def _validate_cmd(cmd):
    """Validate a command list before passing it to subprocess.

    Critical System32 DLLs are never modified through an automatic
    Isolation_Bytes subprocess operation.  In particular, the old unblock
    implementation attempted to restore them with ``icacls /grant
    Administrators:(F)``.  ``icacls`` changes a file's DACL, so silently
    changing that command to another ACL would still be the wrong behavior.
    Refuse the operation instead and require the caller to use a safe
    unblock mechanism that does not alter the DLL's DACL.
    """
    if not isinstance(cmd, (list, tuple)):
        raise ValueError(f'subprocess command must be a list/tuple, got {type(cmd)}')
    if len(cmd) == 0:
        raise ValueError('subprocess command must not be empty')

    safe_cmd = []
    for i, arg in enumerate(cmd):
        if not isinstance(arg, str):
            raise ValueError(
                f'subprocess argument {i} must be str, got {type(arg)}: {arg!r}')
        if '\x00' in arg:
            raise ValueError(f'subprocess argument {i} contains null bytes')
        safe_cmd.append(arg)

    if len(safe_cmd) >= 2 and os.name == 'nt':
        executable = os.path.basename(safe_cmd[0]).lower()
        target = safe_cmd[1]
        if executable == 'icacls.exe' and _CORE_SYSTEM_DLL_RE.fullmatch(target):
            raise PermissionError(
                f'Automatic ACL modification of protected System32 DLL is blocked: {target}'
            )

    return safe_cmd


def safe_run(cmd, **kwargs):
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'run')(validated, **kwargs)


def safe_popen(cmd, **kwargs):
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'Popen')(validated, **kwargs)


def safe_check_call(cmd, **kwargs):
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'check_call')(validated, **kwargs)


def safe_check_output(cmd, **kwargs):
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'check_output')(validated, **kwargs)


def safe_list2cmdline(cmd):
    validated = _validate_cmd(cmd)
    return getattr(subprocess, 'list2cmdline')(validated)
