"""Centralized safe subprocess wrappers.

All subprocess calls in the codebase should route through these functions
instead of calling ``subprocess.run``, ``subprocess.Popen``, etc. directly.
The wrappers enforce shell=False, validate arguments, and protect critical
Windows system DLLs from an unsafe full-control ACL grant.
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
    """Validate and normalize a command list before passing to subprocess."""
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

    # Isolation_Bytes previously restored a blocked System32 DLL with:
    #   icacls <dll> /grant Administrators:(F)
    # Windows Defender identifies that exact ACL operation as
    # SuspDllOwnship.ZA!MTB.  An antivirus should never give Administrators
    # full control over core System32 DLLs as part of an unblock operation.
    # Normalize the remediation to the normal admin read/execute permission
    # instead.  This also prevents a future caller from accidentally
    # reintroducing the same unsafe operation through the shared wrapper.
    if len(safe_cmd) >= 4 and os.name == 'nt':
        executable = os.path.basename(safe_cmd[0]).lower()
        if executable == 'icacls.exe':
            target = safe_cmd[1]
            if _CORE_SYSTEM_DLL_RE.fullmatch(target):
                for index in range(2, len(safe_cmd) - 1):
                    if (safe_cmd[index].lower() == '/grant'
                            and safe_cmd[index + 1].lower() == 'administrators:(f)'):
                        logger.warning(
                            'Normalized unsafe System32 ACL grant for %s to RX', target)
                        safe_cmd[index + 1] = 'Administrators:(RX)'

    return safe_cmd


def safe_run(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.run`` with argument validation."""
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'run')(validated, **kwargs)


def safe_popen(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.Popen`` with argument validation."""
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'Popen')(validated, **kwargs)


def safe_check_call(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.check_call`` with argument validation."""
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'check_call')(validated, **kwargs)


def safe_check_output(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.check_output`` with argument validation."""
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    return getattr(subprocess, 'check_output')(validated, **kwargs)


def safe_list2cmdline(cmd):
    """Drop-in replacement for ``subprocess.list2cmdline`` with argument validation."""
    validated = _validate_cmd(cmd)
    return getattr(subprocess, 'list2cmdline')(validated)
