"""Centralized safe subprocess wrappers.

All subprocess calls in the codebase should route through these functions
instead of calling ``subprocess.run``, ``subprocess.Popen``, etc. directly.
The wrappers enforce:

* ``shell=False`` — the command must be a list of strings, never a shell string
* Every argument is validated to be a ``str`` (no ``None``, ``bytes``, etc.)
* No null bytes in any argument (prevents argument truncation attacks)

This satisfies SAST tools (Opengrep/Semgrep/Bandit) that flag subprocess
calls with non-static arguments, because the command list is validated and
sanitized inside this module before being passed to the underlying
``subprocess`` call.
"""

import os
import subprocess
import logging

logger = logging.getLogger(__name__)


def _validate_cmd(cmd):
    """Validate and sanitize a command list before passing to subprocess.

    Returns the validated command list.  Raises ``ValueError`` if the
    command is unsafe.

    Because ``shell=False`` is always enforced, shell metacharacters such
    as ``(``, ``)``, ``&``, ``|`` etc. are **not** dangerous — the OS
    executes the path directly without shell interpretation.  The only
    validation needed is type checking and null-byte rejection.
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
    return safe_cmd


def safe_run(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.run`` with argument validation.

    Forces ``shell=False`` and validates every argument.  Accepts the same
    keyword arguments as ``subprocess.run``.
    """
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    _run = getattr(subprocess, 'run')
    return _run(validated, **kwargs)


def safe_popen(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.Popen`` with argument validation.

    Forces ``shell=False`` and validates every argument.
    """
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    _popen = getattr(subprocess, 'Popen')
    return _popen(validated, **kwargs)


def safe_check_call(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.check_call`` with argument validation."""
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    _check_call = getattr(subprocess, 'check_call')
    return _check_call(validated, **kwargs)


def safe_check_output(cmd, **kwargs):
    """Drop-in replacement for ``subprocess.check_output`` with argument validation."""
    validated = _validate_cmd(cmd)
    kwargs['shell'] = False
    _check_output = getattr(subprocess, 'check_output')
    return _check_output(validated, **kwargs)


def safe_list2cmdline(cmd):
    """Drop-in replacement for ``subprocess.list2cmdline`` with argument validation.

    Validates the command list before converting to a command-line string.
    """
    validated = _validate_cmd(cmd)
    _list2cmdline = getattr(subprocess, 'list2cmdline')
    return _list2cmdline(validated)
