import os
import pytest

from utils.subprocess_safe import _validate_cmd


def test_core_system32_acl_change_is_blocked():
    cmd = [
        'icacls.exe',
        r'C:\Windows\System32\ntdll.dll',
        '/grant',
        'Administrators:(F)',
    ]
    if os.name == 'nt':
        with pytest.raises(PermissionError):
            _validate_cmd(cmd)
    else:
        # The production guard is Windows-only; on non-Windows this validator
        # still validates the command structure without emulating Windows ACLs.
        assert _validate_cmd(cmd) == cmd


def test_core_system32_acl_change_is_blocked_for_other_core_dlls():
    for dll in ('advapi32.dll', 'kernel32.dll'):
        cmd = ['icacls.exe', rf'C:\Windows\System32\{dll}', '/grant', 'Administrators:(F)']
        if os.name == 'nt':
            with pytest.raises(PermissionError):
                _validate_cmd(cmd)
        else:
            assert _validate_cmd(cmd) == cmd


def test_non_core_acl_grant_is_unchanged():
    cmd = [
        'icacls.exe',
        r'C:\Temp\example.dll',
        '/grant',
        'Administrators:(F)',
    ]
    assert _validate_cmd(cmd) == cmd
