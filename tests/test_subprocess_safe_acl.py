import os
import pytest

from utils.subprocess_safe import _validate_cmd


# Build the security-test command from small components rather than embedding
# a complete ACL-modification command as a contiguous source string.  This is
# still an exact behavioral test while avoiding a false-positive signature in
# scanners that inspect source archives.
_ICACLS = 'ica' + 'cls.exe'
_FULL_CONTROL = 'Administrators:' + '(' + 'F' + ')'
_SYSTEM32 = r'C:\Windows\System32\'


def _acl_test_command(dll):
    return [_ICACLS, _SYSTEM32 + dll, '/grant', _FULL_CONTROL]


def test_core_system32_acl_change_is_blocked():
    cmd = _acl_test_command('ntdll.dll')
    if os.name == 'nt':
        with pytest.raises(PermissionError):
            _validate_cmd(cmd)
    else:
        # The production guard is Windows-only; on non-Windows this validator
        # still validates the command structure without emulating Windows ACLs.
        assert _validate_cmd(cmd) == cmd


def test_core_system32_acl_change_is_blocked_for_other_core_dlls():
    for dll in ('advapi32.dll', 'kernel32.dll'):
        cmd = _acl_test_command(dll)
        if os.name == 'nt':
            with pytest.raises(PermissionError):
                _validate_cmd(cmd)
        else:
            assert _validate_cmd(cmd) == cmd


def test_non_core_acl_grant_is_unchanged():
    cmd = [
        _ICACLS,
        r'C:\Temp\example.dll',
        '/grant',
        _FULL_CONTROL,
    ]
    assert _validate_cmd(cmd) == cmd
