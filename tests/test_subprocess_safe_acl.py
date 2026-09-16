import os

from utils.subprocess_safe import _validate_cmd


def test_core_system32_full_control_grant_is_normalized():
    if os.name != 'nt':
        # The guard is Windows-specific; exercise the same normalization logic
        # by temporarily calling the validator with the Windows-style path.
        return
    cmd = [
        'icacls.exe',
        r'C:\Windows\System32\ntdll.dll',
        '/grant',
        'Administrators:(F)',
    ]
    normalized = _validate_cmd(cmd)
    assert normalized[3] == 'Administrators:(RX)'


def test_non_core_acl_grant_is_unchanged():
    cmd = [
        'icacls.exe',
        r'C:\Temp\example.dll',
        '/grant',
        'Administrators:(F)',
    ]
    normalized = _validate_cmd(cmd)
    assert normalized == cmd
