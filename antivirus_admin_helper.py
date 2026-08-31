"""Launch the unpacked Antivirus Server executable with administrator rights."""
import base64
import os
import struct
import subprocess
import sys
from pathlib import Path


APP_EXECUTABLE = "antivirus_server.exe"
_ELEVATION_FLAG = "--helper-elevation-attempted"


def _ensure_administrator():
    """Re-launch the helper with UAC if its manifest was not applied."""
    if sys.platform != 'win32' or _ELEVATION_FLAG in sys.argv:
        return True
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        params = [*sys.argv[1:], _ELEVATION_FLAG]
        command_line = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in params)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', sys.executable, command_line, None, 1
        )
        if result <= 32:
            print('Administrator privileges were not granted.', file=sys.stderr)
            return False
        return None
    except Exception as error:
        print(f'Could not request Administrator privileges: {error}', file=sys.stderr)
        return False


def _set_shortcut_runas(path: Path) -> None:
    """Mark a Windows shortcut as RunAs so it requests UAC explicitly."""
    try:
        with path.open('r+b') as shortcut:
            if struct.unpack('<I', shortcut.read(4))[0] != 0x4C:
                return
            shortcut.seek(0x14)
            flags = struct.unpack('<I', shortcut.read(4))[0] | 0x2000
            shortcut.seek(0x14)
            shortcut.write(struct.pack('<I', flags))
    except (OSError, struct.error):
        pass


def _create_admin_shortcuts() -> None:
    """Create administrator shortcuts that target this external helper."""
    helper = Path(sys.executable).resolve()
    helper_text = str(helper).replace("'", "''")
    script = f"""
$desktop = [Environment]::GetFolderPath('Desktop')
$wsh = New-Object -ComObject WScript.Shell
$items = @(
    @{{ Name = 'Antivirus Server (Administrator).lnk'; Args = '' }},
    @{{ Name = 'Antivirus Server (standalone).lnk'; Args = '' }},
    @{{ Name = 'Start Conditional Antivirus (Administrator).lnk'; Args = '' }},
    @{{ Name = 'Start Conditional Antivirus.lnk'; Args = '' }},
    @{{ Name = 'Start YARA Scanner (Administrator).lnk'; Args = '--open-yara' }},
    @{{ Name = 'Start YARA Scanner.lnk'; Args = '--open-yara' }}
)
foreach ($item in $items) {{
    $shortcut = $wsh.CreateShortcut((Join-Path $desktop $item.Name))
    $shortcut.TargetPath = '{helper_text}'
    $shortcut.Arguments = $item.Args
    $shortcut.WorkingDirectory = Split-Path -Parent '{helper_text}'
    $shortcut.IconLocation = '{helper_text},0'
    $shortcut.Description = 'Antivirus Server (Administrator)'
    $shortcut.Save()
}}
"""
    encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
    subprocess.run(
        ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
        check=False,
        capture_output=True,
        text=True,
        creationflags=0x08000000,
    )
    desktop = Path(os.environ.get('USERPROFILE', str(Path.home()))) / 'Desktop'
    for name in (
        'Antivirus Server (Administrator).lnk',
        'Antivirus Server (standalone).lnk',
        'Start Conditional Antivirus (Administrator).lnk',
        'Start Conditional Antivirus.lnk',
        'Start YARA Scanner (Administrator).lnk',
        'Start YARA Scanner.lnk',
    ):
        _set_shortcut_runas(desktop / name)


def _application_path() -> Path:
    helper_dir = Path(sys.executable).resolve().parent
    roots = [
        helper_dir,
        helper_dir.parent,
        Path(os.environ.get('ProgramFiles', r'C:\\Program Files')) / 'Antivirus Server',
        Path(os.environ.get('ProgramFiles(x86)', r'C:\\Program Files (x86)')) / 'Antivirus Server',
        Path(os.environ.get('LOCALAPPDATA', '')) / 'AntivirusServerBuild' / 'dist',
        Path(__file__).resolve().parent / 'dist',
    ]
    candidates = []
    for root in roots:
        candidates.extend((root / APP_EXECUTABLE, root / 'antivirus_server' / APP_EXECUTABLE))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    searched = ', '.join(str(root) for root in roots if str(root))
    raise FileNotFoundError(f"Could not find {APP_EXECUTABLE}; searched: {searched}")


def main() -> int:
    elevated = _ensure_administrator()
    if elevated is None:
        return 0
    if not elevated:
        return 1

    _create_admin_shortcuts()

    try:
        application = _application_path()
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 2

    app_args = [arg for arg in sys.argv[1:] if arg != _ELEVATION_FLAG]
    try:
        subprocess.Popen(
            [str(application), *app_args],
            cwd=str(application.parent),
            close_fds=True,
            creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0),
        )
    except OSError as error:
        print(f'Could not start {application}: {error}', file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
