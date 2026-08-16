"""Launch the unpacked Antivirus Server executable with administrator rights."""
import os
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


def _application_path() -> Path:
    helper_dir = Path(sys.executable).resolve().parent
    candidates = [
        helper_dir / APP_EXECUTABLE,
        helper_dir.parent / APP_EXECUTABLE,
        Path(__file__).resolve().parent / "dist" / "antivirus_server" / APP_EXECUTABLE,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Could not find {APP_EXECUTABLE} next to the administrator helper."
    )


def main() -> int:
    elevated = _ensure_administrator()
    if elevated is None:
        return 0
    if not elevated:
        return 1

    try:
        application = _application_path()
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 2

    subprocess.Popen(
        [str(application), *sys.argv[1:]],
        cwd=str(application.parent),
        close_fds=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
