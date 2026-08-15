"""Launch the unpacked Antivirus Server executable with administrator rights."""
import os
import subprocess
import sys
from pathlib import Path


APP_EXECUTABLE = "antivirus_server.exe"


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
