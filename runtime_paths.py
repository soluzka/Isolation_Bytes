"""Canonical writable runtime paths for Isolation Bytes.

All mutable application state belongs under the per-user LocalAppData directory.
On Windows this is always %LOCALAPPDATA%\\IsolationBytes so a packaged EXE,
source checkout, service, or environment override cannot redirect scan state
or quarantine data into the project/install directory.
"""
import os

_DEFAULT_RUNTIME = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local"),
    "IsolationBytes",
)

if os.name == "nt":
    RUNTIME_DIR = os.path.abspath(_DEFAULT_RUNTIME)
else:
    RUNTIME_DIR = os.path.abspath(
        os.path.expandvars(os.environ.get("ANTIVIRUS_RUNTIME_DIR") or _DEFAULT_RUNTIME)
    )

os.environ["ANTIVIRUS_RUNTIME_DIR"] = RUNTIME_DIR

try:
    os.makedirs(RUNTIME_DIR, exist_ok=True)
except OSError:
    pass


def runtime_path(*parts):
    path = os.path.join(RUNTIME_DIR, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def ensure_runtime_dir():
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    return RUNTIME_DIR
