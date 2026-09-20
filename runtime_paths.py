"""Canonical writable runtime paths for Isolation Bytes.

All mutable application state belongs under the per-user LocalAppData directory
unless ANTIVIRUS_RUNTIME_DIR explicitly overrides it.
"""
import os

_DEFAULT_RUNTIME = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local"),
    "IsolationBytes",
)
RUNTIME_DIR = os.path.abspath(
    os.path.expandvars(os.environ.get("ANTIVIRUS_RUNTIME_DIR") or _DEFAULT_RUNTIME)
)
os.environ.setdefault("ANTIVIRUS_RUNTIME_DIR", RUNTIME_DIR)

def runtime_path(*parts):
    path = os.path.join(RUNTIME_DIR, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path

def ensure_runtime_dir():
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    return RUNTIME_DIR
