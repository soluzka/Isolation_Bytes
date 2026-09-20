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


def _create_json_if_missing(filename, payload):
    """Create one runtime JSON file without overwriting an existing state file."""
    try:
        path = runtime_path(filename)
        if os.path.exists(path):
            return path
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            import json
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return path
    except OSError as exc:
        try:
            if "tmp" in locals() and os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        raise OSError(f"Unable to create runtime state file {filename}: {exc}") from exc


def ensure_runtime_state_files():
    """Create the canonical LocalAppData JSON state files on every backend startup.

    This is intentionally idempotent: existing scan state is never replaced.
    """
    ensure_runtime_dir()
    _create_json_if_missing(
        "scan_state.json",
        {
            "scan_id": "",
            "status": "idle",
            "started_at": "",
            "updated_at": None,
            "complete": False,
            "files_scanned": 0,
            "quarantined_count": 0,
            "threats_blocked": 0,
            "findings": 0,
            "ransomware_indicators": 0,
            "persistence_indicators": 0,
            "yara_suspicious": 0,
            "ml_suspicious": 0,
            "scan_dirs": [],
        },
    )
    _create_json_if_missing(
        "conditional_startup_state.json",
        {
            "running": False,
            "run_id": "",
            "findings": [],
            "started_at": None,
            "last_updated": None,
            "last_run": None,
            "duration": None,
            "scanned_files": 0,
            "quarantined_files": 0,
            "errors": 0,
            "process_events": 0,
            "ml_detections": 0,
            "ransomware_indicators": 0,
            "persistence_indicators": 0,
            "yara_suspicious": 0,
            "blocked_threats": 0,
            "scan_phase": "idle",
        },
    )
    _create_json_if_missing(
        "scanner_results.json",
        {
            "scanner_counters": {
                "scanned_files": 0,
                "quarantined_files": 0,
                "errors": 0,
                "process_events": 0,
                "ml_detections": 0,
                "ransomware_indicators": 0,
                "persistence_indicators": 0,
                "yara_suspicious": 0,
            },
            "scanner_results": {
                "errors": [],
                "process_events": [],
                "ml_detections": [],
                "ransomware_indicators": [],
                "persistence_indicators": {},
                "yara_suspicious": [],
                "quarantined_files": [],
            },
        },
    )
    _create_json_if_missing("blocked_files.json", {})
    return RUNTIME_DIR


# Create the state files as soon as any Isolation Bytes backend imports this module.
ensure_runtime_state_files()
