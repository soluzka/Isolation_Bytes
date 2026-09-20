"""Thread-safe live state for the YARA scanning backend.

The YARA engine updates this module for every file it actually processes.
The agent/dashboard can read it without deriving the current path from
historical findings.
"""
import threading
import time

_lock = threading.RLock()
_state = {
    "status": "idle",
    "current_path": "",
    "files_scanned": 0,
    "started_at": "",
    "updated_at": "",
}

def start_scan():
    with _lock:
        _state.update({
            "status": "scanning",
            "current_path": "",
            "files_scanned": 0,
            "started_at": str(time.time()),
            "updated_at": str(time.time()),
        })
        return dict(_state)

def begin_file(path):
    with _lock:
        _state["status"] = "scanning"
        _state["current_path"] = str(path or "")
        _state["files_scanned"] += 1
        _state["updated_at"] = str(time.time())
        return dict(_state)

def finish_scan(status="complete"):
    with _lock:
        _state["status"] = status
        _state["current_path"] = ""
        _state["updated_at"] = str(time.time())
        return dict(_state)

def get_state():
    with _lock:
        return dict(_state)
