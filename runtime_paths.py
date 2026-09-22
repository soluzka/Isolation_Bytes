"""Canonical writable runtime paths for Isolation Bytes.

All mutable application state belongs under the per-user LocalAppData directory.
On Windows this is always %LOCALAPPDATA%\\IsolationBytes so a packaged EXE,
source checkout, service, or environment override cannot redirect scan state
or quarantine data into the project/install directory.
"""
import os
import json

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
    _create_json_if_missing(
        "scheduled_scan_state.json",
        {
            "status": "idle",
            "started_at": None,
            "last_updated": None,
            "scanned_files": 0,
            "quarantined_files": 0,
            "errors": 0,
            "findings": [],
        },
    )
    _create_json_if_missing("quarantine_log.json", [])
    _create_json_if_missing("scan_cache.json", {})
    return RUNTIME_DIR


# Create the state files as soon as any Isolation Bytes backend imports this module.
ensure_runtime_state_files()


# Shared scanner prerequisite. Every local scanner uses this gate so the
# agent is verified/running before detection work begins.
import hashlib
import re
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

_AGENT_PROCESS_LOCK = threading.Lock()
_AGENT_EXE_NAME = "IsolationBytesAgent.exe"
_AGENT_LAUNCHER_NAME = "AntivirusServerLogin.exe"
_AGENT_READY_TIMEOUT = 15
_AGENT_ALLOWED_FOLDERS = ("IsolationBytes", "Isolation Bytes", "Antivirus Server")


def _agent_process_names():
    names = {_AGENT_EXE_NAME.lower()}
    if os.name != "nt":
        names.update(("isolationbytesagent", "isolation-bytes-agent"))
    return names


def _process_matches_agent(info, names):
    name = (info.get("name") or "").lower()
    exe = os.path.basename(info.get("exe") or "").lower()
    if name in names or exe in names:
        return True
    if os.name != "nt":
        command = " ".join(info.get("cmdline") or []).lower()
        return "isolationbytesagent" in command or "isolation-bytes-agent" in command
    return False


def _agent_process_running():
    """Return True when the agent process is running anywhere on the system."""
    try:
        import psutil
    except Exception:
        return False
    names = _agent_process_names()
    for proc in psutil.process_iter(["name", "exe", "cmdline"]):
        try:
            if _process_matches_agent(proc.info, names):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def _configured_path(name):
    value = os.environ.get(name, "").strip()
    return Path(os.path.expandvars(value)) if value else None


def _install_roots():
    roots = [Path(__file__).resolve().parent]
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if local_appdata:
        roots.append(Path(local_appdata))
    program_files = os.environ.get("ProgramFiles", r"C:\\Program Files")
    roots.append(Path(program_files))
    return roots


def _agent_candidates():
    configured = _configured_path("ISOLATION_BYTES_AGENT_EXE")
    candidates = [configured] if configured else []
    for root in _install_roots():
        candidates.extend(root / folder / _AGENT_EXE_NAME for folder in _AGENT_ALLOWED_FOLDERS)
    candidates.extend([
        Path(__file__).resolve().parent / "dist" / _AGENT_EXE_NAME,
        Path(__file__).resolve().parent / "native" / "AntivirusServerLogin" / "bin" / "Release" / "net8.0-windows" / "win-x64" / _AGENT_EXE_NAME,
    ])
    return [path for path in candidates if path is not None]


def _startup_script_candidates():
    name = "start_agent.bat" if os.name == "nt" else "start_agent.sh"
    return [root / name for root in _install_roots()]


def _launcher_candidates():
    configured = _configured_path("ISOLATION_BYTES_LAUNCHER_EXE")
    candidates = [configured] if configured else []
    for root in _install_roots():
        candidates.extend(root / folder / _AGENT_LAUNCHER_NAME for folder in _AGENT_ALLOWED_FOLDERS)
    candidates.append(Path(__file__).resolve().parent / "native" / "AntivirusServerLogin" / "bin" / "Release" / "net8.0-windows" / "win-x64" / _AGENT_LAUNCHER_NAME)
    return candidates


def _is_trusted_executable(executable):
    configured = _configured_path("ISOLATION_BYTES_AGENT_EXE")
    if configured is not None and executable == configured.resolve():
        return True
    if executable.parent == Path(__file__).resolve().parent / "dist":
        return True
    if executable.parent == Path(__file__).resolve().parent / "native" / "AntivirusServerLogin" / "bin" / "Release" / "net8.0-windows" / "win-x64":
        return True
    return executable.parent.name.lower() in {folder.lower() for folder in _AGENT_ALLOWED_FOLDERS}


def _start_process(command, cwd):
    """Start only a path discovered from the allow-listed installation roots."""
    executable = Path(command[0]).resolve()
    allowed = _is_trusted_executable(executable)
    if not allowed or not executable.is_file():
        raise OSError("Agent executable is outside the trusted installation locations")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.Popen(command, cwd=str(cwd), creationflags=flags, close_fds=True)  # nosec B603


def _start_agent_executable(agent_exe):
    server = os.environ.get("CLOUD_URL", "https://isolation-bytes.com").rstrip("/")
    command = [str(agent_exe.resolve()), "--server", server, "--auto-start"]
    api_key = os.environ.get("CLOUD_API_KEY", "").strip()
    if api_key:
        command.insert(2, f"--key={api_key}")
    _start_process(command, agent_exe.parent)


def _start_startup_script(script_path):
    script = script_path.resolve()
    if not script.is_file() or script.name.lower() != ("start_agent.bat" if os.name == "nt" else "start_agent.sh"):
        raise OSError("Untrusted startup script")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if os.name == "nt":
        command = [r"C:\\Windows\\System32\\cmd.exe", "/d", "/c", str(script)]
    else:
        command = ["/bin/sh", str(script)]
    subprocess.Popen(command, cwd=str(script.parent), creationflags=flags, close_fds=True)  # nosec B603 B607


def _start_agent_launcher(launcher_exe):
    _start_process([str(launcher_exe.resolve())], launcher_exe.parent)


def _download_agent_executable():
    if os.name != "nt":
        return None
    try:
        cloud_url = os.environ.get("CLOUD_URL", "https://isolation-bytes.com").rstrip("/")
        update = requests.get(f"{cloud_url}/agent/update-check", timeout=15, verify=True)
        update.raise_for_status()
        metadata = update.json()
        download_url = metadata.get("download_url", "")
        expected_sha = str(metadata.get("sha256", "")).strip().lower()
        parsed = urlparse(download_url)
        server = urlparse(cloud_url)
        if parsed.scheme != "https" or server.scheme != "https" or parsed.netloc != server.netloc:
            return None
        if parsed.path != "/download/IsolationBytesAgent.exe" or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            return None
        response = requests.get(download_url, timeout=60, verify=True)
        response.raise_for_status()
        data = response.content
        if hashlib.sha256(data).hexdigest().lower() != expected_sha:
            return None
        target_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "IsolationBytes"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / _AGENT_EXE_NAME
        temp = target.with_suffix(".download")
        temp.write_bytes(data)
        os.replace(temp, target)
        return target
    except (OSError, ValueError, requests.RequestException, json.JSONDecodeError):
        return None


def _wait_for_agent(timeout=_AGENT_READY_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _agent_process_running():
            return True
        time.sleep(0.25)
    return _agent_process_running()


def _try_start_script_with_agent(script, agent_exe):
    if script is None or agent_exe is None:
        return False
    try:
        _start_startup_script(script)
        return _wait_for_agent()
    except (OSError, ValueError):
        return False


def _try_start_launcher(launcher):
    if launcher is None:
        return False
    try:
        _start_agent_launcher(launcher)
        return _wait_for_agent()
    except (OSError, ValueError):
        return False


def _try_download_and_start():
    downloaded = _download_agent_executable()
    if downloaded is None:
        return False
    try:
        _start_agent_executable(downloaded)
    except (OSError, ValueError):
        return False
    return _wait_for_agent()


def ensure_agent_running():
    """Shared prerequisite for Code Scanner, YARA, and Conditional Startup."""
    if _agent_process_running():
        return True
    with _AGENT_PROCESS_LOCK:
        if _agent_process_running():
            return True
        if os.name != "nt":
            script = next((p for p in _startup_script_candidates() if p.is_file()), None)
            return _try_start_script_with_agent(script, script)
        agent_exe = next((p for p in _agent_candidates() if p.is_file()), None)
        script = next((p for p in _startup_script_candidates() if p.is_file()), None)
        if _try_start_script_with_agent(script, agent_exe):
            return True
        launcher = next((p for p in _launcher_candidates() if p.is_file()), None)
        if _try_start_launcher(launcher):
            return True
        return _try_download_and_start()


def require_agent_running():
    """Raise a clear error when a scanner cannot establish agent readiness."""
    if not ensure_agent_running():
        raise RuntimeError("IsolationBytesAgent is not running and could not be started or downloaded")
    return True
