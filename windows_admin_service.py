"""Allowlisted Windows administrator operations over a local named pipe.

The service is deliberately narrow: it has no shell or arbitrary command API,
accepts only configured scan/restore roots, and requires an explicit
confirmation token for every state-changing operation.  pywin32 is imported
lazily on non-Windows systems so protocol tests can run elsewhere.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import traceback
from pathlib import Path
from threading import Event
from typing import Any

LOGGER = logging.getLogger("antivirus.admin_service")
SERVICE_NAME = "AntivirusProtectedAdmin"
PIPE_NAME = r"\\.\pipe\AntivirusProtectedAdmin"
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_SCAN_FILES = 100
MAX_SCAN_RESULTS = 50
MAX_LIST_ITEMS = 500
CONFIRMATION_TOKEN = "CONFIRM"
KILL_SWITCH_RULE_NAME = "AntivirusServer_KillSwitch"
QUARANTINE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,239}\.enc$")

READ_ONLY_ACTIONS = {"service.status", "scan.protected", "firewall.list", "firewall.kill_switch.status", "quarantine.list"}
MUTATING_ACTIONS = {"firewall.block", "firewall.unblock", "firewall.kill_switch", "quarantine.create", "quarantine.restore", "quarantine.delete"}
ALLOWED_ACTIONS = READ_ONLY_ACTIONS | MUTATING_ACTIONS
ACTION_FIELDS = {
    "service.status": set(),
    "scan.protected": {"paths"},
    "firewall.list": set(),
    "firewall.kill_switch.status": set(),
    "quarantine.list": set(),
    "firewall.block": {"ip", "reason", "confirmation"},
    "firewall.unblock": {"ip", "confirmation"},
    "firewall.kill_switch": {"enabled", "confirmation"},
    "quarantine.create": {"source", "destination", "confirmation"},
    "quarantine.restore": {"filename", "destination", "confirmation"},
    "quarantine.delete": {"filename", "confirmation"},
}


def _audit(action: str, ok: bool, detail: str = "") -> None:
    LOGGER.info("admin_operation action=%s ok=%s detail=%s", action, ok, detail[:240])


def _bounded_text(value: Any, limit: int = 512) -> str:
    return value if isinstance(value, str) else str(value)[:limit]


def _configured_roots(variable: str) -> tuple[Path, ...]:
    roots = []
    for value in os.environ.get(variable, "").split(";"):
        if not value.strip():
            continue
        try:
            path = Path(value).expanduser().resolve(strict=True)
            if path.is_dir():
                roots.append(path)
        except (OSError, RuntimeError):
            LOGGER.warning("Ignoring invalid configured root variable=%s", variable)
    return tuple(roots)


def _inside_configured_root(value: Any, variable: str, *, must_exist: bool = True) -> tuple[Path | None, str | None]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None, "path must be a non-empty string of at most 4096 characters"
    try:
        candidate = Path(value).expanduser().resolve(strict=must_exist)
    except (OSError, RuntimeError):
        return None, "path does not exist" if must_exist else "invalid path"
    if must_exist and not candidate.is_file() and not candidate.is_dir():
        return None, "path must identify a file or directory"
    for root in _configured_roots(variable):
        try:
            candidate.relative_to(root)
            return candidate, None
        except ValueError:
            pass
    return None, f"path is outside configured {variable} roots"


def _path_is_allowed(value: Any) -> tuple[bool, str | None]:
    _, error = _inside_configured_root(value, "ANTIVIRUS_PROTECTED_SCAN_ROOTS")
    return error is None, error


def _valid_public_ip(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or len(value) > 45:
        return False, "ip must be a valid public IP address"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False, "ip must be a valid public IP address"
    if not address.is_global:
        return False, "only globally routable IP addresses are allowed"
    return True, None


def _valid_quarantine_filename(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or not QUARANTINE_FILENAME.fullmatch(value):
        return False, "filename must be a single .enc quarantine filename"
    return True, None


def _quarantine_source(filename: str) -> tuple[Path | None, str | None]:
    valid, error = _valid_quarantine_filename(filename)
    if not valid:
        return None, error
    try:
        from quarantine_utils import QUARANTINE_FOLDER
        source = (Path(QUARANTINE_FOLDER) / filename).resolve(strict=True)
        base = Path(QUARANTINE_FOLDER).resolve(strict=True)
        source.relative_to(base)
        if not source.is_file():
            return None, "quarantine file does not exist"
        return source, None
    except (ImportError, OSError, RuntimeError, ValueError):
        return None, "quarantine file is unavailable"


def _valid_quarantine_source(value: Any) -> tuple[bool, str | None]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False, "source must be a non-empty path of at most 4096 characters"
    try:
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file():
            return False, "source must be an existing file"
        return True, None
    except (OSError, RuntimeError, ValueError):
        return False, "source file does not exist"


def _is_kill_switch_active() -> bool:
    try:
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={KILL_SWITCH_RULE_NAME}'],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return KILL_SWITCH_RULE_NAME in result.stdout
    except Exception:
        return False


def _set_kill_switch(enabled: bool) -> tuple[bool, str]:
    try:
        if enabled:
            if _is_kill_switch_active():
                return True, 'Kill switch already active'
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={KILL_SWITCH_RULE_NAME}', 'dir=out', 'action=block',
                 'enable=yes', 'profile=any', 'remoteip=any'],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if result.returncode != 0:
                return False, result.stderr.strip() or 'netsh failed'
            return True, 'Outbound traffic blocked'
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             f'name={KILL_SWITCH_RULE_NAME}'],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or 'netsh failed'
        return True, 'Outbound traffic restored'
    except Exception as e:
        return False, str(e)


def _confirmation(request: dict[str, Any]) -> bool:
    return request.get("confirmation") == CONFIRMATION_TOKEN


def _trim_items(items: Any, key: str) -> list[Any]:
    if not isinstance(items, (list, dict)):
        return []
    if isinstance(items, dict):
        return [{key: str(k), **(v if isinstance(v, dict) else {"value": v})} for k, v in list(items.items())[:MAX_LIST_ITEMS]]
    return items[:MAX_LIST_ITEMS]


def _scan_paths(paths: list[Path]) -> dict[str, Any]:
    try:
        from security.yara_scanner import scan_file_with_yara
    except Exception:
        return {"ok": False, "error": "YARA scanner is unavailable"}
    scanned = 0
    detections: list[dict[str, Any]] = []
    errors = 0
    for requested in paths:
        candidates = [requested] if requested.is_file() else (
            path for path in requested.rglob("*") if path.is_file() and not path.is_symlink()
        )
        for path in candidates:
            if scanned >= MAX_SCAN_FILES:
                break
            try:
                matches = scan_file_with_yara(str(path))
                if matches and len(detections) < MAX_SCAN_RESULTS:
                    detections.append({"path": str(path), "matches": [str(getattr(m, "rule", m))[:128] for m in matches[:20]]})
            except Exception:
                errors += 1
            scanned += 1
    return {"ok": True, "action": "scan.protected", "scanned": scanned, "detections": detections, "errors": min(errors, MAX_SCAN_FILES), "bounded": True}


def _dispatch(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("version") != PROTOCOL_VERSION:
        return {"ok": False, "error": "unsupported protocol version"}
    action = request.get("action")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        return {"ok": False, "error": "action is not allowlisted"}
    if set(request) - ({"version", "action"} | ACTION_FIELDS[action]):
        return {"ok": False, "error": "request fields are not allowlisted"}
    if action in MUTATING_ACTIONS and not _confirmation(request):
        _audit(action, False, "missing confirmation")
        return {"ok": False, "action": action, "error": f"confirmation must equal {CONFIRMATION_TOKEN!r}"}

    if action == "service.status":
        return {"ok": True, "action": action, "service": SERVICE_NAME, "read_only": True}
    if action == "scan.protected":
        paths = request.get("paths")
        if not isinstance(paths, list) or not paths or len(paths) > 32:
            return {"ok": False, "error": "paths must contain 1 to 32 entries"}
        accepted = []
        for path in paths:
            valid, error = _path_is_allowed(path)
            if not valid:
                return {"ok": False, "error": error}
            accepted.append(Path(path).expanduser().resolve())
        response = _scan_paths(accepted)
        _audit(action, response.get("ok", False), f"paths={len(accepted)}")
        return response
    if action == "firewall.kill_switch.status":
        return {"ok": True, "action": action, "active": _is_kill_switch_active(), "read_only": True}
    if action == "firewall.list":
        try:
            from network_blocking import list_blocked_ips
            return {"ok": True, "action": action, "blocked": _trim_items(list_blocked_ips(), "ip"), "bounded": True, "read_only": True}
        except Exception:
            LOGGER.exception("Could not list firewall state")
            return {"ok": False, "action": action, "error": "firewall state unavailable"}
    if action == "quarantine.list":
        try:
            from quarantine_utils import list_quarantine_files
            return {"ok": True, "action": action, "files": _trim_items(list_quarantine_files(), "filename"), "bounded": True, "read_only": True}
        except Exception:
            LOGGER.exception("Could not list quarantine state")
            return {"ok": False, "action": action, "error": "quarantine state unavailable"}
    if action in {"firewall.block", "firewall.unblock"}:
        valid, error = _valid_public_ip(request.get("ip"))
        if not valid:
            return {"ok": False, "action": action, "error": error}
        try:
            from network_blocking import block_ip, unblock_ip
            if action == "firewall.block":
                success, message = block_ip(request["ip"], _bounded_text(request.get("reason", "admin service"), 240))
            else:
                success, message = unblock_ip(request["ip"])
            _audit(action, success, request["ip"])
            return {"ok": bool(success), "action": action, "message": _bounded_text(message), "mutated": bool(success)}
        except Exception:
            LOGGER.exception("Firewall operation failed")
            _audit(action, False, "helper failure")
            return {"ok": False, "action": action, "error": "firewall operation unavailable"}
    if action == "firewall.kill_switch":
        enabled = request.get("enabled")
        if not isinstance(enabled, bool):
            return {"ok": False, "action": action, "error": "enabled must be a boolean"}
        success, message = _set_kill_switch(enabled)
        _audit(action, success, f"enabled={enabled}")
        return {"ok": success, "action": action, "message": _bounded_text(message), "mutated": success}
    if action == "quarantine.create":
        source_path = request.get("source")
        valid, error = _valid_quarantine_source(source_path)
        if not valid:
            _audit(action, False, error or "invalid source")
            return {"ok": False, "action": action, "error": error}
        source = Path(source_path).expanduser().resolve()
        try:
            from quarantine_utils import quarantine_file, QUARANTINE_FOLDER
            quarantine_file(str(source), reason="admin service quarantine.create")
            dest = Path(QUARANTINE_FOLDER) / (source.name + '.enc')
            if not dest.is_file():
                _audit(action, False, f"quarantine file not created for {source.name}")
                return {"ok": False, "action": action, "error": "quarantine file was not created"}
            _audit(action, True, source.name)
            return {"ok": True, "action": action, "destination": dest.name, "mutated": True}
        except Exception:
            LOGGER.exception("Quarantine create failed")
            _audit(action, False, str(source))
            return {"ok": False, "action": action, "error": "quarantine create failed"}
    if action in {"quarantine.restore", "quarantine.delete"}:
        source, error = _quarantine_source(request.get("filename"))
        if error:
            return {"ok": False, "action": action, "error": error}
        if action == "quarantine.restore":
            destination, error = _inside_configured_root(request.get("destination"), "ANTIVIRUS_QUARANTINE_RESTORE_ROOTS", must_exist=False)
            if error or destination is None:
                return {"ok": False, "action": action, "error": error or "restore destination is required"}
            if destination.exists():
                return {"ok": False, "action": action, "error": "restore destination already exists"}
            try:
                from quarantine_utils import restore_quarantine_file
                success, message = restore_quarantine_file(source.name, str(destination))
            except Exception:
                LOGGER.exception("Quarantine restore failed")
                success, message = False, "restore operation unavailable"
        else:
            try:
                from quarantine_utils import delete_quarantine_file
                success, message = delete_quarantine_file(source.name)
            except Exception:
                LOGGER.exception("Quarantine delete failed")
                success, message = False, "delete operation unavailable"
        _audit(action, bool(success), source.name)
        return {"ok": bool(success), "action": action, "message": _bounded_text(message), "mutated": bool(success)}
    return {"ok": False, "error": "action handler missing"}


class AdminServiceUnavailable(ConnectionError):
    """The local administrator service cannot be reached."""


class AdminServiceProtocolError(RuntimeError):
    """The administrator service returned an invalid response."""


def call_admin_service(action: str, **fields: Any) -> dict[str, Any]:
    if action not in ALLOWED_ACTIONS:
        raise ValueError("administrator-service action is not enabled")
    if set(fields) - ACTION_FIELDS[action]:
        raise ValueError("administrator-service fields are not allowlisted")
    if action == "scan.protected":
        paths = fields.get("paths")
        if not isinstance(paths, list) or not paths or len(paths) > 32 or not all(isinstance(p, str) for p in paths):
            raise ValueError("paths must contain 1 to 32 strings")
    if action in MUTATING_ACTIONS and fields.get("confirmation") != CONFIRMATION_TOKEN:
        raise ValueError(f"confirmation must equal {CONFIRMATION_TOKEN!r}")
    request = {"version": PROTOCOL_VERSION, "action": action, **fields}
    raw_request = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw_request) > MAX_REQUEST_BYTES:
        raise ValueError("administrator-service request is too large")
    if os.name != "nt":
        raise AdminServiceUnavailable("administrator service is Windows-only")
    try:
        import pywintypes
        import win32file
        import win32pipe
        import winerror
        handle = win32file.CreateFile(PIPE_NAME, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None)
        try:
            win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            win32file.WriteFile(handle, raw_request)
            chunks = []
            while True:
                try:
                    _, chunk = win32file.ReadFile(handle, MAX_RESPONSE_BYTES)
                    chunks.append(chunk)
                    break
                except pywintypes.error as error:
                    if error.winerror != winerror.ERROR_MORE_DATA:
                        raise
                    partial = getattr(error, "data", b"")
                    if partial:
                        chunks.append(partial)
        finally:
            win32file.CloseHandle(handle)
        raw_response = b"".join(chunks)
    except Exception as error:
        raise AdminServiceUnavailable(f"administrator service is unavailable; install and start {SERVICE_NAME}") from error
    if len(raw_response) > MAX_RESPONSE_BYTES:
        raise AdminServiceProtocolError("administrator-service response is too large")
    try:
        response = json.loads(raw_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminServiceProtocolError("administrator-service returned invalid JSON") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise AdminServiceProtocolError("administrator-service returned an invalid response")
    if response.get("action") not in (None, action):
        raise AdminServiceProtocolError("administrator-service response action mismatch")
    return response


def handle_json(raw: bytes) -> bytes:
    if len(raw) > MAX_REQUEST_BYTES:
        response = {"ok": False, "error": "request too large"}
    else:
        try:
            request = json.loads(raw.decode("utf-8"))
            response = _dispatch(request) if isinstance(request, dict) else {"ok": False, "error": "JSON object required"}
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            response = {"ok": False, "error": "invalid JSON request"}
    encoded = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
    return encoded if len(encoded) <= MAX_RESPONSE_BYTES else b'{"ok":false,"error":"response too large"}\n'


if os.name == "nt":
    try:
        import pywintypes
        import win32api
        import winerror
        import win32file
        import win32pipe
        import win32security
        import win32service
        import win32serviceutil
    except BaseException:
        try:
            _startup_log = _admin_log_path()
            _startup_log.parent.mkdir(parents=True, exist_ok=True)
            _startup_log.write_text(traceback.format_exc(), encoding='utf-8')
        finally:
            raise

    class AntivirusAdminService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "Antivirus Protected Administrator Service"
        _svc_description_ = "Local allowlisted administrator operations for Antivirus Server."

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = Event()
            self.hWaitStop = win32api.CreateEvent(None, 0, 0, None)

        def GetAcceptedControls(self):
            return super().GetAcceptedControls() | win32service.SERVICE_ACCEPT_STOP

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()
            win32api.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            LOGGER.info("Starting %s", SERVICE_NAME)
            try:
                self._serve_pipe()
            except BaseException:
                _write_startup_failure()
                raise
            LOGGER.info("Stopped %s", SERVICE_NAME)

        @staticmethod
        def _security_attributes():
            # Allow SYSTEM and Administrators full access, and let any logged-in
            # user read/write the pipe so the non-elevated dashboard can connect.
            # Mutating actions still require the CONFIRM token.
            descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGW;;;BU)", win32security.SDDL_REVISION_1
            )
            attributes = pywintypes.SECURITY_ATTRIBUTES()
            attributes.SECURITY_DESCRIPTOR = descriptor
            return attributes

        def _serve_pipe(self):
            while not self.stop_event.is_set():
                handle = win32pipe.CreateNamedPipe(
                    PIPE_NAME, win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, MAX_RESPONSE_BYTES, MAX_REQUEST_BYTES, 1000, self._security_attributes(),
                )
                try:
                    try:
                        win32pipe.ConnectNamedPipe(handle, None)
                    except pywintypes.error as error:
                        if error.winerror != winerror.ERROR_PIPE_CONNECTED:
                            raise
                    _, data = win32file.ReadFile(handle, MAX_REQUEST_BYTES)
                    win32file.WriteFile(handle, handle_json(data))
                except (pywintypes.error, OSError):
                    if not self.stop_event.is_set():
                        LOGGER.exception("Named-pipe request failed")
                finally:
                    try:
                        win32file.CloseHandle(handle)
                    except pywintypes.error:
                        pass
else:
    AntivirusAdminService = None


def _admin_log_path() -> Path:
    return Path(os.environ.get('ProgramData', r'C:\\ProgramData')) / 'AntivirusServer' / 'logs' / 'admin_service.log'


def _configure_logging() -> None:
    try:
        path = _admin_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
        LOGGER.addHandler(handler)
        LOGGER.setLevel(logging.INFO)
    except Exception:
        pass


def _write_startup_failure():
    try:
        path = _admin_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(traceback.format_exc(), encoding='utf-8')
    except Exception:
        pass


def run_worker() -> int:
    if os.name != "nt":
        raise SystemExit("The administrator service is Windows-only")

    import signal

    stop_event = Event()

    def _stop(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGBREAK, _stop)
    LOGGER.info("Starting %s worker", SERVICE_NAME)
    while not stop_event.is_set():
        handle = win32pipe.CreateNamedPipe(
            PIPE_NAME, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, MAX_RESPONSE_BYTES, MAX_REQUEST_BYTES, 1000, AntivirusAdminService._security_attributes(),
        )
        try:
            try:
                win32pipe.ConnectNamedPipe(handle, None)
            except pywintypes.error as error:
                if error.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise
            _, data = win32file.ReadFile(handle, MAX_REQUEST_BYTES)
            win32file.WriteFile(handle, handle_json(data))
        except (pywintypes.error, OSError):
            if not stop_event.is_set():
                LOGGER.exception("Named-pipe request failed")
        finally:
            try:
                win32file.CloseHandle(handle)
            except pywintypes.error:
                pass
    LOGGER.info("Stopped %s worker", SERVICE_NAME)
    return 0


def main() -> int:
    _configure_logging()
    if os.name != "nt":
        raise SystemExit("The administrator service is Windows-only")

    LOGGER.info("main() called with argv=%s", sys.argv)
    if any(arg.lower() == "--worker" for arg in sys.argv[1:]):
        LOGGER.info("Entering worker mode.")
        return run_worker()

    # The SCM starts a packaged desktop6:Service with the COM-style
    # ``-Embedding`` argument.  Do not send that invocation through
    # HandleCommandLine: it is the service-control-dispatcher entrypoint, not
    # a pywin32 install/start command.  MSIX/SCM versions can append other
    # arguments, so test the complete argument vector rather than assuming the
    # switch is sys.argv[1].
    embedding_start = any(arg.lower() == "-embedding" for arg in sys.argv[1:])
    if len(sys.argv) == 1 or embedding_start:
        LOGGER.info("Entering service control dispatcher (embedding=%s).", embedding_start)
        import servicemanager
        # Give pywin32 a stable event source in a frozen package; the default
        # derives it from argv[0], which is not reliable for MSIX service
        # activation.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AntivirusAdminService)
        servicemanager.StartServiceCtrlDispatcher()
        LOGGER.info("Service control dispatcher returned.")
        return 0

    # Retain pywin32's normal command-line management path for install,
    # start, stop, and debug use outside the MSIX package.
    win32serviceutil.HandleCommandLine(AntivirusAdminService)
    return 0


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        _write_startup_failure()
        raise
