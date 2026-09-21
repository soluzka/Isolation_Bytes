import importlib.util
import os
import sys
import io
import json
import getpass
import logging
import threading
import subprocess
import tempfile
import queue

# --- Windows subprocess window suppression ---
if sys.platform == 'win32':
    CREATE_NO_WINDOW = 0x08000000
else:
    CREATE_NO_WINDOW = 0
import requests
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
import warnings
import uuid

# HARD STARTUP BARRIER: Conditional Startup must create the canonical
# per-user LocalAppData JSON state before any scanner/indicator work begins.
# This import is deliberately near the top of this module so a standalone
# Conditional Startup launch cannot bypass runtime initialization.
from runtime_paths import ensure_runtime_state_files, ensure_runtime_dir, runtime_path

_RUNTIME_JSON_FILES = (
    "scan_state.json",
    "conditional_startup_state.json",
    "scanner_results.json",
    "blocked_files.json",
    "scheduled_scan_state.json",
    "quarantine_log.json",
    "scan_cache.json",
)


def _initialize_runtime_state_or_fail():
    runtime_dir = ensure_runtime_state_files()
    missing = [
        name for name in _RUNTIME_JSON_FILES
        if not os.path.isfile(os.path.join(runtime_dir, name))
    ]
    if missing:
        raise RuntimeError(
            "Isolation Bytes runtime JSON initialization failed; missing: "
            + ", ".join(missing)
            + f" (runtime={runtime_dir})"
        )
    return runtime_dir


# Create and verify the JSON state files before loading any scanner modules.
_RUNTIME_DIR = _initialize_runtime_state_or_fail()

# Ensure the base directory is in sys.path for package imports
basedir = os.path.dirname(os.path.abspath(__file__))
if basedir not in sys.path:
    sys.path.insert(0, basedir)

# Dynamically import a module from a given path
def import_module_from_path(module_name, path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Locks for concurrent process + file scanning
results_lock = threading.RLock()
scanner_lock = threading.RLock()


def _run_scan_stage_with_timeout(func, timeout_seconds, stage, filepath, output):
    """Run one file-scan stage behind a kill-independent watchdog.

    A scanner library can occasionally block outside its own timeout handling
    (for example while acquiring a lock, opening a file, or loading rules).
    The Conditional Startup worker must still advance to the next file.
    """
    try:
        timeout = max(1.0, float(timeout_seconds))
    except (TypeError, ValueError):
        timeout = 30.0
    result_queue = queue.Queue(maxsize=1)

    def _worker():
        try:
            result_queue.put(("ok", func()), block=False)
        except Exception as exc:
            try:
                result_queue.put(("error", exc), block=False)
            except Exception:
                pass

    worker = threading.Thread(
        target=_worker,
        name=f"IsolationBytes-{stage}",
        daemon=True,
    )
    worker.start()
    worker.join(timeout=timeout)
    if worker.is_alive():
        message = f"{stage} watchdog timed out after {timeout:.1f}s: {filepath}"
        output.write(f"[WATCHDOG] {message}\n")
        return False, None, message
    try:
        status, value = result_queue.get_nowait()
    except queue.Empty:
        return False, None, f"{stage} worker returned no result: {filepath}"
    if status == "error":
        return True, None, str(value)
    return True, value, None

# Cooperative stop signal used by the dashboard "Break the cycle" button.

def _resolve_critical_directories():
    """Resolve critical system directories, auto-detecting the Windows drive
    when SYSTEMROOT/USERPROFILE/PROGRAMDATA environment variables are missing."""
    import string

    system_root = os.environ.get('SYSTEMROOT')
    if not system_root or not os.path.isdir(system_root):
        for d in string.ascii_uppercase:
            candidate = f"{d}:\\Windows"
            if os.path.isdir(candidate):
                system_root = candidate
                break
        else:
            system_root = 'C:\\Windows'

    user_profile = os.environ.get('USERPROFILE')
    if not user_profile or not os.path.isdir(user_profile):
        username = getpass.getuser()
        for d in string.ascii_uppercase:
            candidate = os.path.join(f"{d}:\\", 'Users', username)
            if os.path.isdir(candidate):
                user_profile = candidate
                break
        else:
            user_profile = 'C:\\Users\\Default'

    program_data = os.environ.get('PROGRAMDATA')
    if not program_data or not os.path.isdir(program_data):
        drive, _ = os.path.splitdrive(system_root)
        candidate = os.path.join(drive + '\\', 'ProgramData')
        if os.path.isdir(candidate):
            program_data = candidate
        else:
            program_data = 'C:\\ProgramData'

    dirs = [
        os.path.join(system_root, 'Temp'),
        os.path.join(user_profile, 'Downloads'),
        os.path.join(user_profile, 'AppData\\Local\\Temp'),
        os.path.join(user_profile, 'Desktop'),
        os.path.join(program_data, 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    ]
    return [d for d in dirs if os.path.isdir(d)]

def load_module(module_name, path, output):
    """Helper to dynamically load a module from the given path."""
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output.write(f"[conditional_startup] Successfully loaded {module_name}.\n")
        return module
    except Exception as e:
        output.write(f"[ERROR] Failed to load {module_name}: {e}\n")
        return None
    
# Get the absolute path to a resource, handling both normal and frozen environments (e.g., PyInstaller)
def get_resource_path(relative_path):
    """
    Returns the absolute path to a resource, handling both normal and frozen environments (e.g., PyInstaller).
    """
    if getattr(sys, 'frozen', False):
        # PyInstaller onedir: resources live next to the executable.
        base_path = os.path.dirname(sys.executable)
    else:
        # If running as a script
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

def routine_maintenance_and_system_recovery():
    """Perform comprehensive routine maintenance and system recovery using multiple scanning methods."""
    output = io.StringIO()
    output.write("[ROUTINE MAINTENANCE] Starting comprehensive system recovery and maintenance...\n")
    
    basedir = os.path.dirname(os.path.abspath(__file__))
    recovery_results = {
        "yara_scans": [],
        "ml_scans": [],
        "heuristic_scans": [],
        "signature_scans": [],
        "behavioral_scans": [],
        "registry_scans": [],
        "memory_scans": [],
        "network_scans": [],
        "rootkit_scans": [],
        "integrity_checks": [],
        "game_malware_scans": [],
        "ransomware_scans": [],
        "spyware_scans": [],
        "trojan_scans": [],
        "worm_scans": [],
        "adware_scans": [],
        "crypto_miner_scans": [],
        "entropy_scans": [],
        "import_scans": [],
        "hash_scans": [],
        "cleaned_files": [],
        "recovered_systems": [],
        "errors": []
    }
    
    try:
        # 1. YARA-based scanning
        output.write("[ROUTINE MAINTENANCE] Performing YARA-based scanning...\n")
        try:
            yara_scanner_path = os.path.join(basedir, 'security', 'yara_scanner.py')
            yara_scanner = import_module_from_path('yara_scanner', yara_scanner_path)
            
            # Scan critical system directories (or use provided override)
            critical_dirs = critical_dirs if critical_dirs else _resolve_critical_directories()
            
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            time.sleep(0)  # yield so the Flask server stays responsive
                            try:
                                yara_result = yara_scanner.scan_file_with_yara(filepath)
                                if yara_result:
                                    recovery_results["yara_scans"].append({
                                        "file": filepath,
                                        "threat": yara_result,
                                        "action": "detected"
                                    })
                                    output.write(f"[YARA] Threat detected in {filepath}: {yara_result}\n")
                            except Exception as e:
                                output.write(f"[YARA ERROR] Error scanning {filepath}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] YARA scanning failed: {e}\n")
            recovery_results["errors"].append(f"YARA scanning: {str(e)}")
        
        # 2. Machine Learning-based scanning
        output.write("[ROUTINE MAINTENANCE] Performing ML-based anomaly detection...\n")
        try:
            from security.detector import detector, ember_detector, bodmas_cnn_detector

            # Both classifiers were trained on PE-executable samples; running
            # them against arbitrary files (photos, videos, documents) floods
            # results with false positives, since compressed non-executable
            # formats share the "high entropy + no imports/sections" signature
            # the models associate with packed malware.
            ml_extensions = {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.com', '.drv'}

            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            if os.path.splitext(file)[1].lower() not in ml_extensions:
                                continue
                            filepath = os.path.join(root, file)
                            time.sleep(0)  # yield so the Flask server stays responsive
                            try:
                                # Prefer the EMBER-trained classifier (real malware/
                                # benign data) when available; otherwise fall back to
                                # the synthetic-data classifier. is_malicious() on the
                                # fallback handles both the trained classifier (0/1
                                # labels) and the untrained IsolationForest fallback
                                # (+1/-1 outlier labels) correctly.
                                if bodmas_cnn_detector.available:
                                    score = bodmas_cnn_detector.score(filepath)
                                    if score is not None and score >= 0.60:
                                        recovery_results["ml_scans"].append({
                                            "file": filepath,
                                            "prediction": "malicious",
                                            "anomaly_score": score,
                                            "model": "bodmas_cnn",
                                            "action": "detected"
                                        })
                                        output.write(f"[ML/BODMAS-CNN] Malicious file detected: {filepath} (score: {score:.3f})\n")
                                elif ember_detector.available:
                                    score = ember_detector.score(filepath)
                                    if score is not None and score >= 0.60:
                                        recovery_results["ml_scans"].append({
                                            "file": filepath,
                                            "prediction": "malicious",
                                            "anomaly_score": score,
                                            "model": "ember",
                                            "action": "detected"
                                        })
                                        output.write(f"[ML/EMBER] Malicious file detected: {filepath} (score: {score:.3f})\n")
                                elif detector.is_malicious(filepath):
                                    anomaly_score = detector.get_anomaly_score(filepath)
                                    recovery_results["ml_scans"].append({
                                        "file": filepath,
                                        "prediction": "malicious",
                                        "anomaly_score": float(anomaly_score),
                                        "model": "synthetic",
                                        "action": "detected"
                                    })
                                    output.write(f"[ML] Malicious file detected: {filepath} (anomaly score: {anomaly_score})\n")
                            except Exception as e:
                                output.write(f"[ML ERROR] Error analyzing {filepath}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] ML scanning failed: {e}\n")
            recovery_results["errors"].append(f"ML scanning: {str(e)}")
        
        # 3. Heuristic-based scanning
        output.write("[ROUTINE MAINTENANCE] Performing heuristic analysis...\n")
        try:
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            time.sleep(0)  # yield so the Flask server stays responsive
                            try:
                                # Heuristic checks
                                file_size = os.path.getsize(filepath)
                                file_ext = os.path.splitext(filepath)[1].lower()
                                mod_time = os.path.getmtime(filepath)
                                
                                # Suspicious characteristics
                                is_suspicious = False
                                reasons = []
                                
                                if file_ext in ['.exe', '.dll', '.sys', '.bat', '.cmd', '.scr', '.vbs']:
                                    is_suspicious = True
                                    reasons.append("suspicious_extension")
                                
                                if file_size < 1024 or file_size > 100 * 1024 * 1024:  # Very small or very large
                                    is_suspicious = True
                                    reasons.append("unusual_size")
                                
                                if time.time() - mod_time < 3600:  # Modified in last hour
                                    is_suspicious = True
                                    reasons.append("recently_modified")
                                
                                if is_suspicious:
                                    recovery_results["heuristic_scans"].append({
                                        "file": filepath,
                                        "reasons": reasons,
                                        "action": "flagged"
                                    })
                                    output.write(f"[HEURISTIC] Suspicious file flagged: {filepath} - {reasons}\n")
                            except Exception as e:
                                output.write(f"[HEURISTIC ERROR] Error analyzing {filepath}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] Heuristic scanning failed: {e}\n")
            recovery_results["errors"].append(f"Heuristic scanning: {str(e)}")
        
        # 4. Signature-based scanning
        output.write("[ROUTINE MAINTENANCE] Performing signature-based scanning...\n")
        try:
            scan_utils_path = os.path.join(basedir, 'scan_utils.py')
            scan_utils = import_module_from_path('scan_utils', scan_utils_path)
            
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            time.sleep(0)  # yield so the Flask server stays responsive
                            try:
                                scan_success, malware_found, msg = scan_utils.scan_file_for_viruses(filepath, stop_event=None)
                                if malware_found:
                                    recovery_results["signature_scans"].append({
                                        "file": filepath,
                                        "message": msg,
                                        "action": "detected"
                                    })
                                    output.write(f"[SIGNATURE] Malware signature detected: {filepath}\n")
                            except Exception as e:
                                output.write(f"[SIGNATURE ERROR] Error scanning {filepath}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] Signature scanning failed: {e}\n")
            recovery_results["errors"].append(f"Signature scanning: {str(e)}")
        
        # 5. Behavioral analysis scanning
        output.write("[ROUTINE MAINTENANCE] Performing behavioral analysis...\n")
        try:
            process_monitor_path = os.path.join(basedir, 'security', 'process_monitor.py')
            process_monitor = import_module_from_path('process_monitor', process_monitor_path)
            
            # Monitor for suspicious process behavior
            suspicious_processes = process_monitor.scan_suspicious_processes()
            for proc in suspicious_processes:
                recovery_results["behavioral_scans"].append({
                    "process": proc.get('name', 'unknown'),
                    "pid": proc.get('pid', 0),
                    "behavior": proc.get('behavior', 'unknown'),
                    "action": "flagged"
                })
                output.write(f"[BEHAVIORAL] Suspicious process detected: {proc}\n")
        except Exception as e:
            output.write(f"[ERROR] Behavioral analysis failed: {e}\n")
            recovery_results["errors"].append(f"Behavioral analysis: {str(e)}")
        
        # 6. Registry scanning
        output.write("[ROUTINE MAINTENANCE] Performing registry scanning...\n")
        try:
            import winreg
            
            # Check common persistence locations
            registry_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            
            for hkey, key_path in registry_keys:
                try:
                    with winreg.OpenKey(hkey, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, type = winreg.EnumValue(key, i)
                                # Check for suspicious values
                                if isinstance(value, str) and any(suspicious in value.lower() for suspicious in ['temp', 'appdata', 'downloads', 'hidden']):
                                    recovery_results["registry_scans"].append({
                                        "key": key_path,
                                        "value_name": name,
                                        "value": value,
                                        "action": "flagged"
                                    })
                                    output.write(f"[REGISTRY] Suspicious registry entry: {name} = {value}\n")
                                i += 1
                            except WindowsError:
                                break
                except Exception as e:
                    output.write(f"[REGISTRY ERROR] Error accessing {key_path}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] Registry scanning failed: {e}\n")
            recovery_results["errors"].append(f"Registry scanning: {str(e)}")
        
        # 7. Memory scanning
        output.write("[ROUTINE MAINTENANCE] Performing memory scanning...\n")
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    # Check for suspicious memory patterns
                    mem_info = proc.info['memory_info']
                    if mem_info and mem_info.rss > 500 * 1024 * 1024:  # > 500MB
                        recovery_results["memory_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "memory_usage": mem_info.rss,
                            "action": "flagged"
                        })
                        output.write(f"[MEMORY] High memory usage: {proc.info['name']} (PID: {proc.info['pid']})\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output.write(f"[ERROR] Memory scanning failed: {e}\n")
            recovery_results["errors"].append(f"Memory scanning: {str(e)}")
        
        # 8. Network scanning
        output.write("[ROUTINE MAINTENANCE] Performing network scanning...\n")
        try:
            import psutil
            
            # Check for suspicious network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    # Check for connections to suspicious ports
                    if conn.raddr.port in [666, 1337, 31337, 12345]:  # Common backdoor ports
                        recovery_results["network_scans"].append({
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "pid": conn.pid,
                            "action": "flagged"
                        })
                        output.write(f"[NETWORK] Suspicious connection: {conn.raddr.ip}:{conn.raddr.port} (PID: {conn.pid})\n")
        except Exception as e:
            output.write(f"[ERROR] Network scanning failed: {e}\n")
            recovery_results["errors"].append(f"Network scanning: {str(e)}")
        
        # 9. Rootkit detection
        # NOTE: this used to run `attrib +h <System32>`, which does not check
        # for hidden files -- it *sets* the hidden attribute on the directory
        # itself (a destructive bug, not a detector). A hidden *executable*
        # sitting directly in System32 (not a normal Windows pattern) is a
        # weak but real static signal, checked here via os.stat's
        # st_file_attributes directly rather than parsing `attrib` text
        # output, whose hidden-flag column isn't at a fixed offset and is
        # easy to misparse.
        output.write("[ROUTINE MAINTENANCE] Performing rootkit detection...\n")
        try:
            import stat as stat_module

            system32 = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32')
            hidden_exes = []
            if os.path.exists(system32):
                for entry in os.listdir(system32):
                    if not entry.lower().endswith(('.exe', '.dll', '.sys')):
                        continue
                    full_path = os.path.join(system32, entry)
                    try:
                        attrs = os.stat(full_path).st_file_attributes
                        if attrs & stat_module.FILE_ATTRIBUTE_HIDDEN:
                            hidden_exes.append(full_path)
                    except OSError:
                        continue
            if hidden_exes:
                for path in hidden_exes[:50]:
                    recovery_results["rootkit_scans"].append({"file": path, "indicator": "hidden_executable"})
                output.write(f"[ROOTKIT] {len(hidden_exes)} hidden executable(s) found directly in {system32}\n")
            else:
                output.write(f"[ROOTKIT] No hidden executables found directly in {system32}\n")
        except Exception as e:
            output.write(f"[ERROR] Rootkit detection failed: {e}\n")
            recovery_results["errors"].append(f"Rootkit detection: {str(e)}")
        
        # 10. System integrity checks
        output.write("[ROUTINE MAINTENANCE] Performing system integrity checks...\n")
        try:
            # Check critical system files
            critical_files = [
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\kernel32.dll'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\ntdll.dll'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\user32.dll'),
            ]
            
            for critical_file in critical_files:
                if os.path.exists(critical_file):
                    try:
                        # Check file size and modification time
                        file_size = os.path.getsize(critical_file)
                        mod_time = os.path.getmtime(critical_file)
                        
                        recovery_results["integrity_checks"].append({
                            "file": critical_file,
                            "size": file_size,
                            "modified": mod_time,
                            "status": "checked"
                        })
                        output.write(f"[INTEGRITY] Checked {critical_file}\n")
                    except Exception as e:
                        output.write(f"[INTEGRITY ERROR] Error checking {critical_file}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] System integrity checks failed: {e}\n")
            recovery_results["errors"].append(f"System integrity checks: {str(e)}")
        
        # 11. Video game malware scanning
        output.write("[ROUTINE MAINTENANCE] Performing video game malware scanning...\n")
        try:
            # Common game directories
            game_dirs = [
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Steam'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Steam'),
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'EpicGamesLauncher'),
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Epic Games'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Origin Games'),
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Ubisoft'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\LocalLow'),  # Many games store data here
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),  # Game save files
            ]
            
            # Game-specific file extensions and patterns
            game_extensions = ['.exe', '.dll', '.pak', '.dat', '.sav', '.bak', '.tmp']
            game_suspicious_names = ['cheat', 'hack', 'trainer', 'inject', 'bypass', 'crack', 'patch', 'mod', 'hook']
            
            for game_dir in game_dirs:
                if os.path.exists(game_dir):
                    for root, dirs, files in os.walk(game_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            file_ext = os.path.splitext(filepath)[1].lower()
                            file_lower = file.lower()
                            
                            try:
                                # Check for suspicious game-related files
                                is_suspicious = False
                                reasons = []
                                
                                # Check file extension
                                if file_ext in game_extensions:
                                    is_suspicious = True
                                    reasons.append("game_executable")
                                
                                # Check for suspicious names
                                if any(suspicious in file_lower for suspicious in game_suspicious_names):
                                    is_suspicious = True
                                    reasons.append("suspicious_gaming_name")
                                
                                # Check for recently modified files in game directories
                                mod_time = os.path.getmtime(filepath)
                                if time.time() - mod_time < 86400:  # Modified in last 24 hours
                                    is_suspicious = True
                                    reasons.append("recently_modified_game_file")
                                
                                # Check for unsigned executables in game directories
                                if file_ext == '.exe':
                                    try:
                                        # Try to get file signature info
                                        import win32api
                                        try:
                                            win32api.GetFileVersionInfo(filepath, '\\')
                                        except:
                                            is_suspicious = True
                                            reasons.append("unsigned_game_executable")
                                    except:
                                        pass
                                
                                if is_suspicious:
                                    # Perform YARA scan on suspicious game files
                                    try:
                                        yara_result = yara_scanner.scan_file_with_yara(filepath)
                                        if yara_result:
                                            recovery_results["game_malware_scans"].append({
                                                "file": filepath,
                                                "threat": yara_result,
                                                "reasons": reasons,
                                                "action": "detected"
                                            })
                                            output.write(f"[GAME MALWARE] Threat detected in game file {filepath}: {yara_result}\n")
                                        else:
                                            recovery_results["game_malware_scans"].append({
                                                "file": filepath,
                                                "reasons": reasons,
                                                "action": "flagged"
                                            })
                                            output.write(f"[GAME MALWARE] Suspicious game file flagged: {filepath} - {reasons}\n")
                                    except Exception as yara_error:
                                        recovery_results["game_malware_scans"].append({
                                            "file": filepath,
                                            "reasons": reasons,
                                            "action": "flagged"
                                        })
                                        output.write(f"[GAME MALWARE] Suspicious game file flagged: {filepath} - {reasons}\n")
                            except Exception as e:
                                output.write(f"[GAME MALWARE ERROR] Error analyzing {filepath}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] Video game malware scanning failed: {e}\n")
            recovery_results["errors"].append(f"Video game malware scanning: {str(e)}")
        
        # 12. Ransomware scanning
        output.write("[ROUTINE MAINTENANCE] Performing ransomware detection...\n")
        try:
            # Ransomware indicators
            ransomware_extensions = ['.encrypted', '.locked', '.crypt', '.crypto', '.locky', '.zepto', '.cerber', '.dharma']
            ransomware_processes = ['crypt', 'lock', 'encrypt', 'decrypt', 'ransom', 'bitcrypt', 'cryptolocker']
            ransomware_patterns = ['HELP_DECRYPT', 'HELP_YOUR_FILES', 'RECOVER_FILES', 'DECRYPT_INSTRUCTIONS']
            
            # Scan for ransomware file patterns
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            file_ext = os.path.splitext(filepath)[1].lower()
                            file_lower = file.lower()
                            
                            try:
                                # Check for ransomware file extensions
                                if file_ext in ransomware_extensions:
                                    recovery_results["ransomware_scans"].append({
                                        "file": filepath,
                                        "indicator": "ransomware_extension",
                                        "action": "detected"
                                    })
                                    output.write(f"[RANSOMWARE] Ransomware file detected: {filepath}\n")
                                
                                # Check for ransomware instruction files
                                if any(pattern in file_lower for pattern in ransomware_patterns):
                                    recovery_results["ransomware_scans"].append({
                                        "file": filepath,
                                        "indicator": "ransomware_instruction",
                                        "action": "detected"
                                    })
                                    output.write(f"[RANSOMWARE] Ransomware instruction file detected: {filepath}\n")
                            except Exception as e:
                                output.write(f"[RANSOMWARE ERROR] Error checking {filepath}: {e}\n")
            
            # Check for ransomware processes
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(ransom_proc in proc_name for ransom_proc in ransomware_processes):
                        recovery_results["ransomware_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "indicator": "ransomware_process",
                            "action": "detected"
                        })
                        output.write(f"[RANSOMWARE] Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output.write(f"[ERROR] Ransomware scanning failed: {e}\n")
            recovery_results["errors"].append(f"Ransomware scanning: {str(e)}")
        
        # 13. Spyware scanning
        output.write("[ROUTINE MAINTENANCE] Performing spyware detection...\n")
        try:
            # Spyware indicators
            spyware_processes = ['keylogger', 'spy', 'monitor', 'track', 'steal', 'log', 'capture', 'screen', 'webcam']
            spyware_files = ['keylog', 'spyware', 'monitor', 'tracker', 'stealer', 'logger', 'capture']
            
            # Check for spyware processes
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(spy_proc in proc_name for spy_proc in spyware_processes):
                        recovery_results["spyware_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "indicator": "spyware_process",
                            "action": "detected"
                        })
                        output.write(f"[SPYWARE] Suspicious spyware process detected: {proc.info['name']} (PID: {proc.info['pid']})\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for spyware files
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            file_lower = file.lower()
                            
                            try:
                                if any(spy_file in file_lower for spy_file in spyware_files):
                                    recovery_results["spyware_scans"].append({
                                        "file": filepath,
                                        "indicator": "spyware_file",
                                        "action": "detected"
                                    })
                                    output.write(f"[SPYWARE] Spyware-related file detected: {filepath}\n")
                            except Exception as e:
                                output.write(f"[SPYWARE ERROR] Error checking {filepath}: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] Spyware scanning failed: {e}\n")
            recovery_results["errors"].append(f"Spyware scanning: {str(e)}")
        
        # 14. Trojan scanning
        output.write("[ROUTINE MAINTENANCE] Performing trojan detection...\n")
        try:
            # Trojan indicators
            trojan_extensions = ['.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1']
            trojan_processes = ['trojan', 'backdoor', 'remote', 'access', 'rat', 'reverse', 'shell', 'bind']
            trojan_registry_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            
            # Check for trojan file extensions in suspicious locations
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            file_ext = os.path.splitext(filepath)[1].lower()
                            
                            try:
                                if file_ext in trojan_extensions:
                                    # Check if file is in startup location
                                    if 'startup' in root.lower() or 'run' in root.lower():
                                        recovery_results["trojan_scans"].append({
                                            "file": filepath,
                                            "indicator": "trojan_startup",
                                            "action": "detected"
                                        })
                                        output.write(f"[TROJAN] Suspicious trojan file in startup: {filepath}\n")
                            except Exception as e:
                                output.write(f"[TROJAN ERROR] Error checking {filepath}: {e}\n")
            
            # Check for trojan processes
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(trojan_proc in proc_name for trojan_proc in trojan_processes):
                        recovery_results["trojan_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "indicator": "trojan_process",
                            "action": "detected"
                        })
                        output.write(f"[TROJAN] Suspicious trojan process detected: {proc.info['name']} (PID: {proc.info['pid']})\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output.write(f"[ERROR] Trojan scanning failed: {e}\n")
            recovery_results["errors"].append(f"Trojan scanning: {str(e)}")
        
        # 15. Worm scanning
        output.write("[ROUTINE MAINTENANCE] Performing worm detection...\n")
        try:
            # Worm indicators
            worm_processes = ['worm', 'autorun', 'spread', 'replicate', 'infect', 'propagate']
            worm_files = ['autorun.inf', 'autorun.exe']
            
            # Check for worm files
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            time.sleep(0)
                            filepath = os.path.join(root, file)
                            file_lower = file.lower()
                            
                            try:
                                if file_lower in worm_files:
                                    recovery_results["worm_scans"].append({
                                        "file": filepath,
                                        "indicator": "worm_file",
                                        "action": "detected"
                                    })
                                    output.write(f"[WORM] Worm-related file detected: {filepath}\n")
                            except Exception as e:
                                output.write(f"[WORM ERROR] Error checking {filepath}: {e}\n")
            
            # Check for worm processes
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(worm_proc in proc_name for worm_proc in worm_processes):
                        recovery_results["worm_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "indicator": "worm_process",
                            "action": "detected"
                        })
                        output.write(f"[WORM] Suspicious worm process detected: {proc.info['name']} (PID: {proc.info['pid']})\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            output.write(f"[ERROR] Worm scanning failed: {e}\n")
            recovery_results["errors"].append(f"Worm scanning: {str(e)}")
        
        # 16. Adware scanning
        output.write("[ROUTINE MAINTENANCE] Performing adware detection...\n")
        try:
            # Adware indicators
            adware_processes = ['adware', 'popup', 'banner', 'ad', 'toolbar', 'coupon', 'deal', 'offer']
            adware_registry_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Internet Explorer\Toolbar",
            ]
            
            # Check for adware processes
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(ad_proc in proc_name for ad_proc in adware_processes):
                        recovery_results["adware_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "indicator": "adware_process",
                            "action": "detected"
                        })
                        output.write(f"[ADWARE] Suspicious adware process detected: {proc.info['name']} (PID: {proc.info['pid']})\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for adware in browser extensions directories
            browser_dirs = [
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Google\\Chrome\\User Data'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Mozilla\\Firefox'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Microsoft\\Edge'),
            ]
            
            for browser_dir in browser_dirs:
                if os.path.exists(browser_dir):
                    try:
                        for root, dirs, files in os.walk(browser_dir):
                            for file in files:
                                time.sleep(0)
                                filepath = os.path.join(root, file)
                                file_lower = file.lower()
                                
                                if any(ad_term in file_lower for ad_term in ['ad', 'popup', 'banner', 'coupon']):
                                    recovery_results["adware_scans"].append({
                                        "file": filepath,
                                        "indicator": "adware_browser_extension",
                                        "action": "flagged"
                                    })
                                    output.write(f"[ADWARE] Suspicious browser extension: {filepath}\n")
                    except Exception as e:
                        output.write(f"[ADWARE ERROR] Error scanning browser directory: {e}\n")
        except Exception as e:
            output.write(f"[ERROR] Adware scanning failed: {e}\n")
            recovery_results["errors"].append(f"Adware scanning: {str(e)}")
        
        # 17. Crypto miner scanning
        output.write("[ROUTINE MAINTENANCE] Performing crypto miner detection...\n")
        try:
            # Crypto miner indicators
            miner_processes = ['miner', 'xmrig', 'cpuminer', 'claymore', 'ethminer', 'nicehash', 'cryptonight']
            miner_ports = [3333, 4444, 14444, 8888]  # Common mining pool ports
            
            # Check for crypto mining processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(miner_proc in proc_name for miner_proc in miner_processes):
                        recovery_results["crypto_miner_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "cpu_usage": proc.info.get('cpu_percent', 0),
                            "indicator": "crypto_miner_process",
                            "action": "detected"
                        })
                        output.write(f"[CRYPTO MINER] Crypto mining process detected: {proc.info['name']} (PID: {proc.info['pid']})\n")
                    
                    # Check for high CPU usage that might indicate mining
                    if proc.info.get('cpu_percent', 0) > 80:
                        recovery_results["crypto_miner_scans"].append({
                            "process": proc.info['name'],
                            "pid": proc.info['pid'],
                            "cpu_usage": proc.info.get('cpu_percent', 0),
                            "indicator": "high_cpu_usage",
                            "action": "flagged"
                        })
                        output.write(f"[CRYPTO MINER] High CPU usage flagged: {proc.info['name']} (PID: {proc.info['pid']}) - {proc.info.get('cpu_percent', 0)}%\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for connections to mining pool ports
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.port in miner_ports:
                    recovery_results["crypto_miner_scans"].append({
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "pid": conn.pid,
                        "indicator": "mining_pool_connection",
                        "action": "detected"
                    })
                    output.write(f"[CRYPTO MINER] Mining pool connection detected: {conn.raddr.ip}:{conn.raddr.port} (PID: {conn.pid})\n")
        except Exception as e:
            output.write(f"[ERROR] Crypto miner scanning failed: {e}\n")
            recovery_results["errors"].append(f"Crypto miner scanning: {str(e)}")
        
        # 19. File entropy analysis for packed/encrypted malware
        output.write("[ROUTINE MAINTENANCE] Performing file entropy analysis...\n")
        try:
            import math
            def calculate_entropy(file_path, block_size=4096):
                """Calculate Shannon entropy of a file to detect packed/encrypted malware"""
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read(block_size)
                    if not data:
                        return 0
                    
                    # Count byte frequencies
                    freq = [0] * 256
                    for byte in data:
                        freq[byte] += 1
                    
                    # Calculate entropy
                    entropy = 0
                    data_len = len(data)
                    for count in freq:
                        if count > 0:
                            probability = count / data_len
                            entropy -= probability * math.log2(probability)
                    
                    return entropy
                except:
                    return 0
            
            # Scan game directories for high-entropy files
            game_dirs = [
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Steam'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Steam'),
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Epic Games'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\EpicGamesLauncher'),
            ]
            
            high_entropy_threshold = 7.5  # High entropy indicates packed/encrypted content
            for game_dir in game_dirs:
                if os.path.exists(game_dir):
                    for root, dirs, files in os.walk(game_dir):
                        for file in files:
                            time.sleep(0)
                            if file.endswith(('.exe', '.dll')):
                                filepath = os.path.join(root, file)
                                try:
                                    entropy = calculate_entropy(filepath)
                                    if entropy > high_entropy_threshold:
                                        output.write(f"[ENTROPY] High entropy file detected: {filepath} (entropy: {entropy:.2f})\n")
                                        recovery_results["entropy_scans"].append({
                                            "file": filepath,
                                            "entropy": entropy,
                                            "status": "suspicious"
                                        })
                                except Exception as e:
                                    pass
        except Exception as e:
            output.write(f"[ERROR] Entropy analysis failed: {e}\n")
            recovery_results["errors"].append(f"Entropy analysis: {str(e)}")
        
        # 20. Digital signature verification for game executables
        output.write("[ROUTINE MAINTENANCE] Performing digital signature verification...\n")
        try:
            import win32api
            import win32con
            
            def verify_signature(file_path):
                """Verify if a file has a valid digital signature"""
                try:
                    info = win32api.GetFileVersionInfo(file_path, "\\")
                    if info:
                        return True
                    return False
                except:
                    return False
            
            # Known trusted publishers for games
            trusted_publishers = ['Valve Corporation', 'Epic Games, Inc.', 'Electronic Arts', 'Ubisoft', 'Microsoft Corporation']
            
            for game_dir in game_dirs:
                if os.path.exists(game_dir):
                    for root, dirs, files in os.walk(game_dir):
                        for file in files:
                            time.sleep(0)
                            if file.endswith('.exe'):
                                filepath = os.path.join(root, file)
                                try:
                                    has_signature = verify_signature(filepath)
                                    if not has_signature:
                                        output.write(f"[SIGNATURE] Unsigned executable detected: {filepath}\n")
                                        recovery_results["signature_scans"].append({
                                            "file": filepath,
                                            "signed": False,
                                            "status": "suspicious"
                                        })
                                except Exception as e:
                                    pass
        except Exception as e:
            output.write(f"[ERROR] Signature verification failed: {e}\n")
            recovery_results["errors"].append(f"Signature verification: {str(e)}")
        
        # 21. Import table analysis for suspicious DLL imports
        output.write("[ROUTINE MAINTENANCE] Performing import table analysis...\n")
        try:
            # Suspicious API imports often used by malware
            suspicious_apis = [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'ReadProcessMemory', 'OpenProcess', 'SetWindowsHookEx',
                'InternetOpen', 'InternetConnect', 'HttpSendRequest',
                'RegSetValueEx', 'RegCreateKeyEx', 'RegOpenKeyEx'
            ]
            
            for game_dir in game_dirs:
                if os.path.exists(game_dir):
                    for root, dirs, files in os.walk(game_dir):
                        for file in files:
                            time.sleep(0)
                            if file.endswith(('.exe', '.dll')):
                                filepath = os.path.join(root, file)
                                try:
                                    # Read file as text to check for API names (simplified approach)
                                    with open(filepath, 'rb') as f:
                                        content = f.read()
                                    
                                    suspicious_imports = []
                                    for api in suspicious_apis:
                                        if api.encode() in content:
                                            suspicious_imports.append(api)
                                    
                                    if suspicious_imports:
                                        output.write(f"[IMPORTS] Suspicious imports in {filepath}: {', '.join(suspicious_imports)}\n")
                                        recovery_results["import_scans"].append({
                                            "file": filepath,
                                            "suspicious_imports": suspicious_imports,
                                            "status": "suspicious"
                                        })
                                except Exception as e:
                                    pass
        except Exception as e:
            output.write(f"[ERROR] Import table analysis failed: {e}\n")
            recovery_results["errors"].append(f"Import table analysis: {str(e)}")
        
        # 22. Memory pattern analysis for process injection
        output.write("[ROUTINE MAINTENANCE] Performing memory pattern analysis...\n")
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    if proc_info['exe'] and any(game_dir.lower() in proc_info['exe'].lower() for game_dir in game_dirs):
                        # Check for suspicious memory patterns
                        try:
                            mem_info = proc.memory_info()
                            # High memory usage might indicate injection
                            if mem_info.rss > 500 * 1024 * 1024:  # > 500MB
                                output.write(f"[MEMORY] High memory usage in game process: {proc_info['name']} (PID: {proc_info['pid']})\n")
                                recovery_results["memory_scans"].append({
                                    "process": proc_info['name'],
                                    "pid": proc_info['pid'],
                                    "memory_mb": mem_info.rss / (1024 * 1024),
                                    "status": "suspicious"
                                })
                        except:
                            pass
                except:
                    pass
        except Exception as e:
            output.write(f"[ERROR] Memory pattern analysis failed: {e}\n")
            recovery_results["errors"].append(f"Memory pattern analysis: {str(e)}")
        
        # 23. File hash comparison against known good values
        output.write("[ROUTINE MAINTENANCE] Performing file hash comparison...\n")
        try:
            import hashlib
            
            def calculate_file_hash(file_path):
                """Calculate SHA256 hash of a file"""
                sha256_hash = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                return sha256_hash.hexdigest()
            
            # In a real implementation, this would compare against a database of known good hashes
            # For now, we'll just calculate and log hashes for monitoring
            for game_dir in game_dirs:
                if os.path.exists(game_dir):
                    for root, dirs, files in os.walk(game_dir):
                        for file in files:
                            time.sleep(0)
                            if file.endswith('.exe'):
                                filepath = os.path.join(root, file)
                                try:
                                    file_hash = calculate_file_hash(filepath)
                                    output.write(f"[HASH] {filepath}: {file_hash}\n")
                                    recovery_results["hash_scans"].append({
                                        "file": filepath,
                                        "hash": file_hash,
                                        "status": "logged"
                                    })
                                except Exception as e:
                                    pass
        except Exception as e:
            output.write(f"[ERROR] File hash comparison failed: {e}\n")
            recovery_results["errors"].append(f"File hash comparison: {str(e)}")
        
        # 24. System cleanup and recovery
        output.write("[ROUTINE MAINTENANCE] Performing system cleanup and recovery...\n")
        try:
            # Clean temporary files
            # NOTE: This recursively deletes every file under %TEMP%, %SYSTEMROOT%\Temp,
            # and %USERPROFILE%\AppData\Local\Temp, which can affect files other
            # applications are actively using. This is destructive and opt-in only:
            # set AV_ENABLE_TEMP_CLEANUP=1 (or true/yes) to enable it.
            temp_cleanup_enabled = os.environ.get('AV_ENABLE_TEMP_CLEANUP', '').strip().lower() in ('1', 'true', 'yes')
            if not temp_cleanup_enabled:
                output.write("[CLEANUP] Skipping temp file cleanup (disabled by default; set AV_ENABLE_TEMP_CLEANUP=1 to enable).\n")
            else:
                temp_dirs = [
                    os.path.join(os.environ.get('TEMP', '')),
                    os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),
                    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),
                ]

                for temp_dir in temp_dirs:
                    if os.path.exists(temp_dir):
                        try:
                            for root, dirs, files in os.walk(temp_dir):
                                for file in files:
                                    time.sleep(0)
                                    filepath = os.path.join(root, file)
                                    try:
                                        os.remove(filepath)
                                        recovery_results["cleaned_files"].append(filepath)
                                        output.write(f"[CLEANUP] Removed temporary file: {filepath}\n")
                                    except Exception as e:
                                        output.write(f"[CLEANUP ERROR] Could not remove {filepath}: {e}\n")
                        except Exception as e:
                            output.write(f"[CLEANUP ERROR] Error cleaning {temp_dir}: {e}\n")
            
            # Quarantine cleanup uses the application's own quarantine root.
            from quarantine_utils import QUARANTINE_FOLDER
            quarantine_folder = QUARANTINE_FOLDER
            if os.path.exists(quarantine_folder):
                try:
                    for filename in os.listdir(quarantine_folder):
                        if filename.endswith('.enc'):
                            filepath = os.path.join(quarantine_folder, filename)
                            try:
                                os.remove(filepath)
                                recovery_results["cleaned_files"].append(filepath)
                                output.write(f"[CLEANUP] Removed quarantined file: {filename}\n")
                                
                                # Remove metadata
                                json_path = filepath + '.json'
                                if os.path.exists(json_path):
                                    os.remove(json_path)
                            except Exception as e:
                                output.write(f"[CLEANUP ERROR] Could not remove {filename}: {e}\n")
                except Exception as e:
                    output.write(f"[CLEANUP ERROR] Error cleaning quarantine: {e}\n")
            
            recovery_results["recovered_systems"].append("cleanup_completed")
            output.write("[ROUTINE MAINTENANCE] System cleanup completed\n")
            
        except Exception as e:
            output.write(f"[ERROR] System cleanup failed: {e}\n")
            recovery_results["errors"].append(f"System cleanup: {str(e)}")
        
        output.write("[ROUTINE MAINTENANCE] Comprehensive maintenance and recovery completed.\n")
        
    except Exception as e:
        output.write(f"[CRITICAL ERROR] Routine maintenance failed: {e}\n")
        recovery_results["errors"].append(f"Critical: {str(e)}")
    
    return output.getvalue(), recovery_results

def _run_routine_maintenance_step(output, results):
    """Opt-in routine maintenance/system recovery step (see NOTE in
    run_conditional_startup_logic for why this defaults to disabled)."""
    routine_maintenance_enabled = os.environ.get('AV_ENABLE_ROUTINE_MAINTENANCE', '').strip().lower() in ('1', 'true', 'yes')
    if not routine_maintenance_enabled:
        output.write("[conditional_startup] Skipping routine maintenance and system recovery (disabled by default; set AV_ENABLE_ROUTINE_MAINTENANCE=1 to enable).\n")
        results["routine_maintenance"] = {"skipped": True}
        return
    output.write("[conditional_startup] Running comprehensive routine maintenance and system recovery...\n")
    try:
        maintenance_log, maintenance_results = routine_maintenance_and_system_recovery()
        output.write(maintenance_log)
        results["routine_maintenance"] = maintenance_results
        output.write("[conditional_startup] Routine maintenance completed.\n")
    except Exception as e:
        output.write(f"[ERROR] Routine maintenance failed: {e}\n")
        results["routine_maintenance"] = {"errors": [str(e)]}


def _load_scan_utilities(basedir, output):
    """Load the scan modules. In a PyInstaller bundle the source .py files are
    already on sys.path, so normal imports are used first. File-based loading is
    kept as a fallback for standalone development use."""
    paths_path = os.path.join(basedir, 'utils', 'paths.py')
    if os.path.exists(paths_path):
        output.write(f"[conditional_startup] Found paths.py at: {paths_path}\n")
    else:
        output.write(f"[ERROR] paths.py not found in {basedir}!\n")

    def _do_import():
        import scan_utils
        import security.yara_scanner as yara_scanner
        import security.process_monitor as process_monitor
        import security.process_security as process_security
        import quarantine_utils
        return {
            'scan_utils': scan_utils,
            'yara_scanner': yara_scanner,
            'process_monitor': process_monitor,
            'process_security': process_security,
            'quarantine_utils': quarantine_utils,
        }

    def _do_file_load():
        scan_utils_path = os.path.join(basedir, 'scan_utils.py')
        yara_scanner_path = os.path.join(basedir, 'security', 'yara_scanner.py')
        process_monitor_path = os.path.join(basedir, 'security', 'process_monitor.py')
        process_security_path = os.path.join(basedir, 'security', 'process_security.py')
        quarantine_utils_path = os.path.join(basedir, 'quarantine_utils.py')
        return {
            'scan_utils': import_module_from_path('scan_utils', scan_utils_path),
            'yara_scanner': import_module_from_path('yara_scanner', yara_scanner_path),
            'process_monitor': import_module_from_path('process_monitor', process_monitor_path),
            'process_security': import_module_from_path('process_security', process_security_path),
            'quarantine_utils': import_module_from_path('quarantine_utils', quarantine_utils_path),
        }

    try:
        modules = _do_import()
        output.write("[conditional_startup] Successfully loaded scan utilities (import).\n")
        return modules, None
    except Exception as e1:
        output.write(f"[WARNING] Normal module import failed: {e1}\n")
        try:
            modules = _do_file_load()
            output.write("[conditional_startup] Successfully loaded scan utilities (file load).\n")
            return modules, None
        except Exception as e2:
            output.write(f"[ERROR] Failed to load scan utilities: {e2}\n")
            return None, f"{e1}; then {e2}"


def _scan_running_processes_step(process_monitor, scan_utils, results, output, progress_callback):
    """Scan running processes, reporting live progress per-event.

    NOTE: process_monitor used to only be imported here but
    scan_running_processes() was never actually called, so
    results["process_events"] stayed empty and the "Process Events" stat in
    the status UI always showed 0 regardless of what happened during the
    scan.
    """
    output.write("[conditional_startup] Scanning running processes...\n")

    def on_process_event(event):
        with results_lock:
            from security.indicator_scans import record_process_event
            record_process_event(results, event)

            exe = event.get('exe')
            if exe and event['type'] == 'process_scanned':
                _run_ml_and_ransomware_checks(exe, results, output)

            # Report progress per-event, not just once after the whole process
            # scan finishes -- scanning a handful of large executables against
            # every YARA rule can take minutes, so waiting until the end would
            # leave the status UI showing 0 the entire time.
            if callable(progress_callback):
                try:
                    progress_callback(results)
                except Exception as e:
                    output.write(f"[WARNING] progress_callback raised during process scan: {e}\n")

    def _locked_scan_file_for_viruses(filepath):
        with scanner_lock:
            return scan_utils.scan_file_for_viruses(filepath, stop_event=None)

    try:
        process_monitor.scan_running_processes(
            _locked_scan_file_for_viruses,
            event_callback=on_process_event
        )
        output.write(f"[conditional_startup] Process scan reported {len(results['process_events'])} event(s).\n")
    except Exception as e:
        output.write(f"[ERROR] Process scan failed: {e}\n")
        from security.indicator_scans import record_error
        record_error(results, "process_scan", e)


def _scan_processes_hardening_step(process_security, results, output, progress_callback):
    """Run the process hardening scanner (YARA, entropy, signatures, memory)
    and report notable findings into the same process_events stream."""
    output.write("[conditional_startup] Running process hardening scan...\n")

    def on_hardening_event(event):
        with results_lock:
            # Only count actionable / notable findings, not the per-process scan heartbeat
            if event.get('type') in ('malware_found', 'yara_match'):
                from security.indicator_scans import record_process_event
                record_process_event(results, event)
            elif event.get('type') == 'process_scanned' and (
                event.get('yara') or
                (event.get('hashes', {}).get('entropy', 0) > 7.5) or
                event.get('signed') is False
            ):
                from security.indicator_scans import record_process_event
                record_process_event(results, event)

            if callable(progress_callback):
                try:
                    progress_callback(results)
                except Exception as e:
                    output.write(f"[WARNING] progress_callback raised during hardening scan: {e}\n")

    try:
        process_security.scan_processes_with_hardening(
            terminate_on_malware=False,
            block_connections=False,
            entropy_threshold=7.5,
            event_callback=on_hardening_event
        )
        with results_lock:
            output.write(f"[conditional_startup] Hardening scan reported {len(results['process_events'])} total process event(s).\n")
    except Exception as e:
        with results_lock:
            output.write(f"[ERROR] Process hardening scan failed: {e}\n")
            from security.indicator_scans import record_error
            record_error(results, "process_hardening", e)


def _check_persistence_indicators_step(results, output, progress_callback=None):
    """Fast, report-only check for processes/autostart entries in unusual
    locations and autorun.inf on removable drives -- see
    security/persistence_checks.py for why this replaces the old
    substring-matching spyware/trojan/worm/adware checks (which flagged
    ordinary software like PowerShell and Remote Desktop) with narrower,
    location-based signals. Not used for auto-quarantine, same rationale as
    the ML/ransomware checks: these are weak proxies, not proof of malware.
    """
    output.write("[conditional_startup] Checking for persistence/execution-location indicators...\n")
    try:
        from security.persistence_checks import run_all_checks
        findings = run_all_checks()
        from security.indicator_scans import record_persistence_indicators
        total = record_persistence_indicators(results, findings)
        output.write(f"[conditional_startup] Persistence checks found {total} indicator(s).\n")
        if callable(progress_callback):
            try:
                progress_callback(results)
            except Exception as e:
                output.write(f"[WARNING] progress_callback raised during persistence checks: {e}\n")
    except Exception as e:
        output.write(f"[ERROR] Persistence checks failed: {e}\n")
        from security.indicator_scans import record_error
        record_error(results, "persistence_checks", e)


def _update_phishing_blocklists_step(basedir, output):
    """Launch phishing detector learning behavior (update blocklists)."""
    try:
        phishing_live_feeds_path = os.path.join(basedir, 'phishing_live_feeds.py')
        phishing_live_feeds = import_module_from_path('phishing_live_feeds', phishing_live_feeds_path)
        phishing_live_feeds.update_all_blocklists()
        output.write("[conditional_startup] Phishing detector blocklists updated (learning behavior launched).\n")
    except Exception as e:
        output.write(f"[ERROR] Failed to update phishing detector blocklists: {e}\n")


def _launch_safe_downloader_step(basedir, output):
    """Launch safe_downloader.py as a background process, if configured."""
    safe_downloader_path = os.path.join(basedir, 'safe_downloader.py')
    # Only launch safe_downloader.py if required arguments are provided (url, encrypted_output)
    # Otherwise, skip and log a warning
    safe_downloader_url = os.environ.get('SAFE_DOWNLOADER_URL')
    safe_downloader_output = os.environ.get('SAFE_DOWNLOADER_OUTPUT')
    if not os.path.exists(safe_downloader_path):
        output.write("[conditional_startup] safe_downloader.py not found!\n")
        return
    if safe_downloader_url and safe_downloader_output:
        try:
            subprocess.Popen([  # nosem; nosec B603
                sys.executable, safe_downloader_path,
                safe_downloader_url, safe_downloader_output
            ], creationflags=CREATE_NO_WINDOW,
               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            output.write(f"[ERROR] Failed to launch safe_downloader.py: {e}\n")
    else:
        output.write("[WARNING] Skipping launch of safe_downloader.py: required arguments (url, encrypted_output) not provided.\n")
        output.write("[conditional_startup] safe_downloader.py started as background process.\n")


def _sync_scan_state_from_results(results, status=None):
    """Mirror Conditional Startup's live counters into canonical scan_state.json."""
    try:
        path = runtime_path("scan_state.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                state = json.load(handle) or {}
        except (OSError, ValueError, TypeError):
            state = {}
        scan_id = str(state.get("scan_id") or uuid.uuid4())
        # Multiple scanner workers can publish this same state file.  Never
        # let a lower per-worker counter overwrite a higher cumulative count
        # from another worker; the live scan state must be monotonic.
        current_files = int(results.get("scanned_files_count") or 0)
        current_quarantined = len(results.get("quarantined_files") or [])
        current_blocked = int(results.get("blocked_threats") or 0)
        current_findings = len(results.get("results") or [])
        current_ransomware = len(results.get("ransomware_indicators") or [])
        current_persistence = sum(
            len(v) if isinstance(v, (list, tuple, dict, set)) else 1
            for v in (results.get("persistence_indicators") or {}).values()
        )
        current_yara = len(results.get("yara_suspicious") or [])
        current_ml = len(results.get("ml_detections") or [])
        current_errors = len(results.get("errors") or [])
        current_process_events = len(results.get("process_events") or [])
        state.update({
            "scan_id": scan_id,
            "scan_owner": "conditional-startup",
            "status": status or ("complete" if results.get("_scan_complete") else "scanning"),
            "started_at": state.get("started_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "complete": bool(status == "complete" or results.get("_scan_complete")),
            "files_scanned": current_files,
            "quarantined_count": max(int(state.get("quarantined_count") or 0), current_quarantined),
            "threats_blocked": max(int(state.get("threats_blocked") or 0), current_blocked),
            "findings": max(int(state.get("findings") or 0), current_findings),
            "ransomware_indicators": max(int(state.get("ransomware_indicators") or 0), current_ransomware),
            "persistence_indicators": max(int(state.get("persistence_indicators") or 0), current_persistence),
            "yara_suspicious": max(int(state.get("yara_suspicious") or 0), current_yara),
            "ml_suspicious": max(int(state.get("ml_suspicious") or 0), current_ml),
            "errors": max(int(state.get("errors") or 0), current_errors),
            "process_events": max(int(state.get("process_events") or 0), current_process_events),
            "last_error": (results.get("errors") or [])[-1] if results.get("errors") else state.get("last_error"),
        })
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError) as exc:
        logging.getLogger(__name__).debug("Could not mirror Conditional Startup to scan_state.json: %s", exc)


def _load_scheduled_scan_state(state_file, output):
    """Read scheduled_scan_state.json, returning whether scans are enabled."""
    candidates = [state_file, get_resource_path('scheduled_scan_state.json')]
    for path in candidates:
        try:
            with open(path, 'r') as f:
                state = json.load(f)
            output.write(f"[conditional_startup] Loaded scheduled scan state from {path}\n")
            return state.get('enabled', False)
        except FileNotFoundError:
            continue
        except Exception as e:
            output.write(f"[conditional_startup] Failed to read {path}: {e}\n")
    # Default to enabled so the full scan still runs if the JSON is missing/wrong.
    output.write("[conditional_startup] scheduled_scan_state.json not found; defaulting scans to enabled.\n")
    return True


def _start_antivirus_cli_step(basedir, output):
    """Start antivirus_cli.py as a background process, if present."""
    cli_path = os.path.join(basedir, 'antivirus_cli.py')
    if not os.path.exists(cli_path):
        output.write("[conditional_startup] antivirus_cli.py not found!\n")
        return
    try:
        subprocess.Popen([sys.executable, cli_path],  # nosem; nosec B603
                         creationflags=CREATE_NO_WINDOW,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output.write("[conditional_startup] antivirus_cli.py started.\n")
    except Exception as e:
        output.write(f"[ERROR] Could not start antivirus_cli.py: {e}\n")


def _get_monitored_folders(basedir, output):
    """Resolve the list of folders to scan via folder_watcher, falling back
    to basedir/uploads and basedir/encrypted if that's unavailable.

    Auto-discovery is now ENABLED so the conditional startup scan covers
    the entire PC (all drives, user profiles, Program Files, AppData,
    system directories) instead of just ~/Downloads, ~/Documents, ~/Desktop.
    """
    fallback_folders = [os.path.join(basedir, 'uploads'), os.path.join(basedir, 'encrypted')]
    try:
        import folder_watcher
        # Auto-discover all drives and important folders across the entire PC.
        monitored_folders = folder_watcher.load_scan_directories("scan_directories.txt", auto_discover=True)
        output.write(f"[conditional_startup] Monitored folders ({len(monitored_folders)} dirs): {monitored_folders[:10]}{'...' if len(monitored_folders) > 10 else ''}\n")
        return monitored_folders
    except AttributeError:
        # If the exact function isn't found, try an alternative approach
        try:
            # Try to use MONITORED_FOLDERS if available
            monitored_folders = folder_watcher.MONITORED_FOLDERS
            output.write(f"[conditional_startup] Using pre-defined monitored folders: {monitored_folders}\n")
            return monitored_folders
        except AttributeError:
            # Fall back to build_monitored_folders if available
            try:
                monitored_folders = folder_watcher.build_monitored_folders()
                output.write(f"[conditional_startup] Built monitored folders: {monitored_folders}\n")
                return monitored_folders
            except Exception as build_exc:
                output.write(f"[ERROR] Could not build monitored folders: {build_exc}\n")
                return fallback_folders
    except Exception as fw_exc:
        output.write(f"[ERROR] Could not import folder_watcher: {fw_exc}\n")
        return fallback_folders



# Extensions the ML classifier's training data actually models. Its features
# (imports, sections, has_certificate, packed) come from adware/malware/
# trojan/worm samples that are all PE executables -- running it against
# arbitrary files (photos, videos, documents) was producing a flood of false
# positives, since compressed non-executable formats have the same "high
# entropy + zero imports/sections" signature the model associates with
# packed malware. Restricting it to executable-like files keeps it within
# the domain it was actually trained on.
_ML_CLASSIFIER_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.com', '.drv'}


def _run_ml_and_ransomware_checks(filepath, results, output):
    """Run the static-file ML classifier and the static-only ransomware
    heuristic against a file, recording any hits into results for visibility.

    ML and ransomware hits that exceed the configured threshold are now
    treated like other malware detections and will be quarantined.
    """
    with results_lock:
        try:
            from security.detector import detector, ember_detector, bodmas_cnn_detector, check_ransomware_indicators

            _, ext = os.path.splitext(filepath)
            ml_hit = None
            if ext.lower() in _ML_CLASSIFIER_EXTENSIONS:
                with scanner_lock:
                    # Prefer the EMBER-trained classifier (real malware/benign data)
                    # when its model file is present; fall back to the
                    # synthetic-data classifier otherwise.
                    if bodmas_cnn_detector.available:
                        score = bodmas_cnn_detector.score(filepath)
                        if score is not None and score >= 0.60:
                            ml_hit = ("bodmas_cnn", score)
                    elif ember_detector.available:
                        score = ember_detector.score(filepath)
                        if score is not None and score >= 0.60:
                            ml_hit = ("ember", score)
                    elif detector.is_malicious(filepath):
                        score = detector.get_anomaly_score(filepath)
                        ml_hit = ("synthetic", float(score))
                if ml_hit:
                    model, score = ml_hit
                    output.write(f"[ML/{model.upper()}] Malicious file detected: {filepath} (score: {score})\n")
                    from security.indicator_scans import record_ml_suspicious
                    record_ml_suspicious(results, filepath, score, model)

            with scanner_lock:
                is_suspicious, reason = check_ransomware_indicators(filepath)
            if is_suspicious:
                output.write(f"[RANSOMWARE HEURISTIC] {filepath}: {reason}\n")
                from security.indicator_scans import record_ransomware_indicator
                record_ransomware_indicator(results, filepath, reason)
        except Exception as ml_exc:
            output.write(f"[INFO] ML/ransomware check skipped for {filepath}: {ml_exc}\n")
            from security.indicator_scans import record_error
            record_error(results, "ml_ransomware_check", ml_exc, filepath)


def _is_trusted_windows_path(filepath):
    """Return True for paths that are part of the normal Windows installation.

    These locations are very unlikely to hold malware in a normal system, so
    YARA-only matches there are downgraded unless another detector corroborates.
    """
    try:
        lower = filepath.lower()
        if not lower.startswith('c:\\\\'):
            return False
        parts = lower.split('\\\\')
        # C:\Windows and C:\Program Files* are treated as trusted core system
        # directories. We deliberately do not include user profile or appdata.
        return parts[1] in {'windows', 'program files', 'program files (x86)'}
    except Exception:
        return False


def _scan_file_and_record(filepath, scan_utils, yara_scanner, quarantine_utils, results, scanned_file_status, output, progress_callback=None):
    """Scan a single file, quarantining it if malware is found, and record
    its outcome into results/scanned_file_status."""
    try:
        # The traversal records the file before entering this function so
        # blocking filesystem operations cannot prevent the progress counter
        # from advancing.
        scan_timeout = os.environ.get("CONDITIONAL_FILE_SCAN_TIMEOUT_SECONDS", "30")
        completed, scan_value, scan_error = _run_scan_stage_with_timeout(
            lambda: scan_utils.scan_file_for_viruses(filepath, stop_event=None),
            scan_timeout,
            "signature_scan",
            filepath,
            output,
        )
        if not completed:
            from security.indicator_scans import record_error
            with results_lock:
                record_error(results, "signature_scan_watchdog", scan_error, filepath)
                scanned_file_status[filepath] = {
                    "malware_found": None,
                    "quarantined": False,
                    "error": scan_error,
                }
            if callable(progress_callback):
                progress_callback(results)
            scan_success, malware_found, msg = False, False, scan_error
        elif scan_error:
            scan_success, malware_found, msg = False, False, scan_error
        else:
            scan_success, malware_found, msg = scan_value
        with results_lock:
            output.write(f"[conditional_startup] {msg}\n")
            scanned_file_status[filepath] = {
                "malware_found": malware_found,
                "quarantined": False,
                "error": None
            }

        # Try YARA scan
        yara_result = None
        try:
            with results_lock:
                results["scan_phase"] = "yara"
            if callable(progress_callback):
                try:
                    progress_callback(results)
                except Exception:
                    pass
            output.write(f"[conditional_startup] ENTER YARA LOOP: {filepath}\n")
            completed, yara_value, yara_error = _run_scan_stage_with_timeout(
                lambda: yara_scanner.scan_file_with_yara(filepath),
                scan_timeout,
                "yara_scan",
                filepath,
                output,
            )
            if not completed:
                from security.indicator_scans import record_error
                with results_lock:
                    record_error(results, "yara_scan_watchdog", yara_error, filepath)
                yara_result = None
            elif yara_error:
                raise RuntimeError(yara_error)
            else:
                yara_result = yara_value
            with results_lock:
                output.write(f"[conditional_startup] Yara Scan result for {filepath}: {yara_result}\n")
                if yara_result:
                    highest = yara_scanner.get_highest_severity(yara_result)
                    # Confidence scoring: count distinct rule families (namespaces).
                    # A hit from multiple independent rule files is stronger than a
                    # single broad rule firing on a clean file.
                    yara_namespaces = {getattr(m, 'namespace', 'default') for m in yara_result}
                    rule_names = [getattr(m, 'rule', 'unknown') for m in yara_result]
                    multi_family = len(yara_namespaces) >= 2
                    trusted_path = _is_trusted_windows_path(filepath)

                    if yara_scanner._rank_of(highest) >= yara_scanner._rank_of('high'):
                        # Path-based trust: in trusted Windows directories we only
                        # record the hit as suspicious if multiple families matched.
                        if not trusted_path or multi_family:
                            from security.indicator_scans import record_yara_suspicious
                            record_yara_suspicious(
                                results, filepath, highest, rule_names, sorted(yara_namespaces)
                            )

                    # Critical YARA only forces quarantine if we have confidence.
                    # For protected Windows paths, wait for ML corroboration.
                    if yara_scanner.has_critical_yara_match(yara_result):
                        critical_rules = [getattr(m, 'rule', 'unknown') for m in yara_result
                                          if yara_scanner.get_match_severity(m) == 'critical']
                        if not trusted_path or multi_family:
                            output.write(f"[CRITICAL YARA] Critical rule(s) matched for {filepath}: {', '.join(critical_rules)}. Forcing quarantine.\n")
                            malware_found = True
                            msg = f"Critical YARA match: {', '.join(critical_rules)}"
                        else:
                            output.write(f"[INFO] Critical YARA match for {filepath} ({', '.join(critical_rules)}) on trusted path; waiting for ML corroboration.\n")
        except Exception as yara_exc:
            with results_lock:
                output.write(f"[INFO] YARA scan skipped for {filepath}: {yara_exc}\n")
                from security.indicator_scans import record_error
                record_error(results, "yara_scan", yara_exc, filepath)

        _run_ml_and_ransomware_checks(filepath, results, output)

        # Escalate high-severity YARA matches to critical when ML also flags the file.
        if yara_result:
            highest = yara_scanner.get_highest_severity(yara_result)
            if yara_scanner._rank_of(highest) >= yara_scanner._rank_of('high'):
                has_ml = any(d.get("file") == filepath for d in results.get("ml_detections", []))
                if has_ml:
                    with results_lock:
                        output.write(f"[CRITICAL YARA] High YARA match for {filepath} escalated to critical because ML also flagged it.\n")
                        malware_found = True
                        scanned_file_status[filepath]["malware_found"] = True

        # Also quarantine if a high-confidence ML or ransomware hit was recorded.
        # To reduce false positives, the synthetic-data ML fallback alone does
        # NOT trigger auto-quarantine -- only the real EMBER/BODMAS models do,
        # or any ML model when a YARA match also flagged the file.  The
        # ransomware heuristic's "ransom note in same directory" proxy is also
        # not sufficient by itself; only a direct ransomware-extension match
        # on the file itself triggers quarantine.
        with results_lock:
            ml_hits = [d for d in results.get("ml_detections", []) if d.get("file") == filepath]
            has_real_ml = any(d.get("model") in ("ember", "bodmas_cnn") for d in ml_hits)
            has_yara = yara_result is not None and len(yara_result) > 0
            has_ml = bool(ml_hits)

            rw_hits = [d for d in results.get("ransomware_indicators", []) if d.get("file") == filepath]
            has_rw_extension = any("extension" in (d.get("reason") or "").lower() for d in rw_hits)

            # Auto-quarantine only when:
            #   - a real (non-synthetic) ML model flagged the file, OR
            #   - any ML model flagged the file AND YARA also matched it, OR
            #   - the file itself has a ransomware extension
            if has_real_ml or (has_ml and has_yara) or has_rw_extension:
                malware_found = True
                scanned_file_status[filepath]["malware_found"] = True

        # Quarantine if malware found
        if malware_found:
            with results_lock:
                try:
                    quarantine_utils.quarantine_file(filepath)
                    output.write(f"[conditional_startup] File {filepath} quarantined.\n")
                    results["quarantined_files"].append(filepath)
                    scanned_file_status[filepath]["quarantined"] = True
                except Exception as quarantine_exc:
                    # Malware was detected but could not be removed (e.g. permission
                    # denied on a protected system file). Previously this was only
                    # written to the internal log and counted toward neither
                    # "Quarantined" nor "Errors", making it look like nothing had
                    # happened when malware had actually been found and left in place.
                    output.write(f"[WARNING] Could not quarantine {filepath}: {quarantine_exc}\n")
                    scanned_file_status[filepath]["error"] = str(quarantine_exc)
                    from security.indicator_scans import record_error
                    record_error(results, "quarantine", quarantine_exc, filepath)

        # ── Adaptive YARA rule reputation ─────────────────────────────────────
        # Feed back into rule_reputation so rules auto-suppress on clean files
        # and auto-unsuppress when they match confirmed malware.
        # This is the "automatic FP / non-FP detection" mechanism: rules that
        # keep firing on clean files get suppressed; rules that hit real malware
        # get re-enabled even if they were suppressed before.
        if yara_result:
            try:
                from security.rule_reputation import record_clean_hit, record_malware_hit
                yara_rule_names = [getattr(m, 'rule', '') for m in yara_result if getattr(m, 'rule', '')]
                if malware_found:
                    # File is confirmed malware — these rules earned their keep
                    for rname in yara_rule_names:
                        record_malware_hit(rname)
                    output.write(f"[rule_reputation] Recorded malware hit for {len(yara_rule_names)} rule(s) on {filepath}\n")
                else:
                    # YARA fired but no independent signal confirmed malware — clean hit
                    for rname in yara_rule_names:
                        record_clean_hit(rname)
                    output.write(f"[rule_reputation] Recorded clean hit for {len(yara_rule_names)} rule(s) on {filepath}\n")
            except Exception as rep_exc:
                output.write(f"[INFO] rule_reputation update skipped for {filepath}: {rep_exc}\n")
        # ──────────────────────────────────────────────────────────────────────

        # Publish the completed-file state after all scan stages have finished.
        if callable(progress_callback):
            progress_callback(results)
    except (PermissionError, OSError) as perm_error:
        with results_lock:
            output.write(f"[INFO] Permission issue for {filepath}: {perm_error}\n")
            scanned_file_status[filepath] = {
                "malware_found": None,
                "quarantined": False,
                "error": str(perm_error)
            }
            if callable(progress_callback):
                progress_callback(results)
    except Exception as scan_exc:
        with results_lock:
            output.write(f"[ERROR] Scan error for {filepath}: {scan_exc}\n")
            from security.indicator_scans import record_error
            record_error(results, "file_scan", scan_exc, filepath)
            scanned_file_status[filepath] = {
                "malware_found": None,
                "quarantined": False,
                "error": str(scan_exc)
            }
            if callable(progress_callback):
                progress_callback(results)


def _scan_monitored_folders_step(monitored_folders, modules, results, scanned_file_status, output, progress_callback):
    """Run the normal scan as an infinite scan stream.

    The function intentionally never reaches a scan-completion boundary.
    The normal filesystem traversal is restarted immediately from inside this
    function, so the first scan remains one indefinitely running scan session.
    """
    scan_utils = modules['scan_utils']
    yara_scanner = modules['yara_scanner']
    quarantine_utils = modules['quarantine_utils']

    # One invocation performs one complete traversal of every monitored folder.
    # Cross-run persistence is handled separately; there is intentionally no
    # "already scanned" set here, so every new run revisits every eligible file.
    #
    # os.walk() can block indefinitely on a broken/offline/reparse-pointed
    # directory. Run each folder enumeration behind a watchdog so a filesystem
    # stall cannot freeze the entire scan at the last file reached.
    try:
        enum_timeout = max(1.0, float(os.environ.get(
            "CONDITIONAL_DIRECTORY_ENUM_TIMEOUT_SECONDS", "30"
        )))
    except (TypeError, ValueError):
        enum_timeout = 30.0

    for folder in monitored_folders:
        output.write(f"[TRAVERSAL] START folder: {folder}\\n")
        entries = queue.Queue(maxsize=1)

        def _enumerate():
            try:
                for root, dirs, files in os.walk(folder, topdown=True, followlinks=False):
                    if "OneDriveTemp" in root:
                        dirs[:] = []
                        continue
                    entries.put(("entry", root, list(dirs), list(files)))
                entries.put(("done", None, None, None))
            except Exception as exc:
                try:
                    entries.put(("error", None, None, exc), block=False)
                except Exception:
                    pass

        worker = threading.Thread(
            target=_enumerate,
            name="IsolationBytes-DirectoryEnumerator",
            daemon=True,
        )
        worker.start()

        while True:
            try:
                item = entries.get(timeout=enum_timeout)
            except queue.Empty:
                message = (
                    f"directory enumeration watchdog timed out after "
                    f"{enum_timeout:.1f}s: {folder}"
                )
                output.write(f"[WATCHDOG] {message}\\n")
                from security.indicator_scans import record_error
                record_error(results, "directory_enum_watchdog", message, folder)
                break

            kind, root, dirs, files = item
            if kind == "done":
                output.write(f"[TRAVERSAL] COMPLETE folder: {folder}\\n")
                break
            if kind == "error":
                output.write(f"[TRAVERSAL ERROR] {dirs}\\n")
                from security.indicator_scans import record_error
                record_error(results, "directory_enumeration", dirs, folder)
                break

            output.write(f"[TRAVERSAL] {root}: {len(files)} file(s)\\n")
            for filename in files:
                filepath = os.path.join(root, filename)

                # Count immediately when the traversal reaches the file.
                # Do not perform a separate open() probe here: on Windows,
                # network/reparse/filter-driver files can block during open()
                # before the scanner watchdog even gets control.
                with results_lock:
                    results["scanned_files_count"] = results.get("scanned_files_count", 0) + 1
                if callable(progress_callback):
                    try:
                        progress_callback(results)
                    except Exception:
                        pass

                _scan_file_and_record(
                    filepath,
                    scan_utils,
                    yara_scanner,
                    quarantine_utils,
                    results,
                    scanned_file_status,
                    output,
                    progress_callback,
                )

    # Return after the full traversal. Continuous mode is implemented by the
    # outer run_conditional_startup_logic() loop, which starts a fresh traversal
    # and therefore rescans every monitored path/file on each pass.

def _open_browser_when_ready(output):
    """Wait for the local server to come up, then open it in a browser."""
    url = 'http://127.0.0.1:5000'
    timeout = 15
    interval = 0.25
    waited = 0
    while waited < timeout:
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                webbrowser.open(url)
                return
        except Exception:
            logging.warning('Conditional startup check failed', exc_info=False)
        time.sleep(interval)
        waited += interval
    output.write(f"[conditional_startup] Warning: Server not available after {timeout} seconds.\n")
    webbrowser.open(url)


def _build_scanned_results(results, scanned_file_status):
    """Build the per-file results list from scanned_files + scanned_file_status."""
    scanned_results = []
    for filepath in results["scanned_files"]:
        status = scanned_file_status.get(filepath, {})
        scanned_results.append({
            "file": filepath,
            "malware_found": status.get("malware_found", False),
            "quarantined": status.get("quarantined", False),
            "error": status.get("error", None)
        })
    return scanned_results


def _persist_conditional_startup_log(log_text, basedir):
    """Persist diagnostics in the module folder and writable runtime folder."""
    log_dirs = [basedir]
    runtime_dir = os.environ.get('ANTIVIRUS_RUNTIME_DIR')
    if runtime_dir and os.path.abspath(runtime_dir) != os.path.abspath(basedir):
        log_dirs.append(runtime_dir)
    for log_dir in log_dirs:
        try:
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, 'conditional_startup.log'), 'w', encoding='utf-8') as f:
                f.write(log_text)
        except Exception:
            continue


def _run_conditional_startup_once(open_browser=True, progress_callback=None, critical_dirs=None):
    # Suppress scikit-learn version warnings
    warnings.filterwarnings("ignore", category=UserWarning)


    output = io.StringIO()

    original_progress_callback = progress_callback
    def _publish_progress(current_results):
        _sync_scan_state_from_results(current_results)
        if callable(original_progress_callback):
            try:
                original_progress_callback(current_results)
            except Exception as exc:
                output.write(f"[WARNING] progress_callback raised: {exc}\\n")
    progress_callback = _publish_progress

    results = {
        "scanned_files": {},
        "scanned_files_count": 0,  # stable integer — only incremented when a file finishes
        "quarantined_files": [],
        "errors": [],
        "process_events": [],
        "results": [],  # Initialize results array immediately
        "routine_maintenance": {},  # Add routine maintenance results
        "ml_detections": [],  # Files flagged by the static-file ML classifier (report-only)
        "ransomware_indicators": [],  # Files flagged by the static ransomware heuristic (report-only)
        "persistence_indicators": {},  # Processes/autostart entries in unusual locations (report-only)
        "yara_suspicious": []  # High/critical YARA matches for review (not auto-quarantined)
    }
    scanned_file_status = {}  # Track status for each scanned file
    results['scanned_files'] = scanned_file_status  # used for progress/idle counts

    # Run comprehensive routine maintenance and system recovery.
    # NOTE: routine_maintenance_and_system_recovery() performs 8+ full recursive
    # scans of critical_dirs, which includes C:\Windows\System32 (tens of
    # thousands of files). That makes it extremely slow and it runs before any
    # scan progress is reported, so it's opt-in only: set
    # AV_ENABLE_ROUTINE_MAINTENANCE=1 (or true/yes) to enable it.
    _run_routine_maintenance_step(output, results)

    basedir = os.path.dirname(os.path.abspath(__file__))
    runtime_dir = os.path.abspath(os.environ.get(
        'ANTIVIRUS_RUNTIME_DIR',
        os.path.join(
            os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
            'IsolationBytes'
        )
    ))
    os.makedirs(runtime_dir, exist_ok=True)
    state_file = os.path.join(runtime_dir, 'scheduled_scan_state.json')

    modules, load_error = _load_scan_utilities(basedir, output)
    if modules is None:
        results["log"] = output.getvalue()
        results["errors"].append({"stage": "module_load", "error": load_error or "Failed to load scan utilities"})
        _persist_conditional_startup_log(results["log"], basedir)
        return results

    # A user-triggered Conditional Startup run is a real file scan; it must
    # not depend on the persistent scheduled-scan toggle. That toggle controls
    # the scheduler, not whether an explicit /run_startup request scans files.
    output.write('[conditional_startup] Running explicit Conditional Startup file scan...\n')
    monitored_folders = _get_monitored_folders(basedir, output)
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_process = executor.submit(
            _scan_running_processes_step,
            modules['process_monitor'], modules['scan_utils'], results, output, progress_callback
        )
        future_file = executor.submit(
            _scan_monitored_folders_step,
            monitored_folders, modules, results, scanned_file_status, output, progress_callback
        )
        future_persistence = executor.submit(
            _check_persistence_indicators_step,
            results, output, progress_callback
        )
        future_hardening = executor.submit(
            _scan_processes_hardening_step,
            modules['process_security'], results, output, progress_callback
        )
        future_process.result()
        future_file.result()
        future_persistence.result()
        future_hardening.result()

    _update_phishing_blocklists_step(basedir, output)
    _launch_safe_downloader_step(basedir, output)
    _start_antivirus_cli_step(basedir, output)

    if open_browser:
        _open_browser_when_ready(output)

    results["results"] = _build_scanned_results(results, scanned_file_status)
    results["log"] = output.getvalue()
    results["_scan_complete"] = True
    _sync_scan_state_from_results(results, status="complete")

    # Persist the detailed log in the module folder and writable runtime folder.
    _persist_conditional_startup_log(results["log"], basedir)

    return results

def run_conditional_startup_logic(open_browser=True, progress_callback=None, critical_dirs=None, continuous=False):
    """Run Conditional Startup once or continuously for the lifetime of the process."""
    # Seed this invocation from the persisted Conditional Startup history.
    # Clicking Run again must continue the existing counters/evidence instead
    # of creating a fresh zero-based view.
    cumulative_scanned = 0
    cumulative_quarantined = []
    cumulative_errors = []
    cumulative_process_events = []
    cumulative_ml = []
    cumulative_ransomware = []
    cumulative_yara = []
    cumulative_persistence = {}
    last_result = None

    runtime_dir = os.path.abspath(os.environ.get(
        "ANTIVIRUS_RUNTIME_DIR",
        os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "IsolationBytes")
    ))
    persisted_path = os.path.join(runtime_dir, "scanner_results.json")
    try:
        with open(persisted_path, "r", encoding="utf-8") as handle:
            persisted = json.load(handle)
        if isinstance(persisted, dict) and isinstance(persisted.get("scanner_results"), dict):
            persisted = persisted["scanner_results"]
        if isinstance(persisted, dict):
            counts = persisted.get("counts") or persisted.get("scanner_counters") or {}
            cumulative_scanned = int(counts.get("scanned_files") or counts.get("files_scanned") or persisted.get("scanned_files") or 0)
            cumulative_quarantined = list(persisted.get("quarantined_files") or [])
            cumulative_errors = list(persisted.get("errors") or [])
            cumulative_process_events = list(persisted.get("process_events") or [])
            cumulative_ml = list(persisted.get("ml_detections") or [])
            cumulative_ransomware = list(persisted.get("ransomware_indicators") or [])
            cumulative_yara = list(persisted.get("yara_suspicious") or [])
            persisted_persistence = persisted.get("persistence_indicators") or {}
            cumulative_persistence = dict(persisted_persistence) if isinstance(persisted_persistence, dict) else {}
    except (OSError, ValueError, TypeError):
        pass

    # In continuous mode, the very first filesystem traversal is itself the
    # live protection session. There is no finite "first scan" to complete.
    # Keep the worker in continuous mode from the moment the first traversal starts.
    # A continuous protection session begins with the normal scan immediately.
    # Each normal scan pass is followed immediately by another pass; there is
    # no separate watchdog/event-monitoring mode.
    while True:
        def _continuous_progress(results):
            if not callable(progress_callback):
                return
            merged = dict(results)
            merged["scanned_files_count"] = cumulative_scanned + int(results.get("scanned_files_count") or 0)
            merged["quarantined_files"] = list(cumulative_quarantined) + list(results.get("quarantined_files") or [])
            merged["errors"] = list(cumulative_errors) + list(results.get("errors") or [])
            merged["process_events"] = list(cumulative_process_events) + list(results.get("process_events") or [])
            merged["ml_detections"] = list(cumulative_ml) + list(results.get("ml_detections") or [])
            merged["ransomware_indicators"] = list(cumulative_ransomware) + list(results.get("ransomware_indicators") or [])
            merged["yara_suspicious"] = list(cumulative_yara) + list(results.get("yara_suspicious") or [])
            persistence = results.get("persistence_indicators") or {}
            merged["persistence_indicators"] = dict(cumulative_persistence)
            for key, value in persistence.items():
                if isinstance(value, list):
                    merged["persistence_indicators"][key] = list(merged["persistence_indicators"].get(key) or []) + list(value)
                else:
                    merged["persistence_indicators"][key] = value
            progress_callback(merged)

        last_result = _run_conditional_startup_once(
            open_browser=open_browser if not continuous else False,
            progress_callback=_continuous_progress if continuous else progress_callback,
            critical_dirs=critical_dirs,
        )

        cumulative_scanned += int(last_result.get("scanned_files_count") or 0)
        cumulative_quarantined.extend(last_result.get("quarantined_files") or [])
        cumulative_errors.extend(last_result.get("errors") or [])
        cumulative_process_events.extend(last_result.get("process_events") or [])
        cumulative_ml.extend(last_result.get("ml_detections") or [])
        cumulative_ransomware.extend(last_result.get("ransomware_indicators") or [])
        cumulative_yara.extend(last_result.get("yara_suspicious") or [])
        for key, value in (last_result.get("persistence_indicators") or {}).items():
            if isinstance(value, list):
                cumulative_persistence.setdefault(key, []).extend(value)
            else:
                cumulative_persistence[key] = value

        if not continuous:
            break


    if last_result is None:
        last_result = {
            "scanned_files": {},
            "scanned_files_count": cumulative_scanned,
            "quarantined_files": cumulative_quarantined,
            "errors": cumulative_errors,
            "process_events": cumulative_process_events,
            "ml_detections": cumulative_ml,
            "ransomware_indicators": cumulative_ransomware,
            "persistence_indicators": cumulative_persistence,
            "yara_suspicious": cumulative_yara,
            "results": [],
            "log": "",
        }
    return last_result

# Run the logic when the script is executed
if __name__ == "__main__":
    result = run_conditional_startup_logic(open_browser=False)
    print(json.dumps(result))
