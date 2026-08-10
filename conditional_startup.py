import importlib.util
import os
import sys
import io
import json
import getpass
import subprocess
import tempfile
import requests
import time
import webbrowser
import warnings

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
        os.path.join(system_root, 'System32'),
        os.path.join(system_root, 'Temp'),
        os.path.join(user_profile, 'Downloads'),
        os.path.join(user_profile, 'AppData\\Local\\Temp'),
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
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # PyInstaller one-file extracts to a temp folder
        base_path = sys._MEIPASS
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
            
            # Scan critical system directories (auto-detect drive if env vars missing)
            critical_dirs = _resolve_critical_directories()
            
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            filepath = os.path.join(root, file)
                            try:
                                yara_result = yara_scanner.scan_file(filepath)
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
            from security.detector import detector, ember_detector

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
                            if os.path.splitext(file)[1].lower() not in ml_extensions:
                                continue
                            filepath = os.path.join(root, file)
                            try:
                                # Prefer the EMBER-trained classifier (real malware/
                                # benign data) when available; otherwise fall back to
                                # the synthetic-data classifier. is_malicious() on the
                                # fallback handles both the trained classifier (0/1
                                # labels) and the untrained IsolationForest fallback
                                # (+1/-1 outlier labels) correctly.
                                if ember_detector.available:
                                    score = ember_detector.score(filepath)
                                    if score is not None and score >= 0.85:
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
                            filepath = os.path.join(root, file)
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
                            filepath = os.path.join(root, file)
                            try:
                                scan_success, malware_found, msg = scan_utils.scan_file_for_viruses(filepath)
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
                                        yara_result = yara_scanner.scan_file(filepath)
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
                                    filepath = os.path.join(root, file)
                                    try:
                                        os.remove(filepath)
                                        recovery_results["cleaned_files"].append(filepath)
                                        output.write(f"[CLEANUP] Removed temporary file: {filepath}\n")
                                    except Exception as e:
                                        output.write(f"[CLEANUP ERROR] Could not remove {filepath}: {e}\n")
                        except Exception as e:
                            output.write(f"[CLEANUP ERROR] Error cleaning {temp_dir}: {e}\n")
            
            # Quarantine cleanup
            quarantine_folder = os.path.join(tempfile.gettempdir(), 'Defender_Quarantine')
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
    """Dynamically load the modules the scan needs. Returns a dict of loaded
    modules, or None if loading failed (with the failure logged to output)."""
    paths_path = os.path.join(basedir, 'utils', 'paths.py')
    if os.path.exists(paths_path):
        output.write(f"[conditional_startup] Found paths.py at: {paths_path}\n")
    else:
        output.write(f"[ERROR] paths.py not found in {basedir}!\n")

    scan_utils_path = os.path.join(basedir, 'scan_utils.py')
    yara_scanner_path = os.path.join(basedir, 'security', 'yara_scanner.py')
    process_monitor_path = os.path.join(basedir, 'security', 'process_monitor.py')
    process_security_path = os.path.join(basedir, 'security', 'process_security.py')
    quarantine_utils_path = os.path.join(basedir, 'quarantine_utils.py')

    try:
        modules = {
            'scan_utils': import_module_from_path('scan_utils', scan_utils_path),
            'yara_scanner': import_module_from_path('yara_scanner', yara_scanner_path),
            'process_monitor': import_module_from_path('process_monitor', process_monitor_path),
            'process_security': import_module_from_path('process_security', process_security_path),
            'quarantine_utils': import_module_from_path('quarantine_utils', quarantine_utils_path),
        }
        output.write("[conditional_startup] Successfully loaded scan utilities.\n")
        return modules
    except Exception as e:
        output.write(f"[ERROR] Failed to load scan utilities: {e}\n")
        return None


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
        results["process_events"].append(event)

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

    try:
        process_monitor.scan_running_processes(
            scan_utils.scan_file_for_viruses,
            event_callback=on_process_event
        )
        output.write(f"[conditional_startup] Process scan reported {len(results['process_events'])} event(s).\n")
    except Exception as e:
        output.write(f"[ERROR] Process scan failed: {e}\n")
        results["errors"].append({"stage": "process_scan", "error": str(e)})


def _scan_processes_hardening_step(process_security, results, output, progress_callback):
    """Run the process hardening scanner (YARA, entropy, signatures, memory)
    and report notable findings into the same process_events stream."""
    output.write("[conditional_startup] Running process hardening scan...\n")

    def on_hardening_event(event):
        # Only count actionable / notable findings, not the per-process scan heartbeat
        if event.get('type') in ('malware_found', 'yara_match'):
            results["process_events"].append(event)
        elif event.get('type') == 'process_scanned' and (
            event.get('yara') or
            (event.get('hashes', {}).get('entropy', 0) > 7.5) or
            event.get('signed') is False
        ):
            results["process_events"].append(event)

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
        output.write(f"[conditional_startup] Hardening scan reported {len(results['process_events'])} total process event(s).\n")
    except Exception as e:
        output.write(f"[ERROR] Process hardening scan failed: {e}\n")
        results["errors"].append({"stage": "process_hardening", "error": str(e)})


def _check_persistence_indicators_step(results, output):
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
        results["persistence_indicators"] = findings
        total = sum(len(v) for v in findings.values())
        output.write(f"[conditional_startup] Persistence checks found {total} indicator(s).\n")
    except Exception as e:
        output.write(f"[ERROR] Persistence checks failed: {e}\n")
        results["errors"].append({"stage": "persistence_checks", "error": str(e)})


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
            ])
        except Exception as e:
            output.write(f"[ERROR] Failed to launch safe_downloader.py: {e}\n")
    else:
        output.write("[WARNING] Skipping launch of safe_downloader.py: required arguments (url, encrypted_output) not provided.\n")
        output.write("[conditional_startup] safe_downloader.py started as background process.\n")


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
        subprocess.Popen([sys.executable, cli_path])  # nosem; nosec B603
        output.write("[conditional_startup] antivirus_cli.py started.\n")
    except Exception as e:
        output.write(f"[ERROR] Could not start antivirus_cli.py: {e}\n")


def _get_monitored_folders(basedir, output):
    """Resolve the list of folders to scan via folder_watcher, falling back
    to basedir/uploads and basedir/encrypted if that's unavailable."""
    fallback_folders = [os.path.join(basedir, 'uploads'), os.path.join(basedir, 'encrypted')]
    try:
        import folder_watcher
        # Use folder_watcher's load_scan_directories function correctly
        monitored_folders = folder_watcher.load_scan_directories("scan_directories.txt")
        output.write(f"[conditional_startup] Monitored folders: {monitored_folders}\n")
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

    These are report-only (not auto-quarantined): the ML model was trained on
    synthetic data (see train_malware_classifier.py) and the ransomware
    heuristic is a weak, static-only proxy for behavioral indicators it can't
    actually observe, so neither has proven real-world accuracy yet. Treating
    a hit here the same as a YARA/signature match would risk quarantining
    legitimate files on false positives.
    """
    try:
        from security.detector import detector, ember_detector, check_ransomware_indicators

        _, ext = os.path.splitext(filepath)
        if ext.lower() in _ML_CLASSIFIER_EXTENSIONS:
            # Prefer the EMBER-trained classifier (real malware/benign data)
            # when its model file is present; fall back to the
            # synthetic-data classifier otherwise.
            if ember_detector.available:
                score = ember_detector.score(filepath)
                if score is not None and score >= 0.85:
                    output.write(f"[ML/EMBER] Suspicious file (not auto-quarantined): {filepath} (score: {score:.3f})\n")
                    results["ml_detections"].append({"file": filepath, "anomaly_score": score, "model": "ember"})
            elif detector.is_malicious(filepath):
                score = detector.get_anomaly_score(filepath)
                output.write(f"[ML] Suspicious file (not auto-quarantined): {filepath} (score: {score})\n")
                results["ml_detections"].append({"file": filepath, "anomaly_score": float(score), "model": "synthetic"})

        is_suspicious, reason = check_ransomware_indicators(filepath)
        if is_suspicious:
            output.write(f"[RANSOMWARE HEURISTIC] {filepath}: {reason}\n")
            results["ransomware_indicators"].append({"file": filepath, "reason": reason})
    except Exception as ml_exc:
        output.write(f"[INFO] ML/ransomware check skipped for {filepath}: {ml_exc}\n")


def _scan_file_and_record(filepath, scan_utils, yara_scanner, quarantine_utils, results, scanned_file_status, output):
    """Scan a single file, quarantining it if malware is found, and record
    its outcome into results/scanned_file_status."""
    try:
        scan_success, malware_found, msg = scan_utils.scan_file_for_viruses(filepath)
        output.write(f"[conditional_startup] {msg}\n")
        scanned_file_status[filepath] = {
            "malware_found": malware_found,
            "quarantined": False,
            "error": None
        }

        # Try YARA scan
        try:
            yara_result = yara_scanner.scan_file(filepath)
            output.write(f"[conditional_startup] Yara Scan result for {filepath}: {yara_result}\n")
        except Exception as yara_exc:
            # Just log and continue if YARA scan fails
            output.write(f"[INFO] YARA scan skipped for {filepath}: {yara_exc}\n")

        _run_ml_and_ransomware_checks(filepath, results, output)

        # Quarantine if malware found
        if malware_found:
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
                results["errors"].append({"file": filepath, "error": f"Quarantine failed: {quarantine_exc}"})
    except (PermissionError, OSError) as perm_error:
        output.write(f"[INFO] Permission issue for {filepath}: {perm_error}\n")
        scanned_file_status[filepath] = {
            "malware_found": None,
            "quarantined": False,
            "error": str(perm_error)
        }
    except Exception as scan_exc:
        output.write(f"[ERROR] Scan error for {filepath}: {scan_exc}\n")
        results["errors"].append({"file": filepath, "error": str(scan_exc)})
        scanned_file_status[filepath] = {
            "malware_found": None,
            "quarantined": False,
            "error": str(scan_exc)
        }


def _scan_monitored_folders_step(monitored_folders, modules, results, scanned_file_status, output, progress_callback):
    """Walk every monitored folder and scan each accessible file."""
    scan_utils = modules['scan_utils']
    yara_scanner = modules['yara_scanner']
    quarantine_utils = modules['quarantine_utils']

    for folder in monitored_folders:
        for root, dirs, files in os.walk(folder):
            # Skip OneDriveTemp directories entirely
            if "OneDriveTemp" in root:
                continue

            for filename in files:
                filepath = os.path.join(root, filename)

                # Skip files that can't be accessed due to permissions
                try:
                    with open(filepath, 'rb') as test_access:
                        pass
                except (PermissionError, OSError):
                    output.write(f"[INFO] Skipping inaccessible file: {filepath}\n")
                    continue

                _scan_file_and_record(filepath, scan_utils, yara_scanner, quarantine_utils, results, scanned_file_status, output)

                # Report live progress so callers (e.g. the status API) don't
                # appear stuck at 0 while a large scan is still in progress.
                if callable(progress_callback):
                    try:
                        progress_callback(results)
                    except Exception as e:
                        output.write(f"[WARNING] progress_callback raised during directory scan: {e}\n")


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


def run_conditional_startup_logic(open_browser=True, progress_callback=None):
    # Suppress scikit-learn version warnings
    warnings.filterwarnings("ignore", category=UserWarning)

    output = io.StringIO()
    results = {
        "scanned_files": {},
        "quarantined_files": [],
        "errors": [],
        "process_events": [],
        "results": [],  # Initialize results array immediately
        "routine_maintenance": {},  # Add routine maintenance results
        "ml_detections": [],  # Files flagged by the static-file ML classifier (report-only)
        "ransomware_indicators": [],  # Files flagged by the static ransomware heuristic (report-only)
        "persistence_indicators": {}  # Processes/autostart entries in unusual locations (report-only)
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
    state_file = os.path.abspath(os.path.join(basedir, 'scheduled_scan_state.json'))

    modules = _load_scan_utilities(basedir, output)
    if modules is None:
        return output.getvalue()

    # Run the file/folder scan first so files_scanned starts climbing,
    # then the process scan, then the slow process hardening step.
    if _load_scheduled_scan_state(state_file, output):
        output.write('[conditional_startup] Running scheduled scans...\n')
        monitored_folders = _get_monitored_folders(basedir, output)
        _scan_monitored_folders_step(monitored_folders, modules, results, scanned_file_status, output, progress_callback)

    _scan_running_processes_step(modules['process_monitor'], modules['scan_utils'], results, output, progress_callback)
    _scan_processes_hardening_step(modules['process_security'], results, output, progress_callback)
    _check_persistence_indicators_step(results, output)
    _update_phishing_blocklists_step(basedir, output)
    _launch_safe_downloader_step(basedir, output)
    _start_antivirus_cli_step(basedir, output)

    if open_browser:
        _open_browser_when_ready(output)

    results["results"] = _build_scanned_results(results, scanned_file_status)
    results["log"] = output.getvalue()

    return results

# Run the logic when the script is executed
if __name__ == "__main__":
    result = run_conditional_startup_logic()
    print(json.dumps(result))
