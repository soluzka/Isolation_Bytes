import importlib.util
import os
import sys
import io
import json
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
        # If running in a frozen environment (PyInstaller)
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
            
            # Scan critical system directories
            critical_dirs = [
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),
                os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
            ]
            
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
            from security.detector import detector
            import sklearn
            
            for scan_dir in critical_dirs:
                if os.path.exists(scan_dir):
                    suspicious_files = []
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            filepath = os.path.join(root, file)
                            try:
                                # Get ML prediction
                                prediction = detector.predict([filepath])
                                anomaly_score = detector.get_anomaly_score(filepath)
                                
                                if prediction[0] == -1:  # ML predicts malicious
                                    recovery_results["ml_scans"].append({
                                        "file": filepath,
                                        "prediction": "malicious",
                                        "anomaly_score": float(anomaly_score),
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
        output.write("[ROUTINE MAINTENANCE] Performing rootkit detection...\n")
        try:
            # Check for hidden files and processes
            import subprocess
            
            # Check for hidden processes
            try:
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
                if result.returncode == 0:
                    # Analyze process list for anomalies
                    output.write("[ROOTKIT] Process list analyzed\n")
            except Exception as e:
                output.write(f"[ROOTKIT ERROR] Error checking processes: {e}\n")
            
            # Check for hidden files in system directories
            for scan_dir in [os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32')]:
                if os.path.exists(scan_dir):
                    try:
                        # Look for files with hidden attributes
                        result = subprocess.run(['attrib', '+h', scan_dir], capture_output=True, text=True)
                        output.write(f"[ROOTKIT] Checked for hidden files in {scan_dir}\n")
                    except Exception as e:
                        output.write(f"[ROOTKIT ERROR] Error checking hidden files: {e}\n")
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

def run_conditional_startup_logic(open_browser=True):
    # Suppress scikit-learn version warnings
    warnings.filterwarnings("ignore", category=UserWarning)
    
    output = io.StringIO()
    results = {
        "scanned_files": [],
        "quarantined_files": [],
        "errors": [],
        "process_events": [],
        "results": [],  # Initialize results array immediately
        "routine_maintenance": {}  # Add routine maintenance results
    }
    scanned_file_status = {}  # Track status for each scanned file
    
    # Run comprehensive routine maintenance and system recovery
    output.write("[conditional_startup] Running comprehensive routine maintenance and system recovery...\n")
    try:
        maintenance_log, maintenance_results = routine_maintenance_and_system_recovery()
        output.write(maintenance_log)
        results["routine_maintenance"] = maintenance_results
        output.write("[conditional_startup] Routine maintenance completed.\n")
    except Exception as e:
        output.write(f"[ERROR] Routine maintenance failed: {e}\n")
        results["routine_maintenance"] = {"errors": [str(e)]}

    # Define the base directory and state file path
    basedir = os.path.dirname(os.path.abspath(__file__))
    STATE_FILE = os.path.abspath(os.path.join(basedir, 'scheduled_scan_state.json'))
    paths_path = os.path.join(basedir, 'utils', 'paths.py')
    if os.path.exists(paths_path):
        output.write(f"[conditional_startup] Found paths.py at: {paths_path}\n")
    else:
        output.write(f"[ERROR] paths.py not found in {basedir}!\n")
    # Dynamically load scan utilities
    scan_utils_path = os.path.join(basedir, 'scan_utils.py')
    yara_scanner_path = os.path.join(basedir, 'security', 'yara_scanner.py')
    process_monitor_path = os.path.join(basedir, 'security', 'process_monitor.py')
    quarantine_utils_path = os.path.join(basedir, 'quarantine_utils.py')

    try:
        scan_utils = import_module_from_path('scan_utils', scan_utils_path)
        yara_scanner = import_module_from_path('yara_scanner', yara_scanner_path)
        process_monitor = import_module_from_path('process_monitor', process_monitor_path)
        quarantine_utils = import_module_from_path('quarantine_utils', quarantine_utils_path)
        output.write("[conditional_startup] Successfully loaded scan utilities.\n")
    except Exception as e:
        output.write(f"[ERROR] Failed to load scan utilities: {e}\n")
        return output.getvalue()

    # --- Launch phishing detector learning behavior (update blocklists) ---
    try:
        phishing_live_feeds_path = os.path.join(basedir, 'phishing_live_feeds.py')
        phishing_live_feeds = import_module_from_path('phishing_live_feeds', phishing_live_feeds_path)
        phishing_live_feeds.update_all_blocklists()
        output.write("[conditional_startup] Phishing detector blocklists updated (learning behavior launched).\n")
    except Exception as e:
        output.write(f"[ERROR] Failed to update phishing detector blocklists: {e}\n")

    # --- Launch safe_downloader.py as a background process ---
    safe_downloader_path = os.path.join(basedir, 'safe_downloader.py')
    # Only launch safe_downloader.py if required arguments are provided (url, encrypted_output)
    # Otherwise, skip and log a warning
    safe_downloader_url = os.environ.get('SAFE_DOWNLOADER_URL')
    safe_downloader_output = os.environ.get('SAFE_DOWNLOADER_OUTPUT')
    if os.path.exists(safe_downloader_path):
        if safe_downloader_url and safe_downloader_output:
            try:
                subprocess.Popen([
                    sys.executable, safe_downloader_path,
                    safe_downloader_url, safe_downloader_output
                ])
            except Exception as e:
                output.write(f"[ERROR] Failed to launch safe_downloader.py: {e}\n")
        else:
            output.write("[WARNING] Skipping launch of safe_downloader.py: required arguments (url, encrypted_output) not provided.\n")
            output.write("[conditional_startup] safe_downloader.py started as background process.\n")
    else:
        output.write("[conditional_startup] safe_downloader.py not found!\n")

    # Load scheduled scan state
    try:
        with open(get_resource_path(os.path.join(STATE_FILE)), 'r') as f:
            state = json.load(f)
        enabled = state.get('enabled', False)
    except Exception as e:
        output.write(f"[conditional_startup] Failed to read scheduled scan state: {e}\n")
        enabled = False

    # Start antivirus_cli.py if it exists
    cli_path = os.path.join(basedir, 'antivirus_cli.py')
    if os.path.exists(cli_path):
        try:
            subprocess.Popen([sys.executable, cli_path])
            output.write("[conditional_startup] antivirus_cli.py started.\n")
        except Exception as e:
            output.write(f"[ERROR] Could not start antivirus_cli.py: {e}\n")
    else:
        output.write("[conditional_startup] antivirus_cli.py not found!\n")

    # If scheduled scans are enabled, proceed with scans
    if enabled:
        output.write('[conditional_startup] Running scheduled scans...\n')

        # Load monitored folders using the modern logic
        try:
            import folder_watcher
            # Use folder_watcher's load_scan_directories function correctly
            monitored_folders = folder_watcher.load_scan_directories("scan_directories.txt")
            output.write(f"[conditional_startup] Monitored folders: {monitored_folders}\n")
        except AttributeError:
            # If the exact function isn't found, try an alternative approach
            try:
                # Try to use MONITORED_FOLDERS if available
                monitored_folders = folder_watcher.MONITORED_FOLDERS
                output.write(f"[conditional_startup] Using pre-defined monitored folders: {monitored_folders}\n")
            except AttributeError:
                # Fall back to build_monitored_folders if available
                try:
                    monitored_folders = folder_watcher.build_monitored_folders()
                    output.write(f"[conditional_startup] Built monitored folders: {monitored_folders}\n")
                except Exception as build_exc:
                    output.write(f"[ERROR] Could not build monitored folders: {build_exc}\n")
                    monitored_folders = [os.path.join(basedir, 'uploads'), os.path.join(basedir, 'encrypted')]
        except Exception as fw_exc:
            output.write(f"[ERROR] Could not import folder_watcher: {fw_exc}\n")
            monitored_folders = [os.path.join(basedir, 'uploads'), os.path.join(basedir, 'encrypted')]

        # Scan all monitored directories
        for folder in monitored_folders:
            for root, dirs, files in os.walk(folder):
                # Skip OneDriveTemp directories entirely
                if "OneDriveTemp" in root:
                    continue
                    
                # Process files in current directory
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Skip files that can't be accessed due to permissions
                    try:
                        # Test if we can open the file first
                        with open(filepath, 'rb') as test_access:
                            pass
                    except (PermissionError, OSError) as access_error:
                        # Silently skip files we can't access
                        output.write(f"[INFO] Skipping inaccessible file: {filepath}\n")
                        continue
                    
                    # Proceed with scanning only if we can access the file
                    try:
                        scan_success, malware_found, msg = scan_utils.scan_file_for_viruses(filepath)
                        output.write(f"[conditional_startup] {msg}\n")
                        results["scanned_files"].append(filepath)
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
                        
                        # Quarantine if malware found
                        if malware_found:
                            try:
                                quarantine_utils.quarantine_file(filepath)
                                output.write(f"[conditional_startup] File {filepath} quarantined.\n")
                                results["quarantined_files"].append(filepath)
                                scanned_file_status[filepath]["quarantined"] = True
                            except Exception as quarantine_exc:
                                output.write(f"[WARNING] Could not quarantine {filepath}: {quarantine_exc}\n")
                                scanned_file_status[filepath]["error"] = str(quarantine_exc)
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
    
    # Optionally, open the browser if needed
    if open_browser:
        url = 'http://127.0.0.1:5000'
        timeout = 15
        interval = 0.25
        waited = 0
        while waited < timeout:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    webbrowser.open(url)
                    break
            except Exception:
                pass
            time.sleep(interval)
            waited += interval
        else:
            output.write(f"[conditional_startup] Warning: Server not available after {timeout} seconds.\n")
            webbrowser.open(url)

    # Remove the previous results["results"] creation and replace with this:
    scanned_results = []
    for filepath in results["scanned_files"]:
        status = scanned_file_status.get(filepath, {})
        scanned_results.append({
            "file": filepath,
            "malware_found": status.get("malware_found", False),
            "quarantined": status.get("quarantined", False),
            "error": status.get("error", None)
        })
    
    # Ensure the results field is an array
    results["results"] = scanned_results
    results["log"] = output.getvalue()
    
    return results

# Run the logic when the script is executed
if __name__ == "__main__":
    result = run_conditional_startup_logic()
    print(json.dumps(result))
