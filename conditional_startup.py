import importlib.util
import os
import sys
import io
import json
import subprocess
import requests
import time
import webbrowser
import warnings

# Ensure the 'utils' directory is in sys.path
basedir = os.path.dirname(os.path.abspath(__file__))
utils_dir = os.path.join(basedir, 'utils')
if utils_dir not in sys.path:
    sys.path.insert(0, utils_dir)

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

def run_conditional_startup_logic(open_browser=True):
    # Suppress scikit-learn version warnings
    warnings.filterwarnings("ignore", category=UserWarning)
    
    output = io.StringIO()
    results = {
        "scanned_files": [],
        "quarantined_files": [],
        "errors": [],
        "process_events": [],
        "results": []  # Initialize results array immediately
    }
    scanned_file_status = {}  # Track status for each scanned file

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
    
    # Convert to JSON-compatible format
    if __name__ == "__main__":
        return json.dumps(results)
    return results

# Run the logic when the script is executed
if __name__ == "__main__":
    result = run_conditional_startup_logic()
    print(json.dumps(result))
