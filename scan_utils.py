from utils.paths import get_resource_path
import os

import os
import shutil
import logging

POWERSHELL_PATH = shutil.which('powershell') or 'powershell'
import platform
import subprocess
from secure_message import encrypt_message  # Ensure encrypt_message is imported
import requests
from datetime import datetime
import json

# --- Windows subprocess window suppression ---
import sys
if sys.platform == 'win32':
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
else:
    DETACHED_PROCESS = 0
    CREATE_NO_WINDOW = 0
import threading
import time
import sys
from config import USE_CLAMAV, USE_YARA, CUSTOM_SIGNATURE_PATH, OPEN_BLOCKLISTS

# --- YARA full-folder scan utility ---
def scan_all_folders_with_yara(monitored_folders, rules_path=None):
    """
    Scan all files in all monitored folders (recursively) with YARA.
    Returns a list of results (matches and errors).
    """
    from security.yara_scanner import scan_file_with_yara
    import os
    results = []
    for folder in monitored_folders:
        for root, dirs, files in os.walk(folder):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    if scan_file_with_yara(filepath, rules_path):
                        results.append(f"YARA match: {filepath}")
                except Exception as e:
                    results.append(f"Error scanning {filepath}: {e}")
    return results

# --- Phishing full-folder scan utility ---
def scan_all_folders_for_phishing(monitored_folders, quarantine_dir=None):
    """
    Scan all files in all monitored folders (recursively) for phishing indicators.
    Quarantines files with phishing findings. Returns a list of findings.
    """
    from phishing_detector import scan_file_for_phishing
    import os
    import shutil
    results = []
    for folder in monitored_folders:
        for root, dirs, files in os.walk(folder):
            for filename in files:
                filepath = os.path.join(root, filename)
                findings = scan_file_for_phishing(filepath)
                if findings:
                    results.append((filepath, findings))
                    # Quarantine if phishing indicators found
                    if quarantine_dir:
                        os.makedirs(quarantine_dir, exist_ok=True)
                        dest = os.path.join(quarantine_dir, os.path.basename(filepath))
                        try:
                            shutil.move(filepath, dest)
                            results.append((filepath, f"Quarantined to {dest}"))
                        except Exception as e:
                            results.append((filepath, f"Failed to quarantine: {e}"))
    return results

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class VirusScanError(Exception):
    pass


def update_windows_defender_definitions():
    """
    Update Windows Defender virus definitions using PowerShell.
    Returns True if successful, False otherwise.
    """
    if platform.system() != "Windows":
        logging.debug("Windows Defender update skipped: Not a Windows system")
        return False
    
    try:
        # PowerShell command to update Windows Defender definitions
        # Fix: Use capture_output instead of stdout and stderr parameters
        result = subprocess.run(  # nosem; nosec B603
            ["powershell", "-Command", "Update-MpSignature"],
            capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            logging.info("Windows Defender definitions updated successfully")
            return True
        else:
            logging.error(f"Error updating Windows Defender definitions: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logging.error("Timeout while updating Windows Defender definitions")
        return False
    except Exception as e:
        logging.error(f"Error updating Windows Defender definitions: {str(e)}")
        return False

def update_malware_bazaar_signatures():
    """
    Update malware signatures from Malware Bazaar.
    Returns True if successful, False otherwise.
    """
    signatures_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'malware_signatures.txt')
    
    try:
        # Create signatures directory if it doesn't exist
        signatures_dir = os.path.dirname(signatures_file)
        os.makedirs(signatures_dir, exist_ok=True)
        
        # Create signatures file if it doesn't exist
        if not os.path.exists(signatures_file):
            with open(get_resource_path(os.path.join(signatures_file)), 'w', encoding='utf-8') as f:
                f.write('# Malware signatures from Malware Bazaar - Updated: {}\n'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                f.write('# Format: signature_name:hash_type:hash_value\n\n')
        
        # Malware Bazaar API endpoint for recent samples
        url = "https://mb-api.abuse.ch/api/v1/"
        
        # Request parameters
        data = {
            'query': 'get_recent',
            'selector': '100'  # Get 100 most recent samples
        }
        
        # Make the API request
        response = requests.post(url, data=data, timeout=60)
        
        if response.status_code == 200:
            try:
                result = response.json()
                
                if result.get('query_status') == 'ok':
                    # Backup existing file
                    if os.path.exists(signatures_file):
                        backup_file = signatures_file + '.bak'
                        if os.path.exists(backup_file):
                            os.remove(backup_file)
                        os.rename(signatures_file, backup_file)
                    
# Read existing signatures first
                    existing_signatures = set()
                    if os.path.exists(signatures_file):
                        with open(get_resource_path(os.path.join(signatures_file)), 'r', encoding='utf-8') as f:
                            for line in f:
                                if line.strip() and not line.startswith('#'):
                                    existing_signatures.add(line.strip())
                    
                    # Write combined signatures
                    with open(get_resource_path(os.path.join(signatures_file)), 'w', encoding='utf-8') as f:
                        f.write('# Malware signatures from Malware Bazaar - Updated: {}\n'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                        f.write('# Format: signature_name:hash_type:hash_value\n\n')
                        
                        # Write existing signatures first
                        for sig in sorted(existing_signatures):
                            f.write(f"{sig}\n")
                        
                        # Process and write new signatures
                        for sample in result.get('data', []):
                            if sample.get('sha256_hash') and sample.get('md5_hash'):
                                malware_name = sample.get('signature', 'unknown')
                                if malware_name:
                                    malware_name = malware_name.replace(':', '_')
                                else:
                                    malware_name = 'unknown'
                                # Add SHA256, SHA1 and MD5 hashes
                                sha256_sig = f"{malware_name}:sha256:{sample['sha256_hash']}"
                                sha1_sig = f"{malware_name}:sha1:{sample.get('sha1_hash', '')}"
                                md5_sig = f"{malware_name}:md5:{sample['md5_hash']}"
                                if sha256_sig not in existing_signatures:
                                    f.write(f"{sha256_sig}\n")
                                if sha1_sig not in existing_signatures and sample.get('sha1_hash'):
                                    f.write(f"{sha1_sig}\n")
                                if md5_sig not in existing_signatures:
                                    f.write(f"{md5_sig}\n")
                    return True
                else:
                    logging.error(f"Malware Bazaar API error: {result.get('query_status')}")
            except json.JSONDecodeError:
                logging.error("Failed to parse Malware Bazaar API response")
        else:
            logging.error(f"Malware Bazaar API request failed with status code: {response.status_code}")
        
        # If we reach here, something went wrong with the API request
        # Check if we have a backup file and restore it
        backup_file = signatures_file + '.bak'
        if os.path.exists(backup_file) and not os.path.exists(signatures_file):
            os.rename(backup_file, signatures_file)
            logging.info("Restored backup signatures file")
        
        # Add some basic signatures if the file is empty or doesn't exist
        if not os.path.exists(signatures_file) or os.path.getsize(signatures_file) == 0:
            with open(get_resource_path(os.path.join(signatures_file)), 'w', encoding='utf-8') as f:
                f.write('# Malware signatures (fallback) - Updated: {}\n'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                f.write('# Format: signature_name:hash_type:hash_value\n\n')
                f.write('eicar_test_file:md5:44d88612fea8a8f36de82e1278abb02f\n')
                f.write('eicar_test_file:sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n')
            logging.info("Created fallback signatures file")
        
        return False
    except Exception as e:
        logging.error(f"Error updating Malware Bazaar signatures: {str(e)}")
        return False

def update_yara_rules():
    """
    Update YARA rules from various sources.
    Returns True if successful, False otherwise.
    """
    yara_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security', 'yara_rules')
    
    try:
        # Create YARA rules directory if it doesn't exist
        os.makedirs(yara_dir, exist_ok=True)
        
        # List of YARA rule repositories to download
        yara_sources = [
            {
                'name': 'YARA-Rules',
                'url': 'https://raw.githubusercontent.com/Yara-Rules/rules/master/index.yar',
                'filename': 'yara_rules_index.yar'
            },
            {
                'name': 'Neo23x0 Signature-Base',
                'url': 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar',
                'filename': 'generic_anomalies.yar'
            }
        ]
        
        success = False
        
        for source in yara_sources:
            try:
                response = requests.get(source['url'], timeout=30)
                
                if response.status_code == 200:
                    rule_file = os.path.join(yara_dir, source['filename'])
                    
                    # Backup existing file
                    if os.path.exists(rule_file):
                        backup_file = rule_file + '.bak'
                        if os.path.exists(backup_file):
                            os.remove(backup_file)
                        os.rename(rule_file, backup_file)
                    
                    # Write new rules
                    with open(get_resource_path(os.path.join(rule_file)), 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    
                    logging.info(f"YARA rules updated successfully from {source['name']}")
                    success = True
                else:
                    logging.error(f"Failed to download YARA rules from {source['name']}: HTTP {response.status_code}")
            except Exception as e:
                logging.error(f"Error downloading YARA rules from {source['name']}: {str(e)}")
        
        # Create a basic YARA rule if no rules were downloaded
        if not success:
            basic_rule_file = os.path.join(yara_dir, 'basic_rules.yar')
            if not os.path.exists(basic_rule_file):
                with open(get_resource_path(os.path.join(basic_rule_file)), 'w', encoding='utf-8') as f:
                    f.write('''
rule EICAR_Test_File {
    meta:
        description = "This is a rule to detect the EICAR test file"
        author = "Fallback Rule Generator"
        reference = "http://www.eicar.org/86-0-Intended-use.html"
        date = "2023-01-01"
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        $eicar
}

rule Suspicious_PowerShell_Command {
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Fallback Rule Generator"
    strings:
        $s1 = "Invoke-Expression" nocase
        $s2 = "IEX" nocase
        $s3 = "Net.WebClient" nocase
        $s4 = "DownloadString" nocase
        $s5 = "hidden" nocase
        $s6 = "encodedcommand" nocase
        $s7 = "bypass" nocase
    condition:
        3 of them
}
''')
                logging.info("Created fallback YARA rules")
                success = True
        
        return success
    except Exception as e:
        logging.error(f"Error updating YARA rules: {str(e)}")
        return False

def update_virus_definitions():
    """
    Update all virus definitions from various sources.
    """
    logging.info("Updating virus definitions...")
    
    # Track success of each update
    windows_defender_success = update_windows_defender_definitions()
    malware_bazaar_success = update_malware_bazaar_signatures()
    yara_rules_success = update_yara_rules()
    
    # Log overall result
    if windows_defender_success and malware_bazaar_success and yara_rules_success:
        logging.info("All virus definitions updated successfully")
    else:
        if not windows_defender_success:
            logging.warning("Windows Defender definitions update failed")
        if not malware_bazaar_success:
            logging.warning("Malware Bazaar signatures update failed")
        if not yara_rules_success:
            logging.warning("YARA rules update failed")
    
    return windows_defender_success or malware_bazaar_success or yara_rules_success

def start_periodic_definition_updates(interval_hours=6):
    """
    Start a background thread to update virus definitions periodically.
    """
    import threading
    
    def update_thread():
        while True:
            try:
                update_virus_definitions()
            except Exception as e:
                logging.error(f"Error in periodic virus definition update: {str(e)}")
            
            # Sleep for the specified interval
            time.sleep(interval_hours * 3600)
    
    # Start the update thread
    thread = threading.Thread(target=update_thread, daemon=True)
    thread.start()
    logging.info(f"Started periodic virus definition updates (every {interval_hours} hours)")

def start_periodic_folder_scans(interval_hours=6):
    """
    Periodically scan all monitored folders for threats
    """
    def scanner():
        while True:
            try:
                from folder_watcher import build_monitored_folders
                from security.yara_scanner import scan_all_folders_with_yara
                
                monitored_folders = build_monitored_folders()
                logging.info(f"Starting periodic scan of monitored folders: {monitored_folders}")
                
                # Scan with YARA rules
                results = scan_all_folders_with_yara(monitored_folders)
                if results:
                    logging.warning(f"Periodic scan found potential threats: {results}")
                
                # Add additional scanning methods as needed
                # e.g., scan for phishing, malware signatures, etc.
                
                logging.info("Periodic scan completed")
            except Exception as e:
                logging.error(f"Error during periodic scan: {e}")
            
            time.sleep(interval_hours * 3600)
    
    t = threading.Thread(target=scanner, daemon=True)
    t.start()

def is_antivirus_available():
    system = platform.system()
    if system == 'Windows':
        # Check if Windows Defender is available
        try:
            result = subprocess.run(  # nosem; nosec B603
                [
                    POWERSHELL_PATH,
                    '-Command',
                    'Get-MpComputerStatus'
                ],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    else:
        try:
            import clamd
            try:
                cd = clamd.ClamdUnixSocket()
            except Exception:
                cd = clamd.ClamdNetworkSocket()
            cd.ping()
            return True
        except Exception:
            return False


def load_malware_signatures():
    """
    Load malware signatures from the signatures file.
    Returns a dictionary of {hash_type: {hash_value: signature_name}}
    """
    signatures = {'md5': {}, 'sha1': {}, 'sha256': {}, 'sha512': {}}
    signatures_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'malware_signatures.txt')
    
    if not os.path.exists(signatures_file):
        logging.warning(f"Malware signatures file not found: {signatures_file}")
        return signatures
    
    try:
        with open(get_resource_path(os.path.join(signatures_file)), 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        signature_name, hash_type, hash_value = parts[0], parts[1].lower(), parts[2].lower()
                        if hash_type in signatures:
                            # Ensure hash_value is a string before adding
                            if not isinstance(hash_value, str):
                                logging.error(f"Invalid hash value type: {type(hash_value)}")
                                continue
                            signatures[hash_type][hash_value] = signature_name
    except Exception as e:
        logging.error(f"Error loading malware signatures: {str(e)}")
        # Return empty signatures if there's an error
        return {'md5': {}, 'sha1': {}, 'sha256': {}, 'sha512': {}}
    
    # Validate the signatures dictionary structure
    if not isinstance(signatures, dict):
        logging.error("Signatures is not a dictionary")
        return {'md5': {}, 'sha1': {}, 'sha256': {}, 'sha512': {}}
    
    for hash_type, hash_dict in signatures.items():
        if not isinstance(hash_dict, dict):
            logging.error(f"Hash type {hash_type} has invalid type: {type(hash_dict)}")
            signatures[hash_type] = {}
        
    return signatures

def calculate_file_hashes(filepath):
    """
    Calculate MD5, SHA1, SHA256 and SHA512 hashes for a file in a single pass.
    Returns a tuple of (md5_hash, sha1_hash, sha256_hash, sha512_hash)
    """
    import hashlib
    
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    
    try:
        with open(get_resource_path(os.path.join(filepath)), 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
        
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), sha512.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating file hashes for {filepath}: {str(e)}")
        raise

def scan_file_for_viruses(filepath):
    """
    Scans a file for viruses using all available definitions.
    Always loads the latest signatures from the signatures file.
    Returns (scan_success, malware_found, message)
    """
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return False, False, f"File not found: {filepath}"
    
    try:
        # Load the latest signatures
        signatures = load_malware_signatures()
        
        # Calculate file hashes in one pass
        md5_hash, sha1_hash, sha256_hash, sha512_hash = calculate_file_hashes(filepath)
        
        # Check against all available signature databases
        for hash_type, hash_value in [('md5', md5_hash), ('sha1', sha1_hash),
                                       ('sha256', sha256_hash), ('sha512', sha512_hash)]:
            if hash_value in signatures[hash_type]:
                signature_name = signatures[hash_type][hash_value]
                return True, True, f"Malware detected: {signature_name} ({hash_type.upper()} match)"
        
        # If we reach here, no malware was found in our signatures
        # Optional: query VirusTotal for the SHA256 hash
        try:
            from security.virus_total import is_malicious
            if is_malicious(filepath):
                from security.virus_total import add_signatures
                add_signatures(filepath)
                return True, True, "Malware detected by VirusTotal lookup"
        except Exception:
            pass
        return True, False, "No malware found in signature database"
    
    except Exception as e:
        logging.error(f"Error scanning file {filepath}: {str(e)}")
        return False, False, f"Scan error: {str(e)}"