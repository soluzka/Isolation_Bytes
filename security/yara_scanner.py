import yara as yara_module
import os
import logging
import sys
import time
from yara import Error as YaraError

def get_basedir():
    """Get the base directory of the project."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    security_dir = os.path.dirname(current_dir)
    base_dir = os.path.dirname(security_dir)
    return base_dir

def load_yara_rules():
    """Load YARA rules from the rules directory structure or create basic rules if none exist."""
    # Create a fallback rule to ensure we have at least one rule available
    fallback_rule = None
    try:
        fallback_rule = yara_module.compile(source='''
        rule SuspiciousFile {
            meta:
                description = "Basic detection for potentially suspicious files"
            strings:
                $s1 = "CreateRemoteThread" nocase
                $s2 = "VirtualAllocEx" nocase
                $s3 = "mimikatz" nocase
                $s4 = "password" nocase
                $s5 = "hack" nocase
                $s6 = "inject" nocase
            condition:
                2 of them
        }
        
        rule AntiDebugCheck {
            meta:
                description = "Detect anti-debugging code"
            strings:
                $a1 = "IsDebuggerPresent" nocase
                $a2 = "CheckRemoteDebuggerPresent" nocase
                $a3 = "OutputDebugString" nocase
            condition:
                any of them
        }
        
        rule AntiVMCheck {
            meta:
                description = "Detect anti-VM code"
            strings:
                $vm1 = "vmware" nocase
                $vm2 = "virtualbox" nocase
                $vm3 = "qemu" nocase
            condition:
                any of them
        }
        ''')
        logging.info("Created in-memory fallback YARA rules")
    except YaraError as e:
        logging.error(f"Failed to create fallback YARA rule: {e}")
    
    # Find the YARA rules directory
    security_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(security_dir, 'yara_rules')
    
    # Check if rules directory exists
    if not os.path.exists(rules_dir):
        logging.warning(f"No YARA rules directory found at: {rules_dir}")
        if fallback_rule:
            return [fallback_rule]
        return []
    
    # First try to load from normal rule files
    try:
        # Compile all rules we can find
        compiled_rules = []
        if fallback_rule:
            compiled_rules.append(fallback_rule)
            
        # Get all rule files
        rule_files = []
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    rule_files.append(os.path.join(root, file))
        
        logging.info(f"Found {len(rule_files)} YARA rule files in {rules_dir}")
        
        # Track which rules were problematic for better debugging
        skipped_rules = []
        failed_rules = []
        successful_rules = []
        
        # Compile each rule file individually
        for rule_path in rule_files:
            file_name = os.path.basename(rule_path)
            try:
                # Skip known problematic rules
                if 'generic_anomalies.yar' in file_name or 'CVE-2010-0805.yar' in file_name:
                    logging.info(f"Skipping known problematic rule file: {file_name}")
                    skipped_rules.append(file_name)
                    continue
                    
                # Skip yara_rules.yar since it has syntax errors (but keep fallback rules)
                if file_name == 'yara_rules.yar':
                    logging.info(f"Skipping problematic main rule file: {file_name} - using embedded fallback rules instead")
                    skipped_rules.append(file_name)
                    continue
                    
                # Try to compile the rule with more detailed error handling
                try:
                    # First attempt with includes (which might reference other files)
                    rule = yara_module.compile(filepath=rule_path, includes=True, error_on_warning=False)
                    compiled_rules.append(rule)
                    successful_rules.append(file_name)
                    logging.info(f"Successfully loaded YARA rule: {file_name}")
                except YaraError as include_error:
                    # If includes fail, try again without them as a fallback
                    logging.warning(f"Failed to load YARA rule with includes, trying without: {file_name}. Error: {include_error}")
                    try:
                        rule = yara_module.compile(filepath=rule_path, includes=False, error_on_warning=False)
                        compiled_rules.append(rule)
                        successful_rules.append(file_name)
                        logging.info(f"Successfully loaded YARA rule (without includes): {file_name}")
                    except YaraError as error:
                        # Both attempts failed
                        raise error
            except YaraError as e:
                logging.error(f"Failed to load YARA rule '{file_name}': {e}")
                failed_rules.append(file_name)
                continue
            except Exception as e:
                logging.error(f"Unexpected error loading rule '{file_name}': {e}")
                failed_rules.append(file_name)
                continue
        
        # Summary logging for better visibility
        logging.info(f"YARA rules summary: {len(successful_rules)} loaded, {len(skipped_rules)} skipped, {len(failed_rules)} failed")
        
        if not compiled_rules and fallback_rule:
            logging.warning("No rules could be compiled, using fallback rule only")
            return [fallback_rule]
            
        return compiled_rules
    
    # Create our own basic rule as a fallback if all rules fail
    except Exception as e:
        logging.error(f"Error loading YARA rules from directory: {e}")
        if fallback_rule:
            return [fallback_rule]
        return []

    # If normal loading failed, try the index file
    try:
        index_path = os.path.join(rules_dir, 'yara_rules_index.yar')
        if os.path.exists(index_path):
            try:
                # Load rules from index file
                rules = yara_module.compile(filepath=index_path, includes=True)
                logging.info(f"Loaded YARA rules from index file: {index_path}")
                return [rules]
            except YaraError as ye:
                logging.error(f"Error loading YARA rules from index: {str(ye)}")
            
        # If index fails or doesn't exist, try to load individual rules again with different options
        rules = []
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')) and file != 'yara_rules_index.yar':
                    rule_path = os.path.join(root, file)
                    try:
                        # Skip known problematic rules
                        if 'generic_anomalies.yar' in file or 'CVE-2010-0805.yar' in file:
                            logging.info(f"Skipping known problematic rule file: {file}")
                            continue
                            
                        rule = yara_module.compile(filepath=rule_path, includes=True)
                        rules.append(rule)
                        logging.info(f"Loaded YARA rules from {rule_path}")
                    except YaraError as ye:
                        logging.error(f"Error loading YARA rules from {rule_path}: {str(ye)}")
                        continue
        
        if rules:
            return rules
    except Exception as e:
        logging.error(f"Error in fallback YARA rule loading: {str(e)}")
        
    # If all else fails, return the fallback rule or empty list
    logging.warning("No valid YARA rules could be loaded")
    if fallback_rule:
        logging.info("Using fallback rule due to error loading regular rules")
        return [fallback_rule]
    return []

def scan_file_with_yara(filepath, timeout=10):
    """
    Scan a file using all available YARA rules. 
    Returns a list of match objects if suspicious, or an empty list if not suspicious.
    Each match object has attributes like: rule, namespace, tags, meta, strings
    
    Args:
        filepath (str): Path to the file to scan
        timeout (int): Maximum time in seconds to wait for a YARA scan to complete
    """
    # Skip files that don't exist
    if not os.path.isfile(filepath):
        logging.warning(f"File does not exist: {filepath}")
        return []
    
    # Skip files that are extremely large (now increased to 500MB)
    try:
        file_size = os.path.getsize(filepath)
        if file_size > 500 * 1024 * 1024:  # 500MB
            # Silently skip files that are too large without logging warnings
            logging.debug(f"Skipping large file (>500MB): {filepath} ({file_size/1024/1024:.2f}MB)")
            return []
        elif file_size > 100 * 1024 * 1024:  # Special handling for large files (100MB - 500MB)
            # Just log at debug level instead of info to reduce noise
            logging.debug(f"Large file being scanned (performance may be impacted): {filepath} ({file_size/1024/1024:.2f}MB)")
            # We could implement special handling for large files if needed
    except Exception as e:
        logging.error(f"Error checking file size: {str(e)}")
    
    # Load the YARA rules
    try:
        rules = load_yara_rules()
        if not rules:
            logging.warning(f"No YARA rules available to scan {filepath}")
            return []
        
        logging.info(f"Scanning file with {len(rules)} YARA rule sets: {filepath}")
        
        # Track scanning metrics
        scan_start = time.time()
        all_matches = []
        timeouts = 0
        errors = 0
        
        # Apply each rule with a timeout
        for rule_index, rule in enumerate(rules):
            try:
                # Apply the rule with timeout
                matches = rule.match(filepath, timeout=timeout)
                
                # Process any matches found
                if matches:
                    all_matches.extend(matches)
                    rule_names = [getattr(m, 'rule', f'Rule-{rule_index}') for m in matches]
                    logging.warning(f"YARA match in {filepath}: {', '.join(rule_names)}")
            except YaraError as ye:
                if 'timeout' in str(ye).lower():
                    timeouts += 1
                    logging.warning(f"YARA timeout scanning {filepath} (rule {rule_index})")
                else:
                    errors += 1
                    logging.error(f"YARA error scanning {filepath}: {str(ye)}")
                continue
            except Exception as e:
                errors += 1
                logging.error(f"Error applying YARA rule to {filepath}: {str(e)}")
                continue
        
        # Log scan summary
        scan_time = time.time() - scan_start
        if all_matches:
            logging.warning(f"Found {len(all_matches)} YARA matches in {filepath} (scan time: {scan_time:.2f}s)")
        else:
            logging.info(f"No YARA matches in {filepath} (scan time: {scan_time:.2f}s, timeouts: {timeouts}, errors: {errors})")
            
        return all_matches
        
    except Exception as e:
        logging.error(f"Unexpected error in YARA scan of {filepath}: {str(e)}")
        return []

def scan_all_folders_with_yara(monitored_folders, rules_path=None):
    """
    YARA-based scanning utilities for security module.
    
    Phishing detection is available via scan_utils.scan_all_folders_for_phishing(monitored_folders),
    which will scan and quarantine files with phishing indicators.
    
    Scan all files in all monitored folders (recursively) with YARA.
    Returns a dictionary with scan statistics and a list of results (matches and errors).
    """
    import os
    
    # Define high-risk file extensions similar to network monitor
    high_risk_extensions = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta', 
        '.scr', '.pif', '.reg', '.com', '.msi', '.jar', '.jnlp', '.vbe', 
        '.wsh', '.sys', '.inf'
    ]
    
    results = []
    scan_stats = {
        'total_directories': len(monitored_folders),
        'total_files_scanned': 0,
        'total_high_risk_files': 0,
        'total_subdirectories': 0,
        'total_matches': 0,
        'total_errors': 0,
        'directories': []
    }
    
    for folder in monitored_folders:
        folder_stats = {
            'path': folder,
            'exists': os.path.exists(folder),
            'accessible': os.path.exists(folder) and os.access(folder, os.R_OK),
            'file_count': 0,
            'high_risk_files': 0,
            'subdirectory_count': 0,
            'matches': 0,
            'errors': 0,
            'subdirectories': []  # List to store subdirectories
        }
        
        if not folder_stats['accessible']:
            scan_stats['directories'].append(folder_stats)
            continue
            
        for root, dirs, files in os.walk(folder):
            # Add subdirectory paths and count
            if root != folder:
                folder_stats['subdirectory_count'] += 1
                scan_stats['total_subdirectories'] += 1
                # Add this subdirectory to our list (with a limit check)
                if len(folder_stats['subdirectories']) < 100:
                    folder_stats['subdirectories'].append(root)
            else:
                # Count immediate subdirectories for folder stats
                folder_stats['subdirectory_count'] += len(dirs)
                scan_stats['total_subdirectories'] += len(dirs)
                
                # Add immediate subdirectories to our list (with a limit check)
                for subdir in dirs:
                    if len(folder_stats['subdirectories']) < 100:
                        subdir_path = os.path.join(folder, subdir)
                        folder_stats['subdirectories'].append(subdir_path)
                
            for filename in files:
                filepath = os.path.join(root, filename)
                folder_stats['file_count'] += 1
                scan_stats['total_files_scanned'] += 1
                
                # Check if high-risk file
                _, ext = os.path.splitext(filename)
                if ext.lower() in high_risk_extensions:
                    folder_stats['high_risk_files'] += 1
                    scan_stats['total_high_risk_files'] += 1
                
                try:
                    # Scan the file with YARA
                    matches = scan_file_with_yara(filepath)
                    if matches:
                        folder_stats['matches'] += len(matches)
                        scan_stats['total_matches'] += len(matches)
                        for match in matches:
                            rule_name = getattr(match, 'rule', 'Unknown rule')
                            results.append(f"YARA match ({rule_name}): {filepath}")
                except Exception as e:
                    folder_stats['errors'] += 1
                    scan_stats['total_errors'] += 1
                    results.append(f"Error scanning {filepath}: {e}")
        
        scan_stats['directories'].append(folder_stats)
    
    return {
        'results': results,
        'stats': scan_stats
    }

if __name__ == '__main__':
    import sys
    import logging
    
    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Test loading rules
    rules = load_yara_rules()
    print(f"Loaded {len(rules) if rules else 0} YARA rule sets")
    
    # If a directory is provided, scan it
    if len(sys.argv) > 1:
        directory = sys.argv[1]
        if not os.path.exists(directory):
            print(f"Directory not found: {directory}")
            sys.exit(1)
            
        print(f"Scanning directory: {directory}")
        results = scan_all_folders_with_yara(monitored_folders=[directory])
        if results:
            print("\nScan Results:")
            for result in results:
                print(result)
        else:
            print("No suspicious files found.")
    else:
        # Use default monitored folders if no directory provided
        try:
            # Try to import from folder watcher
            from folder_watcher import MONITORED_FOLDERS
            if MONITORED_FOLDERS:
                print("\n====================================")
                print(f"SCANNING MONITORED FOLDERS:")
                for folder in MONITORED_FOLDERS:
                    print(f"  - {folder}")
                print("====================================")
                
                results = scan_all_folders_with_yara(monitored_folders=MONITORED_FOLDERS)
                
                print("\n====================================")
                print(f"SCAN COMPLETED - {len(results)} MATCHES FOUND")
                print("====================================")
                
                if results:
                    print("\nSCAN RESULTS:")
                    for i, result in enumerate(results, 1):
                        print(f"{i}. {result}")
                else:
                    print("No suspicious files found in monitored folders.")
            else:
                print("No monitored folders defined")
        except ImportError:
            # Fall back to common folders if folder_watcher not available
            default_folders = []
            # Add user Downloads folder
            downloads = os.path.join(os.path.expanduser('~'), 'Downloads')
            if os.path.exists(downloads):
                default_folders.append(downloads)
            # Add user Desktop folder
            desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
            if os.path.exists(desktop):
                default_folders.append(desktop)
                
            if default_folders:
                print("\n====================================")
                print(f"SCANNING DEFAULT FOLDERS:")
                for folder in default_folders:
                    print(f"  - {folder}")
                print("====================================")
                
                results = scan_all_folders_with_yara(monitored_folders=default_folders)
                
                print("\n====================================")
                print(f"SCAN COMPLETED - {len(results)} MATCHES FOUND")
                print("====================================")
                
                if results:
                    print("\nSCAN RESULTS:")
                    for i, result in enumerate(results, 1):
                        print(f"{i}. {result}")
                else:
                    print("No suspicious files found in default folders.")
            else:
                print("No default folders found to scan")
                print("Usage: python yara_scanner.py <directory>")
                print("Specify a directory to scan")
