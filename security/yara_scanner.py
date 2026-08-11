import yara as yara_module
import os
import logging
import sys
import time
import functools
from yara import Error as YaraError

def get_basedir():
    """Get the base directory of the project."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    security_dir = os.path.dirname(current_dir)
    base_dir = os.path.dirname(security_dir)
    return base_dir

# Default values for YARA external variables used by some rules (e.g.
# generic_anomalies.yar's filename/extension/filetype based conditions).
# Real per-file values are supplied at match time in scan_file_with_yara().
_YARA_EXTERNALS_DEFAULTS = {
    'extension': '',
    'filename': '',
    'filepath': '',
    'filetype': '',
}

# Minimum YARA match severity to log. Defaults to 'medium' to reduce noise.
# Can be overridden with the YARA_LOG_MIN_SEVERITY environment variable.
YARA_LOG_MIN_SEVERITY = os.environ.get('YARA_LOG_MIN_SEVERITY', 'medium').lower().strip()

# Hard-coded list of noisy/broad YARA rules that are known to false-positive
# on normal system files and common legitimate software.
NOISY_RULE_NAMES = {
    # Broad synthetic rules in the main yara_rules.yar / index files
    'AdvancedCodeReuseAttack', 'CustomShellcodePatterns',
    'AntiDebugCheck', 'AntiVMCheck',
    'Suspicious_PE_API_Imports', 'PE_Suspicious_Imports',
    'Suspicious_Network_Connections', 'PDF_Exploit_Indicators',
    'Dropper_Indicators', 'CryptoSignature', 'SuspiciousExecutable_Strict',
    # Third-party rules observed false-positiving on normal Windows files
    'Suspicious_Registry_Persistence', 'Generic_Ransomware_Indicators',
    'China_Chopper_Webshell', 'AsyncRAT',
    'cobalt_strike_tmp01925d3f', 'FormBook_Stealer_Strict',
    'SideChannelAttackTools', 'UseAfterFreePattern',
    'StackPivotDetection', 'ReturnOrientedProgramming',
    'Office_Macro_Malware', 'Ransomware_Indicators',
    'ProtocolManipulation', 'PoetRat_Python',
}

# Rule-name keywords that indicate a known malware family or definitive malware
# class.  If one of these matches a rule whose metadata severity is "high", the
# severity is promoted to "critical" so it is treated as an automatic quarantine
# candidate (unless it is also in NOISY_RULE_NAMES).
DEFINITIVE_MALWARE_KEYWORDS = (
    'malware', 'ransomware', 'trojan', 'stealer', 'backdoor', 'miner',
    'rat', 'apt', 'webshell', 'phishing', 'rootkit', 'botnet', 'cobalt',
    'emotet', 'trickbot', 'trickbot', 'dridex', 'zeus', 'qakbot', 'darkside',
    'gandcrab', 'lockbit', 'maze', 'netwalker', 'revil', 'ryuk', 'wannacry',
    'xmrig', 'agenttesla', 'redline', 'remcos', 'njrat', 'asyncrat', 'plugx',
    'fin7', 'turla', 'carbanak', 'cobaltkitty',
    # Additional families, tools, and common C2 frameworks
    'lokibot', 'azorult', 'smokeloader', 'icedid', 'bokbot', 'vjw0rm',
    'nanocore', 'netwire', 'formbook', 'luminositylink', 'revenge',
    'cryptowall', 'petya', 'notpetya', 'blackcat', 'alphv',
    'sliver', 'metasploit', 'mimikatz', 'bloodhound', 'cobaltstrike',
)

def _classify_filetype(filepath):
    '''Best-effort filetype string for YARA external variables.

    Tries to identify the file by magic bytes first, then falls back to the
    file extension. Returns an empty string if the type cannot be determined.
    '''
    ext = os.path.splitext(filepath)[1].lower()
    ext_type_map = {
        '.vbs': 'VBS', '.wsf': 'VBS',
        '.php': 'PHP',
        '.jsp': 'JSP',
        '.py': 'Python', '.pyc': 'Python',
        '.asp': 'ASP', '.aspx': 'ASP',
        '.bat': 'BATCH', '.cmd': 'BATCH',
        '.rtf': 'RTF',
        '.mdmp': 'MDMP',
        '.ps1': 'PowerShell', '.psm1': 'PowerShell', '.psd1': 'PowerShell',
        '.sh': 'Shell', '.bash': 'Shell',
        '.pl': 'Perl', '.pm': 'Perl',
        '.rb': 'Ruby',
        '.lua': 'Lua',
        '.ts': 'TypeScript',
        '.html': 'HTML', '.htm': 'HTML',
        '.xml': 'XML',
        '.json': 'JSON',
        '.csv': 'CSV',
        '.md': 'Markdown',
        '.eml': 'Email', '.msg': 'Email',
        '.doc': 'Office', '.docx': 'Office', '.xls': 'Office', '.xlsx': 'Office',
        '.ppt': 'Office', '.pptx': 'Office', '.odt': 'Office', '.ods': 'Office', '.odp': 'Office',
        '.zip': 'ZIP', '.jar': 'ZIP', '.war': 'ZIP', '.ear': 'ZIP',
        '.rar': 'RAR',
        '.7z': '7Z',
        '.gz': 'GZIP', '.tgz': 'GZIP',
        '.tar': 'TAR',
        '.jpg': 'JPEG', '.jpeg': 'JPEG',
        '.png': 'PNG',
        '.gif': 'GIF',
        '.bmp': 'BMP',
        '.tiff': 'TIFF', '.tif': 'TIFF',
        '.webp': 'WEBP',
        '.db': 'SQLite', '.sqlite': 'SQLite', '.sqlite3': 'SQLite',
        '.class': 'JavaClass',
        '.lnk': 'LNK',
        # High-risk Windows executable and script extensions
        '.exe': 'EXE', '.dll': 'EXE', '.com': 'EXE', '.scr': 'EXE', '.pif': 'EXE', '.sys': 'EXE',
        '.vbe': 'VBS', '.wsh': 'WScript',
        '.hta': 'HTA',
        '.js': 'JS',
        '.reg': 'Registry',
        '.msi': 'MSI',
        '.jnlp': 'JavaWebStart',
        '.inf': 'INF',
    }
    if ext in ext_type_map:
        return ext_type_map[ext]

    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
    except (OSError, IOError):
        return ''

    if not header:
        return ''

    # PE / Windows executable
    if header[:2] == b'MZ':
        return 'EXE'
    # ELF
    if header[:4] == b'\x7fELF':
        return 'ELF'
    # Mach-O (little- and big-endian, 32- and 64-bit) and fat binaries
    if header[:4] in (b'\xcf\xfa\xed\xfe', b'\xcf\xfa\xed\xff',
                      b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xff',
                      b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        return 'MACH-O'
    # Java class
    if header[:4] == b'\xca\xfe\xba\xbe':
        return 'JavaClass'
    # PDF
    if header[:4] == b'%PDF':
        return 'PDF'
    # JPEG
    if header[:3] == b'\xff\xd8\xff':
        return 'JPEG'
    # PNG
    if header[:4] == b'\x89PNG':
        return 'PNG'
    # GIF
    if header[:4] == b'GIF8':
        return 'GIF'
    # BMP
    if header[:2] == b'BM':
        return 'BMP'
    # WEBP
    if len(header) >= 12 and header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'WEBP'
    # ZIP / OOXML / JAR
    if header[:2] == b'PK':
        return 'ZIP'
    # RAR
    if header[:4] == b'Rar!':
        return 'RAR'
    # 7Z
    if header[:2] == b'7z':
        return '7Z'
    # GZIP
    if header[:2] == b'\x1f\x8b':
        return 'GZIP'
    # SQLite
    if header[:16] == b'SQLite format 3\x00':
        return 'SQLite'
    # OLE2 / old Office
    if header[:4] == b'\xd0\xcf\x11\xe0':
        return 'Office'

    return ''

@functools.lru_cache(maxsize=None)
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
        
        # Compile each rule file individually, using the source filename as the
        # rule namespace so matches can be grouped by rule family later.
        for rule_path in rule_files:
            file_name = os.path.basename(rule_path)
            try:
                # NOTE: generic_anomalies.yar, CVE-2010-0805.yar, and yara_rules.yar
                # used to be unconditionally skipped here as "known problematic".
                # generic_anomalies.yar was missing `import "pe"`/`import "math"`
                # and used an invalid pe.entropy field; yara_rules.yar had a rule
                # with a missing header (orphaned strings:/condition: block) and
                # a triplicated rule name; CVE-2010-0805.yar compiled fine on its
                # own and had no evident reason to be excluded. All three are
                # fixed now (see the .yar files themselves), so they go through
                # the normal compile-with-fallback path below like everything else.

                # Try to compile the rule with more detailed error handling
                try:
                    # First attempt with includes (which might reference other files).
                    # externals declares variables some rules (e.g. generic_anomalies.yar's
                    # extension/filename/filepath/filetype conditions) reference but that
                    # aren't YARA builtins -- the real per-file values are supplied at match
                    # time in scan_file_with_yara(); these defaults just let them compile.
                    rule = yara_module.compile(filepaths={file_name: rule_path}, includes=True,
                                                error_on_warning=False, externals=_YARA_EXTERNALS_DEFAULTS)
                    compiled_rules.append(rule)
                    successful_rules.append(file_name)
                    logging.info(f"Successfully loaded YARA rule: {file_name}")
                except YaraError as include_error:
                    # If includes fail, try again without them as a fallback
                    logging.warning(f"Failed to load YARA rule with includes, trying without: {file_name}. Error: {include_error}")
                    try:
                        rule = yara_module.compile(filepaths={file_name: rule_path}, includes=False,
                                                    error_on_warning=False, externals=_YARA_EXTERNALS_DEFAULTS)
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
    file_size = 0
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
    
    ext = os.path.splitext(filepath)[1].lower()
    if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.wav', '.flac', '.m4a', '.wma', '.aac', '.ogg', '.ico'}:
        return []

    # Skip log, event, and crash files that are not useful for YARA malware matching
    if ext in {'.log', '.evtx', '.evt', '.etl', '.dmp', '.mdmp', '.wer', '.cab'}:
        logging.debug(f"Skipping non-malware log/crash file: {filepath}")
        return []

    # Skip common Windows log/crash directories (Panther, Logs, Minidump, etc.)
    lower_path = filepath.lower()
    if any(skip in lower_path for skip in {'\\logs\\', '\\panther\\', '\\minidump', '\\crashdumps', '\\diagtrack'}):
        logging.debug(f"Skipping log/crash directory file: {filepath}")
        return []

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
        
        # Build per-file external variables for rules that depend on them
        externals = {
            'extension': ext,
            'filename': os.path.basename(filepath),
            'filepath': filepath,
            'filetype': _classify_filetype(filepath),
        }
        
        # Load small files into memory so libyara doesn't have to re-open the
        # path itself, which can trigger spurious "Failed to open" messages on
        # locked/protected or oddly-handled files. Keep using the file path for
        # anything > 100 MB to avoid excessive memory use.
        data = None
        use_data = file_size <= 100 * 1024 * 1024

        # Apply each rule with a timeout
        for rule_index, rule in enumerate(rules):
            try:
                # Apply the rule with timeout and per-file externals
                if use_data:
                    if data is None:
                        with open(filepath, 'rb') as fh:
                            data = fh.read()
                    matches = rule.match(data=data, timeout=timeout, externals=externals, fast=True)
                else:
                    matches = rule.match(filepath, timeout=timeout, externals=externals, fast=True)
                
                # Process any matches found
                if matches:
                    # Hard-coded suppression of known noisy/broad rules.
                    matches = [m for m in matches if getattr(m, 'rule', '') not in NOISY_RULE_NAMES]
                    if not matches:
                        continue
                    all_matches.extend(matches)
                    rule_names = [getattr(m, 'rule', f'Rule-{rule_index}') for m in matches]
                    # Only log this rule if its highest severity meets the configured threshold.
                    rule_highest = get_highest_severity(matches)
                    if _rank_of(rule_highest) >= _rank_of(YARA_LOG_MIN_SEVERITY):
                        logging.warning(f"{rule_highest.upper() if rule_highest else 'YARA'} match in {filepath}: {', '.join(rule_names)}")
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
        
        # Log scan summary, but only if any match reaches the configured threshold.
        scan_time = time.time() - scan_start
        if all_matches:
            highest = get_highest_severity(all_matches)
            if _rank_of(highest) >= _rank_of(YARA_LOG_MIN_SEVERITY):
                logging.warning(f"Found {len(all_matches)} YARA matches in {filepath} (highest: {highest}, scan time: {scan_time:.2f}s)")
            else:
                logging.debug(f"Found {len(all_matches)} low-severity YARA matches in {filepath} (scan time: {scan_time:.2f}s)")
        else:
            logging.info(f"No YARA matches in {filepath} (scan time: {scan_time:.2f}s, timeouts: {timeouts}, errors: {errors})")
            
        return all_matches
        
    except Exception as e:
        logging.error(f"Unexpected error in YARA scan of {filepath}: {str(e)}")
        return []


def _normalize_severity(value):
    """Normalize a YARA metadata severity value to a lower-case string."""
    if value is None:
        return ''
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='ignore')
    return str(value).strip().lower()


def get_match_severity(match):
    """Return the severity string from a yara.Match object's metadata, or empty.

    High-severity matches are promoted to critical when the rule name matches a
    known malware family, so definitive malware triggers automatic quarantine.
    """
    meta = getattr(match, 'meta', {}) or {}
    rule = getattr(match, 'rule', '')
    normalized_rule = rule.lower()
    for key in ('severity', 'Severity', 'SEVERITY'):
        if key in meta:
            sev = _normalize_severity(meta[key])
            if sev == 'high' and any(kw in normalized_rule for kw in DEFINITIVE_MALWARE_KEYWORDS):
                return 'critical'
            return sev
    # Rules with no explicit severity but a definitive malware-family name are
    # treated as critical so they are not ignored by the dashboard/quarantine logic.
    if any(kw in normalized_rule for kw in DEFINITIVE_MALWARE_KEYWORDS):
        return 'critical'
    return ''


def has_critical_yara_match(matches):
    """Return True if any match in the list has severity == 'critical'."""
    if not matches:
        return False
    for match in matches:
        if get_match_severity(match) == 'critical':
            return True
    return False


# Severity ranking (higher number = more severe)
SEVERITY_RANK = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}


def _rank_of(severity):
    """Return the numeric rank for a severity string."""
    return SEVERITY_RANK.get(severity, 0)


def get_highest_severity(matches):
    """Return the highest severity string among a list of yara matches."""
    if not matches:
        return ''
    highest = ''
    highest_rank = 0
    for match in matches:
        severity = get_match_severity(match)
        rank = _rank_of(severity)
        if rank > highest_rank:
            highest = severity
            highest_rank = rank
    return highest


def _severity_prefix(severity):
    """Return a human-readable prefix for a YARA match severity."""
    if not severity:
        return 'YARA match'
    return f'{severity.upper()} YARA match'


def scan_all_folders_with_yara(monitored_folders, rules_path=None):
    """
    YARA-based scanning utilities for security module.
    
    Phishing detection is available via scan_utils.scan_all_folders_for_phishing(monitored_folders),
    which will scan and quarantine files with phishing indicators.
    
    Scan all files in all monitored folders (recursively) with YARA.
    Returns a dictionary with scan statistics and a list of results (matches and errors).
    """
    import os

    # Try to import quarantine utilities so critical matches can be quarantined
    quarantine_utils = None
    try:
        import quarantine_utils
    except Exception:
        quarantine_utils = None

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
        'total_critical_matches': 0,
        'total_high_matches': 0,
        'total_medium_matches': 0,
        'total_low_matches': 0,
        'total_quarantined': 0,
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
            'critical_matches': 0,
            'high_matches': 0,
            'medium_matches': 0,
            'low_matches': 0,
            'quarantined': 0,
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
                        highest = get_highest_severity(matches)

                        # Track match counts by highest severity for this file
                        if highest == 'critical':
                            folder_stats['critical_matches'] += 1
                            scan_stats['total_critical_matches'] += 1
                        elif highest == 'high':
                            folder_stats['high_matches'] += 1
                            scan_stats['total_high_matches'] += 1
                        elif highest == 'medium':
                            folder_stats['medium_matches'] += 1
                            scan_stats['total_medium_matches'] += 1
                        elif highest == 'low':
                            folder_stats['low_matches'] += 1
                            scan_stats['total_low_matches'] += 1

                        for match in matches:
                            rule_name = getattr(match, 'rule', 'Unknown rule')
                            severity = get_match_severity(match)
                            prefix = _severity_prefix(severity)
                            results.append(f"{prefix} ({rule_name}): {filepath}")

                        # Quarantine only critical matches
                        is_critical = highest == 'critical'
                        fernet_key = os.environ.get('FERNET_KEY')
                        if is_critical and quarantine_utils and fernet_key and len(fernet_key) == 44:
                            try:
                                quarantine_utils.quarantine_file(filepath)
                                folder_stats['quarantined'] += 1
                                scan_stats['total_quarantined'] += 1
                                results.append(f"Quarantined critical file: {filepath}")
                            except Exception as qe:
                                logging.warning(f"Could not quarantine critical file {filepath}: {qe}")
                                results.append(f"Could not quarantine critical file {filepath}: {qe}")
                        elif is_critical:
                            results.append(f"CRITICAL match not quarantined (missing/invalid FERNET_KEY): {filepath}")
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
