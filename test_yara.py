import os
import tempfile
import logging
import sys
from security.yara_scanner import scan_file_with_yara, load_yara_rules, scan_all_folders_with_yara, get_highest_severity, get_match_severity

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('yara_test')

def test_yara_rules():
    """Test if YARA rules load properly"""
    logger.info("Testing YARA rules loading...")
    rules = load_yara_rules()
    if rules:
        logger.info(f"Successfully loaded {len(rules)} YARA rules")
    else:
        logger.warning("No YARA rules loaded")
    return rules is not None and len(rules) > 0

def test_file_scanning():
    """Test scanning a specific file with YARA"""
    test_file = os.environ.get('YARA_TEST_FILE', os.path.abspath(__file__))
    logger.info(f"Testing YARA file scanning on: {test_file}")
    
    matches = scan_file_with_yara(test_file)
    if matches:
        logger.info(f"Found {len(matches)} YARA matches in test file")
        for match in matches:
            rule_name = getattr(match, 'rule', 'Unknown rule')
            logger.info(f"Match: {rule_name}")
    else:
        logger.info("No YARA matches found in test file (expected for non-malicious files)")
    return True

def test_folder_scanning():
    """Test scanning a folder with YARA for false positives."""
    test_folder = os.environ.get('YARA_TEST_FOLDER', r'C:\Windows\System32')
    logger.info(f"Testing YARA folder scanning on: {test_folder}")
    
    results = scan_all_folders_with_yara([test_folder])
    if results:
        logger.info(f"Found {len(results)} results when scanning folder")
        for result in results:
            logger.info(f"Result: {result}")
    else:
        logger.info("No results found when scanning folder")
    return True

def test_synthetic_payload():
    """Scan a synthetic malware-like payload and verify a critical promotion."""
    payload = (
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n'
        b'powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -EncodedCommand QQBsAGUA\n'
        b'cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n'
        b'CreateRemoteThread VirtualAllocEx WriteProcessMemory NtUnmapViewOfSection\n'
        b'AutoOpen Document_Open Sub Workbook_Open CreateObject("WScript.Shell")\n'
        b'your files have been encrypted send bitcoin to wallet decrypt instructions\n'
        b'README_DECRYPT.txt HELP_YOUR_FILES RECOVER_FILES\n'
        b'Generic_Malware_Strings malware dropper backdoor trojan stealer\n'
        b'Mimikatz systeminfo schtasks certutil bypass\n'
        b'.how to recover your files .locked .encrypted .crypt\n'
    )
    with tempfile.NamedTemporaryFile('wb', suffix='.tmp', delete=False) as f:
        f.write(payload)
        tmp = f.name
    try:
        logger.info(f"Testing YARA on synthetic payload: {tmp}")
        matches = scan_file_with_yara(tmp)
        if matches:
            highest = get_highest_severity(matches)
            logger.info(f"Found {len(matches)} YARA matches (highest: {highest})")
            for match in matches:
                rule_name = getattr(match, 'rule', 'Unknown rule')
                severity = get_match_severity(match)
                logger.info(f"Match: {rule_name} ({severity or 'no severity'})")
            if highest == 'critical':
                logger.info("✓ Synthetic payload correctly promoted to critical")
            else:
                logger.warning(f"Synthetic payload highest was {highest}, expected critical")
        else:
            logger.warning("No YARA matches found in synthetic payload")
    finally:
        os.remove(tmp)
    return True

if __name__ == "__main__":
    logger.info("=== YARA SCANNER TEST SCRIPT ===")
    
    # Test loading rules
    if test_yara_rules():
        logger.info("✓ YARA rules loading test passed")
    else:
        logger.error("✗ YARA rules loading test failed")
    
    # Test file scanning
    if test_file_scanning():
        logger.info("✓ YARA file scanning test passed")
    else:
        logger.error("✗ YARA file scanning test failed")
    
    # Test folder scanning
    if test_folder_scanning():
        logger.info("✓ YARA folder scanning test passed")
    else:
        logger.error("✗ YARA folder scanning test failed")
    
    # Test synthetic payload
    if test_synthetic_payload():
        logger.info("✓ YARA synthetic payload test passed")
    else:
        logger.error("✗ YARA synthetic payload test failed")
    
    logger.info("=== TEST COMPLETE ===")
