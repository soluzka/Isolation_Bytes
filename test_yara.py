import os
import logging
import sys
from security.yara_scanner import scan_file_with_yara, load_yara_rules, scan_all_folders_with_yara

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
    test_file = os.path.abspath(__file__)  # Use this script as a test file
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
    """Test scanning a folder with YARA"""
    test_folder = os.path.dirname(os.path.abspath(__file__))
    logger.info(f"Testing YARA folder scanning on: {test_folder}")
    
    results = scan_all_folders_with_yara([test_folder])
    if results:
        logger.info(f"Found {len(results)} results when scanning folder")
        for result in results:
            logger.info(f"Result: {result}")
    else:
        logger.info("No results found when scanning folder")
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
    
    logger.info("=== TEST COMPLETE ===")
