import os
import yara
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('simple_yara_test')

# Path to YARA rules directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(SCRIPT_DIR, 'security', 'yara_rules')

def compile_rules():
    """Compile YARA rules from the rules directory."""
    logger.info(f"Looking for YARA rules in: {RULES_DIR}")
    
    # Create a fallback rule
    fallback_rule = None
    try:
        fallback_rule = yara.compile(source='''
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
        ''')
        logger.info("Created fallback rule")
    except Exception as e:
        logger.error(f"Failed to create fallback rule: {e}")
        return None
        
    # Check if rules directory exists
    if not os.path.exists(RULES_DIR):
        logger.warning(f"YARA rules directory not found: {RULES_DIR}")
        if fallback_rule:
            return [fallback_rule]
        return None
    
    # Get rule files
    rules = []
    if fallback_rule:
        rules.append(fallback_rule)
        
    # Look for .yar files
    logger.info("Searching for YARA rule files...")
    rule_files = [os.path.join(RULES_DIR, f) for f in os.listdir(RULES_DIR) 
                 if f.endswith(('.yar', '.yara'))]
    
    logger.info(f"Found {len(rule_files)} rule files: {[os.path.basename(f) for f in rule_files]}")
    
    # Compile individual rules
    for rule_file in rule_files:
        # Skip problematic files
        if 'generic_anomalies.yar' in rule_file:
            logger.info(f"Skipping known problematic rule file: {os.path.basename(rule_file)}")
            continue
            
        try:
            logger.info(f"Compiling rule: {os.path.basename(rule_file)}")
            rule = yara.compile(filepath=rule_file, includes=True)
            rules.append(rule)
            logger.info(f"Successfully compiled rule: {os.path.basename(rule_file)}")
        except Exception as e:
            logger.error(f"Failed to compile rule {os.path.basename(rule_file)}: {e}")
    
    logger.info(f"Successfully compiled {len(rules)} rules")
    return rules

def scan_file(filepath, rules, timeout=5):
    """Scan a file with YARA rules."""
    if not rules:
        logger.error("No rules available for scanning")
        return []
        
    if not os.path.isfile(filepath):
        logger.error(f"File does not exist: {filepath}")
        return []
    
    logger.info(f"Scanning file: {filepath}")
    
    all_matches = []
    for rule in rules:
        try:
            matches = rule.match(filepath, timeout=timeout)
            if matches:
                all_matches.extend(matches)
                rule_names = [getattr(m, 'rule', 'Unknown') for m in matches]
                logger.info(f"Found matches: {rule_names}")
        except Exception as e:
            logger.error(f"Error scanning with rule: {e}")
            
    return all_matches

if __name__ == "__main__":
    # Display header
    print("=" * 60)
    print(" SIMPLE YARA SCANNER TEST ")
    print("=" * 60)
    
    # Try to compile rules
    print("\nCompiling YARA Rules:")
    rules = compile_rules()
    
    if not rules:
        print("\n❌ Failed to compile any YARA rules")
        sys.exit(1)
    
    print(f"\n✅ Successfully compiled {len(rules)} YARA rules")
    
    # Scan this script as a test
    test_file = __file__
    print(f"\nScanning test file: {test_file}")
    matches = scan_file(test_file, rules)
    
    if matches:
        print(f"\n⚠️ Found {len(matches)} YARA matches in test file")
        for match in matches:
            print(f"  - {getattr(match, 'rule', 'Unknown rule')}")
    else:
        print("\n✅ No YARA matches found in test file (expected for non-malicious files)")
    
    print("\nTest complete!")
