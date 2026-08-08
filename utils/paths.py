import os
import sys
import logging

def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Verify malware_signatures.txt file
malware_signatures_path = get_resource_path('malware_signatures.txt')
if os.path.exists(malware_signatures_path):
    logging.info(f'Malware signatures file found: {malware_signatures_path}')
else:
    logging.warning(f'Malware signatures file not found: {malware_signatures_path}')

# Verify scheduled_scan_state.json file
scheduled_scan_state_path = get_resource_path('scheduled_scan_state.json')
if os.path.exists(scheduled_scan_state_path):
    logging.info(f'Scheduled scan state file found: {scheduled_scan_state_path}')
else:
    logging.warning(f'Scheduled scan state file not found: {scheduled_scan_state_path}')
