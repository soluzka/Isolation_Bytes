import os
import sys
import logging

def get_resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        # Onedir build: resources live next to the executable.
        base_path = os.path.dirname(sys.executable)
    else:
        # Standalone development: project root is two levels above this file.
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

# Verify malware_signatures.json file
malware_signatures_path = get_resource_path('malware_signatures.json')
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
