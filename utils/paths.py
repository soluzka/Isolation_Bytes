import os
import sys
import logging

def get_resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        # Onedir build: resources live next to the executable, or inside _internal.
        onedir = os.path.dirname(sys.executable)
        candidates = [
            onedir,
            os.path.join(onedir, '_internal'),
            getattr(sys, '_MEIPASS', None),
        ]
    else:
        # Standalone development: project root is two levels above this file.
        candidates = [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
    candidates = [c for c in candidates if c]
    for base_path in candidates:
        full_path = os.path.join(base_path, relative_path)
        if os.path.exists(full_path):
            return full_path
    return os.path.join(candidates[0], relative_path)

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
