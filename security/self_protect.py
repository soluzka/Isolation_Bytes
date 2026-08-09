from utils.paths import get_resource_path
import os

import os
import sys
import time
import subprocess

def watchdog_restart(target_cmd):
    """
    Restart the antivirus process if it is killed (basic watchdog).
    """
    # --- Windows subprocess window suppression ---
    import sys
    if sys.platform == 'win32':
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
    else:
        DETACHED_PROCESS = 0
        CREATE_NO_WINDOW = 0
    while True:
        proc = subprocess.Popen([get_resource_path(os.path.join(target_cmd))], creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosem; nosec B603
        proc.wait()
        time.sleep(1)  # Short delay before restart