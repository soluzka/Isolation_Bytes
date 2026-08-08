import subprocess
import psutil
import re
import os
import sys
from secure_message import encrypt_message  # Ensure encrypt_message is imported

# --- Windows subprocess window suppression ---
if sys.platform == 'win32':
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
else:
    DETACHED_PROCESS = 0
    CREATE_NO_WINDOW = 0

# 1. Get all netstat output for 127.0.0.1 connections
netstat_cmd = ["netstat", "-ano"]
output = subprocess.check_output(netstat_cmd, text=True, encoding="utf-8", errors="ignore", creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW)

# 2. Extract PIDs for connections to 127.0.0.1
pid_pattern = re.compile(r"127\.0\.0\.1:\d+\s+.*?\s+(\d+)")
pids = set()
for line in output.splitlines():
    match = pid_pattern.search(line)
    if match:
        pids.add(int(match.group(1)))

# 3. Map PIDs to executable paths
exe_paths = set()
for pid in pids:
    try:
        p = psutil.Process(pid)
        exe = p.exe()
        if exe and os.path.exists(exe):
            exe_paths.add(exe)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        continue

# 4. Scan each unique executable using antivirus_cli.py
for exe in exe_paths:
    # print(f"Scanning {exe}...")  # Removed to reduce spam
    try:
        result = subprocess.run([
            "python", "antivirus_cli.py", "scan", exe
        ], cwd=os.path.dirname(os.path.abspath(__file__)), capture_output=True, text=True, creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # print(result.stdout)  # Removed to reduce spam
        if result.stderr:
            print("STDERR:", result.stderr)  # Removed to reduce spam
    except Exception as e:
        print(f"Error scanning {exe}: {e}")  # Removed to reduce spam

if not exe_paths:
    print("No active executables found for 127.0.0.1 connections.")  # Removed to reduce spam
