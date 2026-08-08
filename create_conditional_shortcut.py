import os
import sys

try:
    import win32com.client
except ImportError:
    print("win32com.client is required. Please install pywin32: pip install pywin32")
    sys.exit(1)

# Robustly determine the batch file path (even in temp extraction)
bat_filename = 'start_conditional_antivirus.bat'
bat_path = os.path.abspath(os.path.join(os.path.dirname(__file__), bat_filename))
if not os.path.exists(bat_path):
    print(f"[ERROR] Batch file not found: {bat_path}")
    sys.exit(1)

# Path to the user's desktop
try:
    desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
except KeyError:
    print("[ERROR] Could not find the user's Desktop path.")
    sys.exit(1)

shortcut_path = os.path.join(desktop, 'Start Conditional Antivirus.lnk')

try:
    shell = win32com.client.Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(shortcut_path)
    shortcut.Targetpath = bat_path
    shortcut.WorkingDirectory = os.path.dirname(bat_path)
    shortcut.IconLocation = bat_path
    shortcut.save()
    print(f"[SUCCESS] Shortcut created: {shortcut_path}")
    print(f"[INFO] Shortcut target: {bat_path}")
    print(f"[INFO] Shortcut working dir: {os.path.dirname(bat_path)}")
except Exception as e:
    print(f"[ERROR] Failed to create shortcut: {e}")
    sys.exit(1)
