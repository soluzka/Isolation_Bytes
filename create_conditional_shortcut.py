import os
import sys

try:
    import win32com.client
except ImportError:
    print("win32com.client is required. Please install pywin32: pip install pywin32")
    sys.exit(1)

# Use python.exe and quick_start.py so the shortcut target type is an Application,
# not a Windows batch file.
python_exe = sys.executable
quick_start_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'quick_start.py'))
if not os.path.exists(quick_start_path):
    print(f"[ERROR] quick_start.py not found: {quick_start_path}")
    sys.exit(1)

# Path to the user's actual desktop (works with OneDrive redirection)
try:
    from win32com.shell import shell, shellcon
    desktop = shell.SHGetFolderPath(0, shellcon.CSIDL_DESKTOP, 0, 0)
except Exception:
    try:
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
    except KeyError:
        print("[ERROR] Could not find the user's Desktop path.")
        sys.exit(1)

shortcut_path = os.path.join(desktop, 'Start Conditional Antivirus.lnk')

try:
    shell = win32com.client.Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(shortcut_path)
    shortcut.Targetpath = python_exe
    shortcut.Arguments = f'"{quick_start_path}"'
    shortcut.WorkingDirectory = os.path.dirname(quick_start_path)
    icon_path = os.path.join(os.path.dirname(quick_start_path), 'static', 'favicon.ico')
    shortcut.IconLocation = f"{icon_path},0" if os.path.exists(icon_path) else python_exe
    shortcut.save()
    print(f"[SUCCESS] Shortcut created: {shortcut_path}")
    print(f"[INFO] Shortcut target: {python_exe}")
    print(f"[INFO] Shortcut arguments: {shortcut.Arguments}")
    print(f"[INFO] Shortcut working dir: {os.path.dirname(quick_start_path)}")
except Exception as e:
    print(f"[ERROR] Failed to create shortcut: {e}")
    sys.exit(1)
