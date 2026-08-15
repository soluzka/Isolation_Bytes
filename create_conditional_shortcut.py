import os
import sys
import struct

try:
    import win32com.client
except ImportError:
    print("win32com.client is required. Please install pywin32: pip install pywin32")
    sys.exit(1)


def _set_shortcut_runas(path):
    """Set the SLDF_RUNAS_USER (0x2000) flag on a .lnk file."""
    try:
        with open(path, 'r+b') as f:
            header = struct.unpack('<I', f.read(4))[0]
            if header != 0x4C:
                return
            f.seek(0x14)
            flags = struct.unpack('<I', f.read(4))[0]
            flags |= 0x2000
            f.seek(0x14)
            f.write(struct.pack('<I', flags))
    except Exception:
        pass

# Prefer the compiled EXE so the shortcuts work without a Python install.
# Fall back to python.exe + quick_start.py if the EXE has not been built yet.
is_frozen = getattr(sys, 'frozen', False)
base_dir = os.path.dirname(sys.executable) if is_frozen else os.path.dirname(__file__)
exe_candidates = [
    os.path.abspath(os.path.join(base_dir, 'antivirus_server.exe')),
    os.path.abspath(os.path.join(base_dir, 'dist', 'antivirus_server', 'antivirus_server.exe')),
    os.path.abspath(os.path.join(base_dir, 'dist', 'antivirus_server.exe')),
]
exe_path = next((p for p in exe_candidates if os.path.exists(p)), None)
quick_start_path = os.path.abspath(os.path.join(base_dir, 'quick_start.py'))

if exe_path:
    target = exe_path
    arguments = ''
    icon = exe_path
elif os.path.exists(quick_start_path):
    target = sys.executable
    arguments = f'"{quick_start_path}"'
    icon = os.path.join(os.path.dirname(quick_start_path), 'static', 'favicon.ico')
else:
    print("[ERROR] No executable or quick_start.py found.")
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
    shortcut = shell.CreateShortcut(shortcut_path)
    shortcut.TargetPath = target
    shortcut.Arguments = arguments
    shortcut.WorkingDirectory = os.path.dirname(quick_start_path)
    icon_path = icon if os.path.exists(icon) else target
    shortcut.IconLocation = f"{icon_path},0"
    shortcut.Save()
    _set_shortcut_runas(shortcut_path)
    print(f"[SUCCESS] Shortcut created: {shortcut_path}")
    print(f"[INFO] Shortcut target: {target}")
    print(f"[INFO] Shortcut arguments: {arguments}")
    print(f"[INFO] Shortcut working dir: {os.path.dirname(quick_start_path)}")
except Exception as e:
    import traceback
    traceback.print_exc()
    sys.exit(1)
