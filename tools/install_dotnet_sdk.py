"""Decorated .NET 8 SDK installer/launcher with a GUI."""
import os
import sys
import base64
import tempfile
import zipfile
import shutil
import subprocess
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox


_SDK_ELEVATION_FLAG = '--sdk-elevation-attempted'
_DOTNET_DIR = r'C:\Program Files\dotnet'
_DOTNET_EXE = os.path.join(_DOTNET_DIR, 'dotnet.exe')


def _is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _ensure_admin():
    if sys.platform != 'win32' or _SDK_ELEVATION_FLAG in sys.argv:
        return True
    if _is_admin():
        return True
    try:
        import ctypes
        params = [a for a in sys.argv[1:] if a != _SDK_ELEVATION_FLAG]
        params.append(_SDK_ELEVATION_FLAG)
        command_line = subprocess.list2cmdline(params)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', sys.executable, command_line, None, 1
        )
        return result > 32
    except Exception as e:
        messagebox.showerror('Error', f'Could not request Administrator privileges: {e}')
        return False


def _has_dotnet_sdk(dotnet):
    try:
        result = subprocess.run(
            [dotnet, '--list-sdks'],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def _run_powershell(cmd, description):
    try:
        encoded = base64.b64encode(cmd.encode('utf-16le')).decode('ascii')
        subprocess.check_call(
            ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
            shell=False,
        )
    except Exception as e:
        raise RuntimeError(f'{description} failed: {e}')


def _find_sdk_zip():
    """Look for a bundled .NET SDK zip file."""
    search_dirs = []
    if len(sys.argv) > 1:
        search_dirs.append(os.path.dirname(sys.argv[1]))
        if os.path.isfile(sys.argv[1]) and sys.argv[1].endswith('.zip'):
            if _is_valid_zip(sys.argv[1]):
                return sys.argv[1]
    if getattr(sys, 'frozen', False):
        search_dirs.append(os.path.dirname(sys.executable))
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            search_dirs.append(meipass)
            search_dirs.append(os.path.dirname(meipass))
    search_dirs.append(os.getcwd())
    for directory in search_dirs:
        if not directory or not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            if name.startswith('dotnet-sdk-') and name.endswith('-win-x64.zip'):
                candidate = os.path.join(directory, name)
                if _is_valid_zip(candidate):
                    return candidate
    return None


def _is_valid_zip(path):
    """Check if a file is a valid zip archive."""
    if not path or not os.path.isfile(path):
        return False
    try:
        import zipfile as _zf
        with _zf.ZipFile(path, 'r') as z:
            # Try reading the first entry to confirm it's not truncated
            if z.namelist():
                z.read(z.namelist()[0])
        return True
    except Exception:
        return False


def _download_sdk_zip():
    """Download the .NET SDK installer zip to a temporary file."""
    target = os.path.join(tempfile.gettempdir(), 'dotnet-sdk-8.0.424-win-x64.zip')
    # Delete any existing corrupted/partial download
    if os.path.exists(target):
        if _is_valid_zip(target):
            return target
        try:
            os.remove(target)
        except Exception:
            pass
    print('Downloading .NET 8 SDK...')
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            import urllib.request
            urllib.request.urlretrieve(
                'https://dotnetcli.azureedge.net/dotnet/Sdk/8.0.424/dotnet-sdk-8.0.424-win-x64.zip',
                target
            )
            if _is_valid_zip(target):
                return target
            # Download produced an invalid zip — delete and retry
            try:
                os.remove(target)
            except Exception:
                pass
            print(f'Download attempt {attempt} produced an invalid file, retrying...')
        except Exception as e:
            if attempt == max_retries:
                raise RuntimeError(f'Failed to download .NET SDK after {max_retries} attempts: {e}')
            print(f'Download attempt {attempt} failed: {e}, retrying...')
    raise RuntimeError('Failed to download a valid .NET SDK zip')


def _extract_sdk(zip_path, progress, status, root):
    try:
        status.set('Extracting .NET 8 SDK...')
        os.makedirs(_DOTNET_DIR, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as archive:
            total = len(archive.namelist())
            for i, member in enumerate(archive.namelist(), 1):
                archive.extract(member, _DOTNET_DIR)
                if i % 20 == 0:
                    progress['value'] = (i / total) * 100
                    root.update_idletasks()
        progress['value'] = 100
        root.update_idletasks()

        status.set('Updating PATH...')
        _run_powershell(
            "$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine'); "
            "if ($machinePath -notlike '*C:\\Program Files\\dotnet*') { "
            "    [Environment]::SetEnvironmentVariable('Path', \"$machinePath;C:\\Program Files\\dotnet\", 'Machine') "
            "}",
            'Updating PATH'
        )

        if _has_dotnet_sdk(_DOTNET_EXE):
            status.set('Done! .NET 8 SDK installed.')
            messagebox.showinfo('Done', '.NET 8 SDK installed successfully.')
        else:
            status.set('Done, but SDK was not detected.')
            messagebox.showwarning('Warning', 'Files extracted, but dotnet SDK was not detected.')
    except Exception as e:
        status.set(f'Error: {e}')
        messagebox.showerror('Error', str(e))


def _start_install(progress, status, root, button):
    button.config(state='disabled')
    zip_path = _find_sdk_zip()
    if not zip_path:
        try:
            zip_path = _download_sdk_zip()
        except Exception as e:
            status.set(f'Error: {e}')
            messagebox.showerror('Error', str(e))
            button.config(state='normal')
            return
    if _has_dotnet_sdk(_DOTNET_EXE):
        status.set('.NET SDK already installed.')
        progress['value'] = 100
        messagebox.showinfo('Done', '.NET SDK is already installed.')
        return
    thread = threading.Thread(
        target=_extract_sdk,
        args=(zip_path, progress, status, root),
        daemon=True,
    )
    thread.start()


def main():
    if not _ensure_admin():
        sys.exit(1)
    if _SDK_ELEVATION_FLAG in sys.argv:
        sys.argv.remove(_SDK_ELEVATION_FLAG)

    root = tk.Tk()
    root.title('Install .NET 8 SDK')
    root.geometry('420x180')
    root.resizable(False, False)

    frame = ttk.Frame(root, padding='20')
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    title = ttk.Label(
        frame,
        text='.NET 8 SDK Setup',
        font=('Segoe UI', 14, 'bold'),
    )
    title.grid(row=0, column=0, pady=(0, 10))

    status = tk.StringVar()
    status.set('Ready to install the .NET 8 SDK.')
    status_label = ttk.Label(frame, textvariable=status, wraplength=360)
    status_label.grid(row=1, column=0, pady=(0, 10))

    progress = ttk.Progressbar(frame, length=360, mode='determinate')
    progress.grid(row=2, column=0, pady=(0, 15))
    progress['value'] = 0

    button = ttk.Button(
        frame,
        text='Install .NET 8 SDK',
        command=lambda: _start_install(progress, status, root, button),
    )
    button.grid(row=3, column=0)

    # Auto-install if a bundled zip was supplied.
    zip_path = _find_sdk_zip()
    if zip_path and not _has_dotnet_sdk(_DOTNET_EXE):
        root.after(200, lambda: _start_install(progress, status, root, button))

    root.mainloop()


if __name__ == '__main__':
    main()
