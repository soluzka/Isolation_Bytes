"""Decorated GUI launcher for the SFX installer."""
import base64
import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk


def _sfx_path():
    base = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
    candidates = [
        os.path.join(os.path.dirname(base), 'dist', 'Install_AntivirusServer_SFX.exe'),
        os.path.join(base, 'dist', 'Install_AntivirusServer_SFX.exe'),
        os.path.join(os.path.dirname(base), 'Install_AntivirusServer_SFX.exe'),
        os.path.join(base, 'Install_AntivirusServer_SFX.exe'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def _message(msg):
    tk.messagebox.showerror('Error', msg)


def run_sfx():
    sfx = _sfx_path()
    if not sfx:
        _message('SFX installer not found. Please run build_config.py first.')
        return
    try:
        # Run via -EncodedCommand so the file path is not parsed as PowerShell text.
        escaped_sfx = sfx.replace('"', '`"')
        ps_script = f'Start-Process -FilePath "{escaped_sfx}" -Verb RunAs'
        encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
        subprocess.Popen(
            ['powershell', '-EncodedCommand', encoded],
            shell=False,
            creationflags=0x08000000,
        )
        sys.exit(0)
    except Exception as e:
        _message(f'Could not start SFX installer:\n{e}')


def main():
    root = tk.Tk()
    root.title('Antivirus Server Installer')
    root.geometry('400x220')
    root.resizable(False, False)

    frame = ttk.Frame(root, padding='20')
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    ttk.Label(
        frame,
        text='Antivirus Server Installer',
        font=('Segoe UI', 16, 'bold'),
    ).grid(row=0, column=0, pady=(0, 10))

    ttk.Label(
        frame,
        text='This will run the SFX installer as Administrator.',
        wraplength=360,
    ).grid(row=1, column=0, pady=(0, 20))

    ttk.Button(
        frame,
        text='Install Antivirus Server',
        command=run_sfx,
    ).grid(row=2, column=0, pady=(0, 10))

    ttk.Button(
        frame,
        text='Cancel',
        command=root.destroy,
    ).grid(row=3, column=0)

    root.mainloop()


if __name__ == '__main__':
    main()
