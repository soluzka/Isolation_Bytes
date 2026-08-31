"""Decorated GUI launcher that always opens the secure login first."""
import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk


def _find_login_exe():
    for root in (
        os.environ.get('ProgramW6432'),
        os.environ.get('ProgramFiles'),
        os.environ.get('ProgramFiles(x86)'),
        os.environ.get('ProgramFiles', r'C:\\Program Files'),
        os.environ.get('ProgramFiles(x86)', r'C:\\Program Files (x86)'),
    ):
        if not root:
            continue
        for folder in ('Isolation Bytes', 'Antivirus Server'):
            for name in ('AntivirusServerLogin.exe', 'IsolationBytesLogin.exe'):
                path = os.path.join(root, folder, name)
                if os.path.exists(path):
                    return path
    return os.path.join(os.environ.get('ProgramFiles', r'C:\\Program Files'), 'Isolation Bytes', 'AntivirusServerLogin.exe')


def open_login():
    login = _find_login_exe()
    if not os.path.exists(login):
        tk.messagebox.showerror('Error', 'Isolation Bytes Login not found. Please run the installer.')
        return
    subprocess.Popen([login], creationflags=0x08000000)


def main():
    root = tk.Tk()
    root.title('Isolation Bytes')
    root.geometry('360x200')
    root.resizable(False, False)

    frame = ttk.Frame(root, padding='20')
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    ttk.Label(
        frame,
        text='Isolation Bytes',
        font=('Segoe UI', 16, 'bold'),
    ).grid(row=0, column=0, pady=(0, 10))

    ttk.Label(
        frame,
        text='Click below to open the secure login. The app starts after you log in.',
        wraplength=320,
    ).grid(row=1, column=0, pady=(0, 20))

    ttk.Button(
        frame,
        text='Start Isolation Bytes',
        command=open_login,
    ).grid(row=2, column=0, pady=(0, 10))

    ttk.Button(
        frame,
        text='Cancel',
        command=root.destroy,
    ).grid(row=3, column=0)

    root.mainloop()


if __name__ == '__main__':
    main()
