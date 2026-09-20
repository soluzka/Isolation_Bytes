# -*- mode: python ; coding: utf-8 -*-
import os

_BASE = SPECPATH

a = Analysis(
    [os.path.join(_BASE, 'dist', 'universal_launcher.py')],
    pathex=[_BASE],
    binaries=[],
    datas=[],
    hiddenimports=['urllib.request', 'json', 'ctypes', 'webbrowser',
                   'standalone_agent', 'psutil', 'requests', 'urllib3',
                   'socket', 'platform', 'hashlib', 'threading', 'datetime',
                   'argparse', 'concurrent.futures', 're', 'plistlib'],
    hookspath=['C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\pyinstaller_hooks'],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pydantic', 'pydantic_core'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='IsolationBytesLauncher',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(_BASE, 'static', 'favicon.ico'),
)
