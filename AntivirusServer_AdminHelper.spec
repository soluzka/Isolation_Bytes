# -*- mode: python ; coding: utf-8 -*-
import os

_BASE = SPECPATH

a = Analysis(
    [os.path.join(_BASE, 'antivirus_admin_helper.py')],
    pathex=[_BASE],
    binaries=[],
    datas=[],
    hiddenimports=['standalone_agent', 'psutil', 'requests', 'urllib3', 'socket', 'platform', 'hashlib', 'threading', 'datetime', 'argparse', 'concurrent.futures', 're', 'plistlib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='AntivirusServer_AdminHelper',
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
    uac_admin=True,
    icon=os.path.join(_BASE, 'static', 'favicon.ico'),
)
