# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\windows_admin_service.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['pywintypes', 'win32api', 'win32file', 'win32pipe', 'winerror', 'win32security', 'win32service', 'win32serviceutil', 'win32timezone', 'servicemanager', 'win32event'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'torchaudio', 'h5py', 'numba', 'IPython', 'ipykernel', 'notebook', 'pytest', 'scikit-learn-main'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AntivirusProtectedAdminWorker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='C:\\Users\\bpier\\AppData\\Local\\Temp\\antivirus_server_build_r1dlzxr5\\AntivirusProtectedAdmin_version.txt',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AntivirusProtectedAdminWorker',
)
