# -*- mode: python ; coding: utf-8 -*-
import os

_BASE = SPECPATH

a = Analysis(
    [os.path.join(_BASE, 'windows_admin_service.py')],
    pathex=[_BASE],
    binaries=[],
    datas=[],
    hiddenimports=['pywintypes', 'win32api', 'win32file', 'win32pipe', 'winerror', 'win32security', 'win32service', 'win32serviceutil', 'win32timezone', 'servicemanager', 'win32event',
                   'standalone_agent', 'psutil', 'requests', 'urllib3', 'socket', 'platform', 'hashlib', 'threading', 'datetime', 'argparse', 'concurrent.futures', 're', 'plistlib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'torchaudio', 'h5py', 'numba', 'IPython', 'ipykernel', 'notebook', 'pytest', 'scikit-learn-main', 'nltk', 'transformers', 'accelerate', 'cv2', 'redis', 'onnxruntime', 'pyssdeep', 'ssdeep', 'yara', 'tlsh', 'lief', 'lightgbm', 'pefile', 'pandas', 'matplotlib', 'seaborn', 'scipy', 'sklearn'],
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
    version=None,
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
