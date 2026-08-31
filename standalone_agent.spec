# -*- mode: python ; coding: utf-8 -*-
import os

_BASE = SPECPATH

# Collect the security package and YARA rules as datas
_security_datas = []
_security_dir = os.path.join(_BASE, 'security')
if os.path.isdir(_security_dir):
    for root, dirs, files in os.walk(_security_dir):
        for f in files:
            src = os.path.join(root, f)
            rel = os.path.relpath(root, _BASE)
            _security_datas.append((src, rel))

a = Analysis(
    [os.path.join(_BASE, 'standalone_agent.py')],
    pathex=[_BASE],
    binaries=[],
    datas=_security_datas + [
        # Include folder_watcher and scan_directories config
        (os.path.join(_BASE, 'folder_watcher.py'), '.'),
        (os.path.join(_BASE, 'scan_directories.txt'), '.'),
        (os.path.join(_BASE, 'scan_utils.py'), '.'),
        (os.path.join(_BASE, 'quarantine_utils.py'), '.'),
        (os.path.join(_BASE, 'config.py'), '.'),
        (os.path.join(_BASE, 'utils'), 'utils'),
        # Compiled YARA rules at repo root
        (os.path.join(_BASE, 'compiled_rules.yarc'), '.'),
    ],
    hiddenimports=['psutil', 'requests', 'urllib3', 'socket', 'platform',
                   'hashlib', 'json', 'threading', 'subprocess', 'ctypes',
                   'concurrent.futures', 're', 'argparse', 'plistlib',
                   'yara', 'cryptography.fernet'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'torchaudio', 'h5py', 'numba',
              'IPython', 'ipykernel', 'notebook', 'pytest',
              'nltk', 'transformers', 'accelerate', 'cv2', 'redis', 'onnxruntime',
              'pyssdeep', 'ssdeep', 'tlsh', 'lief', 'lightgbm', 'pefile',
              'pandas', 'matplotlib', 'seaborn', 'scipy', 'sklearn', 'numpy'],
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
    name='IsolationBytesAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window — runs silently
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(_BASE, 'static', 'favicon.ico'),
)
