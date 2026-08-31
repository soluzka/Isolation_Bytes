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
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'torchaudio', 'h5py', 'numba',
              'IPython', 'ipykernel', 'notebook', 'pytest', 'scikit-learn-main',
              'nltk', 'transformers', 'accelerate', 'cv2', 'redis', 'onnxruntime',
              'pyssdeep', 'ssdeep', 'yara', 'tlsh', 'lief', 'lightgbm', 'pefile',
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
