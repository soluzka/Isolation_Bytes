# -*- mode: python ; coding: utf-8 -*-
import os

_BASE = SPECPATH

_security_datas = []
_security_dir = os.path.join(_BASE, 'security')
if os.path.isdir(_security_dir):
    for root, dirs, files in os.walk(_security_dir):
        for f in files:
            src = os.path.join(root, f)
            rel = os.path.relpath(root, _BASE)
            _security_datas.append((src, rel))

a = Analysis(
    [os.path.join(_BASE, 'standalone_agent_unlimited.py')],
    pathex=[_BASE],
    binaries=[],
    datas=_security_datas + [
        (os.path.join(_BASE, 'folder_watcher.py'), '.'),
        (os.path.join(_BASE, 'scan_directories.txt'), '.'),
        (os.path.join(_BASE, 'scan_utils.py'), '.'),
        (os.path.join(_BASE, 'quarantine_utils.py'), '.'),
        (os.path.join(_BASE, 'config.py'), '.'),
        (os.path.join(_BASE, 'standalone_agent.py'), '.'),
        (os.path.join(_BASE, 'utils'), 'utils'),
        (os.path.join(_BASE, 'compiled_rules.yarc'), '.'),
    ],
    hiddenimports=['psutil', 'requests', 'urllib3', 'socket', 'platform',
                   'hashlib', 'json', 'threading', 'subprocess', 'ctypes',
                   'concurrent.futures', 're', 'argparse', 'plistlib',
                   'yara', 'cryptography.fernet', 'standalone_agent',
                   'security.ml_yara_analyzer', 'security.yara_scanner',
                   'sklearn', 'sklearn.ensemble', 'sklearn.preprocessing',
                   'numpy', 'joblib'],
    hookspath=[os.path.join(_BASE, 'pyinstaller_hooks')],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'torchaudio', 'h5py', 'numba',
              'IPython', 'ipykernel', 'notebook', 'pytest',
              'nltk', 'transformers', 'accelerate', 'cv2', 'redis', 'onnxruntime',
              'pyssdeep', 'ssdeep', 'tlsh', 'lief', 'lightgbm', 'pefile',
              'pandas', 'matplotlib', 'seaborn', 'scipy', 'pydantic', 'pydantic_core', 'Crypto', 'Cryptodome'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IsolationBytesAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(_BASE, 'static', 'favicon.ico'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='IsolationBytesAgent',
)
