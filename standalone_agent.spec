# -*- mode: python ; coding: utf-8 -*-
import os
import tempfile

_BASE = SPECPATH

# Build from a generated copy so the shipped agent has no artificial scan
# count/time ceiling. The source agent remains readable while the packaged EXE
# gets the same unlimited behavior without changing its runtime file layout.
_SOURCE = os.path.join(_BASE, 'standalone_agent.py')
_BUILD_SOURCE_DIR = os.path.join(tempfile.gettempdir(), 'IsolationBytesAgentBuild')
os.makedirs(_BUILD_SOURCE_DIR, exist_ok=True)
_BUILD_SOURCE = os.path.join(_BUILD_SOURCE_DIR, 'standalone_agent.py')
with open(_SOURCE, 'r', encoding='utf-8') as _src:
    _agent_source = _src.read()
_agent_source = _agent_source.replace(
    'MAX_FILES_PER_SCAN = 5000    # full-system scan budget; keeps the agent aligned with dashboard scans\n',
    ''
).replace(
    'MAX_SCAN_CYCLE_SECONDS = 600 # allow a full-system scan to run for the dashboard scan window\n',
    ''
).replace(
    '            # Stop scanning this directory tree if the overall cycle is over budget\n            if cycle_start and time.time() - cycle_start > MAX_SCAN_CYCLE_SECONDS:\n                break\n',
    ''
).replace(
    '                # Global per-cycle file budget (shared across all directories)\n                if getattr(self, \'_scan_cycle_remaining\', 0) <= 0:\n                    dirs[:] = []\n                    break\n                # Per-file time budget guard\n                if cycle_start and time.time() - cycle_start > MAX_SCAN_CYCLE_SECONDS:\n                    dirs[:] = []\n                    break\n',
    ''
).replace(
    '                    self._scan_cycle_remaining -= 1\n',
    ''
).replace(
    '            if getattr(self, \'_scan_cycle_remaining\', 0) <= 0:\n                break\n',
    ''
).replace(
    '        self._scan_cycle_remaining = MAX_FILES_PER_SCAN\n',
    ''
).replace(
    '            if time.time() - cycle_start > MAX_SCAN_CYCLE_SECONDS:\n                break\n',
    ''
).replace(
    '            if self._scan_cycle_remaining <= 0:\n                break\n',
    '')
with open(_BUILD_SOURCE, 'w', encoding='utf-8') as _dst:
    _dst.write(_agent_source)

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
    [_BUILD_SOURCE],
    pathex=[_BASE],
    binaries=[],
    datas=_security_datas + [
        (os.path.join(_BASE, 'folder_watcher.py'), '.'),
        (os.path.join(_BASE, 'scan_directories.txt'), '.'),
        (os.path.join(_BASE, 'scan_utils.py'), '.'),
        (os.path.join(_BASE, 'quarantine_utils.py'), '.'),
        (os.path.join(_BASE, 'config.py'), '.'),
        (os.path.join(_BASE, 'utils'), 'utils'),
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
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(_BASE, 'static', 'favicon.ico'),
)
