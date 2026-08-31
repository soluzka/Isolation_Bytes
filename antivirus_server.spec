# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_all

# SPECPATH is the directory containing this .spec file (the repo root).
_BASE = SPECPATH

def _p(*parts):
    return os.path.join(_BASE, *parts)

datas = [
    (_p('security'), 'security'),
    (_p('static'), 'static'),
    (_p('browser_extension'), 'browser_extension'),
    (_p('templates'), 'templates'),
    (_p('utils'), 'utils'),
    (_p('blocklists'), 'blocklists'),
    (_p('malware_signatures.json'), '.'),
    (_p('malware_signatures.txt'), '.'),
    (_p('scan_directories.txt'), '.'),
    (_p('scheduled_scan_state.json'), '.'),
    (_p('models'), 'models'),
    (_p('.env'), '.'),
    (_p('antivirus.db'), '.'),
    (_p('blacklist_fallback.txt'), '.'),
    (_p('blocked_ips.json'), '.'),
    (_p('c2_ports.json'), '.'),
    (_p('iocs.json'), '.'),
    (_p('malicious_domains.json'), '.'),
    (_p('malicious_ips.log'), '.'),
    (_p('network_segments.json'), '.'),
    (_p('phishing_alerts.json'), '.'),
    (_p('trusted_hashes.json'), '.'),
    (_p('version.txt'), '.'),
]

# Only add data files that actually exist so the build doesn't fail on a
# fresh checkout that hasn't generated runtime files yet.
datas = [(src, dst) for src, dst in datas if os.path.exists(src)]

# Add all .py files (except entry point and build scripts) as data so
# conditional_startup can import them at runtime.
_skip_scripts = {
    'antivirus_cli.py', 'safe_downloader.py', 'build_config.py',
    'get_admin_username.py', 'patch_cloud_startup.py',
}
_skip_dirs = {'build', 'dist', 'venv', '__pycache__', '.git', '.github',
              'native', 'node_modules', 'scikit-learn-main'}
for root, _, files in os.walk(_BASE):
    rel = os.path.relpath(root, _BASE)
    if any(part in _skip_dirs for part in rel.split(os.sep)):
        continue
    for f in files:
        if f.endswith('.py') and f != 'quick_start.py' and f not in _skip_scripts:
            datas.append((os.path.join(root, f), rel))

# Locate compiled extension binaries dynamically via importlib.
import importlib.util
binaries = []
for mod_name in ['lief', 'lightgbm', 'pyssdeep', 'tlsh', 'yara']:
    spec = importlib.util.find_spec(mod_name)
    if spec and spec.origin and os.path.isfile(spec.origin):
        binaries.append((spec.origin, '.'))

hiddenimports = [
    'redis', 'redis.client', 'redis.connection', 'redis.exceptions', 'redis.utils',
    'waitress', 'sklearn', 'sklearn.utils', 'sklearn.utils._cython_blas',
    'sklearn.utils._fast_dict', 'sklearn.utils._weight_vector', 'sklearn.utils._sorting',
    'sklearn.utils._random', 'sklearn.utils._typedefs', 'sklearn.utils._heap',
    'sklearn.utils._logistic_sigmoid', 'sklearn.utils._seq_dataset',
    'sklearn.utils._sparsefuncs_fast', 'scipy', 'scipy.sparse',
    'scipy.sparse._sparsetools', 'scipy.special', 'scipy.special._ufuncs_cxx',
    'numpy', 'numpy.random', 'onnxruntime', 'pyssdeep', 'ssdeep', 'yara', 'tlsh',
    'requests', 'lief', 'lightgbm', 'lightgbm.basic', 'lightgbm.sklearn', 'pefile',
    'security.process_monitor', 'security.process_security', 'security.yara_scanner',
    'security.detector', 'security.secure_memory', 'file_crypto', 'safe_downloader',
    'folder_watcher', 'network_monitor', 'hash_verify', 'ml_security', 'utils.paths',
    'scan_utils', 'quarantine_utils', 'win32com.client', 'win32com.shell.shell',
    'win32com.shell.shellcon', 'pythoncom', 'pywintypes',
]

tmp_ret = collect_all('pyssdeep')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('onnxruntime')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

a = Analysis(
    [_p('quick_start.py')],
    pathex=[_BASE],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'torchaudio', 'h5py', 'numba',
              'IPython', 'ipykernel', 'notebook', 'pytest', 'scikit-learn-main',
              'nltk', 'transformers', 'accelerate', 'cv2'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='antivirus_server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_p('static', 'favicon.ico'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='antivirus_server',
)
