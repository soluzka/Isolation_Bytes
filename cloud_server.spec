# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Flask cloud server (cloud_server.py).

Builds a standalone EXE that includes Python + all dependencies so the
launcher can start the website without requiring Python to be installed.
"""
from PyInstaller.utils.hooks import collect_all

datas = [
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\templates', 'templates'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\static', 'static'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\website', 'website'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\security', 'security'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\blocklists', 'blocklists'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\utils', 'utils'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\cloud\\cert.pem', 'cloud'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\cloud\\key.pem', 'cloud'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\cloud\\localhost.crt', 'cloud'),
    ('C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\cloud\\localhost.key', 'cloud'),
]

binaries = []
hiddenimports = [
    'flask', 'flask.sessions', 'werkzeug', 'werkzeug.middleware',
    'requests', 'psutil', 'dotenv',
    'cryptography', 'cryptography.fernet',
    'security.yara_scanner', 'security.c2_detector', 'security.secure_memory',
    'quarantine_utils', 'file_crypto', 'utils.paths',
    'waitress', 'ssl', 'json', 'hashlib', 'secrets',
]

a = Analysis(
    ['C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\cloud\\cloud_server.py'],
    pathex=['C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'torchvision', 'sklearn', 'scipy',
              'numpy', 'onnxruntime', 'lightgbm', 'lief', 'pyssdeep',
              'yara', 'tlsh', 'pefile', 'matplotlib', 'pandas',
              'IPython', 'ipykernel', 'notebook', 'pytest'],
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
    name='cloud_server',
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
    icon=['C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\static\\favicon.ico'],
)
