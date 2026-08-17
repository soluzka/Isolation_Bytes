# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\bpier\\OneDrive\\Documents\\antivirus-yara-rules-c\\antivirus-yara-rules-c\\installer_app.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\bpier\\AppData\\Local\\AntivirusServerBuild\\dist\\AntivirusServer_Store.msix', '.'), ('C:\\Users\\bpier\\AppData\\Local\\AntivirusServerBuild\\dist\\soluzka.cer', '.'), ('C:\\Users\\bpier\\AppData\\Local\\Temp\\antivirus_installer_stage_e1lka_y0\\antivirus_server.zip', '.')],
    hiddenimports=[],
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
    [],
    exclude_binaries=True,
    name='Install_AntivirusServer',
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
    uac_admin=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Install_AntivirusServer',
)
