"""Build a WinRAR self-extracting installer for the Antivirus Server package."""
import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
import PyInstaller.__main__

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
dist_dir = os.environ.get('ANTIVIRUS_BUILD_DIST', os.path.join(base_dir, 'dist'))
app = os.path.join(base_dir, 'installer_app.py')
msix = os.path.join(dist_dir, 'AntivirusServer_Store.msix')
cer = os.path.join(dist_dir, 'soluzka.cer')
standalone = os.path.join(dist_dir, 'antivirus_server')
identity_msix = os.path.join(dist_dir, 'AntivirusServer_Identity.msix')
include_local_model = '--include-local-model' in sys.argv

if not os.path.exists(msix):
    print('AntivirusServer_Store.msix not found at', msix)
    print('Run "python build_config.py" first to build the MSIX.')
    sys.exit(2)

if not os.path.exists(cer):
    print('soluzka.cer not found at', cer)
    print('Run "python build_config.py" first.')
    sys.exit(2)

if not os.path.isdir(standalone):
    print('Standalone application bundle not found at', standalone)
    print('Run "python build_config.py" first.')
    sys.exit(2)

sep = ';' if sys.platform.startswith('win') else ':'

# Stage the standalone bundle separately so the onedir installer can carry
# multi-gigabyte payloads without PyInstaller's one-file archive size limit.
stage_root = Path(tempfile.mkdtemp(prefix='antivirus_installer_stage_'))
work_root = Path(tempfile.mkdtemp(prefix='antivirus_installer_work_'))
staged_standalone = stage_root / 'antivirus_server'
shutil.copytree(
    standalone,
    staged_standalone,
    ignore=None if include_local_model else shutil.ignore_patterns('*.gguf'),
)
if include_local_model:
    print('Including local GGUF assistant model in installer bundle.')
else:
    print('Excluding local GGUF assistant model from installer bundle.')
standalone_archive = Path(shutil.make_archive(
    str(stage_root / 'antivirus_server'),
    'zip',
    root_dir=staged_standalone,
))

# PyInstaller reuses a same-named spec file if it exists; remove stale specs
# so the current data list is used for this installer build.
stale_spec = os.path.join(base_dir, 'Install_AntivirusServer.spec')
if os.path.exists(stale_spec):
    os.remove(stale_spec)

args = [
    '--name=Install_AntivirusServer',
    '--onedir',
    '--clean',
    '--uac-admin',
    '--noconfirm',
    '--log-level=INFO',
    '--distpath', dist_dir,
    '--workpath', str(work_root),
    '--add-data', f"{msix}{sep}.",
    '--add-data', f"{cer}{sep}.",
    '--add-data', f"{standalone_archive}{sep}.",
    app,
]
if os.path.exists(identity_msix):
    args[args.index(app):args.index(app)] = ['--add-data', f"{identity_msix}{sep}."]

upx = shutil.which('upx')
if not upx:
    user_upx = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'UPX', 'upx.exe')
    if os.path.isfile(user_upx):
        upx = user_upx
if upx:
    args.extend(['--upx-dir', os.path.dirname(upx)])
    print('UPX compression enabled:', upx)
else:
    print('UPX not found; executable compression is disabled.')

print('Building onedir installer with:', args)
try:
    PyInstaller.__main__.run(args)
finally:
    shutil.rmtree(stage_root, ignore_errors=True)
    shutil.rmtree(work_root, ignore_errors=True)
winrar = r'C:\Program Files\WinRAR\WinRAR.exe'
if not os.path.exists(winrar):
    raise FileNotFoundError(f'WinRAR was not found at {winrar}')

sfx_output = os.path.join(dist_dir, 'Install_AntivirusServer.exe')
sfx_config = Path(tempfile.mkstemp(prefix='antivirus_server_sfx_', suffix='.txt')[1])
sfx_config.write_text(
    'TempMode=1\\n'
    'Silent=0\\n'
    'Overwrite=1\\n'
    'Setup=Install_AntivirusServer\\Install_AntivirusServer.exe\\n',
    encoding='utf-8',
)
try:
    print('Creating WinRAR self-extracting installer:', sfx_output)
    subprocess.check_call([
        winrar,
        'a',
        '-sfx',
        '-m5',
        '-y',
        f'-z{sfx_config}',
        sfx_output,
        'Install_AntivirusServer',
    ], cwd=dist_dir)
finally:
    sfx_config.unlink(missing_ok=True)

installer_payload = os.path.join(dist_dir, 'Install_AntivirusServer')
if os.path.isdir(installer_payload):
    shutil.rmtree(installer_payload)
    print('Removed unpacked installer payload after creating the SFX.')
print('Done. Single-file installer: ' + sfx_output)
