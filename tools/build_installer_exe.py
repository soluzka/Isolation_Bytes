"""Build a one-file installer EXE for the Antivirus Server MSIX package."""
import os
import sys
import shutil
import tempfile
from pathlib import Path
import PyInstaller.__main__

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
app = os.path.join(base_dir, 'installer_app.py')
msix = os.path.join(base_dir, 'dist', 'AntivirusServer_Store.msix')
cer = os.path.join(base_dir, 'dist', 'soluzka.cer')
standalone = os.path.join(base_dir, 'dist', 'antivirus_server')
identity_msix = os.path.join(base_dir, 'dist', 'AntivirusServer_Identity.msix')
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

# Do not bundle multi-gigabyte local GGUF models into the one-file installer.
# They are downloaded separately on machines that enable the local assistant.
stage_root = Path(tempfile.mkdtemp(prefix='antivirus_installer_stage_'))
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
    '--onefile',
    '--clean',
    '--uac-admin',
    '--noconfirm',
    '--log-level=INFO',
    '--add-data', f"{msix}{sep}.",
    '--add-data', f"{cer}{sep}.",
    '--add-data', f"{standalone_archive}{sep}.",
    app,
]
if os.path.exists(identity_msix):
    args[args.index(app):args.index(app)] = ['--add-data', f"{identity_msix}{sep}."]

print('Building one-file installer with:', args)
try:
    PyInstaller.__main__.run(args)
finally:
    shutil.rmtree(stage_root, ignore_errors=True)
print('Done. dist\\Install_AntivirusServer.exe should be available.')
