"""Build a one-file installer EXE for the Antivirus Server MSIX package."""
import os
import sys
import PyInstaller.__main__

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
app = os.path.join(base_dir, 'installer_app.py')
msix = os.path.join(base_dir, 'dist', 'AntivirusServer_Store.msix')
cer = os.path.join(base_dir, 'dist', 'soluzka.cer')
standalone = os.path.join(base_dir, 'dist', 'antivirus_server')
identity_msix = os.path.join(base_dir, 'dist', 'AntivirusServer_Identity.msix')

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
args = [
    '--name=Install_AntivirusServer',
    '--onefile',
    '--uac-admin',
    '--noconfirm',
    '--log-level=INFO',
    '--add-data', f"{msix}{sep}.",
    '--add-data', f"{cer}{sep}.",
    '--add-data', f"{standalone}{sep}antivirus_server",
    app,
]
if os.path.exists(identity_msix):
    args[args.index(app):args.index(app)] = ['--add-data', f"{identity_msix}{sep}."]

print('Building one-file installer with:', args)
PyInstaller.__main__.run(args)
print('Done. dist\\Install_AntivirusServer.exe should be available.')
