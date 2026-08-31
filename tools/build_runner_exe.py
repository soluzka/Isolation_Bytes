"""
Build a standalone ssdeep_runner.exe using PyInstaller.
Intended to run on Windows (build and runtime must match platform).
"""
import os
import sys
import glob
import shutil
import PyInstaller.__main__

base_dir = os.path.abspath(os.path.dirname(__file__))
repo_root = os.path.abspath(os.path.join(base_dir, '..'))
dist_dir = os.environ.get('ANTIVIRUS_BUILD_DIST', os.path.join(repo_root, 'dist'))
work_dir = os.path.join(os.path.dirname(dist_dir), 'build', 'ssdeep_runner')
runner = os.path.join(repo_root, 'security', 'yara_rules', 'ssdeep_runner.py')
if not os.path.exists(runner):
    print('ssdeep_runner.py not found at', runner)
    sys.exit(2)

# Windows path separator for add-data
sep = ';' if sys.platform.startswith('win') else ':'

args = [
    '--name=ssdeep_runner',
    '--onefile',
    '--uac-admin',
    '--noconfirm',
    '--log-level=INFO',
    '--distpath', dist_dir,
    '--workpath', work_dir,
    '--add-data', f"{os.path.join(repo_root, 'security', 'yara_rules')}{sep}security\\yara_rules",
    '--collect-all', 'pyssdeep',
    '--hidden-import', 'yara',
    runner,
]

upx = shutil.which('upx')
if not upx:
    user_upx = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'UPX', 'upx.exe')
    candidates = [user_upx, *glob.glob(r'C:\Users\*\AppData\Local\UPX\upx.exe')]
    upx = next((path for path in candidates if os.path.isfile(path)), None)
if upx:
    args.extend(['--upx-dir', os.path.dirname(upx)])
    print('UPX compression enabled:', upx)
else:
    print('UPX not found; executable compression is disabled.')

print('Running PyInstaller with args:', args)
PyInstaller.__main__.run(args)
print('Build finished. Dist/ssdeep_runner(.exe) should be available.')
