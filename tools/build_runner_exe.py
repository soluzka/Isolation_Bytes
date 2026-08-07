"""
Build a standalone ssdeep_runner.exe using PyInstaller.
Intended to run on Windows (build and runtime must match platform).
"""
import os
import sys
import PyInstaller.__main__

base_dir = os.path.abspath(os.path.dirname(__file__))
repo_root = os.path.abspath(os.path.join(base_dir, '..'))
runner = os.path.join(repo_root, 'security', 'yara_rules', 'ssdeep_runner.py')
if not os.path.exists(runner):
    print('ssdeep_runner.py not found at', runner)
    sys.exit(2)

# Windows path separator for add-data
sep = ';' if sys.platform.startswith('win') else ':'

args = [
    '--name=ssdeep_runner',
    '--onefile',
    '--noconfirm',
    '--log-level=INFO',
    '--add-data', f"{os.path.join(repo_root, 'security', 'yara_rules')}{sep}security\\yara_rules",
    '--hidden-import', 'pyssdeep',
    '--hidden-import', 'ssdeep',
    '--hidden-import', 'yara',
    runner,
]

print('Running PyInstaller with args:', args)
PyInstaller.__main__.run(args)
print('Build finished. Dist/ssdeep_runner(.exe) should be available.')
