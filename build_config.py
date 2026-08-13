import PyInstaller.__main__
import os
import sys
import glob
import shutil
import logging
import platform
import time



# Application details
app_name = 'antivirus_server'
entry_point = 'quick_start.py'

# Base directory
base_dir = os.path.abspath(os.path.dirname(__file__))

# Folders to include
data_dirs = [
    'security',
    'static',
    'browser_extension',
    'templates',
    'utils',
    'sklearn',
    'scipy',
    'numpy'
]

# Add Redis directory if it exists
redis_dir = os.path.join(base_dir, 'redis')
if os.path.exists(redis_dir):
    data_dirs.append('redis')
    logging.info("Including Redis directory in build")
else:
    logging.warning("Redis directory not found. Redis will be optional in the EXE.")

# Redis configuration
def configure_redis():
    """Configure Redis for EXE build"""
    # First check if Redis is installed in the virtual environment
    redis_dir = os.path.join(base_dir, 'venv', 'Lib', 'site-packages', 'redis')
    if os.path.exists(redis_dir):
        logging.info("Found Redis in virtual environment")
        return True
    
    # Then check if Redis is installed system-wide
    try:
        import redis
        logging.info("Found Redis installed in Python")
        return True
    except ImportError:
        logging.warning("Redis package not found")
        return False

# Hidden imports for scikit-learn and related packages
hidden_imports = [
    'sklearn',
    'sklearn.utils',
    'sklearn.utils._cython_blas',
    'sklearn.utils._fast_dict',
    'sklearn.utils._weight_vector',
    'sklearn.utils._sorting',
    'sklearn.utils._random',
    'sklearn.utils._typedefs',
    'sklearn.utils._heap',
    'sklearn.utils._logistic_sigmoid',
    'sklearn.utils._seq_dataset',
    'sklearn.utils._sparsefuncs_fast',
    'sklearn.utils._sorting',
    'sklearn.utils._weight_vector',
    'scipy',
    'scipy.sparse',
    'scipy.sparse._sparsetools',
    'scipy.special',
    'scipy.special._ufuncs_cxx',
    'numpy',
    'numpy.random',
    'numpy.random.common',
    'numpy.random.bounded_integers',
    'numpy.random.entropy',
    'redis',  # Add Redis to hidden imports
    'onnxruntime',  # Bundle ONNX Runtime for the CNN model
    # Add fuzzy and YARA related packages so PyInstaller bundles them
    'pyssdeep',
    'ssdeep',
    'yara',
    'tlsh',
    'requests',
    # Static-file malware classifier (security/detector.py, security/ember_vendor/,
    # train_ember_classifier.py) -- both have compiled extensions PyInstaller
    # doesn't reliably auto-detect.
    'lief',
    'lightgbm',
    'lightgbm.basic',
    'lightgbm.sklearn',
    'pefile',
    'security.process_monitor',
    'security.process_security',
    'security.yara_scanner',
    'security.detector',
    'folder_watcher',
    'network_monitor',
    'hash_verify',
    'ml_security',
    'utils.paths',
    'scan_utils',
    'quarantine_utils',
    # Shortcut creation (pywin32) dependencies for the one-file EXE
    'win32com.client',
    'win32com.shell.shell',
    'win32com.shell.shellcon',
    'pythoncom',
    'pywintypes',
]

# Path separator based on platform
sep = ';' if sys.platform.startswith('win') else ':'

# Check Redis configuration
redis_available = configure_redis()

# PyInstaller arguments
icon_path = os.path.join(base_dir, 'static', 'favicon.ico')

pyinstaller_args = [
    f'--name={app_name}',
    '--onedir',
    '--contents-directory=.',
    '--clean',
    '--noconfirm',
    '--log-level=DEBUG',
    '--noupx',
    f'--icon={icon_path}',
    '--paths', base_dir,
    os.path.join(base_dir, entry_point),
    '--console'  # Keep console for debugging
]

# Add Redis configuration
redis_available = configure_redis()
if redis_available:
    pyinstaller_args.append('--hidden-import=redis')
    pyinstaller_args.append('--hidden-import=redis.client')
    pyinstaller_args.append('--hidden-import=redis.connection')
    pyinstaller_args.append('--hidden-import=redis.exceptions')
    pyinstaller_args.append('--hidden-import=redis.utils')
    logging.info("Redis configured for EXE build")

# Add hidden imports
if '--admin' in sys.argv:
    pyinstaller_args.append('--uac-admin')
    print('Admin mode enabled: --uac-admin added for local admin build')

pyinstaller_args += [f'--hidden-import={mod}' for mod in hidden_imports]

# Collect the entire pyssdeep package (including bin/windows/fuzzy_64.dll)
pyinstaller_args += ['--collect-all', 'pyssdeep']

# Collect the entire onnxruntime package so the CNN .onnx model can be run
pyinstaller_args += ['--collect-all', 'onnxruntime']

# Exclude large/unnecessary packages that bloat the one-file EXE and can fail
# extraction (e.g. TensorFlow's long internal paths / huge binaries).
EXCLUDE_MODULES = [
    'tensorflow',
    'torch',
    'torchvision',
    'torchaudio',
    'h5py',
    'numba',
    'IPython',
    'ipykernel',
    'notebook',
    'pytest',
    'scikit-learn-main',  # local source tree, not a package
]
pyinstaller_args += [f'--exclude-module={mod}' for mod in EXCLUDE_MODULES]

# Add data directories
for directory in data_dirs:
    full_path = os.path.join(base_dir, directory)
    if os.path.exists(full_path):
        # Ensure __init__.py is present to help PyInstaller recognize it
        init_file = os.path.join(full_path, '__init__.py')
        if not os.path.exists(init_file):
            open(init_file, 'a').close()
        pyinstaller_args.append(f'--add-data={full_path}{sep}{directory}')

# Add the blocklists directory used by the phishing detector/network monitor.
blocklists_dir = os.path.join(base_dir, 'blocklists')
if os.path.isdir(blocklists_dir):
    pyinstaller_args.append(f'--add-data={blocklists_dir}{sep}blocklists')
    logging.info(f'Including blocklists directory: {blocklists_dir}')

# Try to detect compiled extension binaries for fuzzy and YARA libs and include them
def add_extension_binaries(module_names):
    """Locate compiled extension module files (.pyd, .so, .dll) and add them to the bundle."""
    candidates = []
    for name in module_names:
        try:
            mod = __import__(name)
            mfile = getattr(mod, '__file__', None)
            if mfile and os.path.exists(mfile):
                candidates.append(mfile)
                logging.info(f'Found extension file for {name}: {mfile}')
        except Exception:
            # fallback: search site-packages for likely filenames
            for p in sys.path:
                if not p:
                    continue
                try:
                    # look for name*.pyd and name*.so
                    for ext in ('.pyd', '.so', '.dll'):
                        pattern = os.path.join(p, name + '*' + ext)
                        for match in glob.glob(pattern):
                            candidates.append(match)
                            logging.info(f'Found binary candidate for {name}: {match}')
                except Exception:
                    logging.warning(f'Binary candidate rejected for {name}', exc_info=False)

    # Add unique candidates
    for c in sorted(set(candidates)):
        pyinstaller_args.append(f'--add-binary={c}{sep}.')
        logging.info(f'Added binary to PyInstaller args: {c}')

# Add suspected compiled modules
add_extension_binaries(['pyssdeep', 'ssdeep', 'yara', 'lief', 'lightgbm', 'tlsh'])

# Seed the runtime signature database into the bundle so the EXE can place it in
# its own root on first launch (it is not meant to be edited from the temp dir).
# Bundle both .json and .txt if they exist so the EXE can use whichever name
# the current code expects at runtime.
for sig_ext in ('.json', '.txt'):
    malware_signatures_file = os.path.join(base_dir, f'malware_signatures{sig_ext}')
    if os.path.exists(malware_signatures_file):
        pyinstaller_args.append(f'--add-data={malware_signatures_file}{sep}.')
        logging.info(f'Including malware signatures seed: {malware_signatures_file}')

# If no .txt seed exists in the repo, generate a minimal one in the build cache
# so the packaged app still has a starting malware_signatures.txt file.
if not any('malware_signatures.txt' in a and '--add-data=' in a for a in pyinstaller_args):
    txt_seed = os.path.join(base_dir, 'build', 'malware_signatures.txt')
    os.makedirs(os.path.dirname(txt_seed), exist_ok=True)
    with open(txt_seed, 'w', encoding='utf-8') as f:
        f.write('# Malware signatures seed - bundled by build_config.py\n')
        f.write('# Format: signature_name:hash_type:hash_value\n\n')
    pyinstaller_args.append(f'--add-data={txt_seed}{sep}.')
    logging.info(f'Generated and including minimal malware_signatures.txt seed: {txt_seed}')

# Add scan_directories.txt so the EXE knows which folders to scan
scan_directories_file = os.path.join(base_dir, 'scan_directories.txt')
if os.path.exists(scan_directories_file):
    pyinstaller_args.append(f'--add-data={scan_directories_file}{sep}.')

# Add scheduled_scan_state.json file
scheduled_scan_state_file = os.path.join(base_dir, 'scheduled_scan_state.json')
if os.path.exists(scheduled_scan_state_file):
    pyinstaller_args.append(f'--add-data={scheduled_scan_state_file}{sep}.')

# Add the entire trained model directory if it exists (includes subdirectories,
# .pkl and .txt models). These are generated by train_malware_classifier.py /
# train_ember_classifier.py and are not committed to source control, so on a
# build machine without them security/detector.py falls back to its untrained
# placeholder model.
models_dir = os.path.join(base_dir, 'models')
if os.path.isdir(models_dir):
    pyinstaller_args.append(f'--add-data={models_dir}{sep}models')
    logging.info(f'Including models directory in build: {models_dir}')

# Add runtime data/config files that the app reads from the project root
DATA_FILES = [
    '.env',
    'antivirus.db',
    'blacklist_fallback.txt',
    'blocked_ips.json',
    'c2_ports.json',
    'malicious_domains.json',
    'malicious_ips.log',
    'network_segments.json',
    'phishing_alerts.json',
    'trusted_hashes.json',
    'version.txt',
]
for data_file in DATA_FILES:
    data_path = os.path.join(base_dir, data_file)
    if os.path.exists(data_path):
        pyinstaller_args.append(f'--add-data={data_path}{sep}.')

# Optional: Add non-entry-point .py files if needed
# Avoid packaging scripts that conditional_startup tries to launch as
# subprocesses (e.g. antivirus_cli.py, safe_downloader.py), because inside the
# one-file EXE sys.executable is the same dashboard EXE and launching them
# would restart the app instead of running the intended script.
SKIP_DATA_SCRIPTS = {
    'antivirus_cli.py',
    'safe_downloader.py',
    'build_config.py',
}
SKIP_DIRS = {
    'scikit-learn-main',
    'build',
    'dist',
    'venv',
    '__pycache__',
    '.git',
    '.github',
}
for root, _, files in os.walk(base_dir):
    rel_root = os.path.relpath(root, base_dir)
    if any(part in SKIP_DIRS for part in rel_root.split(os.sep)):
        continue
    for file in files:
        if file.endswith('.py') and file != entry_point and file not in SKIP_DATA_SCRIPTS:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(root, base_dir)
            pyinstaller_args.append(f'--add-data={file_path}{sep}{rel_path}')

# Add Redis configuration file
redis_config = os.path.join(base_dir, 'redis', 'redis.conf')
if os.path.exists(redis_config):
    pyinstaller_args.append(f'--add-data={redis_config}{sep}redis')

def _cleanup_dir(path):
    """Remove path if possible; otherwise rename it so PyInstaller can create a fresh one."""
    if not os.path.exists(path):
        return
    for attempt in range(3):
        try:
            shutil.rmtree(path)
            print(f"Removed {path}")
            return
        except (PermissionError, OSError) as e:
            print(f"Warning: could not remove {path}: {e} (attempt {attempt + 1}/3)")
            time.sleep(1)
    # Fallback: rename the locked directory out of the way
    for i in range(100):
        backup = f"{path}.old{i}"
        if not os.path.exists(backup):
            try:
                os.rename(path, backup)
                print(f"Renamed {path} to {backup}")
                return
            except Exception as e:
                print(f"Warning: could not rename {path}: {e}")
                break
    print(f"Warning: {path} is still present; PyInstaller may fail to overwrite it.")

# Remove stale build output directories so PyInstaller can create fresh ones.
# This avoids the WinError 5 'Access is denied' failures when locked files remain.
if '--clean' in pyinstaller_args:
    pyinstaller_args.remove('--clean')
for stale in [os.path.join(base_dir, 'build', app_name), os.path.join(base_dir, 'dist', app_name)]:
    _cleanup_dir(stale)

# Run PyInstaller
try:
    print("Starting EXE build...")
    print("Redis status:", "Available" if redis_available else "Not Available")
    PyInstaller.__main__.run(pyinstaller_args)
    print("Build completed successfully!")
except Exception as e:
    print(f"Error during build: {e}")
    sys.exit(1)

# Build the standalone ssdeep_runner helper so both executables are produced
# by the same top-level build command.
runner_script = os.path.join(base_dir, 'security', 'yara_rules', 'ssdeep_runner.py')
if os.path.exists(runner_script):
    try:
        print("Building ssdeep_runner.exe...")
        sep = ';' if sys.platform.startswith('win') else ':'
        runner_args = [
            '--name=ssdeep_runner',
            '--onefile',
            '--noconfirm',
            '--log-level=INFO',
            '--add-data', f"{os.path.join(base_dir, 'security', 'yara_rules')}{sep}security\\yara_rules",
            '--collect-all', 'pyssdeep',
            '--hidden-import', 'yara',
            runner_script,
        ]
        PyInstaller.__main__.run(runner_args)
        print("ssdeep_runner build completed.")

        # Move the standalone runner into the onedir package root so it lives
        # next to antivirus_server.exe and the packaged app can call it without
        # depending on the source-tree layout.
        runner_src = os.path.join(base_dir, 'dist', 'ssdeep_runner.exe')
        onedir_root = os.path.join(base_dir, 'dist', app_name)
        runner_dst = os.path.join(onedir_root, 'ssdeep_runner.exe')
        if os.path.exists(runner_src) and os.path.isdir(onedir_root):
            os.makedirs(onedir_root, exist_ok=True)
            shutil.move(runner_src, runner_dst)
            print(f"Moved ssdeep_runner.exe to {runner_dst}")
    except Exception as e:
        print(f"Warning: ssdeep_runner build failed: {e}")
else:
    print("Warning: ssdeep_runner.py not found; skipping ssdeep_runner build.")
