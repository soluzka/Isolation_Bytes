import PyInstaller.__main__
import os
import sys
import glob
import stat
import shutil
import logging
import subprocess
import platform
import time
import argparse



# Application details
app_name = 'antivirus_server'
entry_point = 'quick_start.py'

# Base directory
base_dir = os.path.abspath(os.path.dirname(__file__))

repo_dist_dir = os.path.join(base_dir, 'dist')
if os.environ.get('ANTIVIRUS_BUILD_DIST'):
    dist_dir = os.path.abspath(os.environ['ANTIVIRUS_BUILD_DIST'])
elif 'OneDrive' in base_dir:
    dist_dir = os.path.join(os.environ.get('LOCALAPPDATA', base_dir), 'AntivirusServerBuild', 'dist')
else:
    dist_dir = repo_dist_dir
build_dir = os.path.join(os.path.dirname(dist_dir), 'build')

upx_executable = shutil.which('upx')
if not upx_executable:
    user_upx = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'UPX', 'upx.exe')
    if os.path.isfile(user_upx):
        upx_executable = user_upx
upx_dir = os.path.dirname(upx_executable) if upx_executable else None

# Parse optional MSIX certificate arguments (not PyInstaller flags)
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--store-cert', dest='store_cert', default=None, help='Path to Partner Center .pfx')
parser.add_argument('--store-cert-password', dest='store_cert_password', default=None, help='Password for the Partner Center .pfx')
parser.add_argument('--store-publisher', dest='store_publisher', default='CN=soluzka', help='Publisher CN for the MSIX manifest')
parser.add_argument('--store-version', dest='store_version', default=None, help='MSIX version, e.g. 1.0.958.0')
parser.add_argument('--skip-install', dest='skip_install', action='store_true', help='Build the installer EXE without running it')
parser.add_argument('--include-local-model', dest='include_local_model', action='store_true', help='Include the large local GGUF assistant model in the installer')
parser.add_argument('--help', '-h', action='help', help='Show this help message and exit')
parser.add_argument('extra', nargs='*', help='Extra positional arguments are ignored')
build_args, _ = parser.parse_known_args()

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
    'waitress',
    'pkg_resources',
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
    '--clean',
    '--noconfirm',
    '--log-level=DEBUG',
    f'--icon={icon_path}',
    '--paths', base_dir,
    '--distpath', dist_dir,
    '--workpath', build_dir,
    os.path.join(base_dir, entry_point),
    '--console'  # Keep console for debugging
]


def add_upx_option(args):
    if upx_dir:
        args.extend(['--upx-dir', upx_dir])
        logging.info("UPX compression enabled: %s", upx_executable)
    else:
        logging.warning("UPX not found; executable compression is disabled.")


add_upx_option(pyinstaller_args)

# Add Redis configuration
redis_available = configure_redis()
if redis_available:
    pyinstaller_args.append('--hidden-import=redis')
    pyinstaller_args.append('--hidden-import=redis.client')
    pyinstaller_args.append('--hidden-import=redis.connection')
    pyinstaller_args.append('--hidden-import=redis.exceptions')
    pyinstaller_args.append('--hidden-import=redis.utils')
    logging.info("Redis configured for EXE build")

# The MSIX package must use an asInvoker executable. Windows does not support
# launching a packaged full-trust executable with requireAdministrator.
# Standalone shortcuts explicitly request RunAs where elevation is required.

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

# Add runtime data/config files that the app reads from the project root.
DATA_FILES = [
    '.env',
    'antivirus.db',
    'blacklist_fallback.txt',
    'blocked_ips.json',
    'c2_ports.json',
    'iocs.json',
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

def _clear_readonly(func, path, _exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _cleanup_dir(path):
    """Remove a stale build directory while tolerating transient Windows locks."""
    if not os.path.exists(path):
        return
    last_error = None
    for attempt in range(10):
        try:
            shutil.rmtree(path, onerror=_clear_readonly)
            print(f"Removed {path}")
            return
        except (PermissionError, OSError) as e:
            last_error = e
            print(f"Warning: could not remove {path}: {e} (attempt {attempt + 1}/10)")
            time.sleep(2)
    for i in range(100):
        backup = f"{path}.old{i}"
        if not os.path.exists(backup):
            try:
                os.rename(path, backup)
                print(f"Renamed {path} to {backup}")
                return
            except (PermissionError, OSError) as e:
                last_error = e
                break
    raise PermissionError(
        f"Could not clear locked build directory {path}. "
        "Close the packaged app and pause OneDrive synchronization, then retry."
    ) from last_error

# Remove stale build output directories and .spec files so PyInstaller creates
# a fresh onedir build instead of reusing a stale onefile .spec.
if '--clean' in pyinstaller_args:
    pyinstaller_args.remove('--clean')
for stale in [os.path.join(build_dir, app_name), os.path.join(dist_dir, app_name)]:
    _cleanup_dir(stale)
for stale_spec in [os.path.join(base_dir, 'antivirus_server.spec'), os.path.join(base_dir, 'Install_AntivirusServer.spec')]:
    if os.path.exists(stale_spec):
        os.remove(stale_spec)
        print(f"Removed stale spec file: {stale_spec}")

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
            '--uac-admin',
            '--noconfirm',
            '--log-level=INFO',
            '--distpath', dist_dir,
            '--workpath', os.path.join(build_dir, 'ssdeep_runner'),
            '--add-data', f"{os.path.join(base_dir, 'security', 'yara_rules')}{sep}security\\yara_rules",
            '--collect-all', 'pyssdeep',
            '--hidden-import', 'yara',
            runner_script,
        ]
        add_upx_option(runner_args)
        PyInstaller.__main__.run(runner_args)
        print("ssdeep_runner build completed.")

        # Move the standalone runner into the onedir internal folder so it is
        # included with the installed project and its packaged dependencies.
        runner_src = os.path.join(dist_dir, 'ssdeep_runner.exe')
        onedir_root = os.path.join(dist_dir, app_name)
        internal_dir = os.path.join(onedir_root, '_internal')
        runner_dst = os.path.join(internal_dir, 'ssdeep_runner.exe')
        if os.path.exists(runner_src) and os.path.isdir(onedir_root):
            os.makedirs(internal_dir, exist_ok=True)
            shutil.move(runner_src, runner_dst)
            print(f"Moved ssdeep_runner.exe to {runner_dst}")
    except Exception as e:
        print(f"Warning: ssdeep_runner build failed: {e}")
else:
    print("Warning: ssdeep_runner.py not found; skipping ssdeep_runner build.")

# Build an unpacked administrator helper for the traditional installers.
# This helper is intentionally kept outside MSIX activation paths.
helper_script = os.path.join(base_dir, 'antivirus_admin_helper.py')
if os.path.exists(helper_script):
    try:
        print("Building AntivirusServer_AdminHelper.exe...")
        helper_args = [
            '--name=AntivirusServer_AdminHelper',
            '--onefile',
            '--uac-admin',
            '--noconfirm',
            '--log-level=INFO',
            '--distpath', dist_dir,
            '--workpath', os.path.join(build_dir, 'admin_helper'),
            f'--icon={icon_path}',
            helper_script,
        ]
        add_upx_option(helper_args)
        PyInstaller.__main__.run(helper_args)
        helper_src = os.path.join(dist_dir, 'AntivirusServer_AdminHelper.exe')
        helper_dst = os.path.join(dist_dir, app_name, 'AntivirusServer_AdminHelper.exe')
        if os.path.exists(helper_src) and os.path.isdir(os.path.dirname(helper_dst)):
            shutil.move(helper_src, helper_dst)
            print(f"Moved AntivirusServer_AdminHelper.exe to {helper_dst}")
    except Exception as e:
        print(f"Warning: administrator helper build failed: {e}")
else:
    print("Warning: antivirus_admin_helper.py not found; skipping administrator helper build.")

# Build the MSIX packages from the onedir that was just produced.
# build_msix.ps1 will prompt for UAC elevation if it needs to manage certs,
# install, and launch the app. Use build_msix.ps1 -NoCertManagement if you
# want to pack/sign without installing.
build_msix_ps1 = os.path.join(base_dir, 'build_msix.ps1')
if os.path.exists(build_msix_ps1):
    try:
        skip_test = True  # Test launcher is no longer built.
        print("Building MSIX packages (certificate trust/install/launch will be elevated if needed)...")
        args = [
            'powershell.exe',
            '-ExecutionPolicy', 'Bypass',
            '-File', build_msix_ps1,
            '-SkipBuild',
            '-NoCertManagement'
        ]
        if skip_test:
            args.append('-SkipTest')
            print("Skipping test launcher (--no-test).")
        if build_args.store_cert:
            args.extend(['-StoreCertFile', build_args.store_cert])
        if build_args.store_cert_password:
            args.extend(['-StoreCertPassword', build_args.store_cert_password])
        if build_args.store_publisher:
            args.extend(['-StorePublisher', build_args.store_publisher])
        if build_args.store_version:
            args.extend(['-StoreVersion', build_args.store_version])
        subprocess.check_call(args)
        print("MSIX build completed.")

        # Build the sparse/external-location identity package before the
        # installer app is bundled. It is registered after Program Files is populated.
        identity_script = os.path.join(base_dir, 'build_external_identity.ps1')
        if os.path.exists(identity_script):
            identity_args = [
                'powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', identity_script,
                '-NoCertManagement', '-StorePublisher', build_args.store_publisher
            ]
            if build_args.store_version:
                identity_args.extend(['-StoreVersion', build_args.store_version])
            if build_args.store_cert:
                identity_args.extend(['-StoreCertFile', build_args.store_cert])
            try:
                subprocess.check_call(identity_args)
                print("External-location identity package completed.")
            except Exception as e:
                print(f"Warning: external identity package failed: {e}")

        # Keep the MSIX shortcut on normal AUMID activation. The admin
        # shortcuts below target unpacked executables only.
        msix_shortcut = os.path.join(os.path.expanduser('~'), 'Desktop', 'Antivirus Server.lnk')
        if os.path.exists(msix_shortcut):
            try:
                from installer_app import _clear_shortcut_runas
                _clear_shortcut_runas(msix_shortcut)
                print(f"Cleared administrator flag from MSIX shortcut: {msix_shortcut}")
            except Exception as e:
                print(f"Warning: could not clear MSIX shortcut administrator flag: {e}")

    except Exception as e:
        print(f"Warning: MSIX build failed: {e}")
else:
    print("Warning: build_msix.ps1 not found; skipping MSIX build.")


def build_and_run_installer_app():
    """Always build the installer app when its MSIX inputs are available."""
    one_file_installer = os.path.join(base_dir, 'tools', 'build_installer_exe.py')
    store_msix = os.path.join(dist_dir, 'AntivirusServer_Store.msix')
    store_cer = os.path.join(dist_dir, 'soluzka.cer')
    if not os.path.exists(one_file_installer):
        print("Warning: tools/build_installer_exe.py not found; skipping installer app.")
        return
    if not os.path.exists(store_msix) or not os.path.exists(store_cer):
        print("Warning: MSIX or certificate output is missing; installer app was not built.")
        return

    print("Building onedir installer...")
    installer_args = [sys.executable, one_file_installer]
    if build_args.include_local_model:
        installer_args.append('--include-local-model')
    subprocess.check_call(installer_args)
    src = os.path.join(dist_dir, 'Install_AntivirusServer', 'Install_AntivirusServer.exe')
    if not os.path.exists(src):
        raise FileNotFoundError(f"Installer app was not produced: {src}")
    print(f"Installer app produced: {src}")
    print("The onedir installer remains in the dist directory; run its EXE to install.")

    if not build_args.skip_install:
        print("Running the installer app with UAC elevation...")
        if sys.platform.startswith('win'):
            escaped_src = src.replace("'", "''")
            install_command = f"Start-Process -FilePath '{escaped_src}' -Verb RunAs -Wait"
            subprocess.check_call([
                'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-Command', install_command
            ])
        else:
            subprocess.check_call([src])
        print("Installer app completed.")

    for script in ['create_conditional_shortcut.py', 'create_yara_scanner_shortcut.py']:
        shortcut_script = os.path.join(base_dir, script)
        if os.path.exists(shortcut_script):
            print(f"Creating shortcut from {script}...")
            subprocess.check_call([sys.executable, shortcut_script])


try:
    build_and_run_installer_app()
except Exception as e:
    print(f"Warning: installer app build/install failed: {e}")
