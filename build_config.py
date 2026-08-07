import PyInstaller.__main__
import os
import sys
import glob
import logging
import platform

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
    # Add fuzzy and YARA related packages so PyInstaller bundles them
    'ssdeep',
    'yara',
]

# Path separator based on platform
sep = ';' if sys.platform.startswith('win') else ':'

# Check Redis configuration
redis_available = configure_redis()

# PyInstaller arguments
pyinstaller_args = [
    f'--name={app_name}',
    '--onefile',
    '--clean',
    '--log-level=DEBUG',
    '--noupx',
    '--paths', base_dir,
    os.path.join(base_dir, entry_point),
    '--windowed'  # Hide console window (no console)
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
pyinstaller_args += [f'--hidden-import={mod}' for mod in hidden_imports]

# Add data directories
for directory in data_dirs:
    full_path = os.path.join(base_dir, directory)
    if os.path.exists(full_path):
        # Ensure __init__.py is present to help PyInstaller recognize it
        init_file = os.path.join(full_path, '__init__.py')
        if not os.path.exists(init_file):
            open(init_file, 'a').close()
        pyinstaller_args.append(f'--add-data={full_path}{sep}{directory}')

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
                    continue

    # Add unique candidates
    for c in sorted(set(candidates)):
        pyinstaller_args.append(f'--add-binary={c}{sep}.')
        logging.info(f'Added binary to PyInstaller args: {c}')

# Add suspected compiled modules
add_extension_binaries(['pyssdeep', 'ssdeep', 'yara'])

# Add malware_signatures.txt file
malware_signatures_file = os.path.join(base_dir, 'malware_signatures.txt')
if os.path.exists(malware_signatures_file):
    pyinstaller_args.append(f'--add-data={malware_signatures_file}{sep}.')

# Add scheduled_scan_state.json file
scheduled_scan_state_file = os.path.join(base_dir, 'scheduled_scan_state.json')
if os.path.exists(scheduled_scan_state_file):
    pyinstaller_args.append(f'--add-data={scheduled_scan_state_file}{sep}.')

# Optional: Add non-entry-point .py files if needed
for root, _, files in os.walk(base_dir):
    for file in files:
        if file.endswith('.py') and file != entry_point:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(root, base_dir)
            pyinstaller_args.append(f'--add-data={file_path}{sep}{rel_path}')

# Add Redis configuration file
redis_config = os.path.join(base_dir, 'redis', 'redis.conf')
if os.path.exists(redis_config):
    pyinstaller_args.append(f'--add-data={redis_config}{sep}redis')

# Run PyInstaller
try:
    print("Starting EXE build...")
    print("Redis status:", "Available" if redis_available else "Not Available")
    PyInstaller.__main__.run(pyinstaller_args)
    print("Build completed successfully!")
except PermissionError as e:
    print(f"Warning: Permission error occurred: {e}")
    print("Continuing with build without cleaning previous build directory...")
    pyinstaller_args.remove('--clean')
    PyInstaller.__main__.run(pyinstaller_args)
except Exception as e:
    print(f"Error during build: {e}")
    sys.exit(1)
