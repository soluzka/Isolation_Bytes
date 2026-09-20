"""
PyInstaller hook for cryptography module to fix build issues.
"""

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# Collect all cryptography submodules
hiddenimports = collect_submodules('cryptography')

# Collect data files for cryptography
datas = collect_data_files('cryptography')

# Collect OpenSSL libraries if available
try:
    from PyInstaller.utils.hooks import get_package_paths
    crypto_paths = get_package_paths('cryptography')
    for path in crypto_paths:
        if 'OpenSSL' in path or 'openssl' in path.lower():
            binaries = [(path, '.')]
except Exception:
    pass