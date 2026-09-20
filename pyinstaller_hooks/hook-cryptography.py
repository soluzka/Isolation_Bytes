"""
PyInstaller hook for cryptography module to fix build issues.
This hook overrides the problematic built-in hook.
"""

from PyInstaller.utils.hooks import collect_submodules, collect_data_files, is_module_satisfies
import sys

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

# Force override of built-in hook by ensuring this hook takes precedence
def get_hook_module(module_name):
    """Override built-in hook to prevent the TypeError."""
    if module_name == 'Crypto' or module_name == 'cryptography':
        # Return empty dict to skip built-in hook processing
        return {}
    return None