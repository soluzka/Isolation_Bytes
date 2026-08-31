from PyInstaller.utils.hooks import collect_submodules

# Collect all submodules except the problematic ones
hiddenimports = collect_submodules('setuptools._vendor', filter=lambda name: 'jaraco' not in name)
