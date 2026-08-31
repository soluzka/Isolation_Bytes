from PyInstaller.utils.hooks import collect_submodules

# Collect all submodules except the problematic ones
hiddenimports = collect_submodules('problematic_module', filter=lambda name: 'submodule_to_exclude' not in name)
