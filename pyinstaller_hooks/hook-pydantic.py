# PyInstaller compatibility hook for modern Pydantic 2.x.
#
# Older pyinstaller-hooks-contrib releases probe pydantic.compiled,
# which was removed in Pydantic 2.13+. Avoid that probe and collect
# Pydantic's importable submodules directly.
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("pydantic")
