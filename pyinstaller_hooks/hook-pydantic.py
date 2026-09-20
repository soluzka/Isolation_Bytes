"""PyInstaller compatibility hook for Pydantic 2.x.

The bundled pyinstaller-hooks-contrib hook probes the removed Pydantic v1
attribute ``pydantic.compiled``. This project uses Pydantic 2.x, so keep the
hook side-effect free and let PyInstaller collect the package normally.
"""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("pydantic")
