"""Safe Pydantic hook for the cloud-server build.

The installed pyinstaller-hooks-contrib hook assumes Pydantic exposes the
Pydantic-2-only ``compiled`` module attribute. The cloud server does not
need Pydantic as a direct dependency, but optional/transitive packages can
cause PyInstaller to inspect it. Keep this hook deliberately minimal so that
Pydantic 1.x and 2.x can both be analyzed without the contrib hook failing.
"""

# Do not import pydantic or inspect version-specific attributes here.
# PyInstaller's normal module graph will collect modules actually imported by
# the application.
hiddenimports = []
datas = []
binaries = []
