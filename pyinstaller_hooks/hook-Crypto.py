"""Safe override for the broken pyinstaller-hooks-contrib Crypto hook.

Isolation Bytes does not use the legacy Crypto namespace. The installed
contrib hook can crash while probing a missing module location, so keep this
namespace empty when PyInstaller encounters it transitively.
"""

hiddenimports = []
datas = []
binaries = []
excludedimports = []
