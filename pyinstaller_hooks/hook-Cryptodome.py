"""Safe override for the Cryptodome PyInstaller hook.

Isolation Bytes does not use the legacy Cryptodome namespace. Keep the
namespace empty if it is discovered transitively during packaging.
"""

hiddenimports = []
datas = []
binaries = []
excludedimports = []
