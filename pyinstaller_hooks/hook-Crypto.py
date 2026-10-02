# PyInstaller compatibility hook for pycryptodome / pycryptodomex.
#
# pyinstaller-hooks-contrib's hook-Crypto.py calls
# get_module_file_attribute('Crypto') which returns None when Crypto/
# Cryptodome are not installed, causing a TypeError in os.path.dirname().
#
# This project uses `cryptography` (pyca), not the legacy Crypto/Cryptodome
# namespaces.  The hook below is a no-op that keeps PyInstaller happy
# without trying to locate a package that isn't present.
#
# It must live in our local hookspath so PyInstaller finds it *before*
# the contributed hook in pyinstaller-hooks-contrib.

hiddenimports = []
datas = []
binaries = []
excludedimports = ['Crypto', 'Cryptodome']
