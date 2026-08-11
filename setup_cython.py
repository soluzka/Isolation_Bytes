import sys
from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Compiler import Options

Options.fast_fail = True

modules = [
    'folder_watcher',
    'scan_utils',
    'quarantine_utils',
    'ml_security',
    'network_monitor',
    'hash_verify',
    'utils',
    'file_crypto',
    'security.process_security',
    'security.process_monitor',
]

sources = [m.replace('.', '/') + '.py' for m in modules]

ext_modules = cythonize(
    [Extension(m, [s]) for m, s in zip(modules, sources)],
    compiler_directives={'language_level': '3'},
    annotate=False,
)

setup(
    name='antivirus_cython',
    ext_modules=ext_modules,
    zip_safe=False,
)