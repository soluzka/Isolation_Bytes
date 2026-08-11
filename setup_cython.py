import sys
from setuptools import setup, Extension
from Cython.Build import cythonize
from Cython.Compiler import Options

Options.fast_fail = True

modules = [
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