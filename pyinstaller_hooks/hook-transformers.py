"""Safe override for the optional transformers package.

The standalone agent does not package Hugging Face Transformers. The installed
contrib hook imports transformers at build time and can trigger an incompatible
Torch installation, so leave the optional package empty during analysis.
"""
hiddenimports=[]
datas=[]
binaries=[]
excludedimports=[]
