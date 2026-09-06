"""Vendored, patched subset of https://github.com/elastic/ember (features.py
only) -- see the comments at the top of features.py for what was patched and
why. This package intentionally does not include the rest of the upstream
ember package (training/vectorization scripts, etc.); train_malware_classifier.py
and security/detector.py in this project implement their own equivalents.
"""

from .features import PEFeatureExtractor  # noqa: F401
