"""Helpers for loading persisted model artifacts across library versions."""

import pickle
import threading
import warnings

import joblib
from sklearn.exceptions import InconsistentVersionWarning

# NumPy 2 renamed the private ``numpy.core`` namespace to ``numpy._core``.
# Pickles produced under NumPy 2 reference the new name, so loading them with
# the NumPy 1.x that the desktop build bundles raises
# ``ModuleNotFoundError: No module named 'numpy._core'``.
_NUMPY2_MODULE_PREFIX = 'numpy._core'
_NUMPY1_MODULE_PREFIX = 'numpy.core'


def _numpy1_compat_unpickler():
    """Return an unpickler that maps NumPy 2 module names onto NumPy 1, or
    ``None`` when the running NumPy already provides ``numpy._core``."""
    import numpy as np
    import joblib.numpy_pickle as numpy_pickle

    if hasattr(np, '_core'):
        return None

    class _Numpy1CompatUnpickler(numpy_pickle.NumpyUnpickler):
        def find_class(self, module, name):
            if (module == _NUMPY2_MODULE_PREFIX
                    or module.startswith(_NUMPY2_MODULE_PREFIX + '.')):
                module = _NUMPY1_MODULE_PREFIX + module[len(_NUMPY2_MODULE_PREFIX):]
            return super().find_class(module, name)

    return _Numpy1CompatUnpickler


_NUMPY_COMPAT_LOCK = threading.Lock()


def _compat_pickle_load(handle):
    """Unpickle a nested array stream, remapping NumPy 2 module names."""
    class _CompatUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            if (module == _NUMPY2_MODULE_PREFIX
                    or module.startswith(_NUMPY2_MODULE_PREFIX + '.')):
                module = _NUMPY1_MODULE_PREFIX + module[len(_NUMPY2_MODULE_PREFIX):]
            return super().find_class(module, name)

    return _CompatUnpickler(handle).load()


def _load_with_numpy_compat(model_path):
    """Load a joblib file, remapping NumPy 2 module names for NumPy 1.x."""
    import joblib.numpy_pickle as numpy_pickle

    unpickler_cls = _numpy1_compat_unpickler()
    path = str(model_path)
    wrapper_cls = numpy_pickle.NumpyArrayWrapper
    original_read_array = wrapper_cls.read_array

    def read_array(self, unpickler):
        # Only object arrays are stored as a nested pickle; the numeric
        # array path does not reference NumPy module names.
        if not self.dtype.hasobject:
            return original_read_array(self, unpickler)
        return _compat_pickle_load(unpickler.file_handle)

    # The nested array unpickler is joblib's, so patch it for the duration
    # of this load and restore it afterwards.
    with _NUMPY_COMPAT_LOCK:
        wrapper_cls.read_array = read_array
        try:
            with open(path, 'rb') as handle:
                with numpy_pickle._read_fileobject(handle, path) as fileobj:
                    if isinstance(fileobj, str):
                        # Legacy joblib format without a pickle stream.
                        return numpy_pickle.load_compatibility(fileobj)
                    return unpickler_cls(path, fileobj).load()
        finally:
            wrapper_cls.read_array = original_read_array


def load_model_safely(model_path):
    """Load a scikit-learn/joblib artifact, tolerating version differences.

    Suppresses scikit-learn's version-mismatch warning and retries with a
    compatibility unpickler when the artifact was pickled under NumPy 2 but
    the running interpreter has NumPy 1.x.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
        try:
            return joblib.load(model_path)
        except ModuleNotFoundError as exc:
            if 'numpy._core' not in str(exc):
                raise
            return _load_with_numpy_compat(model_path)
        except AttributeError as exc:
            # Some joblib builds surface the missing module as an
            # attribute error on the NumPy module itself.
            if 'numpy._core' not in str(exc):
                raise
            return _load_with_numpy_compat(model_path)


def initialize_database():
    """Initialize database connection with proper error handling."""
    try:
        # Add your database initialization code here
        pass
    except Exception as e:
        import logging
        logging.error(f"Database initialization failed: {str(e)}")
        # Provide fallback behavior
        return None
