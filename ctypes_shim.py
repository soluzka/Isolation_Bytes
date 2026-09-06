"""Compatibility shim for Windows-specific ctypes usage on Linux/macOS.

On Windows, ``ctypes.windll`` is used to access Win32 APIs. On Linux/macOS
this attribute does not exist, so code that does ``ctypes.windll.something``
raises ``AttributeError``. This shim provides a no-op stand-in so that
modules importing Windows-specific functionality can be imported on the
cloud server without crashing.
"""
import ctypes
import sys

if not hasattr(ctypes, 'windll'):
    class _WinDllStub:
        """No-op stand-in for ``ctypes.windll`` on non-Windows platforms."""
        def __getattr__(self, name):
            raise AttributeError(
                f'windll.{name} is not available on {sys.platform}'
            )
    ctypes.windll = _WinDllStub()

if not hasattr(ctypes, 'oledll'):
    class _OleDllStub:
        def __getattr__(self, name):
            raise AttributeError(
                f'oledll.{name} is not available on {sys.platform}'
            )
    ctypes.oledll = _OleDllStub()

# winreg is Windows-only; provide a stub module on other platforms
if sys.platform != 'win32':
    import types
    winreg = types.ModuleType('winreg')
    winreg.HKEY_CLASSES_ROOT = -2147483648
    winreg.HKEY_LOCAL_MACHINE = -2147483646
    winreg.HKEY_CURRENT_USER = -2147483647
    winreg.HKEY_USERS = -2147483645
    winreg.HKEY_CURRENT_CONFIG = -2147483643
    winreg.KEY_READ = 131097
    winreg.KEY_WRITE = 131078
    winreg.KEY_ALL_ACCESS = 983103
    winreg.REG_SZ = 1
    winreg.REG_DWORD = 4
    winreg.REG_EXPAND_SZ = 2
    winreg.REG_BINARY = 3
    winreg.REG_MULTI_SZ = 7
    class _FakeKey:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def Close(self):
            pass
    def _stub_open(*args, **kwargs):
        return _FakeKey()
    def _stub_query(*args, **kwargs):
        return ('', 0)
    def _stub_enum(*args, **kwargs):
        raise OSError('No more data')
    winreg.OpenKey = _stub_open
    winreg.OpenKeyEx = _stub_open
    winreg.CloseKey = lambda key: None
    winreg.QueryValueEx = _stub_query
    winreg.QueryValue = lambda key, name: ''
    winreg.SetValueEx = lambda *a, **k: None
    winreg.SetValue = lambda *a, **k: None
    winreg.EnumKey = _stub_enum
    winreg.EnumValue = _stub_enum
    winreg.DeleteKey = lambda *a, **k: None
    winreg.DeleteValue = lambda *a, **k: None
    winreg.CreateKey = _stub_open
    winreg.CreateKeyEx = _stub_open
    winreg.FlushKey = lambda: None
    winreg.SaveKey = lambda *a, **k: None
    winreg.LoadKey = lambda *a, **k: None
    winreg.UnloadKey = lambda *a, **k: None
    winreg.DisableReflectionKey = lambda *a, **k: None
    winreg.EnableReflectionKey = lambda *a, **k: None
    winreg.QueryReflectionKey = lambda *a, **k: False
    winreg.ExpandEnvironmentStrings = lambda s: s
    sys.modules['winreg'] = winreg
