import ctypes


class SecureBuffer:
    """A bytes buffer that is pinned in memory and zeroed on unlock."""

    def __init__(self, key_bytes):
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode('utf-8')
        self.size = len(key_bytes)
        self.buffer = ctypes.create_string_buffer(key_bytes, self.size)
        ctypes.windll.kernel32.VirtualLock(ctypes.byref(self.buffer), self.size)

    def get_bytes(self):
        return self.buffer.raw

    def zero_and_unlock(self):
        ctypes.memset(self.buffer, 0, self.size)
        ctypes.windll.kernel32.VirtualUnlock(ctypes.byref(self.buffer), self.size)
