import ctypes

class SecureBuffer:
    def __init__(self, key_bytes):
        self.size = len(key_bytes)
        self.buffer = ctypes.create_string_buffer(key_bytes, self.size)
        ctypes.windll.kernel32.VirtualLock(ctypes.byref(self.buffer), self.size)

    def get_bytes(self):
        return self.buffer.raw

    def zero_and_unlock(self):
        ctypes.memset(self.buffer, 0, self.size)
        ctypes.windll.kernel32.VirtualUnlock(ctypes.byref(self.buffer), self.size)
