"""
secure_message.py

Encrypt and decrypt messages for secure sharing over the internet using Fernet symmetric encryption.

Usage:
  python secure_message.py encrypt "your message here"
  python secure_message.py decrypt "encrypted_token_here"

Requires the FERNET_KEY environment variable (44-character base64 string) or config.py.
"""
import sys
from cryptography.fernet import Fernet
from secure_memory import SecureBuffer

try:
    from config import FERNET_KEY
except ImportError:
    import os
    FERNET_KEY = os.environ.get('FERNET_KEY')

if not FERNET_KEY or len(FERNET_KEY) != 44:
    print("[ERROR] FERNET_KEY must be set (44 chars, base64). Set it in config.py or as an environment variable.")
    sys.exit(1)

secure_key = SecureBuffer(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
fernet = Fernet(secure_key.get_bytes())

def encrypt_message(message: str) -> str:
    result = fernet.encrypt(message.encode()).decode()
    secure_key.zero_and_unlock()
    return result

def decrypt_message(token: str) -> str:
    result = fernet.decrypt(token.encode()).decode()
    secure_key.zero_and_unlock()
    return result

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        print("Usage:")
        print("  python secure_message.py encrypt \"your message here\"")
        print("  python secure_message.py decrypt \"encrypted_token_here\"")
        sys.exit(1)
    mode = sys.argv[1]
    arg = sys.argv[2]
    if mode == "encrypt":
        print(encrypt_message(arg))
    elif mode == "decrypt":
        try:
            print(decrypt_message(arg))
        except Exception as e:
            print(f"[ERROR] Failed to decrypt: {e}")
            sys.exit(2)
