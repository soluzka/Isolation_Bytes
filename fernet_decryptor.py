from utils.paths import get_resource_path
import os

import sys
from cryptography.fernet import Fernet

def decrypt_fernet_token(token_b64, key_b64):
    try:
        f = Fernet(key_b64)
        plaintext = f.decrypt(token_b64.encode())
        print("Decryption successful!")
        try:
            print("Plaintext (utf-8):", plaintext.decode('utf-8'))
        except UnicodeDecodeError:
            print("Plaintext (hex):", plaintext.hex())
        return plaintext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) == 3:
        key_b64 = sys.argv[1]
        token_b64 = sys.argv[2]
    else:
        with open("get_resource_path(os.path.join(fernet_key.txt))", "r") as kf:
            key_b64 = kf.read().strip()
        with open("get_resource_path(os.path.join(fernet_token.txt))", "r") as tf:
            token_b64 = tf.read().strip()
    decrypt_fernet_token(token_b64, key_b64)