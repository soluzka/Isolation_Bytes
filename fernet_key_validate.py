import base64
import os

# Read the Fernet key from environment or from the fernet_token.txt file.
key_source = os.environ.get('FERNET_KEY', '')
if not key_source:
    token_path = 'fernet_token.txt'
    if os.path.exists(token_path):
        with open(token_path, 'rb') as f:
            key_source = f.read().strip()
    else:
        raise SystemExit('Set FERNET_KEY or place the key in fernet_token.txt')

key = key_source if isinstance(key_source, bytes) else key_source.encode()

try:
    decoded = base64.urlsafe_b64decode(key)
    print(f"Decoded length: {len(decoded)} bytes")
    print(f"Decoded bytes: {decoded}")
    # Check if this is a valid Fernet key (32 bytes)
    if len(decoded) == 32:
        correct_key = base64.urlsafe_b64encode(decoded)
        print(f"This is a valid Fernet key! Use this for Fernet:")
        print(correct_key.decode())
    else:
        print("This is NOT a valid Fernet key (should be 32 bytes when decoded)")
except Exception as e:
    print(f"Failed to decode: {e}")
