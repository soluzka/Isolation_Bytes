import base64

# 88-character key from fernet_token.txt
key = b'Z0FBQUFBQm9CNXViS2EyRHpMYV9oYk1TU1MzS3RwdlkxWG11OS1HY1dyWEF5bTl4OTlTUHpIb3ZqcWJsZDRwTlFBUEMwUWpmNl9zaXZWcnNBcXVVZ2VEcXFGVlhDNDVkTnc9PT09'

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
