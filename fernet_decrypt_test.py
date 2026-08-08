from cryptography.fernet import Fernet
import os

# Ensure the key is valid
key = os.environ.get('FERNET_KEY')
if not key or len(key) != 44:
    print("Generating a new Fernet key as the environment variable is missing or invalid.")
    key = Fernet.generate_key().decode()
    os.environ['FERNET_KEY'] = key
    print(f"Generated Fernet key: {key}")

try:
    f = Fernet(key)
    print("Fernet key is valid.")
except ValueError as e:
    print(f"Invalid Fernet key: {e}")

# Fernet-encrypted message from base64.txt
ciphertext = b'gAAAAABoB5ubKa2DzLa_hbMSSS3KtpvY1Xmu9-GcWrXAym9x99SPzHovjqbld4pNQAPC0Qjf6_sivVrsAquUgeDqqFVXC45dNw===='

try:
    plaintext = f.decrypt(ciphertext)
    print('Decrypted message:')
    try:
        print(plaintext.decode())
    except UnicodeDecodeError:
        print(plaintext)  # Print raw bytes if not UTF-8
except Exception as e:
    print(f'Failed to decrypt: {e}')
