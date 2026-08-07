from utils.paths import get_resource_path
import os

import os
import logging
import sys

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

import argparse
from cryptography.fernet import Fernet
from data_analysis import analyze_data
from secure_memory import SecureBuffer

# Setup logging
logging.basicConfig(
    filename='crypto_events.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Get Fernet key from environment variable
FERNET_KEY = os.environ.get('FERNET_KEY')
if FERNET_KEY is None:
    raise EnvironmentError("FERNET_KEY environment variable not set. Please set it before running this script.")
if isinstance(FERNET_KEY, str):
    FERNET_KEY = FERNET_KEY.encode()

# Securely lock Fernet key in memory
secure_key = SecureBuffer(FERNET_KEY)


def encrypt_file(input_path, output_path, key=FERNET_KEY):
    logging.info(f"ENCRYPT START: input='{input_path}' output='{output_path}'")

    # Read input
    if input_path == '-':
        data = sys.stdin.buffer.read()
        logging.info("Read data from stdin for encryption.")
    else:
        with open(get_resource_path(os.path.join(input_path)), 'rb') as f:
            data = f.read()
        logging.info(f"Read data from file: {input_path}")

    # Run data analysis (kept for parity with existing behavior; its result is
    # not the encryption key -- see NOTE below).
    analyze_data(data)

    # Use secure key for Fernet
    actual_key = secure_key.get_bytes()
    fernet = Fernet(actual_key)
    encrypted = fernet.encrypt(data)

    # Write output: prepend the actual key used for encryption as header (44 bytes).
    # NOTE: This used to write the unrelated key returned by analyze_data() as the
    # header instead of the key actually used to encrypt (actual_key, from
    # FERNET_KEY). Since decrypt_file() auto-extracts the header as the
    # decryption key when none is supplied, that mismatch meant decryption
    # would always fail with InvalidToken unless the caller separately knew
    # and passed the real FERNET_KEY by hand.
    if output_path == '-':
        sys.stdout.buffer.write(actual_key + encrypted)
        logging.info("Wrote encrypted data with key header to stdout.")
    else:
        with open(get_resource_path(os.path.join(output_path)), 'wb') as f:
            f.write(actual_key + encrypted)
        logging.info(f"Wrote encrypted data with key header to file: {output_path}")

    if input_path != '-' and output_path != '-':
        print(f"Encrypted {input_path} -> {output_path} (binary-safe, key in header)")
        logging.info(f"ENCRYPT SUCCESS: {input_path} -> {output_path}")

    # Zero and unlock the secure key after use
    secure_key.zero_and_unlock()


def decrypt_file(input_path, output_path, key=None):
    logging.info(f"DECRYPT START: input='{input_path}' output='{output_path}'")

    # Read input
    if input_path == '-':
        encrypted = sys.stdin.buffer.read()
        logging.info("Read encrypted data from stdin for decryption.")
    else:
        with open(get_resource_path(os.path.join(input_path)), 'rb') as f:
            encrypted = f.read()
        logging.info(f"Read encrypted data from file: {input_path}")

    # Extract key from header if not provided
    if key is None:
        key = encrypted[:44]  # Fernet keys are 44 bytes base64
        encrypted = encrypted[44:]

    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    # Write output
    if output_path == '-':
        sys.stdout.buffer.write(decrypted)
        logging.info("Wrote decrypted data to stdout.")
    else:
        with open(get_resource_path(os.path.join(output_path)), 'wb') as f:
            f.write(decrypted)
        logging.info(f"Wrote decrypted data to file: {output_path}")

    if input_path != '-' and output_path != '-':
        print(f"Decrypted {input_path} -> {output_path} (binary-safe, key from header)")
        logging.info(f"DECRYPT SUCCESS: {input_path} -> {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a file using Fernet."
    )
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode: encrypt or decrypt")
    parser.add_argument('input_file', help="Input file path")
    parser.add_argument('output_file', help="Output file path")
    args = parser.parse_args()

    if args.mode == 'encrypt':
        encrypt_file(args.input_file, args.output_file)
    elif args.mode == 'decrypt':
        decrypt_file(args.input_file, args.output_file)

if __name__ == "__main__":
    main()