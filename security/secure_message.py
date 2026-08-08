"""
Secure messaging module for encrypting log messages and sensitive information
This provides encryption functions to protect sensitive data in logs
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_encryption_key():
    """Generate a deterministic encryption key based on machine-specific information"""
    # Use a combination of machine-specific values as salt
    import socket
    salt = socket.gethostname().encode() + b'secure_log_salt'
    # Use a fixed passphrase (in production, this would be securely stored)
    password = b"windows_defender_secure_logging_key"
    
    # Use PBKDF2 to derive a secure key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_message(message):
    """Encrypt a message string for secure logging"""
    try:
        if not isinstance(message, str):
            message = str(message)
            
        # Get encryption key
        key = get_encryption_key()
        fernet = Fernet(key)
        
        # Encrypt the message
        encrypted_data = fernet.encrypt(message.encode())
        return f"[ENCRYPTED]{base64.b64encode(encrypted_data).decode()}[/ENCRYPTED]"
    except Exception:
        # If encryption fails, return the original message with a note
        return f"{message} [encryption failed]"

def decrypt_message(encrypted_message):
    """Decrypt a message that was encrypted with encrypt_message"""
    try:
        # Extract the encrypted data
        if not encrypted_message.startswith("[ENCRYPTED]") or not encrypted_message.endswith("[/ENCRYPTED]"):
            return encrypted_message
            
        encrypted_data = encrypted_message[len("[ENCRYPTED]"):-len("[/ENCRYPTED]")]
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Get encryption key
        key = get_encryption_key()
        fernet = Fernet(key)
        
        # Decrypt the message
        decrypted_data = fernet.decrypt(encrypted_bytes)
        return decrypted_data.decode()
    except Exception:
        # If decryption fails, return the original encrypted message
        return encrypted_message
