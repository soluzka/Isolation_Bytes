import logging
from security.secure_message import encrypt_message
import os
import sys
from logging.handlers import RotatingFileHandler

def get_basedir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def log_secure_message(logger, level, message, sensitive=False):
    """Log a message with optional encryption for sensitive data"""
    if sensitive:
        # Use the imported encrypt_message function
        encrypted_msg = encrypt_message(message)
        logger.log(level, encrypted_msg)
    else:
        logger.log(level, message)

def setup_secure_logging(log_file, max_bytes=5*1024*1024, backup_count=3):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    # Use the absolute path based on the application's base directory
    log_path = os.path.join(get_basedir(), log_file)
    file_handler = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)
    logger.handlers = [file_handler, console_handler]
    return logger
