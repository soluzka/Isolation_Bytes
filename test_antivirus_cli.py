from utils.paths import get_resource_path
import os

import os
import tempfile
import shutil
import pytest
import subprocess
import sys
from unittest.mock import patch
from cryptography.fernet import Fernet

FERNET_KEY = Fernet.generate_key().decode()
os.environ['FERNET_KEY'] = FERNET_KEY

# Helper to run CLI commands with patching
def run_cli(args, input_text=None):
    env = os.environ.copy()
    env['FORCE_MALWARE'] = '1'
    env['FERNET_KEY'] = FERNET_KEY
    cmd = [sys.executable, 'antivirus_cli.py'] + args
    result = subprocess.run(cmd, input=input_text, text=True, capture_output=True, env=env)  # nosem; nosec B603
    return result

def test_scan_nonexistent_file():
    result = run_cli(['scan', 'not_a_real_file.txt'])
    assert 'Path not found' in result.stdout

def test_quarantine_and_release():
    import os, time
    # Create a file that will always be detected as malware (e.g. EICAR test string)
    # Use a 'fake' EICAR string to avoid antivirus interference
    malware_string = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-FAKE-ANTIVIRUS-TEST-FILE!$H+H*'
    test_file = os.path.join(os.getcwd(), 'dummy.txt')
    with open(get_resource_path(os.path.join(test_file)), 'wb') as f:
        f.write(malware_string.encode('ascii'))
    time.sleep(0.1)  # Ensure file is closed and flushed
    # print('Test file exists before CLI:', os.path.exists(test_file))  # Removed to reduce spam
    try:
        # print('Test file stat:', os.stat(test_file))  # Removed to reduce spam
        with open(get_resource_path(os.path.join(test_file)), 'rb') as f:
            data = f.read()
        # print('Test file binary read length:', len(data))  # Removed to reduce spam
    except Exception as e:
        # print('Error reading test file before CLI:', e)  # Removed to reduce spam
        pass
    # Quarantine the file (simulate user confirmation)
    result = run_cli(['scan', test_file], input_text='y\n')
    assert 'quarantine' in result.stdout.lower() or 'infected file' in result.stdout.lower()
    # Check that the file is gone (delete if not)
    if os.path.exists(test_file):
        os.unlink(test_file)
    # Check that .enc exists in CLI quarantine dir
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    # print('Quarantine directory contents after scan:', os.listdir(quarantine_dir))  # Removed to reduce spam
    enc_file = os.path.join(quarantine_dir, 'dummy.txt.enc')
    if not os.path.exists(enc_file):
        # Enc file not found; this might indicate an issue with the quarantine process
        raise FileNotFoundError(f"Expected file not found in quarantine: {enc_file}")
    assert os.path.exists(enc_file)
    # Release the file
    released_dir = os.path.join(os.getcwd(), 'released')
    os.makedirs(released_dir, exist_ok=True)
    result = run_cli(['quarantine', 'release', 'dummy.txt.enc', released_dir])
    # Check that the file is released
    released_file = os.path.join(released_dir, 'dummy.txt')
    assert os.path.exists(released_file)
    # Cleanup
    if os.path.exists(enc_file):
        os.unlink(enc_file)
    if os.path.exists(released_file):
        os.unlink(released_file)
    if os.path.isdir(released_dir):
        try:
            os.rmdir(released_dir)
        except OSError:
            pass


def test_delete_from_quarantine():
    import os, time
    # Create a file that will always be detected as malware
    # Use a 'fake' EICAR string to avoid antivirus interference
    malware_string = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-FAKE-ANTIVIRUS-TEST-FILE!$H+H*'
    test_file = os.path.join(os.getcwd(), 'delete_me.txt')
    with open(get_resource_path(os.path.join(test_file)), 'wb') as f:
        f.write(malware_string.encode('ascii'))
    time.sleep(0.1)
    run_cli(['scan', test_file], input_text='y\n')
    if os.path.exists(test_file):
        os.unlink(test_file)
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    # print('Quarantine directory contents after scan:', os.listdir(quarantine_dir))  # Removed to reduce spam
    enc_file = os.path.join(quarantine_dir, 'delete_me.txt.enc')
    if not os.path.exists(enc_file):
        raise FileNotFoundError(f"Expected file not found in quarantine: {enc_file}")
    assert os.path.exists(enc_file)
    # Delete from quarantine (simulate user confirmation)
    result = run_cli(['quarantine', 'delete', 'delete_me.txt.enc'], input_text='y\n')
    assert 'deleted' in result.stdout.lower()
    assert not os.path.exists(enc_file)


def test_quarantine_cancel(tmp_path):
    # Create a file that will always be detected as malware
    malware_string = r'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'  # Use raw string or escape backslash
    test_file = tmp_path / 'cancel.txt'
    test_file.write_text(malware_string)
    # User cancels quarantine
    result = run_cli(['scan', str(test_file)], input_text='n\n')
    assert 'cancelled' in result.stdout.lower()
    assert test_file.exists()

# Additional edge case tests can be added as needed.

if __name__ == '__main__':
    pytest.main([__file__])