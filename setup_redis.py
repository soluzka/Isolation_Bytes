import os
import urllib.request
import zipfile
import shutil
import winreg
import sys
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
REDIS_URL = "https://github.com/microsoftarchive/redis/releases/download/win-3.2.100/Redis-x64-3.2.100.zip"
REDIS_DIR = Path("C:\\Redis")
REDIS_HOME_KEY = r"Environment"

# Create Redis directory if it doesn't exist
def create_redis_dir():
    try:
        REDIS_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"Created Redis directory at {REDIS_DIR}")
        return True
    except Exception as e:
        logging.error(f"Error creating Redis directory: {e}")
        return False

# Download Redis
def download_redis():
    try:
        logging.info("Downloading Redis...")
        temp_zip = REDIS_DIR / "redis.zip"
        
        # Download using urllib
        urllib.request.urlretrieve(REDIS_URL, temp_zip)
        
        logging.info("Download completed successfully")
        return temp_zip
    except Exception as e:
        logging.error(f"Error downloading Redis: {e}")
        return None

# Extract Redis
def extract_redis(zip_file):
    try:
        logging.info("Extracting Redis...")
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(REDIS_DIR)
        logging.info("Redis extracted successfully")
        return True
    except Exception as e:
        logging.error(f"Error extracting Redis: {e}")
        return False

# Set up environment variable
def setup_env_variable():
    try:
        # Open user environment variables
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REDIS_HOME_KEY, 0, winreg.KEY_ALL_ACCESS)
        
        # Get current PATH
        path, _ = winreg.QueryValueEx(key, "Path")
        
        # Add Redis directory if not already present
        if str(REDIS_DIR) not in path:
            path = f"{path};{REDIS_DIR}"
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, path)
        
        # Set REDIS_HOME
        winreg.SetValueEx(key, "REDIS_HOME", 0, winreg.REG_SZ, str(REDIS_DIR))
        
        winreg.CloseKey(key)
        logging.info(f"Set REDIS_HOME environment variable to {REDIS_DIR}")
        logging.info(f"Added {REDIS_DIR} to user PATH")
        return True
    except Exception as e:
        logging.error(f"Error setting up environment variable: {e}")
        return False

# Add Redis to PATH
def add_to_path():
    try:
        # Open user environment variables
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REDIS_HOME_KEY, 0, winreg.KEY_ALL_ACCESS)
        
        # Get current PATH
        path, _ = winreg.QueryValueEx(key, "Path")
        
        # Add Redis directory if not already present
        if str(REDIS_DIR) not in path:
            path = f"{path};{REDIS_DIR}"
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, path)
            logging.info(f"Added {REDIS_DIR} to user PATH")
        
        winreg.CloseKey(key)
        return True
    except Exception as e:
        logging.error(f"Error adding Redis to PATH: {e}")
        return False

def start_redis_server():
    """Start the Redis server"""
    try:
        # Create a config file if it doesn't exist
        config_path = REDIS_DIR / "redis.conf"
        if not config_path.exists():
            with open(config_path, 'w') as f:
                f.write("""
# Redis configuration
port 6379
dir C:\\Redis
dbfilename dump.rdb
appendonly yes
""")
        
        # Start Redis server
        import subprocess
        redis_exe = REDIS_DIR / "redis-server.exe"
        if not redis_exe.exists():
            logging.error("Redis executable not found!")
            return False
            
        # Start Redis as a service
        try:
            subprocess.run([str(redis_exe), str(config_path)], check=True)
            logging.info("Redis server started successfully!")
            return True
        except subprocess.CalledProcessError:
            logging.error("Failed to start Redis server!")
            return False
            
    except Exception as e:
        logging.error(f"Error starting Redis server: {e}")
        return False

def main():
    # Create Redis directory
    if not create_redis_dir():
        sys.exit(1)
    
    # Download Redis
    zip_file = download_redis()
    if not zip_file:
        sys.exit(1)
    
    # Extract Redis
    if not extract_redis(zip_file):
        sys.exit(1)
    
    # Set up environment variable
    if not setup_env_variable():
        sys.exit(1)
    
    # Add to PATH
    if not add_to_path():
        sys.exit(1)
    
    # Start Redis server
    if not start_redis_server():
        sys.exit(1)
    
    # Clean up
    try:
        os.remove(zip_file)
    except:
        pass
    
    logging.info("Redis setup and server started successfully!")
    logging.info("Redis is now running on port 6379")

if __name__ == "__main__":
    main()
