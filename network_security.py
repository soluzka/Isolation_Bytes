from cryptography.fernet import Fernet
import socket
import threading
import json
import base64
import logging
from typing import Dict, Any
import time

class NetworkSecurity:
    def __init__(self):
        self._encryption_key = None
        self._encryption_enabled = False
        self._decryption_cache = {}
        self._cache_timeout = 300  # 5 minutes
        self._lock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize security parameters
        self._max_key_age = 86400  # 24 hours
        self._key_generation_time = None
        self._key_rotation_interval = 3600  # 1 hour
        self._key_rotation_thread = None
        self._key_rotation_running = False
        
        # Initialize secure socket wrapper
        self._secure_socket = None
        
        # Initialize security metrics
        self._encryption_metrics = {
            'total_encrypted': 0,
            'total_decrypted': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'last_key_rotation': None
        }

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_security.log'),
                logging.StreamHandler()
            ]
        )

    def generate_key(self) -> bytes:
        """Generate a new encryption key with security checks"""
        try:
            self._encryption_key = Fernet.generate_key()
            self._key_generation_time = time.time()
            self._logger.info("Generated new encryption key")
            self._encryption_metrics['last_key_rotation'] = time.time()
            
            # Start key rotation if not already running
            if not self._key_rotation_running:
                self._start_key_rotation()
                
            return self._encryption_key
        except Exception as e:
            self._logger.error(f"Error generating encryption key: {str(e)}")
            raise

    def load_key(self, key: bytes):
        """Load an existing encryption key with validation"""
        try:
            # Validate key length
            if len(key) != 32:
                raise ValueError("Invalid key length. Must be 32 bytes")
                
            # Test key validity
            f = Fernet(key)
            test_data = f.encrypt(b"test")
            f.decrypt(test_data)
            
            self._encryption_key = key
            self._key_generation_time = time.time()
            self._logger.info("Loaded encryption key successfully")
            
            # Reset key rotation timer
            if self._key_rotation_thread:
                self._key_rotation_running = False
                self._key_rotation_thread.join()
                self._start_key_rotation()
                
        except Exception as e:
            self._logger.error(f"Error loading encryption key: {str(e)}")
            raise ValueError(f"Invalid encryption key: {str(e)}")

    def _start_key_rotation(self):
        """Start key rotation thread with enhanced security"""
        if not self._key_rotation_running:
            self._key_rotation_running = True
            self._key_rotation_thread = threading.Thread(
                target=self._key_rotation_loop,
                daemon=True,
                name="network_key_rotation"
            )
            self._key_rotation_thread.start()
            self._logger.info("Started key rotation thread")

    def _key_rotation_loop(self):
        """Key rotation loop with enhanced security checks"""
        while self._key_rotation_running:
            try:
                if self._key_generation_time:
                    current_age = time.time() - self._key_generation_time
                    
                    # Rotate key if it's too old
                    if current_age > self._key_rotation_interval:
                        self.generate_key()
                        self._logger.info(f"Key rotated due to age ({current_age:.0f}s)")
                    
                    # Log key age statistics
                    if current_age > self._key_rotation_interval * 0.8:
                        self._logger.warning(f"Key age approaching rotation threshold ({current_age:.0f}s)")
                    
                # Check every minute
                time.sleep(60)
                
            except Exception as e:
                self._logger.error(f"Error in key rotation loop: {str(e)}")
                # Wait before retrying with exponential backoff
                wait_time = 60 * min(16, 2 ** self._encryption_metrics.get('key_rotation_errors', 0))
                self._logger.info(f"Waiting {wait_time}s before retrying key rotation")
                time.sleep(wait_time)
                
                # Track rotation errors
                with self._lock:
                    self._encryption_metrics['key_rotation_errors'] = \
                        self._encryption_metrics.get('key_rotation_errors', 0) + 1

    def enable_encryption(self) -> bool:
        """Enable network encryption"""
        if not self._encryption_key:
            self.generate_key()
        self._encryption_enabled = True
        self._logger.info("Network encryption enabled")
        return True

    def disable_encryption(self) -> bool:
        """Disable network encryption"""
        self._encryption_enabled = False
        self._logger.info("Network encryption disabled")
        return True

    def encrypt_data(self, data: Dict[str, Any]) -> str:
        """Encrypt network data with security checks"""
        if not self._encryption_enabled:
            return json.dumps(data)

        try:
            # Check if key needs rotation
            if self._key_generation_time and \
               time.time() - self._key_generation_time > self._max_key_age:
                self.generate_key()
                
            f = Fernet(self._encryption_key)
            json_data = json.dumps(data).encode()
            encrypted = f.encrypt(json_data)
            
            # Update metrics
            with self._lock:
                self._encryption_metrics['total_encrypted'] += 1
                
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            self._logger.error(f"Error encrypting data: {str(e)}")
            raise

    def decrypt_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt network data with cache and security checks"""
        if not self._encryption_enabled:
            return json.loads(encrypted_data)

        try:
            # Check cache first
            with self._lock:
                if encrypted_data in self._decryption_cache:
                    cached = self._decryption_cache[encrypted_data]
                    if time.time() - cached['timestamp'] < self._cache_timeout:
                        with self._lock:
                            self._encryption_metrics['cache_hits'] += 1
                        return cached['data']

            # Not in cache or cache expired, decrypt
            f = Fernet(self._encryption_key)
            encrypted = base64.b64decode(encrypted_data)
            decrypted = f.decrypt(encrypted)
            data = json.loads(decrypted)

            # Validate decrypted data
            if not isinstance(data, dict):
                raise ValueError("Decrypted data is not a dictionary")
                
            # Cache the result
            with self._lock:
                self._decryption_cache[encrypted_data] = {
                    'data': data,
                    'timestamp': time.time()
                }
                self._encryption_metrics['cache_misses'] += 1
                self._encryption_metrics['total_decrypted'] += 1

            return data
        except Exception as e:
            self._logger.error(f"Error decrypting data: {str(e)}")
            raise

    def clear_cache(self):
        """Clear the decryption cache with metrics reset"""
        with self._lock:
            self._decryption_cache.clear()
            self._encryption_metrics['cache_hits'] = 0
            self._encryption_metrics['cache_misses'] = 0
        self._logger.info("Decryption cache cleared and metrics reset")

    def get_encryption_status(self) -> Dict[str, Any]:
        """Get comprehensive encryption status with security metrics"""
        key_age = None
        if self._key_generation_time:
            key_age = time.time() - self._key_generation_time
            
        return {
            'enabled': self._encryption_enabled,
            'key_present': bool(self._encryption_key),
            'key_age_seconds': key_age,
            'cache_size': len(self._decryption_cache),
            'metrics': self._encryption_metrics,
            'key_rotation_running': self._key_rotation_running,
            'next_rotation': self._next_rotation_time(),
            'key_health': self._get_key_health(),
            'rotation_status': self._get_rotation_status()
        }
        
    def _next_rotation_time(self) -> float:
        """Get time until next key rotation"""
        if not self._key_generation_time:
            return 0
            
        current_age = time.time() - self._key_generation_time
        if current_age >= self._max_key_age:
            return 0
            
        return self._max_key_age - current_age
        
    def _get_key_health(self) -> Dict[str, Any]:
        """Get key health metrics"""
        if not self._key_generation_time:
            return {
                'status': 'unknown',
                'age': 0,
                'health_score': 0
            }
            
        current_age = time.time() - self._key_generation_time
        age_percentage = (current_age / self._max_key_age) * 100
        
        # Calculate health score
        health_score = 100
        if age_percentage > 80:
            health_score = 30
        elif age_percentage > 60:
            health_score = 60
        elif age_percentage > 40:
            health_score = 80
            
        return {
            'status': 'healthy' if health_score > 60 else 'warning',
            'age': current_age,
            'health_score': health_score,
            'age_percentage': age_percentage
        }
        
    def _get_rotation_status(self) -> Dict[str, Any]:
        """Get key rotation status"""
        return {
            'running': self._key_rotation_running,
            'interval': self._key_rotation_interval,
            'errors': self._encryption_metrics.get('key_rotation_errors', 0),
            'last_rotation': self._encryption_metrics.get('last_key_rotation', None)
        }

    def protect_socket(self, sock: socket.socket) -> socket.socket:
        """Wrap a socket with encryption/decryption"""
        class ProtectedSocket(socket.socket):
            def __init__(self, sock, security):
                self._sock = sock
                self._security = security

            def send(self, data: Dict[str, Any]):
                encrypted = self._security.encrypt_data(data)
                return self._sock.send(encrypted.encode())

            def recv(self, bufsize: int) -> Dict[str, Any]:
                encrypted = self._sock.recv(bufsize).decode()
                return self._security.decrypt_data(encrypted)

            def __getattr__(self, name):
                return getattr(self._sock, name)

        return ProtectedSocket(sock, self)

# Global instance with singleton pattern
class NetworkSecurityManager:
    _instance = None
    _lock = threading.Lock()

    @staticmethod
    def get_instance():
        """Get singleton instance with thread-safe initialization"""
        if NetworkSecurityManager._instance is None:
            with NetworkSecurityManager._lock:
                if NetworkSecurityManager._instance is None:
                    NetworkSecurityManager._instance = NetworkSecurity()
        return NetworkSecurityManager._instance

# Example usage:
if __name__ == "__main__":
    # Create security instance
    security = NetworkSecurity()
    
    # Generate key and enable encryption
    security.generate_key()
    security.enable_encryption()
    
    # Test encryption/decryption
    data = {"message": "Hello, secure network!", "timestamp": time.time()}
    encrypted = security.encrypt_data(data)
    decrypted = security.decrypt_data(encrypted)
    
    print(f"Original: {data}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
