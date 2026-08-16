import hashlib
import base64
import numpy as np
from ml_security import SecurityMLModel
import logging
from datetime import datetime

class HashVerifier:
    def __init__(self):
        self.ml_model = SecurityMLModel()
        self.supported_hashes = ['sha256', 'sha512', 'sha3_256', 'sha3_512']
        self.suspicious_patterns = []
        
    def verify_hash(self, data: bytes, expected_hash: str, hash_type: str = 'sha256') -> bool:
        """
        Verify if the hash of the data matches the expected hash.
        
        Args:
            data: The data to hash
            expected_hash: The expected hash value
            hash_type: The type of hash algorithm to use
            
        Returns:
            bool: True if hash matches, False otherwise
        """
        if hash_type not in self.supported_hashes:
            raise ValueError(f"Unsupported hash type: {hash_type}")
            
        # Calculate hash
        h = hashlib.new(hash_type)
        h.update(data)
        calculated_hash = h.hexdigest()
        
        # Verify hash
        match = calculated_hash == expected_hash
        
        # Log verification
        logging.info(f"Hash verification result: {match}")
        logging.info(f"Expected: {expected_hash[:8]}... Actual: {calculated_hash[:8]}...")
        
        return match
        
    def verify_base64(self, b64_string: str, expected_hash: str, hash_type: str = 'sha256') -> bool:
        """
        Verify a base64 encoded string against an expected hash.
        """
        try:
            decoded = base64.urlsafe_b64decode(b64_string)
            return self.verify_hash(decoded, expected_hash, hash_type)
        except Exception as e:
            logging.error(f"Error decoding base64: {e}")
            return False
            
    def analyze_suspicious_patterns(self, data: bytes) -> dict:
        """
        Use ML to analyze data for suspicious patterns.
        """
        # Create features from hash
        hash_features = self._extract_hash_features(data)
        
        # Use ML model to analyze
        result = self.ml_model.pipeline.predict([hash_features])
        
        return {
            'is_suspicious': result[0] == -1,
            'confidence': self._calculate_confidence(result[0]),
            'timestamp': datetime.now().isoformat()
        }
        
    def _extract_hash_features(self, data: bytes) -> np.ndarray:
        """
        Extract features from data for ML analysis.
        """
        features = []
        
        # Calculate multiple hashes
        for hash_type in self.supported_hashes:
            h = hashlib.new(hash_type)
            h.update(data)
            features.extend(self._hash_to_features(h.hexdigest()))
            
        # Add length features
        features.append(len(data))
        features.append(len(data) % 256)
        
        return np.array(features)
        
    def _hash_to_features(self, hash_str: str) -> list:
        """
        Convert hash string to numerical features.
        """
        features = []
        
        # Character frequency
        for char in set(hash_str):
            features.append(hash_str.count(char))
            
        # Hex digit distribution
        hex_digits = '0123456789abcdef'
        for digit in hex_digits:
            features.append(hash_str.count(digit))
            
        # Pair frequency
        for i in range(0, len(hash_str)-1, 2):
            pair = hash_str[i:i+2]
            features.append(hash_str.count(pair))
            
        return features
        
    def _calculate_confidence(self, result: int) -> float:
        """
        Calculate confidence score from ML result.
        """
        if result == 1:
            return 0.95  # Normal
        else:
            return 0.05  # Suspicious

# Example usage
def main():
    verifier = HashVerifier()
    
    # Test data
    test_data = b"This is a test file contents"
    expected_sha256 = "a45678b9012345678901234567890123456789012345678901234567890123456"
    
    # Create and test verifier
    verifier = HashVerifier()
    
    # Train the ML model with some sample data
    sample_data = [
        b"This is a normal file",
        b"Another regular file contents",
        b"Yet another normal file",
        b"This is a test of the emergency broadcast system"
    ]
    
    # Extract features from sample data
    sample_features = []
    for data in sample_data:
        hash_features = verifier._extract_hash_features(data)
        sample_features.append(hash_features)
    
    # Train the model
    verifier.ml_model.train_model(np.array(sample_features))
    
    # Now we can use the verifier
    result = verifier.verify_hash(test_data, expected_sha256)
    print(f"Hash verification result: {result}")
    
    # Analyze for suspicious patterns
    analysis = verifier.analyze_suspicious_patterns(test_data)
    print(f"ML analysis: {analysis}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
    print("hash2 does NOT match SHA-256 or BLAKE2s of input_data")
