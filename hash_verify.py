import hashlib
import base64
import logging
import os
from datetime import datetime

import numpy as np
from ml_security import SecurityMLModel


class HashVerifier:
    def __init__(self):
        self.ml_model = SecurityMLModel()
        self.supported_hashes = [
            'sha256', 'sha512', 'sha3_256', 'sha3_512'
        ]
        self.suspicious_patterns = []

    @staticmethod
    def fingerprint_file(filepath: str, chunk_size: int = 1024 * 1024) -> dict:
        """Calculate stable content identities without loading the whole file.

        This is an identity primitive, not a malware verdict. Every supported
        digest is calculated from the exact bytes read from disk, so callers can
        detect genuinely new/changed content without treating hash characters
        as malware features.
        """
        if not filepath or not os.path.isfile(filepath):
            raise FileNotFoundError(filepath)
        if chunk_size < 4096:
            chunk_size = 4096

        algorithms = ('sha256', 'sha512', 'sha3_256', 'sha3_512')
        hashers = {name: hashlib.new(name) for name in algorithms}
        size = 0
        with open(filepath, 'rb') as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                size += len(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
        return {
            name: hashers[name].hexdigest()
            for name in algorithms
        } | {'size': size}

    def verify_hash(
        self, data: bytes, expected_hash: str, hash_type: str = 'sha256'
    ) -> bool:
        """Verify if the hash of the data matches the expected hash."""
        if hash_type not in self.supported_hashes:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        h = hashlib.new(hash_type)
        h.update(data)
        calculated_hash = h.hexdigest()
        match = calculated_hash == expected_hash
        logging.info("Hash verification result: %s", match)
        logging.info(
            "Expected: %s... Actual: %s...",
            expected_hash[:8], calculated_hash[:8]
        )
        return match

    def verify_base64(
        self, b64_string: str, expected_hash: str, hash_type: str = 'sha256'
    ) -> bool:
        """Verify a base64 encoded string against an expected hash."""
        try:
            decoded = base64.urlsafe_b64decode(b64_string)
            return self.verify_hash(decoded, expected_hash, hash_type)
        except Exception as exc:
            logging.error("Error decoding base64: %s", exc)
            return False

    def analyze_suspicious_patterns(self, data: bytes) -> dict:
        """Return hash identity information without using hashes as ML features."""
        try:
            digests = {
                name: hashlib.new(name, data).hexdigest()
                for name in self.supported_hashes
            }
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'hashes': digests,
                'identity_only': True,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as exc:
            logging.error("Hash analysis failed: %s", exc)
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'identity_only': True,
                'error': str(exc),
                'timestamp': datetime.now().isoformat(),
            }

    def _extract_hash_features(self, data: bytes) -> np.ndarray:
        """Legacy helper retained for compatibility; not used for malware ML."""
        features = []
        for hash_type in self.supported_hashes:
            h = hashlib.new(hash_type)
            h.update(data)
            features.extend(self._hash_to_features(h.hexdigest()))
        features.extend((len(data), len(data) % 256))
        return np.array(features)

    def _hash_to_features(self, hash_str: str) -> list:
        """Legacy hash feature helper retained for compatibility."""
        features = [hash_str.count(char) for char in set(hash_str)]
        features.extend(hash_str.count(digit) for digit in '0123456789abcdef')
        features.extend(
            hash_str.count(hash_str[i:i + 2])
            for i in range(0, len(hash_str) - 1, 2)
        )
        return features

    def _calculate_confidence(self, result: int) -> float:
        """Legacy confidence helper retained for compatibility."""
        return 0.95 if result == 1 else 0.05


def main():
    verifier = HashVerifier()
    test_data = b"This is a test file contents"
    expected_sha256 = (
        "a45678b9012345678901234567890123456789012345678901234567890123456"
    )
    result = verifier.verify_hash(test_data, expected_sha256)
    print(f"Hash verification result: {result}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
