import os
import json
import hashlib
import psutil
import socket
import time
from datetime import datetime
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO)

class DataCollector:
    def __init__(self, data_dir='data', max_samples=10000):
        self.data_dir = Path(data_dir)
        self.max_samples = max_samples
        self.initialize_directories()
        
    def initialize_directories(self):
        """Create necessary directories for data storage."""
        os.makedirs(self.data_dir / 'raw', exist_ok=True)
        os.makedirs(self.data_dir / 'processed', exist_ok=True)
        os.makedirs(self.data_dir / 'labeled', exist_ok=True)
        
    def collect_malware_data(self, file_path: str, label: int = 1) -> Dict:
        """Collect features from a file for malware detection."""
        try:
            features = {}
            
            # Basic file features
            features['file_size'] = os.path.getsize(file_path)
            features['file_hash'] = self._get_file_hash(file_path)
            features['file_extension'] = os.path.splitext(file_path)[1]
            
            # File entropy
            features['entropy'] = self._calculate_entropy(file_path)
            
            # PE file analysis (if applicable)
            if file_path.lower().endswith(('.exe', '.dll')):
                try:
                    pe = pefile.PE(file_path)
                    features['imports_count'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
                    features['exports_count'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
                    features['sections_count'] = len(pe.sections)
                    features['digital_signature'] = int(bool(getattr(pe, 'DIRECTORY_ENTRY_SECURITY', None)))
                except Exception as e:
                    logging.warning(f"PE analysis failed for {file_path}: {e}")
                    features['imports_count'] = 0
                    features['exports_count'] = 0
                    features['sections_count'] = 0
                    features['digital_signature'] = 0
            
            return {
                'features': features,
                'label': label,
                'timestamp': datetime.now().isoformat(),
                'file_path': file_path
            }
            
        except Exception as e:
            logging.error(f"Error collecting malware data: {e}")
            return None
            
    def collect_network_data(self, connection: socket.socket, label: int = 1) -> Dict:
        """Collect network features from a connection."""
        try:
            features = {}
            
            # Get connection details
            conn_info = psutil.net_connections()
            for conn in conn_info:
                if conn.laddr.port == connection.getsockname()[1]:
                    features['packet_rate'] = self._calculate_packet_rate(connection)
                    features['bytes_per_second'] = self._calculate_bandwidth(connection)
                    features['connection_duration'] = self._calculate_connection_duration(connection)
                    features['protocol'] = conn.type.name
                    features['local_port'] = conn.laddr.port
                    features['remote_port'] = conn.raddr.port if conn.raddr else 0
                    
            return {
                'features': features,
                'label': label,
                'timestamp': datetime.now().isoformat(),
                'connection_info': str(connection.getsockname())
            }
            
        except Exception as e:
            logging.error(f"Error collecting network data: {e}")
            return None
            
    def save_data(self, data: Dict, threat_type: str, label: int):
        """Save collected data to appropriate directory."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{threat_type}_{label}_{timestamp}.json"
            filepath = self.data_dir / 'raw' / filename
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            
            logging.info(f"Saved {threat_type} data to {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving data: {e}")
            return False
            
    def _get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
        
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy."""
        with open(file_path, "rb") as f:
            byte_array = list(f.read())
        file_size = len(byte_array)
        if file_size == 0:
            return 0
            
        frequency = np.zeros(256)
        for byte in byte_array:
            frequency[byte] += 1
            
        frequency = frequency / file_size
        entropy = -np.sum(frequency * np.log2(frequency + 1e-10))
        return entropy
        
    def _calculate_packet_rate(self, connection: socket.socket) -> float:
        """Calculate packet rate from connection."""
        # This is a simplified implementation
        # In a real system, you would need to monitor packets over time
        return 0.0
        
    def _calculate_bandwidth(self, connection: socket.socket) -> float:
        """Calculate bandwidth usage."""
        # This is a simplified implementation
        # In a real system, you would need to monitor bytes over time
        return 0.0
        
    def _calculate_connection_duration(self, connection: socket.socket) -> float:
        """Calculate connection duration."""
        # This is a simplified implementation
        # In a real system, you would track connection start time
        return 0.0

class DataLabeler:
    def __init__(self, data_dir='data'):
        self.data_dir = Path(data_dir)
        
    def label_data(self, threat_type: str, label: int, sample_ids: List[str]):
        """Label collected data samples."""
        try:
            for sample_id in sample_ids:
                raw_path = self.data_dir / 'raw' / f"{sample_id}.json"
                if raw_path.exists():
                    with open(raw_path, 'r') as f:
                        data = json.load(f)
                        
                    data['label'] = label
                    labeled_path = self.data_dir / 'labeled' / f"{sample_id}.json"
                    
                    with open(labeled_path, 'w') as f:
                        json.dump(data, f, indent=4)
                        
                    logging.info(f"Labeled sample {sample_id} as {label}")
                    
        except Exception as e:
            logging.error(f"Error labeling data: {e}")

# Example usage
collector = DataCollector()
labeler = DataLabeler()

# Collect malware sample
data = collector.collect_malware_data("path/to/suspicious/file.exe", label=1)
if data:
    collector.save_data(data, "malware", 1)

# Label collected data
labeler.label_data("malware", 1, ["sample_id_1", "sample_id_2"])
