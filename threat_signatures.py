import os
import json
import hashlib
import logging
from typing import Dict, Set, List, Tuple
from collections import defaultdict
import time
from datetime import datetime
import requests

class ThreatSignatureDatabase:
    def __init__(self, signature_dir='threat_signatures'):
        self.signature_dir = signature_dir
        self.signatures = {
            'connections': defaultdict(lambda: {
                'ip': '',
                'port': 0,
                'protocol': '',
                'first_seen': 0,
                'last_seen': 0,
                'bytes_sent': 0,
                'bytes_recv': 0,
                'status': '',
                'process': {
                    'pid': 0,
                    'name': '',
                    'exe': ''
                },
                'threat_details': {
                    'score': 0.0,
                    'main_threat': '',
                    'malware_score': 0.0,
                    'ddos_score': 0.0,
                    'exfiltration_score': 0.0,
                    'lateral_score': 0.0,
                    'anomaly_score': 0.0
                },
                'history': {
                    'connections': [],
                    'timestamps': [],
                    'intervals': []
                }
            })
        }
        self.last_update = 0
        self.update_interval = 3600  # Update every hour
        self.initialize_database()

    def load_threat_db(self):
        """Load threat signatures from file."""
        try:
            with open(os.path.join(self.signature_dir, 'threat_signatures.json'), 'r') as f:
                data = json.load(f)
                self.signatures.update(data)
                logging.info("Threat signatures loaded successfully")
        except FileNotFoundError:
            logging.warning("Threat signatures file not found")
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding threat signatures: {e}")
        except Exception as e:
            logging.error(f"Error loading threat signatures: {e}")

    def save_threat_db(self):
        """Save threat signatures to file."""
        try:
            os.makedirs(self.signature_dir, exist_ok=True)
            with open(os.path.join(self.signature_dir, 'threat_signatures.json'), 'w') as f:
                json.dump(self.signatures, f, indent=4)
                logging.info("Threat signatures saved successfully")
        except Exception as e:
            logging.error(f"Error saving threat signatures: {e}")

    def initialize_database(self):
        """Initialize the threat signature database."""
        try:
            os.makedirs(self.signature_dir, exist_ok=True)
            self.load_signatures()
            self.update_signatures()
        except Exception as e:
            logging.error(f"Error initializing signature database: {e}")
            
    def load_signatures(self):
        """Load existing signatures from files."""
        try:
            signature_files = [f for f in os.listdir(self.signature_dir) 
                             if f.endswith('.json')]
            
            for file in signature_files:
                with open(os.path.join(self.signature_dir, file), 'r') as f:
                    data = json.load(f)
                    # Update connection signatures
                    for conn_key, conn_data in data.get('connections', {}).items():
                        self.signatures['connections'][conn_key].update(conn_data)
                    
        except Exception as e:
            logging.error(f"Error loading signatures: {e}")
            
    def update_signatures(self):
        """Update signatures from multiple sources."""
        try:
            current_time = time.time()
            if current_time - self.last_update < self.update_interval:
                return
                
            # Update from various sources
            self.update_from_virustotal()
            self.update_from_abuseipdb()
            self.update_from_local_database()
            
            self.last_update = current_time
            
        except Exception as e:
            logging.error(f"Error updating signatures: {e}")
            
    def update_from_virustotal(self):
        """Update signatures from VirusTotal."""
        try:
            url = "https://www.virustotal.com/api/v3/intelligence/search"
            headers = {
                'x-apikey': os.getenv('VIRUSTOTAL_API_KEY')
            }
            
            params = {
                'query': 'malware',
                'limit': 100
            }
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                self.process_signatures(data.get('data', []))
                
        except Exception as e:
            logging.error(f"Error updating from VirusTotal: {e}")
            
    def update_from_abuseipdb(self):
        """Update signatures from AbuseIPDB."""
        try:
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {
                'Key': os.getenv('ABUSEIPDB_API_KEY'),
                'Accept': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.process_signatures(data.get('data', []))
                
        except Exception as e:
            logging.error(f"Error updating from AbuseIPDB: {e}")
            
    def update_from_local_database(self):
        """Update from local threat database. Create if it doesn't exist."""
        try:
            signature_file = os.path.join(self.signature_dir, 'local_signatures.json')
            # Load existing signatures
            self.load_signatures()
        except Exception as e:
            logging.error(f"Error updating from local database: {e}")
            default_signatures = {
                }
            with open(signature_file, 'w') as f:
                json.dump(default_signatures, f, indent=4)
                logging.info(f"Created new local signatures file at {signature_file}")
        
            with open(signature_file, 'r') as f:
                data = json.load(f)
                self.process_signatures(data)
                
        except Exception as e:
            logging.error(f"Error updating from local database: {e}")
            
    def process_signatures(self, signatures):
        """Process and store signatures."""
        try:
            for sig in signatures:
                # Process signature data
                ip = sig.get('ip')
                port = sig.get('port')
                if ip and port:
                    conn_key = f"{ip}:{port}"
                    self.signatures['connections'][conn_key].update({
                        'ip': ip,
                        'port': port,
                        'protocol': sig.get('protocol', ''),
                        'threat_details': {
                            'score': sig.get('score', 0.0),
                            'main_threat': sig.get('threat_type', ''),
                            'malware_score': sig.get('malware_score', 0.0),
                            'ddos_score': sig.get('ddos_score', 0.0),
                            'exfiltration_score': sig.get('exfil_score', 0.0),
                            'lateral_score': sig.get('lateral_score', 0.0),
                            'anomaly_score': sig.get('anomaly_score', 0.0)
                        }
                    })
                    signature_data = {
                        'signature': sig,
                        'confidence': sig.get('confidence', 0.9),
                        'category': sig.get('category', 'unknown'),
                        'last_seen': time.time(),
                        'source': sig.get('source', 'unknown')
                    }
                    self.signatures['connections'][conn_key].update(signature_data)
        except Exception as e:
            logging.error(f"Error processing signatures: {e}")
            
    def match_signature(self, connection_data: Dict) -> Tuple[float, str]:
        """Match connection data against known signatures."""
        try:
            # Extract features
            features = {
                'ip_address': connection_data.get('ip'),
                'port': connection_data.get('port'),
                'protocol': connection_data.get('protocol'),
                'behavior_pattern': connection_data.get('behavior_pattern'),
                'geolocation': connection_data.get('geolocation'),
                'connection_pattern': connection_data.get('connection_pattern')
            }
            
            # Calculate signature match score
            best_match = None
            best_score = 0.0
            
            for sig in self.signatures.values():
                score = self.calculate_match_score(features, sig['signature'])
                if score > best_score:
                    best_score = score
                    best_match = sig
                    
            return best_score, best_match['category'] if best_match else 'unknown'
            
        except Exception as e:
            logging.error(f"Error matching signature: {e}")
            return 0.0, 'unknown'
            
    def calculate_match_score(self, features: Dict, signature: Dict) -> float:
        """Calculate match score between features and signature."""
        score = 0.0
        
        # IP address match
        if signature.get('ip') and features.get('ip_address') == signature['ip']:
            score += 0.3
            
        # Port match
        if signature.get('port') and features.get('port') == signature['port']:
            score += 0.2
            
        # Protocol match
        if signature.get('protocol') and features.get('protocol') == signature['protocol']:
            score += 0.1
            
        # Behavior pattern match
        if signature.get('behavior_pattern'):
            pattern_score = self.calculate_pattern_similarity(
                features.get('behavior_pattern', ''),
                signature['behavior_pattern']
            )
            score += pattern_score * 0.2
            
        # Geolocation match
        if signature.get('geolocation'):
            geo_score = self.calculate_geo_similarity(
                features.get('geolocation', {}),
                signature['geolocation']
            )
            score += geo_score * 0.1
            
        # Connection pattern match
        if signature.get('connection_pattern'):
            conn_score = self.calculate_pattern_similarity(
                features.get('connection_pattern', ''),
                signature['connection_pattern']
            )
            score += conn_score * 0.1
            
        return min(score, 1.0)
        
    def calculate_pattern_similarity(self, pattern1: str, pattern2: str) -> float:
        """Calculate similarity between two patterns using Levenshtein distance."""
        if not pattern1 or not pattern2:
            return 0.0
            
        import Levenshtein
        distance = Levenshtein.distance(pattern1, pattern2)
        max_length = max(len(pattern1), len(pattern2))
        return 1.0 - (distance / max_length) if max_length > 0 else 1.0
        
    def calculate_geo_similarity(self, geo1: Dict, geo2: Dict) -> float:
        """Calculate similarity between two geolocation data points."""
        score = 0.0
        
        # Country match
        if geo1.get('country') == geo2.get('country'):
            score += 0.4
            
        # Region match
        if geo1.get('region') == geo2.get('region'):
            score += 0.3
            
        # City match
        if geo1.get('city') == geo2.get('city'):
            score += 0.2
            
        # Distance-based score
        if 'latitude' in geo1 and 'longitude' in geo1 and \
           'latitude' in geo2 and 'longitude' in geo2:
            distance = self.calculate_distance(
                (geo1['latitude'], geo1['longitude']),
                (geo2['latitude'], geo2['longitude'])
            )
            if distance <= 100:  # Within 100km
                score += 0.1
            
        return min(score, 1.0)
        
    def calculate_distance(self, coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
        """Calculate distance between two coordinates using Haversine formula."""
        from math import radians, sin, cos, sqrt, atan2
        
        lat1, lon1 = coord1
        lat2, lon2 = coord2
        
        R = 6371.0  # Earth radius in kilometers
        
        lat1 = radians(lat1)
        lon1 = radians(lon1)
        lat2 = radians(lat2)
        lon2 = radians(lon2)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c

# Initialize the threat signature database
threat_db = ThreatSignatureDatabase()
