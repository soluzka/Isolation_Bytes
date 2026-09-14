import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import logging
from typing import Dict, List, Tuple
import time
from datetime import datetime
import json

class ThreatDetectionModel:
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        self.models = {}
        self.scalers = {}
        self.pcas = {}
        self.model_loaded = False
        
    def initialize_models(self, force_reload=False):
        """Initialize and load ML models for different threat types.
        
        Args:
            force_reload: If True, will reload models even if they were previously loaded
        """
        if self.model_loaded and not force_reload:
            return
            
        try:
            # Check numpy version compatibility
            import numpy as np
            if np.__version__ < '1.21.0':
                logging.warning("Warning: Using numpy version < 1.21.0 may cause compatibility issues with saved models")
                
            # Load models and their components
            for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
                try:
                    # Load the model
                    model_path = os.path.join(self.model_dir, f'{threat_type}_model.pkl')
                    self.models[threat_type] = joblib.load(model_path)
                    
                    # Load the scaler
                    scaler_path = os.path.join(self.model_dir, f'{threat_type}_scaler.pkl')
                    self.scalers[threat_type] = joblib.load(scaler_path)
                    
                    # Load the PCA
                    pca_path = os.path.join(self.model_dir, f'{threat_type}_pca.pkl')
                    self.pcas[threat_type] = joblib.load(pca_path)
                    
                    logging.info(f"Successfully loaded {threat_type} model and components")
                except FileNotFoundError:
                    logging.warning(f"No saved {threat_type} model found, creating new model")
                    if threat_type == 'malware':
                        self.models[threat_type] = self.create_malware_model()
                    elif threat_type == 'ddos':
                        self.models[threat_type] = self.create_ddos_model()
                    elif threat_type == 'exfiltration':
                        self.models[threat_type] = self.create_exfiltration_model()
                    elif threat_type == 'lateral_movement':
                        self.models[threat_type] = self.create_lateral_movement_model()
                        
                    # Create new scaler and PCA
                    self.scalers[threat_type] = StandardScaler()
                    self.pcas[threat_type] = PCA(n_components=0.95)
                    
                    # Save newly created model and components
                    joblib.dump(self.models[threat_type], model_path)
                    joblib.dump(self.scalers[threat_type], scaler_path)
                    joblib.dump(self.pcas[threat_type], pca_path)
                    logging.info(f"Created and saved new {threat_type} model and components")
                    
            self.model_loaded = True
        except Exception as e:
            logging.error(f"Error initializing models: {str(e)}")
            raise
        
    def initialize_and_train_models(self):
        """Initialize and train saved ML models for different threat types."""
        self.models = {}
        self.scalers = {}
        self.pcas = {}
        
        # Load models and their components
        for threat_type in ['malware', 'ddos', 'exfiltration', 'lateral_movement']:
            try:
                # Load the model
                model_path = os.path.join(self.model_dir, f'{threat_type}_model.pkl')
                self.models[threat_type] = joblib.load(model_path)
                
                # Load the scaler
                scaler_path = os.path.join(self.model_dir, f'{threat_type}_scaler.pkl')
                self.scalers[threat_type] = joblib.load(scaler_path)
                
                # Load the PCA
                pca_path = os.path.join(self.model_dir, f'{threat_type}_pca.pkl')
                self.pcas[threat_type] = joblib.load(pca_path)
                
                logging.info(f"Successfully loaded {threat_type} model and components")
            except FileNotFoundError:
                logging.warning(f"No saved {threat_type} model found, creating new model")
                if threat_type == 'malware':
                    self.models[threat_type] = self.create_malware_model()
                elif threat_type == 'ddos':
                    self.models[threat_type] = self.create_ddos_model()
                elif threat_type == 'exfiltration':
                    self.models[threat_type] = self.create_exfiltration_model()
                elif threat_type == 'lateral_movement':
                    self.models[threat_type] = self.create_lateral_movement_model()
                
                # Initialize scaler and PCA
                self.scalers[threat_type] = StandardScaler()
                self.pcas[threat_type] = PCA(n_components=0.95)

                # Generate realistic synthetic training data (not purely random)
                X, y = self._make_synthetic_training_data(threat_type, n_samples=1000)

                # Fit scaler and PCA
                X_scaled = self.scalers[threat_type].fit_transform(X)
                X_pca = self.pcas[threat_type].fit_transform(X_scaled)

                # Train the model (OneClassSVM for DDoS is unsupervised — fit on benign only)
                if threat_type == 'ddos':
                    X_benign_pca = X_pca[y == 0]
                    self.models[threat_type].fit(X_benign_pca)
                else:
                    self.models[threat_type].fit(X_pca, y)
                
                # Save the models
                joblib.dump(self.models[threat_type], model_path)
                joblib.dump(self.scalers[threat_type], scaler_path)
                joblib.dump(self.pcas[threat_type], pca_path)
                
                logging.info(f"Created and saved new {threat_type} model")
            except Exception as e:
                logging.error(f"Failed to initialize {threat_type} model: {e}")
                raise
            
    def create_malware_model(self):
        """Create model for malware detection."""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
    def create_ddos_model(self):
        """Create model for DDoS detection."""
        return Pipeline([
            ('scaler', MinMaxScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', OneClassSVM(
                kernel='rbf',
                nu=0.01,
                gamma='auto'
            ))
        ])
        
    def create_exfiltration_model(self):
        """Create model for data exfiltration detection."""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=8,
                random_state=42
            ))
        ])
        
    def create_lateral_movement_model(self):
        """Create model for lateral movement detection."""
        return Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', RandomForestClassifier(
                n_estimators=150,
                max_depth=12,
                min_samples_split=4,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
    def train_model(self, threat_type: str, X, y):
        """Train a specific threat detection model."""
        try:
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train model
            self.models[threat_type].fit(X_train, y_train)
            
            # Evaluate
            predictions = self.models[threat_type].predict(X_test)
            report = classification_report(y_test, predictions, zero_division=0)
            logging.info(f"{threat_type} model evaluation:\n{report}")
            
            # Save model
            self.save_model(threat_type)
            return True
            
        except Exception as e:
            logging.error(f"Error training {threat_type} model: {e}")
            return False
            
    def save_model(self, threat_type: str):
        """Save a trained model."""
        try:
            os.makedirs(self.model_dir, exist_ok=True)
            model_path = os.path.join(self.model_dir, f"{threat_type}_model.pkl")
            joblib.dump(self.models[threat_type], model_path)
            logging.info(f"Saved {threat_type} model to {model_path}")
            
            # Save scaler and PCA
            scaler_path = os.path.join(self.model_dir, f"{threat_type}_scaler.pkl")
            pca_path = os.path.join(self.model_dir, f"{threat_type}_pca.pkl")
            joblib.dump(self.scalers[threat_type], scaler_path)
            joblib.dump(self.pcas[threat_type], pca_path)
            
        except Exception as e:
            logging.error(f"Error saving {threat_type} model: {e}")
            
    def load_model(self, threat_type: str):
        """Load a trained model."""
        try:
            model_path = os.path.join(self.model_dir, f"{threat_type}_model.pkl")
            if os.path.exists(model_path):
                self.models[threat_type] = joblib.load(model_path)
                
                # Load scaler and PCA
                scaler_path = os.path.join(self.model_dir, f"{threat_type}_scaler.pkl")
                pca_path = os.path.join(self.model_dir, f"{threat_type}_pca.pkl")
                self.scalers[threat_type] = joblib.load(scaler_path)
                self.pcas[threat_type] = joblib.load(pca_path)
                
                logging.info(f"Loaded {threat_type} model successfully")
                return True
            return False
            
        except Exception as e:
            logging.error(f"Error loading {threat_type} model: {e}")
            return False
            
    def train_all_models(self):
        """Train all threat detection models with realistic synthetic training data."""
        try:
            for threat_type in self.models.keys():
                # Use realistic synthetic data shaped to actual feature distributions
                X, y = self._make_synthetic_training_data(threat_type, n_samples=1000)

                if threat_type not in self.scalers:
                    self.scalers[threat_type] = StandardScaler()
                if threat_type not in self.pcas:
                    self.pcas[threat_type] = PCA(n_components=0.95)

                X_scaled = self.scalers[threat_type].fit_transform(X)
                X_transformed = self.pcas[threat_type].fit_transform(X_scaled)

                # OneClassSVM (DDoS) is unsupervised — train on benign samples only
                if threat_type == 'ddos':
                    self.models[threat_type].fit(X_transformed[y == 0])
                else:
                    self.models[threat_type].fit(X_transformed, y)

                self.save_model(threat_type)
                # Save the trained model and components
                self.save_model(threat_type)
                
            logging.info("All threat detection models trained successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error training models: {e}")
            return False
            
    def _make_synthetic_training_data(self, threat_type: str, n_samples: int = 1000):
        """Generate statistically meaningful synthetic training data shaped to the
        25-feature vector produced by get_advanced_features().

        Benign traffic is centred around typical enterprise values.
        Malicious traffic has characteristic patterns per threat type:
          - malware:          large bytes_sent bursts, unusual hours, high packet variance
          - ddos:             extreme packet_rate, very high connection_rate, short duration
          - exfiltration:     high bytes_sent, off-hours, unusual geo_distance
          - lateral_movement: high connection_count, many short-duration connections, odd ports
        """
        rng = np.random.RandomState(42)
        n_features = 25  # must match get_advanced_features()

        # ── Benign baseline (80 % of samples) ──────────────────────────────────
        n_benign = int(n_samples * 0.80)
        X_benign = rng.randn(n_benign, n_features) * 0.3  # tight cluster near 0

        # ── Malicious samples (20 % of samples) ────────────────────────────────
        n_malicious = n_samples - n_benign
        X_malicious = rng.randn(n_malicious, n_features) * 0.5

        # Feature indices (order from get_advanced_features):
        # 0 bytes_sent, 1 bytes_received, 2 packet_rate, 3 connection_duration,
        # 4 protocol_type, 5 port_number, 6 packet_size_variance,
        # 7 connection_rate, 8 time_between_connections, 9 connection_pattern,
        # 10 geo_distance, 11 country_code, 12 region_code,
        # 13 service_type, 14 service_version, 15 service_access_pattern,
        # 16 time_of_day, 17 day_of_week, 18 connection_time_variance,
        # 19 packet_size_mean, 20 packet_size_std, 21 connection_count,
        # 22 connection_pattern_score, 23 protocol_mismatch_score, 24 anomaly_score

        if threat_type == 'malware':
            X_malicious[:, 0] += 3.0   # bytes_sent spike
            X_malicious[:, 2] += 2.0   # high packet_rate
            X_malicious[:, 6] += 2.5   # high packet_size_variance
            X_malicious[:, 16] += 2.0  # unusual time_of_day (off-hours)
            X_malicious[:, 24] += 2.0  # anomaly_score elevated

        elif threat_type == 'ddos':
            X_malicious[:, 2] += 5.0   # extreme packet_rate
            X_malicious[:, 7] += 5.0   # extreme connection_rate
            X_malicious[:, 3] -= 2.0   # very short duration
            X_malicious[:, 21] += 4.0  # very high connection_count
            X_malicious[:, 23] += 2.0  # protocol mismatch

        elif threat_type == 'exfiltration':
            X_malicious[:, 0] += 4.0   # massive bytes_sent
            X_malicious[:, 10] += 3.0  # high geo_distance (unusual geography)
            X_malicious[:, 16] += 2.5  # off-hours
            X_malicious[:, 15] += 2.0  # unusual service_access_pattern
            X_malicious[:, 24] += 1.5  # anomaly score elevated

        elif threat_type == 'lateral_movement':
            X_malicious[:, 21] += 4.0  # high connection_count
            X_malicious[:, 3] -= 1.5   # short duration per connection
            X_malicious[:, 5] += 3.0   # unusual port_number
            X_malicious[:, 9] += 2.5   # unusual connection_pattern
            X_malicious[:, 22] += 2.5  # high connection_pattern_score

        X = np.vstack([X_benign, X_malicious])
        y = np.concatenate([np.zeros(n_benign), np.ones(n_malicious)])

        # Shuffle
        idx = rng.permutation(len(X))
        return X[idx], y[idx]
        """
        Predict threat score and type using the appropriate ML model.

        Handles both supervised classifiers (predict_proba) and the DDoS
        OneClassSVM (decision_function, which has no predict_proba).

        Args:
            threat_type: 'malware', 'ddos', 'exfiltration', or 'lateral_movement'
            feature_vector: Raw feature array shaped (1, n_features)

        Returns:
            Tuple of (score 0.0–1.0, threat_class 'malicious'|'benign')
        """
        try:
            if threat_type not in self.models:
                logging.warning(f"Unknown threat_type '{threat_type}' — returning benign")
                return 0.0, 'benign'

            # Scale features
            scaled_features = self.scalers[threat_type].transform(feature_vector)

            # Apply PCA
            if self.pcas.get(threat_type) is not None:
                scaled_features = self.pcas[threat_type].transform(scaled_features)

            model = self.models[threat_type]

            # OneClassSVM (DDoS) has no predict_proba — use decision_function instead.
            # decision_function returns negative scores for outliers (anomalies).
            # We map it to [0, 1] so a more-negative score → higher threat score.
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(scaled_features)[0]
                # Index 1 = malicious class probability
                score = float(proba[1]) if len(proba) > 1 else float(proba[0])
            else:
                # OneClassSVM / any model without predict_proba
                raw = float(model.decision_function(scaled_features)[0])
                # decision_function: negative = anomaly, positive = normal.
                # Clip to [-3, 3] then invert and normalise to [0, 1].
                raw_clipped = max(-3.0, min(3.0, raw))
                score = (3.0 - raw_clipped) / 6.0  # anomaly → score near 1.0

            # Clamp to [0, 1]
            score = max(0.0, min(1.0, score))

            # Threat-type sensitivity multipliers (modest — don't inflate past 1.0)
            multipliers = {
                'malware': 1.15,
                'ddos': 1.10,
                'exfiltration': 1.12,
                'lateral_movement': 1.10,
            }
            score = min(score * multipliers.get(threat_type, 1.0), 1.0)

            threat_class = 'malicious' if score > 0.5 else 'benign'
            return score, threat_class

        except Exception as e:
            logging.error(f"Error in {threat_type} prediction: {e}")
            return 0.0, 'benign'
            
    def get_advanced_features(self, connection_data: Dict) -> Dict:
        """Extract advanced features for threat detection."""
        features = {
            # Network features
            'bytes_sent': connection_data.get('bytes_sent', 0),
            'bytes_received': connection_data.get('bytes_received', 0),
            'packet_rate': connection_data.get('packet_rate', 0),
            'connection_duration': connection_data.get('duration', 0),
            
            # Protocol features
            'protocol_type': connection_data.get('protocol', 0),
            'port_number': connection_data.get('port', 0),
            'packet_size_variance': connection_data.get('packet_size_variance', 0),
            
            # Behavioral features
            'connection_rate': connection_data.get('connection_rate', 0),
            'time_between_connections': connection_data.get('time_between_connections', 0),
            'connection_pattern': connection_data.get('connection_pattern', 0),
            
            # Geolocation features
            'geo_distance': connection_data.get('geo_distance', 0),
            'country_code': connection_data.get('country_code', 0),
            'region_code': connection_data.get('region_code', 0),
            
            # Service features
            'service_type': connection_data.get('service_type', 0),
            'service_version': connection_data.get('service_version', 0),
            'service_access_pattern': connection_data.get('service_access_pattern', 0),
            
            # Time-based features
            'time_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'connection_time_variance': connection_data.get('connection_time_variance', 0),
            
            # Statistical features
            'packet_size_mean': connection_data.get('packet_size_mean', 0),
            'packet_size_std': connection_data.get('packet_size_std', 0),
            'connection_count': connection_data.get('connection_count', 0),
            
            # Pattern features
            'connection_pattern_score': connection_data.get('connection_pattern_score', 0),
            'protocol_mismatch_score': connection_data.get('protocol_mismatch_score', 0),
            'anomaly_score': connection_data.get('anomaly_score', 0)
        }
        
        return features

# Create a global detector instance but don't initialize immediately
detector = ThreatDetectionModel()
