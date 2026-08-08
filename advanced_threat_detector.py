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
        
    def initialize_models(self):
        """Initialize and load saved ML models for different threat types."""
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
                
                # Create synthetic data for initial training
                X = np.random.rand(100, 10)  # 100 samples with 10 features
                y = np.zeros(100)
                y[:20] = 1  # 20% positive samples
                
                # Fit scaler and PCA
                X_scaled = self.scalers[threat_type].fit_transform(X)
                X_pca = self.pcas[threat_type].fit_transform(X_scaled)
                
                # Train the model
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
        """Train all threat detection models with default training data."""
        try:
            # Generate synthetic training data for each threat type
            for threat_type in self.models.keys():
                # Generate random features
                n_samples = 1000
                n_features = 10  # Number of features in get_advanced_features
                X = np.random.rand(n_samples, n_features)
                
                # Create labels (0 for benign, 1 for malicious)
                y = np.zeros(n_samples)
                # Add some malicious samples
                y[:int(n_samples * 0.2)] = 1
                
                # Initialize model components
                if threat_type not in self.models:
                    self.models[threat_type] = self.create_malware_model()  # Using malware model as base
                if threat_type not in self.scalers:
                    self.scalers[threat_type] = StandardScaler()
                if threat_type not in self.pcas:
                    self.pcas[threat_type] = PCA(n_components=0.95)
                
                # Fit scaler
                self.scalers[threat_type].fit(X)
                
                # Transform data using scaler
                X_scaled = self.scalers[threat_type].transform(X)
                
                # Fit PCA
                self.pcas[threat_type].fit(X_scaled)
                
                # Transform data using PCA
                X_transformed = self.pcas[threat_type].transform(X_scaled)
                
                # Train the model with transformed data
                self.models[threat_type].fit(X_transformed, y)
                
                # Save the trained model and components
                self.save_model(threat_type)
                
            logging.info("All threat detection models trained successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error training models: {e}")
            return False
            
    def predict_threat(self, threat_type: str, feature_vector: np.ndarray) -> Tuple[float, str]:
        """
        Predict threat score and type using the appropriate ML model.
        
        Args:
            threat_type: Type of threat to predict ('malware', 'ddos', 'exfiltration', 'lateral_movement')
            feature_vector: Feature vector to predict
            
        Returns:
            Tuple of (score: float, threat_type: str)
        """
        try:
            # Scale features
            scaled_features = self.scalers[threat_type].transform(feature_vector)
            
            # Apply PCA if available
            if self.pcas[threat_type]:
                scaled_features = self.pcas[threat_type].transform(scaled_features)
            
            # Get prediction
            prediction = self.models[threat_type].predict_proba(scaled_features)[0]
            score = prediction[1]  # Probability of being malicious
            
            # Map score to 0-1 range and apply threshold adjustments
            score = max(0, min(1, score))
            
            # Apply threat-specific score adjustments
            if threat_type == 'malware':
                score = min(score * 1.2, 1.0)  # Malware scores can be slightly higher
            elif threat_type == 'ddos':
                score = min(score * 1.1, 1.0)  # DDoS scores can be slightly higher
            elif threat_type == 'exfiltration':
                score = min(score * 1.15, 1.0)  # Exfiltration scores can be slightly higher
            elif threat_type == 'lateral_movement':
                score = min(score * 1.1, 1.0)  # Lateral movement scores can be slightly higher
            
            # Get threat type
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
