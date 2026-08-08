import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
import joblib
import os
from datetime import datetime
import logging

class SecurityMLModel:
    def __init__(self, model_path='models/malware_model.pkl', 
                 pca_path='models/malware_pca.pkl',
                 scaler_path='models/malware_scaler.pkl'):
        self.model_path = model_path
        self.pca_path = pca_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.pca = None
        self.pipeline = None
        self.initialize_model()
        
    def initialize_model(self):
        """Initialize or load the ML model and its components."""
        # Load components if they exist
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.create_new_model()
            self.save_model()

        # Load PCA if it exists
        if os.path.exists(self.pca_path):
            self.pca = joblib.load(self.pca_path)
        else:
            self.pca = PCA(n_components=0.95)

        # Load scaler if it exists
        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)
        else:
            self.scaler = StandardScaler()

        # Create pipeline with loaded components
        self.pipeline = Pipeline([
            ('scaler', self.scaler),
            ('pca', self.pca),
            ('model', self.model)
        ])
            
    def create_new_model(self):
        """Create a new ML pipeline."""
        self.pipeline = Pipeline([
            ('scaler', self.scaler),
            ('pca', self.pca),
            ('model', IsolationForest(
                n_estimators=100,
                contamination='auto',
                max_samples='auto',
                random_state=42,
                n_jobs=-1
            ))
        ])

    def train_model(self, X_train):
        """Train the model on training data."""
        self.pipeline.fit(X_train)
        logging.info("Security ML model trained successfully")
        
    def save_model(self):
        """Save the trained model."""
        joblib.dump(self.pipeline, self.model_path)
        logging.info("Security ML model saved successfully")
        
    def load_model(self):
        """Load the existing model."""
        try:
            self.pipeline = joblib.load(self.model_path)
            logging.info("Security ML model loaded successfully")
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            self.create_new_model()
            
    def train_model(self, X, y=None):
        """Train the model with new data."""
        try:
            self.pipeline.fit(X)
            self.save_model()
            logging.info("Model trained successfully")
            return True
        except Exception as e:
            logging.error(f"Error training model: {e}")
            return False
            
    def predict(self, X):
        """Predict anomalies."""
        try:
            if self.pipeline is None:
                raise ValueError("Model not initialized. Please train the model first.")
            
            # Check if the model is fitted
            if not hasattr(self.pipeline.named_steps['model'], 'is_fitted_'):
                raise ValueError("Model not trained. Please train the model first.")
            
            predictions = self.pipeline.predict(X)
            scores = self.pipeline.decision_function(X)
            return predictions, scores
        except ValueError as ve:
            logging.error(f"Model error: {ve}")
            return None, None
        except Exception as e:
            logging.error(f"Error making predictions: {e}")
            return np.zeros(len(X)), np.zeros(len(X))
            
    def get_features(self, connection_data):
        """Extract comprehensive features from connection data."""
        features = {
            'bytes_sent': connection_data.get('bytes_sent', 0),
            'bytes_received': connection_data.get('bytes_received', 0),
            'duration': connection_data.get('duration', 0),
            'port': connection_data.get('port', 0),
            'protocol': connection_data.get('protocol', 0),
            'connection_count': connection_data.get('connection_count', 0),
            'time_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'packet_rate': connection_data.get('packet_rate', 0),
            'packet_size': connection_data.get('packet_size', 0),
            'connection_state': connection_data.get('state', 0),
            'service_type': connection_data.get('service', 0),
            'geolocation': connection_data.get('geo', 0),
            'user_agent': connection_data.get('user_agent', 0)
        }
        return np.array(list(features.values())).reshape(1, -1)

# Initialize the ML model
security_ml = SecurityMLModel()
