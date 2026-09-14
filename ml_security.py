import logging
import os
from datetime import datetime

import joblib
import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted


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

    @staticmethod
    def _new_isolation_forest():
        return IsolationForest(
            n_estimators=100,
            contamination='auto',
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
        )

    def initialize_model(self):
        """Load a trained pipeline or construct an unfitted pipeline safely."""
        if os.path.exists(self.model_path):
            self.load_model()
            if self.pipeline is not None:
                self._sync_pipeline_components()
                return

        self.scaler = joblib.load(self.scaler_path) if os.path.exists(self.scaler_path) else StandardScaler()
        self.pca = joblib.load(self.pca_path) if os.path.exists(self.pca_path) else PCA(n_components=0.95)
        self.model = self._new_isolation_forest()
        self.pipeline = Pipeline([
            ('scaler', self.scaler),
            ('pca', self.pca),
            ('model', self.model),
        ])

    def _sync_pipeline_components(self):
        """Expose pipeline steps through the public component attributes."""
        self.scaler = self.pipeline.named_steps.get('scaler')
        self.pca = self.pipeline.named_steps.get('pca')
        self.model = self.pipeline.named_steps.get('model')

    def create_new_model(self):
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=0.95)
        self.model = self._new_isolation_forest()
        self.pipeline = Pipeline([
            ('scaler', self.scaler),
            ('pca', self.pca),
            ('model', self.model),
        ])
        return self.pipeline

    def train_model(self, X_train):
        self.pipeline.fit(X_train)
        self._sync_pipeline_components()
        logging.info('Security ML model trained successfully')

    def save_model(self):
        if self.pipeline is None:
            raise ValueError('Model is not initialized')
        directory = os.path.dirname(os.path.abspath(self.model_path))
        os.makedirs(directory, exist_ok=True)
        joblib.dump(self.pipeline, self.model_path)
        # Keep the component files for compatibility with older deployments.
        if self.pca is not None:
            joblib.dump(self.pca, self.pca_path)
        if self.scaler is not None:
            joblib.dump(self.scaler, self.scaler_path)
        logging.info('Security ML model saved successfully')

    def load_model(self):
        try:
            loaded = joblib.load(self.model_path)
            if not isinstance(loaded, Pipeline):
                raise TypeError('Stored malware model is not a sklearn Pipeline')
            self.pipeline = loaded
            self._sync_pipeline_components()
            logging.info('Security ML model loaded successfully')
            return True
        except Exception as exc:
            logging.error('Error loading model: %s', exc)
            self.pipeline = None
            self.model = None
            return False

    def retrain_model(self, X, y=None):
        try:
            if self.pipeline is None:
                self.create_new_model()
            self.pipeline.fit(X)
            self._sync_pipeline_components()
            self.save_model()
            logging.info('Model trained successfully')
            return True
        except Exception as exc:
            logging.error('Error training model: %s', exc)
            return False

    def _is_fitted(self):
        """Use sklearn's fitted-state contract instead of checking for an attribute.

        IsolationForest exposes fitted attributes such as estimators_, but it does
        not provide a reliable boolean ``is_fitted_`` attribute. ``check_is_fitted``
        is the supported sklearn mechanism and also handles pipeline components.
        """
        if self.pipeline is None:
            return False
        try:
            check_is_fitted(self.pipeline)
            return True
        except (TypeError, AttributeError, ValueError):
            return False

    def predict(self, X):
        try:
            if self.pipeline is None:
                raise ValueError('Model not initialized. Please train the model first.')
            if not self._is_fitted():
                raise ValueError('Model not trained. Please train the model first.')

            predictions = self.pipeline.predict(X)
            scores = self.pipeline.decision_function(X)
            return predictions, scores
        except ValueError as exc:
            logging.error('Model error: %s', exc)
            return None, None
        except Exception as exc:
            logging.error('Error making predictions: %s', exc)
            return np.zeros(len(X)), np.zeros(len(X))

    def get_features(self, connection_data):
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
            'user_agent': connection_data.get('user_agent', 0),
        }
        return np.array(list(features.values())).reshape(1, -1)


security_ml = SecurityMLModel()
