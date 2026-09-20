import logging
import math
import os
import re
from datetime import datetime

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
try:
    import skops.io as skops_io
except ImportError:
    skops_io = None


class SecurityMLModel:
    """Defensive anomaly model for network and static file/code analysis."""

    def __init__(self, model_path='models/malware_model.skops',
                 pca_path='models/malware_pca.skops',
                 scaler_path='models/malware_scaler.skops'):
        self.model_path = model_path
        self.pca_path = pca_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.pca = None
        self.pipeline = None
        self.initialize_model()

    def initialize_model(self):
        if skops_io is not None and os.path.exists(self.model_path):
            self.load_model()
        else:
            self.create_new_model()
        self.pipeline = self.pipeline or Pipeline([
            ('scaler', StandardScaler()),
            ('pca', PCA(n_components=0.95)),
            ('model', self.model),
        ])

    def create_new_model(self):
        self.model = IsolationForest(
            n_estimators=100, contamination='auto', max_samples='auto',
            random_state=42, n_jobs=-1
        )
        self.pipeline = Pipeline([
            ('scaler', StandardScaler()), ('pca', PCA(n_components=0.95)),
            ('model', self.model)
        ])

    def train_model(self, X_train):
        """Train only on an explicitly supplied baseline dataset.

        The scanner never trains on files it is currently deciding about.
        This prevents an attacker-controlled file from poisoning the model.
        """
        X_train = np.asarray(X_train, dtype=np.float64)
        if X_train.ndim != 2 or X_train.shape[0] < 10:
            raise ValueError("At least 10 baseline samples are required for ML training")
        if not np.isfinite(X_train).all():
            raise ValueError("Training data contains non-finite values")
        self.pipeline.fit(X_train)
        self.model = self.pipeline.named_steps['model']
        logging.info("Security ML model trained successfully on %d baseline samples", X_train.shape[0])

    def save_model(self):
        if skops_io is None:
            logging.warning("skops is unavailable; refusing to persist an executable ML artifact")
            return False
        os.makedirs(os.path.dirname(self.model_path) or '.', exist_ok=True)
        skops_io.dump(self.pipeline if self.pipeline is not None else self.model, self.model_path)
        logging.info("Security ML model saved in safe skops format")
        return True

    def load_model(self):
        if skops_io is None:
            logging.warning("skops is unavailable; ML artifact loading disabled")
            self.model = None
            self.create_new_model()
            return False
        try:
            loaded = skops_io.load(self.model_path, trusted=[])
            if not isinstance(loaded, Pipeline):
                raise ValueError("ML artifact is not a scikit-learn Pipeline")
            self.pipeline = loaded
            self.model = loaded.named_steps.get('model')
            if not isinstance(self.model, IsolationForest):
                raise ValueError("ML artifact contains an unexpected estimator")
            logging.info("Security ML model loaded from safe skops artifact")
            return True
        except Exception as exc:
            logging.error("Unsafe or invalid ML model artifact rejected: %s", exc)
            self.model = None
            self.create_new_model()
            return False

    def retrain_model(self, X, y=None):
        """Retrain from an explicitly supplied baseline dataset only."""
        try:
            self.train_model(X)
            return bool(self.save_model())
        except (TypeError, ValueError, OSError) as exc:
            logging.error("Error training model: %s", exc)
            return False

    @staticmethod
    def _is_fitted(estimator):
        if estimator is None:
            return False
        try:
            from sklearn.utils.validation import check_is_fitted
            check_is_fitted(estimator)
            return True
        except (AttributeError, TypeError, ValueError):
            return False

    def is_fitted(self):
        """Use sklearn's fitted-state API; never rely on is_fitted_."""
        return self.pipeline is not None and self._is_fitted(self.pipeline)

    def predict(self, X):
        try:
            if self.pipeline is None or not self.is_fitted():
                raise ValueError("Model not trained. Please train the model first.")
            return self.pipeline.predict(X), self.pipeline.decision_function(X)
        except ValueError as exc:
            logging.error("Model error: %s", exc)
            return None, None
        except Exception as exc:
            logging.error("Error making predictions: %s", exc)
            try:
                return np.zeros(len(X)), np.zeros(len(X))
            except Exception:
                return None, None

    @staticmethod
    def _safe_number(value, default=0.0):
        try:
            value = float(value)
            return value if math.isfinite(value) else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _entropy(data):
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0].astype(np.float64) / len(data)
        return float(-(probs * np.log2(probs)).sum())

    def get_file_features(self, filepath, yara_matches=None):
        """Build static, non-executing code/file features for ML corroboration."""
        try:
            stat = os.stat(filepath)
            size = int(stat.st_size)
            with open(filepath, 'rb') as handle:
                data = handle.read(min(size, 2 * 1024 * 1024))
        except (OSError, IOError):
            return np.zeros((1, 18), dtype=np.float64)
        lower = data.lower()
        suffix = os.path.splitext(filepath)[1].lower()
        text = data.decode('utf-8', errors='ignore').lower()
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
        strings = re_find_ascii_strings(data)
        suspicious_tokens = (
            b'powershell', b'cmd.exe', b'wscript', b'cscript', b'frombase64string',
            b'base64_decode', b'eval(', b'exec(', b'createprocess', b'winexec',
            b'virtualalloc', b'writeprocessmemory', b'bitsadmin', b'certutil',
            b'regsvr32', b'rundll32', b'webshell', b'cmd=', b'command=',
        )
        token_hits = sum(lower.count(token) for token in suspicious_tokens)
        yara_count = len(yara_matches or [])
        yara_severity = 0.0
        for match in yara_matches or []:
            severity = match.get('severity') if isinstance(match, dict) else getattr(match, 'severity', None)
            if isinstance(severity, str):
                yara_severity = max(yara_severity, {
                    'critical': 1.0, 'high': 0.85, 'medium': 0.55, 'low': 0.25
                }.get(severity.lower(), 0.0))
            else:
                yara_severity = max(yara_severity, self._safe_number(severity))
        extension_risk = 1.0 if suffix in {
            '.exe', '.dll', '.scr', '.sys', '.ps1', '.vbs', '.vbe', '.js', '.jse',
            '.hta', '.php', '.asp', '.aspx', '.jsp', '.bat', '.cmd'
        } else 0.0
        return np.array([[
            self._safe_number(size) / 1_000_000.0,
            self._entropy(data) / 8.0,
            printable / max(1, len(data)),
            min(len(strings), 1000) / 1000.0,
            min(token_hits, 50) / 50.0,
            min(yara_count, 20) / 20.0,
            yara_severity,
            extension_risk,
            1.0 if lower[:2] == b'mz' else 0.0,
            1.0 if lower[:4] == b'\x7felf' else 0.0,
            1.0 if b'<?php' in lower[:256] else 0.0,
            1.0 if b'<%@ page' in lower[:512] else 0.0,
            1.0 if b'createprocess' in lower else 0.0,
            1.0 if b'socket' in lower or b'connect(' in lower else 0.0,
            1.0 if b'base64' in lower else 0.0,
            min(text.count('http://') + text.count('https://'), 50) / 50.0,
            min(text.count('powershell'), 20) / 20.0,
            min(text.count('cmd.exe'), 20) / 20.0,
        ]], dtype=np.float64)

    def ml_status(self):
        """Expose whether ML is actually usable for a scan decision."""
        return {
            'available': bool(self.pipeline is not None and self.is_fitted()),
            'model_type': type(self.model).__name__ if self.model is not None else None,
        }

    def file_anomaly_confidence(self, filepath, yara_matches=None):
        """Map IsolationForest's anomaly margin to a bounded confidence.

        This is a monotonic anomaly-confidence transform, not a calibrated
        probability. It is only returned when a genuinely fitted model exists.
        """
        if not os.path.isfile(filepath) or not self.is_fitted():
            return 0.0
        features = self.get_file_features(filepath, yara_matches=yara_matches)
        _, scores = self.predict(features)
        if scores is None or len(scores) == 0:
            return 0.0
        margin = self._safe_number(scores[0])
        if not math.isfinite(margin):
            return 0.0
        confidence = 1.0 / (1.0 + math.exp(max(-60.0, min(60.0, 8.0 * margin))))
        return max(0.0, min(1.0, confidence))

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


def re_find_ascii_strings(data, minimum=4):
    strings = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= minimum:
                strings.append(current.decode('ascii', errors='ignore'))
            current.clear()
    if len(current) >= minimum:
        strings.append(current.decode('ascii', errors='ignore'))
    return strings


security_ml = SecurityMLModel()
