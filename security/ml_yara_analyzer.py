"""
Machine Learning YARA Analyzer
Enhances YARA scanning with ML-based threat analysis and anomaly detection
"""

import os
import logging
import numpy as np
from typing import List, Dict, Tuple, Optional
import json
from datetime import datetime

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("scikit-learn not available - ML features disabled")

class MLYaraAnalyzer:
    """Machine Learning analyzer for YARA scan results and file characteristics."""
    
    def __init__(self, model_dir: str = None):
        """Initialize ML analyzer with model directory."""
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), 'ml_models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.threat_classifier = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.feature_extractor = None
        
        if ML_AVAILABLE:
            self._load_or_create_models()
    
    def _load_or_create_models(self):
        """Load existing models or create new ones."""
        try:
            # Try to load existing models
            threat_model_path = os.path.join(self.model_dir, 'threat_classifier.pkl')
            anomaly_model_path = os.path.join(self.model_dir, 'anomaly_detector.pkl')
            
            if os.path.exists(threat_model_path):
                self.threat_classifier = joblib.load(threat_model_path)
                logging.info("Loaded existing threat classifier model")
            else:
                self.threat_classifier = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42
                )
                logging.info("Created new threat classifier model")
            
            if os.path.exists(anomaly_model_path):
                self.anomaly_detector = joblib.load(anomaly_model_path)
                logging.info("Loaded existing anomaly detector model")
            else:
                self.anomaly_detector = IsolationForest(
                    contamination=0.1,
                    random_state=42
                )
                logging.info("Created new anomaly detector model")
                
        except Exception as e:
            logging.error(f"Error loading ML models: {e}")
            self.threat_classifier = None
            self.anomaly_detector = None
    
    def extract_features(self, yara_matches: List, file_metadata: Dict) -> np.ndarray:
        """Extract features from YARA matches and file metadata for ML analysis."""
        features = []
        
        # YARA match features
        match_count = len(yara_matches)
        features.append(match_count)
        
        # Severity distribution
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for match in yara_matches:
            severity = getattr(match, 'meta', {}).get('severity', 'medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        features.extend([severity_counts['critical'], severity_counts['high'], 
                        severity_counts['medium'], severity_counts['low']])
        
        # Category diversity
        categories = set()
        for match in yara_matches:
            match_categories = getattr(match, '_categories', [])
            categories.update(match_categories)
        features.append(len(categories))
        
        # File metadata features
        file_size = file_metadata.get('size', 0)
        features.append(file_size)
        features.append(1 if file_size > 0 else 0)  # has size
        
        file_type = file_metadata.get('type', 'unknown')
        features.append(hash(file_type) % 1000)  # hash for type
        
        # Entropy (if available)
        entropy = file_metadata.get('entropy', 0)
        features.append(entropy)
        
        # Suspicious patterns
        suspicious_patterns = file_metadata.get('suspicious_patterns', 0)
        features.append(suspicious_patterns)
        
        return np.array(features).reshape(1, -1)
    
    def analyze_threat_level(self, yara_matches: List, file_metadata: Dict) -> Dict:
        """Analyze threat level using ML classifier."""
        if not ML_AVAILABLE or self.threat_classifier is None:
            return self._rule_based_analysis(yara_matches, file_metadata)
        
        try:
            features = self.extract_features(yara_matches, file_metadata)
            
            # Predict threat level
            threat_score = self.threat_classifier.predict_proba(features)[0]
            threat_level = self._get_threat_level_from_score(threat_score)
            
            return {
                'threat_level': threat_level,
                'confidence': float(max(threat_score)),
                'ml_analysis': True,
                'features_used': len(features[0])
            }
        except Exception as e:
            logging.error(f"ML threat analysis failed: {e}")
            return self._rule_based_analysis(yara_matches, file_metadata)
    
    def detect_anomalies(self, yara_matches: List, file_metadata: Dict) -> Dict:
        """Detect anomalous behavior patterns using isolation forest."""
        if not ML_AVAILABLE or self.anomaly_detector is None:
            return {'anomaly_detected': False, 'anomaly_score': 0.0}
        
        try:
            features = self.extract_features(yara_matches, file_metadata)
            anomaly_score = self.anomaly_detector.decision_function(features)[0]
            is_anomaly = self.anomaly_detector.predict(features)[0] == -1
            
            return {
                'anomaly_detected': is_anomaly,
                'anomaly_score': float(anomaly_score),
                'ml_analysis': True
            }
        except Exception as e:
            logging.error(f"ML anomaly detection failed: {e}")
            return {'anomaly_detected': False, 'anomaly_score': 0.0}
    
    def _rule_based_analysis(self, yara_matches: List, file_metadata: Dict) -> Dict:
        """Fallback rule-based analysis when ML is unavailable."""
        critical_count = sum(1 for m in yara_matches 
                           if getattr(m, 'meta', {}).get('severity') == 'critical')
        high_count = sum(1 for m in yara_matches 
                        if getattr(m, 'meta', {}).get('severity') == 'high')
        
        if critical_count > 0:
            threat_level = 'critical'
        elif high_count > 0:
            threat_level = 'high'
        elif len(yara_matches) > 3:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        return {
            'threat_level': threat_level,
            'confidence': 0.7,
            'ml_analysis': False,
            'rule_based': True
        }
    
    def _get_threat_level_from_score(self, scores: np.ndarray) -> str:
        """Convert ML probability scores to threat level."""
        if len(scores) >= 4:
            # Assuming classes: [critical, high, medium, low]
            max_idx = np.argmax(scores)
            levels = ['critical', 'high', 'medium', 'low']
            return levels[max_idx]
        return 'medium'
    
    def update_model(self, yara_matches: List, file_metadata: Dict, 
                    actual_threat: str, was_correct: bool):
        """Update ML model with new training data."""
        if not ML_AVAILABLE or self.threat_classifier is None:
            return
        
        try:
            features = self.extract_features(yara_matches, file_metadata)
            # In a real implementation, you'd accumulate training data
            # and periodically retrain the model
            logging.info(f"Model update: threat={actual_threat}, correct={was_correct}")
        except Exception as e:
            logging.error(f"Model update failed: {e}")
    
    def save_models(self):
        """Save trained models to disk."""
        if not ML_AVAILABLE:
            return
        
        try:
            if self.threat_classifier:
                joblib.dump(self.threat_classifier, 
                          os.path.join(self.model_dir, 'threat_classifier.pkl'))
            if self.anomaly_detector:
                joblib.dump(self.anomaly_detector, 
                          os.path.join(self.model_dir, 'anomaly_detector.pkl'))
            logging.info("ML models saved successfully")
        except Exception as e:
            logging.error(f"Failed to save ML models: {e}")
    
    def get_security_recommendations(self, analysis_result: Dict) -> List[str]:
        """Generate security recommendations based on analysis results."""
        recommendations = []
        
        threat_level = analysis_result.get('threat_level', 'low')
        
        if threat_level == 'critical':
            recommendations.append("Immediate quarantine recommended")
            recommendations.append("Scan system for related infections")
            recommendations.append("Review network connections")
        elif threat_level == 'high':
            recommendations.append("Quarantine recommended")
            recommendations.append("Investigate file origin")
        elif threat_level == 'medium':
            recommendations.append("Monitor file behavior")
            recommendations.append("Consider quarantining if suspicious")
        
        if analysis_result.get('anomaly_detected', False):
            recommendations.append("Anomalous behavior detected - investigate")
        
        return recommendations

# Global ML analyzer instance
_ml_analyzer = None

def get_ml_analyzer() -> MLYaraAnalyzer:
    """Get or create the global ML analyzer instance."""
    global _ml_analyzer
    if _ml_analyzer is None:
        _ml_analyzer = MLYaraAnalyzer()
    return _ml_analyzer