import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import IsolationForest

from ml_security import SecurityMLModel


class SecurityMLTests(unittest.TestCase):
    def test_fitted_state_uses_sklearn_validation(self):
        model = IsolationForest(random_state=42)
        self.assertFalse(SecurityMLModel._is_fitted(model))
        model.fit(np.random.RandomState(42).randn(20, 4))
        self.assertTrue(SecurityMLModel._is_fitted(model))

    def test_unfitted_model_never_claims_anomaly_confidence(self):
        model = SecurityMLModel.__new__(SecurityMLModel)
        model.pipeline = IsolationForest(random_state=42)
        model.model = model.pipeline
        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            handle.write(b"plain baseline content")
            handle.flush()
            self.assertFalse(model.is_fitted())
            self.assertEqual(model.file_anomaly_confidence(handle.name), 0.0)

    def test_anomaly_confidence_is_monotonic_for_anomaly_margin(self):
        model = SecurityMLModel.__new__(SecurityMLModel)
        model.pipeline = object()
        model.model = object()
        model.is_fitted = lambda: True
        model.get_file_features = lambda *_args, **_kwargs: np.zeros((1, 18))
        with patch.object(model, "predict", side_effect=[
            (np.array([-1]), np.array([-0.40])),
            (np.array([1]), np.array([0.40])),
        ]):
            with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
                handle.write(b"test")
                handle.flush()
                anomalous = model.file_anomaly_confidence(handle.name)
                normal = model.file_anomaly_confidence(handle.name)
        self.assertGreater(anomalous, normal)
        self.assertGreaterEqual(anomalous, 0.5)
        self.assertLessEqual(normal, 0.5)


if __name__ == "__main__":
    unittest.main()
