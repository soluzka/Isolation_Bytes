import unittest

from threat_level_engine import ThreatLevelEngine


class ThreatLevelEngineTests(unittest.TestCase):
    def test_combines_signals(self):
        engine = ThreatLevelEngine()
        result = engine.score(
            'sample',
            yara_severity='high',
            ml_confidence=0.8,
            behavioral_signals={'c2': 0.9},
        )
        self.assertGreaterEqual(result['score'], 0.65)
        self.assertIn(result['level'], {'high', 'critical'})

    def test_score_fluctuates_with_new_telemetry(self):
        engine = ThreatLevelEngine(decay_seconds=1)
        high = engine.score('network:1.2.3.4', yara_severity='critical', ml_confidence=1.0, behavior_score=1.0)
        low = engine.score('network:1.2.3.4', yara_severity=0, ml_confidence=0, behavior_score=0)
        self.assertGreater(high['score'], low['score'])
        self.assertEqual(low['signals']['yara'], 0.0)


if __name__ == '__main__':
    unittest.main()
