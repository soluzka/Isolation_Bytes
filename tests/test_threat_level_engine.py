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

    def test_known_c2_port_immediately_reaches_blocking_threshold(self):
        engine = ThreatLevelEngine(ema_alpha=0.35)
        result = engine.update(
            'network:203.0.113.10:8443',
            behavioral_signals={'known_c2_port': 0.75},
        )
        self.assertGreaterEqual(result['score'], 90.0)
        self.assertEqual(result['level'], 'critical')
        self.assertEqual(result['behavioral_signals']['known_c2_port'], 0.75)

    def test_non_c2_network_signal_does_not_force_critical(self):
        engine = ThreatLevelEngine(ema_alpha=0.35)
        result = engine.update(
            'network:203.0.113.20:443',
            behavioral_signals={'repeated_remote_connection': 0.25},
        )
        self.assertLess(result['score'], 80.0)


if __name__ == '__main__':
    unittest.main()
