import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security.hardened_scan_pipeline import iter_files, scan_file


class HardenedScanPipelineTests(unittest.TestCase):
    def test_iter_files_has_no_size_cap(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'large-server.bin')
            with open(path, 'wb') as handle:
                handle.write(b'x' * (2 * 1024 * 1024))
            self.assertEqual(list(iter_files(root)), [path])

    @patch('security.hardened_scan_pipeline._ml_confidence', return_value=0.0)
    @patch('security.hardened_scan_pipeline._yara', return_value=[])
    def test_legitimate_audio_capability_is_not_quarantined(self, _yara, _ml):
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as handle:
            handle.write(b'RIFF' + b'WAVE' + b'AudioClient PortAudio')
            path = handle.name
        try:
            result = scan_file(path, quarantine=True)
            self.assertFalse(result['quarantine'])
            self.assertEqual(result['status'], 'clean_or_uncorroborated')
        finally:
            os.unlink(path)

    @patch('security.hardened_scan_pipeline._ml_confidence', return_value=0.9)
    @patch('security.hardened_scan_pipeline._yara', return_value=[{'severity': 'high'}])
    @patch('quarantine_utils.quarantine_file')
    def test_correlated_detection_attempts_quarantine(self, quarantine, _yara, _ml):
        php_open = b'<' + b'?php'
        command = b'sys' + b'tem'
        request = b'$_' + b'GET'
        webshell = php_open + b' ' + command + b'(' + request
        network = b' socket(' + b'connect(' + b' C2)'
        payload = webshell + b'["cmd"];' + network + b' lsass mimikatz uploadfile'
        with tempfile.NamedTemporaryFile(suffix='.php', delete=False) as handle:
            handle.write(payload)
            path = handle.name
        try:
            result = scan_file(path, quarantine=True)
            self.assertTrue(result['quarantine'])
            quarantine.assert_called_once()
        finally:
            os.unlink(path)

    @patch('security.hardened_scan_pipeline._ml_confidence', return_value=0.9)
    @patch('security.hardened_scan_pipeline._yara', return_value=[{'severity': 'critical'}])
    @patch('quarantine_utils.quarantine_file')
    def test_yara_rule_sources_are_reported_but_not_quarantined(self, quarantine, _yara, _ml):
        with tempfile.TemporaryDirectory() as root:
            rule_root = Path(root) / 'yara_rules'
            rule_root.mkdir()
            path = rule_root / 'research_rule.yar'
            path.write_text('rule research_fixture { condition: true }', encoding='utf-8')
            with patch('security.hardened_scan_pipeline._SECURITY_RULE_ROOT', rule_root.resolve()):
                result = scan_file(str(path), quarantine=True)
            self.assertTrue(result['security_research_asset'])
            self.assertFalse(result['quarantine'])
            self.assertEqual(result['status'], 'security_research_asset_review')
            quarantine.assert_not_called()


if __name__ == '__main__':
    unittest.main()
