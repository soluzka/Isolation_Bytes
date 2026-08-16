import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import windows_admin_service as service


class AdminServiceProtocolTests(unittest.TestCase):
    def request(self, value):
        return json.loads(service.handle_json(json.dumps(value).encode()).decode())

    def test_rejects_unknown_action(self):
        response = self.request({'version': service.PROTOCOL_VERSION, 'action': 'process.exec'})
        self.assertFalse(response['ok'])
        self.assertIn('allowlisted', response['error'])

    def test_mutations_require_exact_confirmation(self):
        response = self.request({'version': service.PROTOCOL_VERSION, 'action': 'firewall.block', 'ip': '8.8.8.8'})
        self.assertFalse(response['ok'])
        self.assertIn('confirmation', response['error'])

    @patch.dict('sys.modules', {'network_blocking': SimpleNamespace(
        block_ip=lambda ip, reason: (True, 'Blocked'),
        unblock_ip=lambda ip: (True, 'Unblocked'),
    )})
    def test_confirmed_firewall_mutation_is_dispatched(self):
        response = self.request({
            'version': service.PROTOCOL_VERSION, 'action': 'firewall.block',
            'ip': '8.8.8.8', 'reason': 'test', 'confirmation': service.CONFIRMATION_TOKEN,
        })
        self.assertTrue(response['ok'])
        self.assertTrue(response['mutated'])

    def test_firewall_rejects_non_public_ip(self):
        response = self.request({
            'version': service.PROTOCOL_VERSION, 'action': 'firewall.block',
            'ip': '192.168.1.1', 'confirmation': service.CONFIRMATION_TOKEN,
        })
        self.assertFalse(response['ok'])
        self.assertIn('globally routable', response['error'])

    def test_scan_requires_configured_root(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'ANTIVIRUS_PROTECTED_SCAN_ROOTS': directory}):
            target = Path(directory) / 'sample.bin'
            target.write_bytes(b'sample')
            with patch.object(service, '_scan_paths', return_value={
                'ok': True, 'action': 'scan.protected', 'scanned': 1,
                'detections': [], 'errors': 0, 'bounded': True,
            }):
                response = self.request({
                    'version': service.PROTOCOL_VERSION,
                    'action': 'scan.protected',
                    'paths': [str(target)],
                })
        self.assertTrue(response['ok'])
        self.assertEqual(response['action'], 'scan.protected')
        self.assertEqual(response['scanned'], 1)
        self.assertEqual(response['detections'], [])

    def test_scan_rejects_path_outside_root(self):
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / 'sample.bin'
            target.write_bytes(b'sample')
            with patch.dict(os.environ, {'ANTIVIRUS_PROTECTED_SCAN_ROOTS': allowed}):
                response = self.request({
                    'version': service.PROTOCOL_VERSION,
                    'action': 'scan.protected',
                    'paths': [str(target)],
                })
        self.assertFalse(response['ok'])
        self.assertIn('outside', response['error'])

    def test_quarantine_mutations_validate_filename_and_confirmation(self):
        response = self.request({
            'version': service.PROTOCOL_VERSION, 'action': 'quarantine.delete',
            'filename': '..\\secret.enc', 'confirmation': service.CONFIRMATION_TOKEN,
        })
        self.assertFalse(response['ok'])
        self.assertIn('filename', response['error'])

        response = self.request({
            'version': service.PROTOCOL_VERSION, 'action': 'quarantine.delete',
            'filename': 'sample.enc',
        })
        self.assertFalse(response['ok'])
        self.assertIn('confirmation', response['error'])

    def test_request_fields_are_strictly_allowlisted(self):
        response = self.request({
            'version': service.PROTOCOL_VERSION, 'action': 'service.status', 'extra': True,
        })
        self.assertFalse(response['ok'])
        self.assertIn('fields', response['error'])

    def test_request_size_is_bounded(self):
        response = json.loads(service.handle_json(b'x' * (service.MAX_REQUEST_BYTES + 1)).decode())
        self.assertFalse(response['ok'])
        self.assertEqual(response['error'], 'request too large')


if __name__ == '__main__':
    unittest.main()
