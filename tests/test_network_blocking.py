import sys
import types
import unittest
from unittest.mock import patch

import network_blocking


class NetworkBlockingTests(unittest.TestCase):
    def test_non_admin_fails_closed(self):
        with patch.object(network_blocking.os, 'name', 'nt'), patch.object(
            network_blocking, 'is_windows_admin', return_value=False
        ), patch.object(network_blocking, '_run_netsh') as run_netsh:
            ok, message = network_blocking.block_connection('8.8.8.8', 443)
        self.assertFalse(ok)
        self.assertIn('Administrator', message)
        run_netsh.assert_not_called()

    def test_firewall_creation_requires_post_create_verification(self):
        def fake_netsh(args):
            if args[:2] == ['add', 'rule']:
                return True, 'OK'
            if args[:2] == ['show', 'rule']:
                return True, 'unrelated rule output'
            if args[:2] == ['delete', 'rule']:
                return True, 'Deleted 1 rule(s).'
            return False, 'unexpected command'

        with patch.object(network_blocking.os, 'name', 'nt'), patch.object(
            network_blocking, 'is_windows_admin', return_value=True
        ), patch.object(network_blocking, '_run_netsh', side_effect=fake_netsh), patch.object(
            network_blocking, '_load_state', return_value={}
        ), patch.object(network_blocking, '_save_state') as save_state:
            ok, message = network_blocking.block_connection('8.8.8.8', 443)
        self.assertFalse(ok)
        self.assertIn('was not found after creation', message)
        save_state.assert_not_called()

    def test_confirmed_c2_fails_if_any_active_connection_cannot_be_blocked(self):
        class FakeProcess:
            def __init__(self, pid):
                self.pid = pid

            def exe(self):
                return f'C:/bad-{self.pid}.exe'

        fake_psutil = types.SimpleNamespace(
            net_connections=lambda kind='inet': [
                types.SimpleNamespace(raddr=('203.0.113.10', 443), pid=101),
                types.SimpleNamespace(raddr=('203.0.113.10', 8443), pid=102),
            ],
            Process=FakeProcess,
        )

        results = [(True, 'verified'), (False, 'firewall failure')]
        with patch.dict(sys.modules, {'psutil': fake_psutil}), patch.object(
            network_blocking, 'block_connection', side_effect=results
        ):
            ok, message = network_blocking._block_active_connections_for_ip(
                '203.0.113.10', reason='confirmed C2'
            )
        self.assertFalse(ok)
        self.assertIn('1/2', message)

    def test_suspicious_endpoint_requires_high_confidence(self):
        self.assertFalse(
            network_blocking.should_block_suspicious_connection(
                '203.0.113.10', 443,
                threat_level={'level': 'high', 'score': 0.84},
            )
        )
        self.assertTrue(
            network_blocking.should_block_suspicious_connection(
                '203.0.113.10', 443,
                threat_level={'level': 'high', 'score': 0.85},
            )
        )
        self.assertTrue(
            network_blocking.should_block_suspicious_connection(
                '203.0.113.10', 443,
                confidence=0.90,
            )
        )

    def test_suspicious_endpoint_blocks_specific_ip_and_port(self):
        with patch.object(network_blocking, 'block_connection', return_value=(True, 'blocked and verified')) as blocker:
            ok, message = network_blocking.block_suspicious_connection(
                '203.0.113.10', 8443,
                program='C:/bad.exe',
                pid=101,
                threat_level={'level': 'critical', 'score': 0.92},
                reason='high-confidence suspicious connection',
            )
        self.assertTrue(ok)
        self.assertIn('blocked and verified', message)
        blocker.assert_called_once_with(
            '203.0.113.10', 8443,
            program='C:/bad.exe',
            pid=101,
            reason='high-confidence suspicious connection',
        )

    def test_auto_block_requires_actual_confirmation(self):
        ok, message = network_blocking.auto_block_confirmed_c2(
            '203.0.113.10', threat_level={'level': 'medium', 'score': 0.5}, confirmed_c2=False
        )
        self.assertFalse(ok)
        self.assertEqual(message, 'C2 confirmation threshold not met')


if __name__ == '__main__':
    unittest.main()
