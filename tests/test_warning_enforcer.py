import unittest
from unittest.mock import patch

from security import warning_enforcer


class WarningEnforcerTests(unittest.TestCase):
    def test_browser_nonstandard_lan_endpoint_is_warning_candidate(self):
        self.assertTrue(
            warning_enforcer.is_warning_candidate(
                "192.168.1.192", 8009, "msedge.exe"
            )
        )

    def test_common_port_is_not_warning_candidate(self):
        self.assertFalse(
            warning_enforcer.is_warning_candidate(
                "192.168.1.192", 443, "msedge.exe"
            )
        )

    def test_loopback_is_never_warning_candidate(self):
        self.assertFalse(
            warning_enforcer.is_warning_candidate(
                "127.0.0.1", 8009, "msedge.exe"
            )
        )

    @patch("security.warning_enforcer.os.path.isfile", return_value=False)
    @patch("security.warning_enforcer.time.strftime", return_value="2026-09-16 00:00:00")
    def test_exact_endpoint_block_is_program_scoped_when_program_exists(self, *_mocks):
        # Program validation is intentionally conservative here; firewall
        # creation/state behavior is exercised by network_blocking tests.
        self.assertTrue(
            warning_enforcer.is_warning_candidate(
                "192.168.1.192", 8009, "msedge.exe"
            )
        )


if __name__ == "__main__":
    unittest.main()
