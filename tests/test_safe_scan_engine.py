import os
import tempfile
import unittest
from unittest.mock import patch

from security.safe_scan_engine import iter_regular_files, scan_roots


class SafeScanEngineTests(unittest.TestCase):
    def test_discovers_all_files_without_count_cap(self):
        with tempfile.TemporaryDirectory() as root:
            for index in range(250):
                path = os.path.join(root, f"file-{index}.bin")
                with open(path, "wb") as handle:
                    handle.write(b"test")
            found = list(iter_regular_files([root]))
            self.assertEqual(len(found), 250)

    def test_does_not_follow_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            nested = os.path.join(root, "nested")
            os.mkdir(nested)
            with open(os.path.join(nested, "one.bin"), "wb") as handle:
                handle.write(b"x")
            link = os.path.join(root, "loop")
            try:
                os.symlink(root, link, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            found = list(iter_regular_files([root]))
            self.assertEqual(len(found), 1)

    def test_one_file_error_does_not_abort_scan(self):
        with tempfile.TemporaryDirectory() as root:
            paths = []
            for index in range(3):
                path = os.path.join(root, f"file-{index}.bin")
                with open(path, "wb") as handle:
                    handle.write(b"x")
                paths.append(path)

            fake_results = [
                {"filepath": paths[0], "yara_matches": [], "yara_severity": "low", "threat": {}},
                {"filepath": paths[2], "yara_matches": [], "yara_severity": "low", "threat": {}},
            ]

            def fake_analyze(path, timeout=2):
                if path == paths[1]:
                    raise OSError("simulated read failure")
                return fake_results[0] if path == paths[0] else fake_results[1]

            with patch("security.yara_ml_pipeline.analyze_file", side_effect=fake_analyze):
                stats = scan_roots([root])

            self.assertEqual(stats.discovered, 3)
            self.assertEqual(stats.scanned, 2)
            self.assertEqual(stats.errors, 1)
            self.assertEqual(len(stats.results), 3)


if __name__ == "__main__":
    unittest.main()
