import json
import tempfile
import unittest
from pathlib import Path

from config_tool import main


class ConfigToolTests(unittest.TestCase):
    def test_init_writes_commentated_template_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "profile.ini"
            self.assertEqual(main(["init", "--path", str(path)]), 0)
            content = path.read_text(encoding="utf-8")
            self.assertIn("[keepass]", content)
            self.assertIn("# Examples:", content)
            self.assertIn("timeout_seconds = 30", content)
            self.assertEqual(main(["init", "--path", str(path)]), 1)

    def test_validate_accepts_profile_and_reports_values(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "vault.kdbx"
            database.write_bytes(b"placeholder")
            config = Path(directory) / "profile.ini"
            config.write_text(f"[keepass]\ncli_path = keepassxc-cli\ndatabase_path = {database}\ntimeout_seconds = 15\n[other]\nignored = yes\n", encoding="utf-8")
            self.assertEqual(main(["validate", "--path", str(config)]), 0)

    def test_validate_rejects_unknown_key(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "vault.kdbx"
            database.write_bytes(b"placeholder")
            config = Path(directory) / "profile.ini"
            config.write_text(f"[keepass]\ncli_path = cli\ndatabase_path = {database}\nwrong_name = value\n", encoding="utf-8")
            self.assertEqual(main(["validate", "--path", str(config)]), 1)


if __name__ == "__main__":
    unittest.main()
