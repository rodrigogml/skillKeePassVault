import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from keepass_vault import Cli, Settings, VaultError, handle, load_settings, main


class FakeCompleted:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = "secret should never be forwarded"


class KeepassVaultTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings("keepassxc-cli", "vault.kdbx", 5)

    @patch("keepass_vault.subprocess.run")
    def test_read_returns_only_requested_value(self, run):
        run.return_value = FakeCompleted("alice\n")
        result = handle({"operation": "read", "entry": {"path": "Mail/Example"}, "field": "username", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(result["value"], "alice")
        self.assertEqual(run.call_args.kwargs["input"], "master\n")
        self.assertNotIn("--pw-stdin", run.call_args.args[0])

    @patch("keepass_vault.subprocess.run")
    def test_password_read_requests_protected_attribute(self, run):
        run.return_value = FakeCompleted("secret\n")
        result = handle({"operation": "read", "entry": {"path": "Mail/Example"}, "field": "password", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(result["value"], "secret")
        command = run.call_args.args[0]
        self.assertIn("--show-protected", command)

    @patch("keepass_vault.subprocess.run")
    def test_list_uses_supported_keepassxc_flags(self, run):
        run.side_effect = [FakeCompleted("Mail/Example\n")]
        result = Cli(self.settings, "master").list_entries()
        self.assertEqual(result[0]["path"], "Mail/Example")
        self.assertIsNone(result[0]["uuid"])
        self.assertIsNone(result[0]["has_totp"])
        self.assertEqual(run.call_count, 1)
        command = run.call_args_list[0].args[0]
        self.assertEqual(command[1:5], ["ls", "-q", "-R", "-f"])

    @patch("keepass_vault.subprocess.run")
    def test_delete_requires_confirmation(self, run):
        with self.assertRaises(VaultError) as raised:
            handle({"operation": "delete", "entry": {"path": "Mail/Example"}, "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "confirmation_required")
        run.assert_not_called()

    @patch("keepass_vault.subprocess.run")
    def test_copy_reads_source_and_edits_destination(self, run):
        run.side_effect = [FakeCompleted("alice\n"), FakeCompleted("")]
        result = handle({"operation": "copy", "source": {"path": "Old/Example"}, "destination": {"path": "New/Example"}, "field": "username", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertTrue(result["copied"])
        self.assertEqual(run.call_count, 2)
        self.assertIn("--username", run.call_args_list[1].args[0])

    def test_unsupported_clone(self):
        with self.assertRaises(VaultError) as raised:
            handle({"operation": "clone", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "unsupported_operation")

    @patch("keepass_vault.subprocess.run")
    def test_copy_rejects_totp_before_reading_or_writing(self, run):
        with self.assertRaises(VaultError) as raised:
            handle({"operation": "copy", "source": {"path": "Old/Example"}, "destination": {"path": "New/Example"}, "field": "totp", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "invalid_field")
        run.assert_not_called()

    @patch("keepass_vault.Cli.command")
    def test_totp_returns_only_a_validated_code(self, command):
        command.return_value = "Current TOTP: 123456\n"
        result = Cli(self.settings, "master").show("Mail/Example", "totp")
        self.assertEqual(result, "123456")

    @patch("keepass_vault.Cli.command")
    def test_totp_rejects_an_unrecognised_cli_response(self, command):
        command.return_value = "Title: Example\nUsername: alice\n"
        with self.assertRaises(VaultError) as raised:
            Cli(self.settings, "master").show("Mail/Example", "totp")
        self.assertEqual(raised.exception.code, "totp_not_found")

    def test_main_rejects_missing_contract_version(self):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps({"operation": "list", "auth": {"mode": "stdin", "password": "master"}}))), redirect_stdout(output):
            self.assertEqual(main(["--config", "unused.ini"]), 1)
        response = json.loads(output.getvalue())
        self.assertEqual(response["error"]["code"], "unsupported_version")

    def test_main_rejects_unsupported_contract_version(self):
        output = io.StringIO()
        request = {"version": 2, "operation": "list", "auth": {"mode": "stdin", "password": "master"}}
        with patch("sys.stdin", io.StringIO(json.dumps(request))), redirect_stdout(output):
            self.assertEqual(main(["--config", "unused.ini"]), 1)
        response = json.loads(output.getvalue())
        self.assertEqual(response["error"]["code"], "unsupported_version")

    def test_config_ignores_other_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "profile.ini"
            database = Path(directory) / "vault.kdbx"
            database.write_bytes(b"test")
            config.write_text(f"[keepass]\ncli_path = cli\ndatabase_path = {database}\n[other]\nsecret = ignored\n", encoding="utf-8")
            settings = load_settings(str(config))
            self.assertEqual(settings.cli_path, "cli")
            self.assertEqual(settings.database_path, str(database))


if __name__ == "__main__":
    unittest.main()
