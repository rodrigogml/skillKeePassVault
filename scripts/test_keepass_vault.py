import io
import json
import os
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

    @patch("keepass_vault.Cli.command")
    def test_list_totp_returns_only_entries_with_an_otp_field(self, command):
        command.return_value = """<KeePassFile><Root><Group><Name>Root</Name><Entry><String><Key>Title</Key><Value>With TOTP</Value></String><String><Key>otp</Key><Value>otpauth://totp/a?secret=JBSWY3DPEHPK3PXP</Value></String></Entry><Entry><String><Key>Title</Key><Value>Without TOTP</Value></String></Entry><Group><Name>Mail</Name><Entry><String><Key>Title</Key><Value>Nested</Value></String><String><Key>otp</Key><Value>otpauth://totp/b?secret=JBSWY3DPEHPK3PXP</Value></String></Entry></Group></Group></Root></KeePassFile>"""
        result = handle({"operation": "list.totp", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(result["entries"], [{"path": "With TOTP", "uuid": None, "has_totp": True}, {"path": "Mail/Nested", "uuid": None, "has_totp": True}])
        self.assertEqual(command.call_args.args[0], ["export", "-q", "--format", "xml", "vault.kdbx"])

    @patch("keepass_vault.subprocess.run")
    def test_delete_requires_confirmation(self, run):
        with self.assertRaises(VaultError) as raised:
            handle({"operation": "delete", "entry": {"path": "Mail/Example"}, "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "confirmation_required")
        run.assert_not_called()

    @patch("keepass_vault.subprocess.run")
    def test_attachment_export_returns_destination_without_content(self, run):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "id_ed25519"
            run.return_value = FakeCompleted("")
            result = handle({"operation": "attachment.export", "entry": {"path": "SSH/server"}, "attachment": "id_ed25519", "destination": str(destination), "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertTrue(result["exported"])
        self.assertEqual(result["destination"], str(destination.resolve()))
        command = run.call_args.args[0]
        self.assertIn("attachment-export", command)
        self.assertNotIn("id_ed25519", run.call_args.kwargs["input"])

    @patch("keepass_vault.subprocess.run")
    def test_attachment_export_rejects_existing_destination(self, run):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "existing"
            destination.write_text("do not overwrite", encoding="utf-8")
            with self.assertRaises(VaultError) as raised:
                handle({"operation": "attachment.export", "entry": {"path": "SSH/server"}, "attachment": "key", "destination": str(destination), "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "destination_exists")
        run.assert_not_called()

    @patch("keepass_vault.subprocess.run")
    def test_attachment_import_requires_confirmation(self, run):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "key"
            source.write_text("private key", encoding="utf-8")
            with self.assertRaises(VaultError) as raised:
                handle({"operation": "attachment.import", "entry": {"path": "SSH/server"}, "attachment": "key", "source": str(source), "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "confirmation_required")
        run.assert_not_called()

    @patch("keepass_vault.subprocess.run")
    def test_attachment_import_can_force_replace(self, run):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "key"
            source.write_text("private key", encoding="utf-8")
            run.return_value = FakeCompleted("")
            result = handle({"operation": "attachment.import", "entry": {"path": "SSH/server"}, "attachment": "key", "source": str(source), "overwrite": True, "confirm": True, "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertTrue(result["imported"])
        command = run.call_args.args[0]
        self.assertIn("--force", command)
        self.assertIn("attachment-import", command)

    @patch("keepass_vault.subprocess.run")
    def test_attachment_delete_requires_confirmation_and_calls_cli(self, run):
        with self.assertRaises(VaultError) as raised:
            handle({"operation": "attachment.delete", "entry": {"path": "SSH/server"}, "attachment": "key", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "confirmation_required")
        run.assert_not_called()

        run.return_value = FakeCompleted("")
        result = handle({"operation": "attachment.delete", "entry": {"path": "SSH/server"}, "attachment": "key", "confirm": True, "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertTrue(result["deleted"])
        self.assertIn("attachment-rm", run.call_args.args[0])

    def test_attachment_name_rejects_path_traversal(self):
        with self.assertRaises(VaultError) as raised:
            handle({"operation": "attachment.export", "entry": {"path": "SSH/server"}, "attachment": "..\\key", "destination": "C:\\temp\\key", "auth": {"mode": "stdin", "password": "master"}}, self.settings)
        self.assertEqual(raised.exception.code, "invalid_attachment")

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

    @patch("keepass_vault.time.time", return_value=59)
    @patch("keepass_vault.Cli._totp_uris", return_value={"Mail/Example": "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP"})
    def test_totp_returns_a_code_derived_from_the_entry_uri(self, _uris, _time):
        result = Cli(self.settings, "master").show("Mail/Example", "totp")
        self.assertEqual(result, "996554")

    @patch("keepass_vault.Cli._totp_uris", return_value={})
    def test_totp_rejects_an_entry_without_otp(self, _uris):
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

    def test_config_reports_database_read_access_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "profile.ini"
            database = Path(directory) / "vault.kdbx"
            database.write_bytes(b"test")
            config.write_text(f"[keepass]\ncli_path = cli\ndatabase_path = {database}\n", encoding="utf-8")
            original_open = Path.open
            def open_path(path, *args, **kwargs):
                if path == database:
                    raise PermissionError
                return original_open(path, *args, **kwargs)
            with patch.object(Path, "open", new=open_path):
                with self.assertRaises(VaultError) as raised:
                    load_settings(str(config))
        self.assertEqual(raised.exception.code, "database_access_denied")

    def test_read_only_environment_rejects_vault_mutation(self):
        request = {"operation": "edit", "entry": {"path": "Mail/Example"}, "fields": {"username": "alice"}}
        with patch.dict(os.environ, {"KEEPASS_VAULT_ACCESS": "read_only"}, clear=False):
            with self.assertRaises(VaultError) as raised:
                handle(request, self.settings)
        self.assertEqual(raised.exception.code, "access_denied")

    @patch("keepass_vault.read_windows_credential", return_value="master")
    @patch("keepass_vault.subprocess.run")
    def test_authentication_can_default_to_neutral_environment(self, run, credential):
        run.return_value = FakeCompleted("alice\n")
        environment = {
            "KEEPASS_VAULT_ACCESS": "read_only",
            "KEEPASS_VAULT_AUTH_MODE": "windows_credential_manager",
            "KEEPASS_VAULT_AUTH_TARGET": "bot-vault",
        }
        request = {"operation": "read", "entry": {"path": "Mail/Example"}, "field": "username"}
        with patch.dict(os.environ, environment, clear=False):
            result = handle(request, self.settings)
        self.assertEqual(result["value"], "alice")
        credential.assert_called_once_with("bot-vault")


if __name__ == "__main__":
    unittest.main()
