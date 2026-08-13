import configparser
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from keepass_vault import main


class KeepassVaultIntegrationTests(unittest.TestCase):
    password = "integration-master-password"

    def setUp(self):
        self.cli_path = shutil.which("keepassxc-cli")
        if not self.cli_path:
            self.skipTest("keepassxc-cli não está instalado; teste de integração indisponível.")
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = self.root / "vault.kdbx"
        self.config = self.root / "keepass-vault_integration.ini"
        created = subprocess.run(
            [self.cli_path, "db-create", "--set-password", str(self.database)],
            input=f"{self.password}\n{self.password}\n",
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if created.returncode != 0 or not self.database.is_file():
            self.skipTest("A versão instalada do keepassxc-cli não criou um KDBX temporário de modo não interativo.")
        created_group = subprocess.run(
            [self.cli_path, "--pw-stdin", "mkdir", str(self.database), "Test"],
            input=f"{self.password}\n",
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if created_group.returncode != 0:
            self.skipTest("A versão instalada do keepassxc-cli não criou o grupo temporário de integração.")
        parser = configparser.ConfigParser()
        parser["keepass"] = {
            "cli_path": self.cli_path,
            "database_path": str(self.database),
            "timeout_seconds": "30",
        }
        with self.config.open("w", encoding="utf-8") as file:
            parser.write(file)

    def tearDown(self):
        self.tempdir.cleanup()

    def invoke(self, request):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps(request))), redirect_stdout(output):
            exit_code = main(["--config", str(self.config)])
        self.assertEqual(exit_code, 0)
        return json.loads(output.getvalue())

    def request(self, operation, **data):
        return {
            "version": 1,
            "operation": operation,
            "auth": {"mode": "stdin", "password": self.password},
            **data,
        }

    def test_entry_lifecycle(self):
        added = self.invoke(self.request("add", entry={"path": "Test/Source"}, fields={"username": "alice"}))
        self.assertTrue(added["data"]["saved"])

        read = self.invoke(self.request("read", entry={"path": "Test/Source"}, field="username"))
        self.assertEqual(read["data"]["value"], "alice")

        edited = self.invoke(self.request("edit", entry={"path": "Test/Source"}, fields={"username": "bob"}))
        self.assertTrue(edited["data"]["saved"])

        self.invoke(self.request("add", entry={"path": "Test/Destination"}, fields={"username": "placeholder"}))
        copied = self.invoke(self.request("copy", source={"path": "Test/Source"}, destination={"path": "Test/Destination"}, field="username"))
        self.assertTrue(copied["data"]["copied"])

        destination = self.invoke(self.request("read", entry={"path": "Test/Destination"}, field="username"))
        self.assertEqual(destination["data"]["value"], "bob")

        listed = self.invoke(self.request("list"))
        self.assertTrue(any(entry["path"] == "Test/Source" for entry in listed["data"]["entries"]))

        deleted = self.invoke(self.request("delete", entry={"path": "Test/Source"}, confirm=True))
        self.assertTrue(deleted["data"]["deleted"])


if __name__ == "__main__":
    unittest.main()
