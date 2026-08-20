#!/usr/bin/env python3
"""Secure, one-request JSON wrapper around keepassxc-cli."""

from __future__ import annotations

import argparse
import base64
import configparser
import ctypes
import getpass
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

FIELDS = {"title", "username", "password", "url", "notes"}
READ_FIELDS = FIELDS | {"totp"}
CONTRACT_VERSION = 1
UNSUPPORTED = {"clone", "attribute", "attributes", "custom_attribute"}
CONFIG_KEYS = {"cli_path", "database_path", "timeout_seconds"}


class VaultError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Settings:
    cli_path: str
    database_path: str
    timeout_seconds: float


def fail(code: str, message: str) -> None:
    raise VaultError(code, message)


def load_settings(path: str) -> Settings:
    config_path = Path(path)
    if not config_path.is_file():
        fail("config_not_found", f"Arquivo de configuração não encontrado: {config_path}")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError) as exc:
        fail("invalid_config", f"Não foi possível ler o arquivo de configuração: {exc.__class__.__name__}")
    if not parser.has_section("keepass"):
        fail("missing_config_section", "O arquivo deve conter a seção [keepass].")
    section = parser["keepass"]
    unknown = sorted(set(section) - CONFIG_KEYS)
    if unknown:
        fail("unknown_config", f"Chaves desconhecidas em [keepass]: {', '.join(unknown)}.")
    cli_path = section.get("cli_path", "").strip()
    database_path = section.get("database_path", "").strip()
    if not cli_path:
        fail("missing_config", "A chave [keepass] cli_path é obrigatória.")
    if not database_path:
        fail("missing_config", "A chave [keepass] database_path é obrigatória.")
    database = Path(database_path)
    if not database.is_file():
        fail("database_not_found", f"Arquivo KDBX não encontrado: {database_path}")
    try:
        with database.open("rb"):
            pass
    except PermissionError:
        fail("database_access_denied", "O processo não possui permissão de leitura para o arquivo KDBX configurado.")
    except OSError as exc:
        fail("database_unavailable", f"Não foi possível abrir o arquivo KDBX configurado: {exc.__class__.__name__}")
    try:
        timeout = float(section.get("timeout_seconds", "30"))
    except ValueError:
        fail("invalid_config", "A chave [keepass] timeout_seconds deve ser numérica.")
    if timeout <= 0:
        fail("invalid_config", "A chave [keepass] timeout_seconds deve ser maior que zero.")
    return Settings(cli_path, database_path, timeout)


def read_windows_credential(target: str) -> str:
    if os.name != "nt":
        fail("auth_unavailable", "windows_credential_manager só está disponível no Windows.")
    if not target:
        fail("invalid_auth", "auth.target é obrigatório para windows_credential_manager.")

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", ctypes.c_uint32), ("Type", ctypes.c_uint32), ("TargetName", ctypes.c_wchar_p),
            ("Comment", ctypes.c_wchar_p), ("LastWritten", ctypes.c_byte * 8),
            ("CredentialBlobSize", ctypes.c_uint32), ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", ctypes.c_uint32), ("AttributeCount", ctypes.c_uint32), ("Attributes", ctypes.c_void_p),
            ("TargetAlias", ctypes.c_wchar_p), ("UserName", ctypes.c_wchar_p),
        ]

    advapi = ctypes.WinDLL("Advapi32.dll")
    credential = ctypes.POINTER(CREDENTIALW)()
    if not advapi.CredReadW(target, 1, 0, ctypes.byref(credential)):
        fail("credential_not_found", "Credencial não encontrada no Windows Credential Manager.")
    try:
        item = credential.contents
        blob = ctypes.string_at(item.CredentialBlob, item.CredentialBlobSize)
        try:
            return blob.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return blob.decode("utf-8", errors="strict").rstrip("\x00")
    finally:
        advapi.CredFree(credential)


def resolve_password(request: Mapping[str, Any]) -> str:
    auth = request.get("auth")
    if not isinstance(auth, Mapping):
        fail("missing_auth", "A chamada deve informar auth.mode.")
    mode = auth.get("mode")
    if mode == "stdin":
        password = auth.get("password")
        if not isinstance(password, str):
            fail("invalid_auth", "auth.password é obrigatório para o modo stdin.")
        return password
    if mode == "windows_credential_manager":
        return read_windows_credential(str(auth.get("target", "")))
    if mode == "prompt":
        if not sys.stdin.isatty() and not sys.stderr.isatty():
            fail("auth_unavailable", "O modo prompt exige um terminal interativo.")
        try:
            return getpass.getpass("KeePassXC master password: ")
        except (EOFError, KeyboardInterrupt):
            fail("auth_cancelled", "A leitura interativa da credencial foi cancelada.")
    fail("invalid_auth", "auth.mode deve ser stdin, windows_credential_manager ou prompt.")


def entry_path(request: Mapping[str, Any], key: str = "entry") -> str:
    value = request.get(key)
    if isinstance(value, str):
        path = value
    elif isinstance(value, Mapping):
        path = value.get("path")
    else:
        path = None
    if not isinstance(path, str) or not path.strip():
        fail("invalid_entry", f"{key}.path é obrigatório.")
    return path.strip()


def field_name(request: Mapping[str, Any], required: bool = True) -> str | None:
    field = request.get("field")
    if field is None and not required:
        return None
    if not isinstance(field, str) or field not in READ_FIELDS:
        fail("invalid_field", f"field deve ser um de: {', '.join(sorted(READ_FIELDS))}.")
    return field


def attachment_name(request: Mapping[str, Any]) -> str:
    name = request.get("attachment", request.get("name"))
    if not isinstance(name, str) or not name.strip() or "\\" in name or "/" in name or name in {".", ".."}:
        fail("invalid_attachment", "attachment deve ser um nome simples obrigatório.")
    return name.strip()


def attachment_path(request: Mapping[str, Any], key: str) -> str:
    value = request.get(key)
    if not isinstance(value, str) or not value.strip():
        fail("invalid_path", f"{key} deve ser um caminho obrigatório.")
    return str(Path(value).resolve())


class Cli:
    def __init__(self, settings: Settings, password: str, key_file: str | None = None):
        self.settings = settings
        self.password = password
        self.key_file = key_file

    def command(self, args: Sequence[str], extra_input: str = "", allow_failure: bool = False) -> str | None:
        command = [self.settings.cli_path]
        if self.key_file:
            command.extend(["--key-file", self.key_file])
        if args and args[0] in {"add", "edit", "ls", "rm", "show", "attachment-export", "attachment-import", "attachment-rm"}:
            command.extend([args[0], "-q", *args[1:]])
        else:
            command.extend(args)
        try:
            result = subprocess.run(
                command, input=self.password + "\n" + extra_input, text=True,
                capture_output=True, timeout=self.settings.timeout_seconds, check=False,
            )
        except FileNotFoundError:
            fail("cli_not_found", "keepassxc-cli não foi encontrado; revise cli_path.")
        except subprocess.TimeoutExpired:
            fail("cli_timeout", "keepassxc-cli excedeu o timeout configurado.")
        except OSError as exc:
            fail("cli_unavailable", f"Não foi possível executar keepassxc-cli: {exc.__class__.__name__}")
        if result.returncode != 0 and allow_failure:
            return None
        if result.returncode != 0:
            fail("cli_error", "keepassxc-cli recusou a operação; verifique vault, caminho e credenciais.")
        return result.stdout

    def show(self, path: str, field: str) -> str:
        if field == "totp":
            uri = self._totp_uris().get(path)
            if uri is None:
                fail("totp_not_found", "A entrada não possui um TOTP configurado.")
            return self._current_totp(uri)
        options = ["show"]
        if field == "password":
            options.append("--show-protected")
        return self.command([*options, "-a", field, self.settings.database_path, path]).rstrip("\r\n")

    def list_entries(self) -> list[dict[str, Any]]:
        output = self.command(["ls", "-R", "-f", self.settings.database_path])
        entries = []
        for line in output.splitlines():
            path = line.strip()
            if not path or path.endswith("/") or path.lower().startswith("total"):
                continue
            entries.append({"path": path, "uuid": None, "has_totp": None})
        return entries

    def list_totp_entries(self) -> list[dict[str, Any]]:
        return [{"path": path, "uuid": None, "has_totp": True} for path in self._totp_uris()]

    def _totp_uris(self) -> dict[str, str]:
        output = self.command(["export", "-q", "--format", "xml", self.settings.database_path])
        assert output is not None
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            fail("cli_error", "keepassxc-cli retornou uma exportação XML inválida.")
        root_group = root.find("./Root/Group")
        if root_group is None:
            fail("cli_error", "A exportação XML não contém o grupo raiz do vault.")
        result: dict[str, str] = {}

        def walk(group: ET.Element, prefix: str) -> None:
            for entry in group.findall("Entry"):
                fields = {item.findtext("Key"): item.findtext("Value", "") for item in entry.findall("String")}
                title, otp = fields.get("Title"), fields.get("otp")
                if title and otp:
                    result["/".join(part for part in (prefix, title) if part)] = otp
            for child in group.findall("Group"):
                name = child.findtext("Name", "")
                walk(child, "/".join(part for part in (prefix, name) if part))

        walk(root_group, "")
        return result

    @staticmethod
    def _current_totp(uri: str) -> str:
        parsed = urllib.parse.urlsplit(uri)
        parameters = urllib.parse.parse_qs(parsed.query)
        secret = parameters.get("secret", [""])[0].replace(" ", "").upper()
        algorithm = parameters.get("algorithm", ["SHA1"])[0].upper()
        try:
            digits = int(parameters.get("digits", ["6"])[0])
            period = int(parameters.get("period", ["30"])[0])
            key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
            digest = getattr(hashlib, algorithm.lower())
        except (AttributeError, ValueError, base64.binascii.Error):
            fail("invalid_totp", "A configuração TOTP da entrada é inválida.")
        if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp" or not key or digits not in {6, 7, 8} or period <= 0:
            fail("invalid_totp", "A configuração TOTP da entrada é inválida.")
        counter = int(time.time()) // period
        digest_bytes = hmac.new(key, counter.to_bytes(8, "big"), digest).digest()
        offset = digest_bytes[-1] & 0x0F
        value = int.from_bytes(digest_bytes[offset:offset + 4], "big") & 0x7FFFFFFF
        return str(value % (10 ** digits)).zfill(digits)

    def add_or_edit(self, operation: str, request: Mapping[str, Any]) -> None:
        path = entry_path(request)
        fields = request.get("fields")
        if not isinstance(fields, Mapping) or not fields:
            fail("invalid_fields", "fields deve conter ao menos um campo padrão.")
        if set(fields) - FIELDS:
            fail("unsupported_operation", "Somente campos padrão podem ser escritos.")
        args = [operation, self.settings.database_path, path]
        extra = ""
        if operation == "add" and "title" in fields:
            fail("unsupported_operation", "add usa o último componente de entry.path como título; --title só é suportado em edit.")
        for field in ("title", "username", "url", "notes"):
            if field in fields:
                args.extend(["--title" if field == "title" else f"--{field}", str(fields[field])])
        if "password" in fields:
            args.append("--password-prompt")
            extra = str(fields["password"]) + "\n"
        self.command(args, extra)

    def attachment_export(self, request: Mapping[str, Any]) -> None:
        name = attachment_name(request)
        destination = attachment_path(request, "destination")
        target = Path(destination)
        if target.exists() and request.get("overwrite") is not True:
            fail("destination_exists", "O destino já existe; use overwrite=true para substituí-lo.")
        if not target.parent.is_dir():
            fail("invalid_destination", "A pasta de destino não existe.")
        self.command(["attachment-export", self.settings.database_path, entry_path(request), name, destination])

    def attachment_import(self, request: Mapping[str, Any]) -> None:
        name = attachment_name(request)
        source = attachment_path(request, "source")
        if not Path(source).is_file():
            fail("file_not_found", "O arquivo do anexo não foi encontrado.")
        args = ["attachment-import", self.settings.database_path, entry_path(request), name, source]
        if request.get("overwrite") is True:
            args.insert(1, "--force")
        self.command(args)

    def attachment_delete(self, request: Mapping[str, Any]) -> None:
        self.command(["attachment-rm", self.settings.database_path, entry_path(request), attachment_name(request)])

    def delete(self, request: Mapping[str, Any]) -> None:
        if request.get("confirm") is not True:
            fail("confirmation_required", "delete exige confirm=true.")
        self.command(["rm", self.settings.database_path, entry_path(request)])


def handle(request: Mapping[str, Any], settings: Settings) -> dict[str, Any]:
    operation = request.get("operation")
    if not isinstance(operation, str):
        fail("invalid_operation", "operation é obrigatório.")
    if operation in UNSUPPORTED:
        fail("unsupported_operation", "Clone e atributos customizados não fazem parte da v1.")
    password = resolve_password(request)
    auth = request["auth"]
    key_file = auth.get("key_file") if isinstance(auth, Mapping) else None
    cli = Cli(settings, password, key_file if isinstance(key_file, str) else None)
    if operation == "list":
        return {"entries": cli.list_entries()}
    if operation == "list.totp":
        return {"entries": cli.list_totp_entries()}
    if operation == "read":
        field = field_name(request)
        path = entry_path(request)
        return {"entry": path, "field": field, "value": cli.show(path, field)}
    if operation in {"attachment.export", "attachment.import", "attachment.delete"}:
        if operation != "attachment.export" and request.get("confirm") is not True:
            fail("confirmation_required", "Alterações em anexos exigem confirm=true.")
        if operation == "attachment.export":
            cli.attachment_export(request)
            return {"entry": entry_path(request), "attachment": attachment_name(request), "destination": attachment_path(request, "destination"), "exported": True}
        if operation == "attachment.import":
            cli.attachment_import(request)
            return {"entry": entry_path(request), "attachment": attachment_name(request), "imported": True}
        cli.attachment_delete(request)
        return {"entry": entry_path(request), "attachment": attachment_name(request), "deleted": True}
    if operation in {"add", "edit"}:
        cli.add_or_edit(operation, request)
        return {"entry": entry_path(request), "operation": operation, "saved": True}
    if operation == "delete":
        cli.delete(request)
        return {"entry": entry_path(request), "operation": operation, "deleted": True}
    if operation == "copy":
        field = field_name(request)
        if field not in FIELDS:
            fail("invalid_field", "copy aceita somente campos graváveis: notes, password, title, url ou username.")
        source = entry_path(request, "source")
        destination = entry_path(request, "destination")
        value = cli.show(source, field)
        cli.add_or_edit("edit", {"entry": {"path": destination}, "fields": {field: value}})
        return {"source": source, "destination": destination, "field": field, "copied": True}
    fail("invalid_operation", "operation deve ser list, list.totp, read, add, edit, delete, copy ou attachment.*.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Arquivo INI do perfil KeePassXC")
    args = parser.parse_args(argv)
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, Mapping):
            fail("invalid_json", "A requisição JSON deve ser um objeto.")
        if request.get("version") != CONTRACT_VERSION:
            fail("unsupported_version", f"version deve ser {CONTRACT_VERSION}.")
        settings = load_settings(args.config)
        data = handle(request, settings)
        print(json.dumps({"version": CONTRACT_VERSION, "ok": True, "operation": request.get("operation"), "data": data}, ensure_ascii=False))
        return 0
    except json.JSONDecodeError:
        error = {"code": "invalid_json", "message": "A entrada não contém JSON válido."}
    except VaultError as exc:
        error = {"code": exc.code, "message": exc.message}
    except Exception:
        error = {"code": "internal_error", "message": "Falha interna ao processar a solicitação."}
    print(json.dumps({"version": CONTRACT_VERSION, "ok": False, "error": error}, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
