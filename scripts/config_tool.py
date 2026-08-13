#!/usr/bin/env python3
"""Create and validate KeePass Vault configuration files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

try:
    from keepass_vault import CONFIG_KEYS, VaultError, load_settings
except ImportError:  # Direct execution from outside scripts/
    from scripts.keepass_vault import CONFIG_KEYS, VaultError, load_settings


TEMPLATE = """# KeePass Vault profile configuration
# This file is read only from the [keepass] section.
# Other sections may belong to other skills and are ignored by this skill.

[keepass]

# Executable used to access the database.
# Examples: keepassxc-cli | C:\\Program Files\\KeePassXC\\keepassxc-cli.exe
cli_path = keepassxc-cli

# Full path to the KDBX vault file.
# Example: C:\\Users\\alice\\Documents\\personal.kdbx
database_path = C:\\path\\to\\vault.kdbx

# Maximum time, in seconds, allowed for each keepassxc-cli call.
# Must be a number greater than zero. Example: 30
timeout_seconds = 30
"""


def result(ok: bool, code: str, message: str, **data: object) -> dict[str, object]:
    payload: dict[str, object] = {"ok": ok, "code": code, "message": message}
    payload.update(data)
    return payload


def init_config(path: str, force: bool) -> dict[str, object]:
    target = Path(path)
    if target.exists() and not force:
        raise VaultError("config_exists", f"O arquivo já existe: {target}. Use --force para substituí-lo.")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(TEMPLATE, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise VaultError("config_write_error", f"Não foi possível escrever o modelo: {exc.__class__.__name__}") from exc
    return result(True, "template_created", f"Modelo criado em: {target}", path=str(target))


def validate_config(path: str) -> dict[str, object]:
    settings = load_settings(path)
    return result(
        True,
        "config_valid",
        "Arquivo de configuração válido.",
        path=str(Path(path)),
        cli_path=settings.cli_path,
        database_path=settings.database_path,
        timeout_seconds=settings.timeout_seconds,
        accepted_keys=sorted(CONFIG_KEYS),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="criar um modelo comentado")
    init_parser.add_argument("--path", required=True, help="caminho completo do arquivo a criar")
    init_parser.add_argument("--force", action="store_true", help="substituir um arquivo existente")

    validate_parser = subparsers.add_parser("validate", help="validar um arquivo existente")
    validate_parser.add_argument("--path", required=True, help="caminho do arquivo INI")

    args = parser.parse_args(argv)
    try:
        payload = init_config(args.path, args.force) if args.command == "init" else validate_config(args.path)
    except VaultError as exc:
        payload = result(False, exc.code, exc.message)
    except Exception:
        payload = result(False, "internal_error", "Falha interna ao processar a configuração.")
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
