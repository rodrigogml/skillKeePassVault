---
name: keepass-vault
description: Read and modify KeePassXC password vault entries and encrypted attachments through the bundled secure JSON wrapper. Use when an agent needs to list entry paths, read standard fields or current TOTP codes, modify entries, or export, import and remove attachments in a configured KDBX vault. Requires a project-specific INI configuration passed to the wrapper. Do not use for cloning entries or custom KeePass attributes, which are unsupported in v1.
---

# KeePass Vault

Use `scripts/keepass_vault.py` as the only interface to the vault. Pass one project-specific INI file with `--config` and one JSON request containing `version: 1` on stdin. The script writes exactly one JSON response to stdout; diagnostic output goes to stderr and never includes secret values.

Use `scripts/config_tool.py` to create and validate configuration files. Always generate a model instead of writing the INI from memory:

```text
python scripts/config_tool.py init --path C:\\project\\config\\keepass-personal.ini
python scripts/config_tool.py validate --path C:\\project\\config\\keepass-personal.ini
```

`init` creates parent directories and refuses to overwrite an existing file unless `--force` is supplied. `validate` returns exit code 0 only when the file has the required section, accepted keys, valid values, and an existing KDBX file.

## Configuration

Use a separate file for each vault/profile. The script reads only `[keepass]` and ignores other sections:

```ini
[keepass]
cli_path = keepassxc-cli
database_path = C:\vaults\personal.kdbx
timeout_seconds = 30
```

`cli_path` and `database_path` are required. `timeout_seconds` defaults to 30. The only accepted keys are `cli_path`, `database_path`, and `timeout_seconds`; unknown keys produce an error. Do not put the database password in the INI file.

## Request rules

Use the contract in [references/contract.md](references/contract.md). The supported operations are `list`, `list.totp`, `read`, `add`, `edit`, `delete`, `copy`, `attachment.export`, `attachment.import`, and `attachment.delete`. Address entries by their full KeePass group path. Use `confirm: true` for `delete`, attachment import, and attachment deletion.

Supported standard fields are `title`, `username`, `password`, `url`, and `notes`. `totp` is read-only and returns the current code, never the TOTP secret. Use the `list.totp` operation when only entries with a configured TOTP must be discovered; it returns paths only and never exposes generated codes. Clone operations and custom attributes return `unsupported_operation`.

Attachments are addressed by their configured filename and explicit local paths. `attachment.export` writes the bytes to `destination` and returns only metadata and the resolved path; it never returns attachment content in JSON. Existing destinations require `overwrite: true`. `attachment.import` reads `source` into the encrypted KDBX and can use `overwrite: true` to replace an existing attachment. `attachment.delete` removes an attachment from the vault. Import and deletion always require `confirm: true`. Attachment names must be simple filenames without path separators. The installed KeePassXC CLI does not expose a dedicated attachment-list operation, so callers must know the attachment name.

An exported attachment is plaintext on disk even though it is encrypted inside the KDBX. Consumers such as an SSH integration should use a temporary directory, restrict its permissions where supported, avoid logging the contents, and remove the file immediately after use.

Authentication is selected per request with `auth.mode`:

- `stdin`: provide the database password in the request's `auth.password` field;
- `windows_credential_manager`: provide `auth.target`, the Windows Credential Manager target name;
- `prompt`: read the database password interactively without echoing it.

Never put a password or key file in a command-line argument. Do not copy values to the clipboard. Do not repeat secrets in logs or error messages.

## Execution guidance

1. Select the intended profile file and invoke the wrapper with `--config`.
2. Resolve the requested entry path and field without exposing unrelated fields.
3. For writes, invoke only the corresponding KeePassXC CLI operation and save immediately on success.
4. Treat non-zero CLI exits as structured errors; do not forward raw CLI output when it may contain sensitive data.
5. If an operation is not supported by the installed CLI, return a descriptive `unsupported_operation` response.
