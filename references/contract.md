# Contrato JSON

Invocar:

```text
python scripts/keepass_vault.py --config profiles/personal.ini < request.json
```

Cada processo recebe uma requisição e retorna uma resposta.

`version` é obrigatória e deve ser `1`. Outras versões retornam `unsupported_version`.

## Configuração

Gere e valide o arquivo com a ferramenta fornecida:

```text
python scripts/config_tool.py init --path C:\\project\\config\\keepass-personal.ini
python scripts/config_tool.py validate --path C:\\project\\config\\keepass-personal.ini
```

O comando `init` não sobrescreve arquivos existentes sem `--force`. O comando `validate` exige a seção `[keepass]`, aceita somente `cli_path`, `database_path` e `timeout_seconds`, valida `timeout_seconds` como número maior que zero e confirma que o arquivo KDBX existe.

## Autenticação

```json
{"mode":"stdin","password":"..."}
```

```json
{"mode":"windows_credential_manager","target":"KeePass/personal"}
```

```json
{"mode":"prompt"}
```

Opcionalmente, `key_file` pode apontar para o arquivo de chave. O segredo principal nunca deve aparecer em argumentos ou no arquivo INI.

## Exemplos

Listar:

```json
{"version":1,"operation":"list","auth":{"mode":"stdin","password":"..."}}
```

Ler senha:

```json
{"version":1,"operation":"read","entry":{"path":"Finance/Example"},"field":"password","auth":{"mode":"stdin","password":"..."}}
```

Adicionar ou editar:

```json
{"version":1,"operation":"edit","entry":{"path":"Finance/Example"},"fields":{"username":"alice","url":"https://example.test"},"auth":{"mode":"stdin","password":"..."}}
```

Copiar um campo:

```json
{"version":1,"operation":"copy","source":{"path":"Old/Example"},"destination":{"path":"New/Example"},"field":"username","auth":{"mode":"stdin","password":"..."}}
```

Excluir:

```json
{"version":1,"operation":"delete","entry":{"path":"Finance/Example"},"confirm":true,"auth":{"mode":"stdin","password":"..."}}
```

Exportar um anexo sem colocar seus bytes no contexto:

```json
{"version":1,"operation":"attachment.export","entry":{"path":"SSH/server"},"attachment":"id_ed25519","destination":"C:\\temp\\id_ed25519","auth":{"mode":"windows_credential_manager","target":"Akuma/KeePassXC/KeeVault"}}
```

Importar ou substituir um anexo:

```json
{"version":1,"operation":"attachment.import","entry":{"path":"SSH/server"},"attachment":"id_ed25519","source":"C:\\temp\\id_ed25519","overwrite":true,"confirm":true,"auth":{"mode":"windows_credential_manager","target":"Akuma/KeePassXC/KeeVault"}}
```

Excluir um anexo:

```json
{"version":1,"operation":"attachment.delete","entry":{"path":"SSH/server"},"attachment":"id_ed25519","confirm":true,"auth":{"mode":"windows_credential_manager","target":"Akuma/KeePassXC/KeeVault"}}
```

## Campos

Campos legíveis: `title`, `username`, `password`, `url`, `notes` e `totp`.

`totp` retorna somente o código corrente. A chave TOTP nunca é retornada.

Campos graváveis: `title`, `username`, `password`, `url` e `notes`.

Clone e atributos customizados retornam `unsupported_operation`.

Anexos usam os comandos `attachment-export`, `attachment-import` e `attachment-rm` do `keepassxc-cli`. O nome deve ser simples, sem separadores de diretório. A exportação retorna somente o caminho de destino; os bytes nunca são serializados na resposta. A importação e a exclusão exigem `confirm: true`; a exportação exige `overwrite: true` para substituir um arquivo local existente. O CLI instalado não fornece um comando dedicado para listar anexos, portanto o nome deve ser conhecido pela aplicação consumidora.

## Erros

Erros possuem `ok: false`, `error.code` estável e `error.message` descritiva. Nunca incluem valores secretos nem a saída bruta do KeePassXC.
