# Contrato JSON

Invocar:

```text
python scripts/keepass_vault.py --config profiles/personal.ini < request.json
```

Cada processo recebe uma requisição e retorna uma resposta.

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

## Campos

Campos legíveis: `title`, `username`, `password`, `url`, `notes` e `totp`.

`totp` retorna somente o código corrente. A chave TOTP nunca é retornada.

Campos graváveis: `title`, `username`, `password`, `url` e `notes`.

Clone e atributos customizados retornam `unsupported_operation`.

## Erros

Erros possuem `ok: false`, `error.code` estável e `error.message` descritiva. Nunca incluem valores secretos nem a saída bruta do KeePassXC.
