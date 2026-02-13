# dotkc

[![npm version](https://img.shields.io/npm/v/dotkc.svg)](https://www.npmjs.com/package/dotkc)
[![license](https://img.shields.io/npm/l/dotkc.svg)](./LICENSE)

`dotkc` is a small secrets CLI + dotenv-style runner for OpenClaw/local-agent workflows.

- Encrypted vault file (typically iCloud Drive synced)
- Per-machine local key file (NOT synced)

Usage manual + best practices: **https://dotkc.hczhang.com/**

---

## Install

```bash
npm i -g dotkc
# or
pnpm add -g dotkc
```

---

## Paths & environment variables

### Vault / key locations

Defaults:

- `DOTKC_VAULT_PATH` → `~/Library/Mobile Documents/com~apple~CloudDocs/dotkc/dotkc.vault`
- `DOTKC_VAULT_KEY_PATH` → `~/.dotkc/key`

Override:

```bash
export DOTKC_VAULT_PATH="/path/to/dotkc.vault"
export DOTKC_VAULT_KEY_PATH="$HOME/.dotkc/key"
```

### Backup settings (P0 safety)

Before overwriting the vault, dotkc creates a backup and refuses to write if backup fails.
If the vault changes on disk during an operation (sync conflict), dotkc refuses to overwrite and asks you to retry.

- `DOTKC_BACKUP_KEEP=3` keep last 3 backups (default)
- `DOTKC_BACKUP_KEEP=0` disable backups
- `DOTKC_BACKUP_DIR=/path/to/dir` store backups in a separate directory

Backup filenames look like:

- `dotkc.vault.bak-YYYYMMDD-HHMMSSmmm`

---

## Command reference

### `dotkc init`

```bash
dotkc init [--vault <path>] [--key <path>]
```

Creates the vault (if missing) and the local key file (if missing). If they already exist, dotkc may prompt before overwriting.

### `dotkc status`

```bash
dotkc status [--vault <path>] [--key <path>]
```

Prints JSON describing paths + whether the vault can be decrypted.

### `dotkc doctor`

```bash
dotkc doctor [--vault <path>] [--key <path>] [--json]
```

Runs diagnostics for common issues (missing key/vault, wrong permissions, decrypt failures) and prints suggested fixes.

### `dotkc key install`

```bash
# reads key from stdin
cat ~/.dotkc/key | dotkc key install [--key <path>] [--force]
```

Installs a key file (chmod 600). Refuses to overwrite an existing key unless `--force`.

### `dotkc set`

```bash
dotkc set <service> <category> <KEY> [value|-]
```

- Omitting `value` prompts (hidden input)
- `value=-` reads from stdin (non-interactive)

### `dotkc get`

```bash
dotkc get <service> <category> <KEY>
```

Prints the secret to stdout.

### `dotkc del`

```bash
dotkc del <service> <category> <KEY>
```

Deletes the secret.

### `dotkc list`

```bash
dotkc list <service> [category]
```

- If `category` omitted: prints categories
- If `category` provided: prints keys

### `dotkc search`

```bash
dotkc search <query> [--json]
```

Search keys by substring across `service/category/KEY`. Never prints secret values.

### `dotkc import`

```bash
dotkc import <service> <category> [dotenv_file]
```

Interactive picker to import keys from a dotenv file (default: `.env`).

### `dotkc run`

```bash
# inspect mode (no command): prints redacted values by default
dotkc run [options] <spec>[,<spec>...]

# exec mode: inject env and run a command
dotkc run [options] <spec>[,<spec>...] -- <cmd> [args...]
```

Spec formats:

- wildcard: `<service>:<category>`
- exact: `<service>:<category>:<KEY>`

Run options:

- `--json` inspect mode: output JSON (redacted unless `--unsafe-values`)
- `--unsafe-values` inspect mode: print full secret values (unsafe)
- `--dotenv` / `--dotenv-file <path>` / `--dotenv-override` / `--no-default-dotenv`

---

## Exit codes (selected)

- `3` NOT_FOUND

---

## License

Apache-2.0
