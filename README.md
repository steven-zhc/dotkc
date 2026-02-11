# dotkc (Vault backend)

[![npm version](https://img.shields.io/npm/v/dotkc.svg)](https://www.npmjs.com/package/dotkc)
[![license](https://img.shields.io/npm/l/dotkc.svg)](./LICENSE)

A secrets CLI + dotenv-style runner designed for OpenClaw/local-agent workflows.

This branch documents the **Vault backend**: an encrypted vault file stored in iCloud Drive (synced) plus a **per-machine local key file** (not synced).

> Looking for the Keychain backend docs? See the `main` branch.

---

## What problem does this solve?

- You want secrets available on multiple Macs (MacBook → Mac mini hosting OpenClaw)
- You want the secrets **synced reliably** (file sync is simpler than Keychain enumeration across machines)
- You want secrets **encrypted at rest** and never committed to git or pasted into chats

**Model:**
- iCloud Drive stores only encrypted data (`dotkc.vault`)
- Each machine stores a local decryption key (`~/.dotkc/key`)

Any machine that has both files can decrypt and inject secrets.

---

## Security & threat model (read first)

- The vault file is encrypted with **AES-256-GCM**.
- The key file is a random 32-byte key stored locally.
- If an attacker gets **both** the vault file and the key file, they can decrypt.
- Do **not** store the key file in iCloud Drive.
- Avoid printing env vars in logs.

---

## Install

```bash
npm i -g dotkc
```

### pnpm note

`dotkc` includes native dependencies in the published package (even if you only use the Vault backend), so `pnpm` may require approving build scripts:

```bash
pnpm add -g dotkc
pnpm approve-builds -g
```

---

## Vault locations (defaults)

- Vault file (synced):
  - `~/Library/Mobile Documents/com~apple~CloudDocs/dotkc/dotkc.vault`
- Key file (per-machine, NOT synced):
  - `~/.dotkc/key` (chmod 600)

Overrides:

```bash
export DOTKC_VAULT_PATH="/path/to/dotkc.vault"
export DOTKC_VAULT_KEY_PATH="$HOME/.dotkc/key"
```

---

## Data model

A secret is identified by:
- `service` — SaaS name (e.g. `fly.io`, `vercel`)
- `category` — project/env/group (e.g. `nextloom-ai-dev`)
- `KEY` — env var name (e.g. `CLERK_PUBLISHABLE_KEY`)

Stored inside the vault as:
- `service` → `{ "<category>:<KEY>": "<value>" }`

Recommendation: keep `category` free of `:` (use `-` or `/`) so prefix matching is unambiguous.

---

## Quickstart

### 1) Initialize vault + key

On your primary machine (A):

```bash
dotkc vault init
```

This will create:
- vault file (if missing)
- key file (if missing)

### 2) Add secrets

Interactive (hidden prompt):

```bash
dotkc vault set fly.io nextloom-ai-dev CLERK_PUBLISHABLE_KEY
```

Import from dotenv (interactive picker):

```bash
dotkc vault import fly.io nextloom-ai-dev .env
```

### 3) Inspect (no command)

Omit `-- <cmd>` to enter inspect mode (prints **redacted** values by default):

```bash
dotkc vault run fly.io:nextloom-ai-dev
```

Unsafe (print full values):

```bash
dotkc vault run --unsafe-values fly.io:nextloom-ai-dev
```

JSON output:

```bash
dotkc vault run --json fly.io:nextloom-ai-dev
```

### 4) Run a command with secrets injected

```bash
dotkc vault run fly.io:nextloom-ai-dev -- pnpm dev
```

---

## Bootstrap a new machine (B)

To decrypt the synced vault on machine B, you must copy the **key file** to B:

- Copy `~/.dotkc/key` from A → B (secure channel)
- On B:

```bash
mkdir -p ~/.dotkc
chmod 600 ~/.dotkc/key
```

Then verify:

```bash
dotkc vault status
```

---

## Commands (vault)

- `dotkc vault init [--vault <path>] [--key <path>]`
- `dotkc vault status [--vault <path>] [--key <path>]`
- `dotkc vault set/get/del <service> <category> <KEY>`
- `dotkc vault list <service> [category]`
- `dotkc vault import <service> <category> [dotenv_file]`
- `dotkc vault run [--json] [--unsafe-values] [dotenv options] <spec>[,<spec>...] [-- <cmd> ...]`

`spec` formats:
- wildcard: `<service>:<category>`
- exact: `<service>:<category>:<KEY>`

---

## License

Apache-2.0
