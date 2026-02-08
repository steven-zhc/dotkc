# dotkc

[![npm version](https://img.shields.io/npm/v/dotkc.svg)](https://www.npmjs.com/package/dotkc)
[![license](https://img.shields.io/npm/l/dotkc.svg)](./LICENSE)

Keychain-backed secrets with a dotenv-style CLI runner.

`dotkc` stores secrets in your OS credential store (macOS Keychain), which can be synced across Macs via **iCloud Keychain**.

## Security & threat model (read first)

- `dotkc` does **not** upload secrets anywhere.
- Secrets live in your OS credential store. Access control and syncing are managed by your OS (e.g. iCloud Keychain on macOS).
- Prefer stdin for `set` (use `-`) to avoid secrets in shell history and process listings.
- Avoid printing environment variables in logs.

## Why dotkc (core value)

`dotkc` was built for **OpenClaw-style local agents** and developer workflows where you want to safely use API keys/tokens **without pasting secrets into chats** or committing them to git.

### The problem

- `.env` files are convenient, but secrets end up **on disk**, can be copied around, and sometimes get committed by accident.
- Sending tokens to an assistant (or any remote system) can create unwanted **logs/history** and accidental disclosure.

### The approach

`dotkc` keeps secrets in **macOS Keychain** and injects them into a command environment *only at runtime*:
- **Never commit secrets to AI**: you store them locally and run commands that fetch secrets from Keychain.
- **Sync across Macs** via iCloud Keychain (MacBook ↔ Mac mini, etc.).
- **Dotenv-like ergonomics**: `dotkc run ... -- <cmd>`.
- Organize secrets with 3 dimensions: **service (SaaS) + category (project/env) + key (ENV name)**.

### Practical use cases

- OpenClaw: keep provider tokens in Keychain and inject only for the specific agent/gateway command that needs them.
- Multi-machine dev: define secrets once, then reuse on another Mac after iCloud Keychain sync.
- Personal projects: keep secrets off-disk but still easy to run locally.

## Install

```bash
npm i -g dotkc
```

> Note: `keytar` is a native module. You need build tooling for your platform.

## Data model

A secret is identified by:
- `service` — SaaS name (e.g. `vercel`, `stripe`, `openai`)
- `category` — project/env/free-form group (e.g. `acme-app-dev`, `acme-app-prod`)
- `KEY` — environment variable name (e.g. `GITHUB_TOKEN`, `DEPLOY_TOKEN`)

Storage convention:
- stored as Keychain entry `(service, "<category>:<KEY>")`
- injected into environment as `KEY=<value>`

Recommendation: keep `category` free of `:` (use `-` or `/`) so prefix matching is unambiguous.

## Usage

### Set a secret

Prefer stdin (`-`) to avoid shell history leaks:

```bash
(echo -n '...') | dotkc set vercel acme-app-dev GITHUB_TOKEN -
(echo -n '...') | dotkc set vercel acme-app-dev DEPLOY_TOKEN -
```

### Get / delete

```bash
dotkc get vercel acme-app-dev GITHUB_TOKEN
dotkc del vercel acme-app-dev GITHUB_TOKEN
```

### List (categories and keys, no values)

```bash
# list categories under a SaaS
dotkc list vercel

# list keys under a category
dotkc list vercel acme-app-dev
```

### Run a command with secrets injected

Wildcard (load *all* secrets under a category):

```bash
dotkc run vercel:acme-app-dev -- node ./my-app.mjs
```

Exact selection (pick specific keys):

```bash
dotkc run vercel:acme-app-dev:GITHUB_TOKEN,vercel:acme-app-dev:DEPLOY_TOKEN -- node ./my-app.mjs
```

### Run with dotenv files (optional)

If your project already uses `.env` / `.env.local`, you can load them first, then override with Keychain:

```bash
# loads .env then .env.local (if present)
dotkc run --dotenv vercel:acme-app-dev -- node ./my-app.mjs

# load a specific file (repeatable)
dotkc run --dotenv-file .env.staging vercel:acme-app-dev -- node ./my-app.mjs

# allow dotenv to override existing process.env (default is: do NOT override)
dotkc run --dotenv --dotenv-override vercel:acme-app-dev -- node ./my-app.mjs
```

#### Recommended env precedence order

1) Existing `process.env` (e.g. CI, shell exports)
2) Dotenv files (`.env`, `.env.local`, and any `--dotenv-file`)
3) Keychain secrets injected by `dotkc` (**always override**)

This keeps explicit environment exports in control, but guarantees the Keychain secrets win last.

## License

Apache-2.0
