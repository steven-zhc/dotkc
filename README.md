# dotkc

Keychain-backed secrets with a dotenv-style CLI runner.

`dotkc` stores secrets in your OS credential store (macOS Keychain), which can be synced across Macs via **iCloud Keychain**.

## Why dotkc (core value)

Most projects either:
- keep secrets in `.env` files (easy, but they end up on disk, get copied around, and can leak), or
- use a cloud secret manager (great for servers/CI, but heavy for local dev).

`dotkc` is a *local-first* middle ground:
- **No `.env` file required** for secrets (store in Keychain instead)
- **Sync across Macs** via iCloud Keychain
- **Dotenv-like ergonomics**: run any command with secrets injected
- Organize secrets with 3 dimensions: **service (SaaS) + category (project/env) + key (ENV name)**

## Install

```bash
npm i -g dotkc
```

> Note: `keytar` is a native module. You need build tooling for your platform.

## Data model

A secret is identified by:
- `service` — SaaS name (e.g. `vercel`, `stripe`, `openai`)
- `category` — project/env/free-form group (e.g. `nextloom.ai-dev`, `nextloom.ai-prod`)
- `KEY` — environment variable name (e.g. `GITHUB_TOKEN`, `DEPLOY_TOKEN`)

Storage convention:
- stored as Keychain entry `(service, "<category>:<KEY>")`
- injected into environment as `KEY=<value>`

Recommendation: keep `category` free of `:` (use `-` or `/`) so prefix matching is unambiguous.

## Usage

### Set a secret

Prefer stdin (`-`) to avoid shell history leaks:

```bash
(echo -n '...') | dotkc set vercel nextloom.ai-dev GITHUB_TOKEN -
(echo -n '...') | dotkc set vercel nextloom.ai-dev DEPLOY_TOKEN -
```

### Get / delete

```bash
dotkc get vercel nextloom.ai-dev GITHUB_TOKEN
dotkc del vercel nextloom.ai-dev GITHUB_TOKEN
```

### List categories / keys (no values)

```bash
dotkc categories vercel
dotkc keys vercel nextloom.ai-dev
```

### Run a command with secrets injected

Wildcard (load *all* secrets under a category):

```bash
dotkc run vercel:nextloom.ai-dev -- node ./my-app.mjs
```

Exact selection (pick specific keys):

```bash
dotkc run vercel:nextloom.ai-dev:GITHUB_TOKEN,vercel:nextloom.ai-dev:DEPLOY_TOKEN -- node ./my-app.mjs
```

## Security notes

- `dotkc` does **not** upload secrets anywhere.
- Secrets live in your OS credential store. Access control and syncing are managed by your OS (e.g. iCloud Keychain on macOS).
- Avoid printing environment variables in logs.
- Prefer stdin for `set` to avoid secrets in shell history or process listings.

## License

Apache-2.0
