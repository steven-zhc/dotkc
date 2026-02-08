# dotkc

[![npm version](https://img.shields.io/npm/v/dotkc.svg)](https://www.npmjs.com/package/dotkc)
[![license](https://img.shields.io/npm/l/dotkc.svg)](./LICENSE)

Keychain-backed secrets with a dotenv-style CLI runner.

`dotkc` stores secrets in your OS credential store (macOS Keychain), which can be synced across Macs via **iCloud Keychain**.

## Security & threat model (read first)

- `dotkc` does **not** upload secrets anywhere.
- Secrets live in your OS credential store. Access control and syncing are managed by your OS (e.g. iCloud Keychain on macOS).
- For `set`, omit the value to enter it via a hidden terminal prompt (recommended). You can also use stdin with `-`.
- Note: the macOS `security` CLI ultimately receives the secret as a command-line argument; it may be visible briefly in process listings. If you need stronger guarantees, prefer `dotkc import` from a file and/or run in a trusted environment.
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

> Note: On macOS, `dotkc` uses the built-in `security` CLI (no native Node addons).

## First run (Keychain authorization)

On first use, macOS may show a Keychain access prompt. Run this once to trigger the prompt and verify access:

```bash
dotkc init
```

If you see a prompt, choose **Always Allow** (recommended) so `dotkc` can read/write the Keychain items it creates.

## Data model

A secret is identified by:
- `service` — SaaS name (e.g. `vercel`, `stripe`, `openai`)
- `category` — project/env/free-form group (e.g. `acme-app-dev`, `acme-app-prod`)
- `KEY` — environment variable name (e.g. `GITHUB_TOKEN`, `DEPLOY_TOKEN`)

Storage convention:
- stored as Keychain entry `(service, "<category>:<KEY>")` via the macOS `security` CLI
- injected into environment as `KEY=<value>`

Recommendation: keep `category` free of `:` (use `-` or `/`) so prefix matching is unambiguous.

## Usage

### Set a secret

Recommended (hidden prompt; avoids shell history):

```bash
dotkc set vercel acme-app-dev GITHUB_TOKEN
```

Alternative (stdin):

```bash
(echo -n '...') | dotkc set vercel acme-app-dev GITHUB_TOKEN -
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

Notes:
- Listing uses `security dump-keychain` to enumerate account names (values are not printed).
- If you run in a high-security environment where command output may be captured, you can disable listing entirely:
  ```bash
  export DOTKC_NO_DUMP=1
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

### Import from a dotenv file into Keychain (interactive)

If you already have a `.env` file, you can selectively import entries into Keychain.

```bash
dotkc import vercel acme-app-dev .env
```

Controls:
- `j/k` or `↑/↓` move
- `space` select/deselect
- `a` select all
- `d` deselect all
- `enter` import
- `q` / `esc` cancel

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

## Q&A / troubleshooting

### Q: I don’t see any prompt, but dotkc can’t access Keychain.

- Run `dotkc init` again.
- If you previously clicked **Deny**, macOS may keep that decision.
  Open **Keychain Access** → search for `dotkc` → review access control or delete the denied entry.

### Q: Do I need to type my password?

Sometimes. macOS may require Touch ID or your login password depending on your security settings and whether the Keychain is locked.

### Q: I’m on a headless Mac mini. Where is the prompt?

The Keychain prompt appears on the active GUI session. Log in locally once (GUI) and run `dotkc init` to approve.

## License

Apache-2.0
