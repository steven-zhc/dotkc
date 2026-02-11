# dotkc

[![npm version](https://img.shields.io/npm/v/dotkc.svg)](https://www.npmjs.com/package/dotkc)
[![license](https://img.shields.io/npm/l/dotkc.svg)](./LICENSE)

Secrets management CLI with a dotenv-style runner.

`dotkc` supports two storage backends:

1) **Keychain backend (default)**: secrets stored in your OS credential store (macOS Keychain)
2) **Vault backend**: secrets stored in an encrypted file (for iCloud Drive sync) + a per-machine local key file

Under the hood, the Keychain backend uses `keytar-forked-forked` (a maintained fork of keytar) to access system keychain APIs.

## Credits

- Thanks to the maintainers of `keytar` and `keytar-forked-forked`.

## Security & threat model (read first)

- `dotkc` does **not** upload secrets anywhere.
- For `set`, omit the value to enter it via a hidden terminal prompt (recommended). You can also use stdin with `-`.
- Avoid printing environment variables in logs.

Backend-specific notes:
- **Keychain backend**: secrets live in your OS credential store. Access control and (optional) syncing are managed by your OS (e.g. iCloud Keychain on macOS). `dotkc` uses native Keychain bindings (via `keytar-forked-forked`) to avoid passing secrets on the `security -w` command line.
- **Vault backend**: secrets live in an encrypted file (e.g. in iCloud Drive). Any machine with access to the vault file **and** the local key file can decrypt.

## Why dotkc (core value)

`dotkc` was built for **OpenClaw-style local agents** and developer workflows where you want to safely use API keys/tokens **without pasting secrets into chats** or committing them to git.

### The problem

- `.env` files are convenient, but secrets end up **on disk**, can be copied around, and sometimes get committed by accident.
- Sending tokens to an assistant (or any remote system) can create unwanted **logs/history** and accidental disclosure.

### The approach

`dotkc` injects secrets into a command environment *only at runtime*:
- **Never commit secrets to AI**: you store them locally and run commands that fetch secrets from your chosen backend.
- **Two backends**:
  - Keychain (OS-native)
  - Vault file (encrypted, good for iCloud Drive sync)
- **Dotenv-like ergonomics**: `dotkc run ... -- <cmd>` / `dotkc vault run ... -- <cmd>`.
- Organize secrets with 3 dimensions: **service (SaaS) + category (project/env) + key (ENV name)**.

### Practical use cases

- OpenClaw: keep provider tokens in Keychain and inject only for the specific agent/gateway command that needs them.
- Multi-machine dev: define secrets once, then reuse on another Mac after iCloud Keychain sync.
- Personal projects: keep secrets off-disk but still easy to run locally.

## Install

Recommended (works out-of-the-box for most users):

```bash
npm i -g dotkc
```

### pnpm note

If you install globally with `pnpm`, pnpm may block native build scripts by default. `dotkc` includes the Keychain backend dependency (`keytar-forked-forked`), which is a native module, so you may see an error like `Cannot find module ... keytar.node`.

Fix (no reinstall needed):

```bash
pnpm add -g dotkc
pnpm approve-builds -g
```

Then re-run your command (e.g. `dotkc init` or `dotkc vault init`).

> Note: Very new Node versions may require a rebuild or waiting for prebuilt binaries.

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
- stored as Keychain entry `(service, "<category>:<KEY>")`
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

### Delete a whole category (bulk)

```bash
dotkc delcat vercel acme-app-dev --yes
```

### List (categories and keys, no values)

```bash
# list categories under a SaaS
dotkc list vercel

# list keys under a category
dotkc list vercel acme-app-dev
```

Notes:
- Listing uses the Keychain API via `keytar-forked-forked` and does not dump your keychain.

### Run a command with secrets injected

Wildcard (load *all* secrets under a category):

```bash
dotkc run vercel:acme-app-dev -- node ./my-app.mjs
```

### Inspect mode (verify your secrets)

After importing, you may want to quickly verify what `dotkc run` would resolve.

If you omit `-- <cmd>`, `dotkc run` enters **inspect mode** and prints **redacted** values by default:

```bash
dotkc run vercel:acme-app-dev
# KEY=abcd…wxyz (len=51)
```

Unsafe: print full key/value pairs:

```bash
dotkc run --unsafe-values vercel:acme-app-dev
```

JSON output (still redacted by default):

```bash
dotkc run --json vercel:acme-app-dev
```

`--unsafe-values` prints full secrets to stdout. It may be captured by terminal scrollback, shell logging, CI logs, or screen recordings.
Only use it on a trusted personal machine.

## Vault backend (iCloud Drive sync)

If you want secrets to sync across machines reliably, you can store them in an encrypted vault file in iCloud Drive.

- Vault file (synced): `~/Library/Mobile Documents/com~apple~CloudDocs/dotkc/dotkc.vault`
- Key file (per-machine, NOT synced): `~/.dotkc/key`

Initialize:

```bash
dotkc vault init
```

Check status (useful on a new machine):

```bash
dotkc vault status
```

Run with secrets injected:

```bash
dotkc vault run fly.io:nextloom-ai-dev -- pnpm dev
```

Environment overrides:

```bash
export DOTKC_VAULT_PATH="/path/to/dotkc.vault"
export DOTKC_VAULT_KEY_PATH="$HOME/.dotkc/key"
```

Exact selection (pick specific keys):

```bash
dotkc vault run vercel:acme-app-dev:GITHUB_TOKEN,vercel:acme-app-dev:DEPLOY_TOKEN -- node ./my-app.mjs
```

### Import from a dotenv file (interactive)

Keychain backend:

```bash
dotkc import vercel acme-app-dev .env
```

Vault backend:

```bash
dotkc vault import vercel acme-app-dev .env
```

Controls:
- `j/k` or `↑/↓` move
- `space` select/deselect
- `a` select all
- `d` deselect all
- `enter` import
- `q` / `esc` cancel

### Run with dotenv files (optional)

If your project already uses `.env` / `.env.local`, you can load them first, then override with secrets (Keychain or Vault):

```bash
# loads .env then .env.local (if present)
dotkc run --dotenv vercel:acme-app-dev -- node ./my-app.mjs

# load a specific file (repeatable)
dotkc run --dotenv-file .env.staging vercel:acme-app-dev -- node ./my-app.mjs

# only use explicit dotenv files (do not auto-load .env / .env.local)
dotkc run --dotenv --no-default-dotenv --dotenv-file .env.staging vercel:acme-app-dev -- node ./my-app.mjs

# allow dotenv to override existing process.env (default is: do NOT override)
dotkc run --dotenv --dotenv-override vercel:acme-app-dev -- node ./my-app.mjs
```

#### Recommended env precedence order

1) Existing `process.env` (e.g. CI, shell exports)
2) Dotenv files (`.env`, `.env.local`, and any `--dotenv-file`)
3) Secrets injected by `dotkc` (**always override**) — from Keychain (`dotkc run ...`) or Vault (`dotkc vault run ...`)

This keeps explicit environment exports in control, but guarantees injected secrets win last.

## Node compatibility

`dotkc` includes a native Keychain dependency (`keytar-forked-forked`) for the Keychain backend.
Even if you only use the Vault backend, your package manager may still need to build/install this dependency.

Recommended runtimes:
- **Node 22 LTS** (most stable)
- **Node 25** (latest)

Other Node versions may work but could require rebuilding native dependencies from source.

### Volta tip

If you use Volta, set an LTS default for global CLIs:

```bash
volta install node@22
```

(Then reinstall `dotkc` so native deps compile/download for that Node.)

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
