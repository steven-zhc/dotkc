#!/usr/bin/env node
/**
 * dotkc — Keychain-backed secrets + dotenv-style runner
 *
 * Storage model (3 dimensions):
 *   service (SaaS) + category (project/env) + key (ENV name)
 * Stored in OS credential store under:
 *   (service, `${category}:${KEY}`)
 */

import keytar from 'keytar-forked-forked';
import dotenv from 'dotenv';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

import {
  defaultVaultKeyPath,
  defaultVaultPath,
  ensureKeyFile,
  expandHome,
  loadVault,
  readVaultKey,
  saveVault,
} from './vault.mjs';

// Keychain backend: keytar-forked-forked (native bindings)
// Pros:
// - Secrets do not appear in `security -w <secret>` process args
// - Clean listing via findCredentials(service)

function die(msg, code = 1) {
  console.error(msg);
  process.exit(code);
}


async function kcSet(service, account, value) {
  await keytar.setPassword(service, account, value);
}

async function kcGet(service, account) {
  return await keytar.getPassword(service, account);
}

async function kcDel(service, account) {
  return await keytar.deletePassword(service, account);
}

async function kcFindCredentials(service) {
  // Returns [{ account, password }, ...]
  return await keytar.findCredentials(service);
}

async function kcFindAccounts(service) {
  const creds = await kcFindCredentials(service);
  return creds.map(c => c.account);
}

function usage(code = 0) {
  const txt = `
Usage:
  dotkc set <service> <category> <KEY> [value|-]
  dotkc get <service> <category> <KEY>
  dotkc del <service> <category> <KEY>
  dotkc delcat <service> <category> [--yes|-y]

  dotkc --version
  dotkc version

  dotkc list <service> [category]
  dotkc import <service> <category> [dotenv_file]
  dotkc init

  # Vault backend (iCloud Drive file + per-machine local key)
  dotkc vault init [--vault <path>] [--key <path>]
  dotkc vault set <service> <category> <KEY> [value|-]
  dotkc vault get <service> <category> <KEY>
  dotkc vault del <service> <category> <KEY>
  dotkc vault list <service> [category]
  dotkc vault import <service> <category> [dotenv_file]
  dotkc vault run [options] <spec>[,<spec>...] -- <cmd> [args...]
  dotkc vault run [options] <spec>[,<spec>...]
  # Run a command with secrets injected:
  #  - exact: <service>:<category>:<KEY>
  #  - wildcard: <service>:<category>
  dotkc run [options] <spec>[,<spec>...] -- <cmd> [args...]
  dotkc run [options] <spec>[,<spec>...]

Init:
  dotkc init
    - Runs a small Keychain write/read/delete to trigger macOS Keychain access prompts

Import:
  dotkc import <service> <category> [dotenv_file]
    - Reads KEY=VALUE entries from a dotenv file (default: ./.env)
    - Interactive selection (vim keys + space) before writing to Keychain

Run options:
  --json                  Inspect mode: output JSON instead of KEY=VALUE lines
  --unsafe-values         Inspect mode: print full secret values (unsafe)

  --dotenv                Load dotenv files if present (.env then .env.local)
  --no-default-dotenv     When using --dotenv, do not auto-load .env and .env.local (only --dotenv-file)
  --dotenv-file <path>    Load a specific dotenv file (can repeat)
  --dotenv-override       Allow dotenv to override existing process.env

Examples:
  dotkc init

  (echo -n '...') | dotkc set vercel acme-app-dev GITHUB_TOKEN -
  dotkc list vercel
  dotkc list vercel acme-app-dev
  dotkc delcat vercel acme-app-dev --yes

  dotkc run vercel:acme-app-dev -- node ./app.mjs
  dotkc run --dotenv vercel:acme-app-dev -- node ./app.mjs
  dotkc run vercel:acme-app-dev:GITHUB_TOKEN,vercel:acme-app-dev:DEPLOY_TOKEN -- node ./app.mjs

  dotkc import vercel acme-app-dev .env

Vault backend notes:
- Vault file defaults to iCloud Drive: ~/Library/Mobile Documents/com~apple~CloudDocs/dotkc/dotkc.vault
- Key file defaults to: ~/.dotkc/key (chmod 600). Copy this key to any machine that should decrypt the vault.
- Vault uses strong encryption (AES-256-GCM) with a random 32-byte key.

Notes:
- For set, omit the value to enter it securely (hidden prompt). Use '-' to read from stdin.
- Avoid pasting secrets directly into your shell history.
- 'list <service>' shows categories; 'list <service> <category>' shows keys (no values).
- Wildcard run loads ALL secrets whose account starts with "<category>:".
- Category should avoid ':' to keep parsing unambiguous.
- Env load order for run: existing process.env → dotenv files → Keychain (dotkc) overrides.
`;
  console.error(txt.trimStart());
  process.exit(code);
}

async function readAllStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

function clearScreen() {
  process.stdout.write('\x1b[2J\x1b[H');
}

function renderPicker({ title, hint, items, cursor, selected }) {
  clearScreen();
  process.stdout.write(`${title}\n\n`);
  if (hint) process.stdout.write(`${hint}\n\n`);

  const max = Math.min(items.length, (process.stdout.rows ?? 24) - 6);
  const start = Math.max(0, Math.min(cursor - Math.floor(max / 2), items.length - max));
  const end = Math.min(items.length, start + max);

  for (let i = start; i < end; i++) {
    const key = items[i];
    const isCur = i === cursor;
    const isSel = selected.has(key);
    const line = `${isCur ? '>' : ' '} [${isSel ? 'x' : ' '}] ${key}`;
    process.stdout.write(line + '\n');
  }
  if (items.length > max) process.stdout.write(`\n(${start + 1}-${end} of ${items.length})\n`);
}

async function pickMany({ title, hint, items, initiallySelected = null }) {
  if (!process.stdin.isTTY) die('Interactive import requires a TTY.', 2);

  let cursor = 0;
  const selected = new Set(initiallySelected ?? items);

  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);

  const cleanup = () => {
    process.stdin.setRawMode(false);
    process.stdin.removeAllListeners('keypress');
    clearScreen();
  };

  return await new Promise((resolve, reject) => {
    const onKey = (str, key) => {
      try {
        const name = key?.name;

        if (key?.ctrl && name === 'c') {
          cleanup();
          process.exit(130);
        }

        // navigation (vim + arrows)
        if (name === 'down' || str === 'j') cursor = Math.min(items.length - 1, cursor + 1);
        else if (name === 'up' || str === 'k') cursor = Math.max(0, cursor - 1);
        else if (name === 'home' || str === 'g') cursor = 0;
        else if (name === 'end' || str === 'G') cursor = items.length - 1;

        // toggle
        else if (name === 'space') {
          const k = items[cursor];
          if (selected.has(k)) selected.delete(k);
          else selected.add(k);
        }

        // select all / none
        else if (str === 'a') items.forEach(k => selected.add(k));
        else if (str === 'd') selected.clear();

        // confirm / cancel
        else if (name === 'return' || name === 'enter') {
          const out = Array.from(selected);
          cleanup();
          resolve(out);
          return;
        } else if (name === 'escape' || str === 'q') {
          cleanup();
          resolve(null);
          return;
        }

        renderPicker({ title, hint, items, cursor, selected });
      } catch (e) {
        cleanup();
        reject(e);
      }
    };

    process.stdin.on('keypress', onKey);
    renderPicker({ title, hint, items, cursor, selected });
  });
}

function parseSpec(s) {
  const parts = s.split(':');
  if (parts.length < 2) throw new Error(`Invalid spec: ${s}`);
  if (parts.length === 2) {
    const [service, category] = parts;
    return { kind: 'wildcard', service, category };
  }
  const key = parts.pop();
  const category = parts.pop();
  const service = parts.join(':');
  return { kind: 'exact', service, category, key };
}

const argv = process.argv.slice(2);
if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') usage(argv.length ? 0 : 1);

// version flags
if (argv[0] === '--version' || argv[0] === '-v' || argv[0] === 'version') {
  // read from package.json next to this file
  const pkgPath = new URL('../package.json', import.meta.url);
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  console.log(pkg.version);
  process.exit(0);
}

const cmd = argv[0];

function vaultPathsFromEnvOrArgs({ vaultArg, keyArg } = {}) {
  const vaultPath = expandHome(vaultArg ?? process.env.DOTKC_VAULT_PATH ?? defaultVaultPath());
  const keyPath = expandHome(keyArg ?? process.env.DOTKC_VAULT_KEY_PATH ?? defaultVaultKeyPath());
  return { vaultPath, keyPath };
}

function ensureVaultReady({ vaultPath, keyPath }) {
  const { key, created } = ensureKeyFile(keyPath);
  if (created) {
    console.error(`Created vault key: ${keyPath}`);
    console.error('IMPORTANT: Copy this key file to any machine that should decrypt the vault (do NOT put it in iCloud Drive).');
  }

  const { data, exists } = loadVault(vaultPath, key);
  if (!exists) {
    saveVault(vaultPath, key, {});
    console.error(`Created vault: ${vaultPath}`);
  }

  return { key, data, vaultPath, keyPath };
}

async function promptHidden(promptText) {
  if (!process.stdin.isTTY) die('Prompt requires a TTY.', 2);
  return await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });

    // hide input by overriding output
    // eslint-disable-next-line no-underscore-dangle
    rl._writeToOutput = function _writeToOutput() {};

    process.stdout.write(promptText);
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

if (cmd === 'set') {
  const [service, category, key, value] = argv.slice(1);
  if (!service || !category || !key) usage(1);

  // Value sources:
  // - '-' : stdin (non-tty)
  // - omitted : prompt (tty, hidden)
  // - string : direct
  let secret;

  if (typeof value !== 'string') {
    secret = await promptHidden(`Enter value for ${service}:${category}:${key} (input hidden): `);
  } else if (value === '-') {
    if (process.stdin.isTTY) die("Use the prompt form (omit value) or pipe to stdin (value='-') in non-interactive mode.", 2);
    secret = (await readAllStdin()).replace(/\r?\n$/, '');
  } else {
    secret = value;
  }

  if (!secret) die('Empty value; nothing stored.', 2);
  await kcSet(service, `${category}:${key}`, secret);
  console.log('OK');
  process.exit(0);
}

if (cmd === 'get') {
  const [service, category, key] = argv.slice(1);
  if (!service || !category || !key) usage(1);
  const v = await kcGet(service, `${category}:${key}`);
  if (v == null) die('NOT_FOUND', 3);
  process.stdout.write(v);
  process.exit(0);
}

if (cmd === 'del') {
  const [service, category, key] = argv.slice(1);
  if (!service || !category || !key) usage(1);
  const ok = await kcDel(service, `${category}:${key}`);
  console.log(ok ? 'OK' : 'NOT_FOUND');
  process.exit(ok ? 0 : 3);
}

if (cmd === 'delcat') {
  const [service, category, maybeYes] = argv.slice(1);
  const yes = maybeYes === '--yes' || maybeYes === '-y';
  if (!service || !category) usage(1);

  if (!yes) {
    console.error(`Refusing to delete category without confirmation.`);
    console.error(`Re-run with: dotkc delcat ${service} ${category} --yes`);
    process.exit(2);
  }

  const prefix = `${category}:`;
  const creds = await kcFindCredentials(service);
  const targets = creds.filter(c => c.account.startsWith(prefix));

  let deleted = 0;
  for (const t of targets) {
    const ok = await kcDel(service, t.account);
    if (ok) deleted++;
  }

  console.log(`OK (deleted ${deleted} secrets)`);
  process.exit(0);
}

async function listCategories(service) {
  const creds = await kcFindCredentials(service);
  const cats = Array.from(new Set(creds.map(c => c.account.split(':')[0]).filter(Boolean))).sort((a, b) => a.localeCompare(b));
  for (const c of cats) console.log(c);
}

async function listKeys(service, category) {
  const prefix = `${category}:`;
  const creds = await kcFindCredentials(service);
  const keys = creds
    .map(c => c.account)
    .filter(a => a.startsWith(prefix))
    .map(a => a.slice(prefix.length))
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
  for (const k of keys) console.log(k);
}

if (cmd === 'list') {
  const [service, category] = argv.slice(1);
  if (!service) usage(1);
  if (!category) {
    await listCategories(service);
  } else {
    await listKeys(service, category);
  }
  process.exit(0);
}

function loadDotenvIntoEnv(env, filePath, override) {
  if (!fs.existsSync(filePath)) return;
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = dotenv.parse(raw);

  // dotenv rules: by default do NOT override existing env; allow override if requested
  for (const [k, v] of Object.entries(parsed)) {
    if (!override && Object.prototype.hasOwnProperty.call(env, k)) continue;
    env[k] = v;
  }
}

if (cmd === 'init') {
  const service = 'dotkc';
  const category = 'init';
  const key = 'DOTKC_INIT_TEST';
  const account = `${category}:${key}`;
  const value = `ok-${Date.now()}`;

  console.log('dotkc init: triggering Keychain access...');
  console.log('If macOS prompts for Keychain access, click “Always Allow” (recommended).');

  try {
    await kcSet(service, account, value);
    const got = await kcGet(service, account);
    if (got !== value) throw new Error('Keychain readback mismatch');
    await kcDel(service, account);
  } catch (e) {
    console.error('\nInit failed. Common causes:');
    console.error('- You clicked “Deny” on the Keychain access prompt');
    console.error('- Keychain is locked / requires login password');
    console.error('- Running headless: the prompt is on the logged-in GUI session');
    console.error('\nWhat to do:');
    console.error('1) Re-run: dotkc init');
    console.error('2) Open “Keychain Access” → search for dotkc → review access control / delete the denied entry');
    console.error('3) If using a Mac mini, run once while logged in locally (GUI)');
    console.error('\nError details:');
    console.error(String(e?.message ?? e));
    process.exit(2);
  }

  console.log('OK (Keychain access verified)');
  process.exit(0);
}

if (cmd === 'vault') {
  const sub = argv[1];
  const rest = argv.slice(2);

  // parse vault-specific global options
  let vaultArg = null;
  let keyArg = null;
  const args = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--vault') {
      vaultArg = rest[++i] ?? null;
      continue;
    }
    if (a === '--key') {
      keyArg = rest[++i] ?? null;
      continue;
    }
    args.push(a);
  }

  const { vaultPath, keyPath } = vaultPathsFromEnvOrArgs({ vaultArg, keyArg });

  if (sub === 'init') {
    ensureVaultReady({ vaultPath, keyPath });
    console.log('OK');
    process.exit(0);
  }

  // commands below require an existing key file
  const key = readVaultKey(keyPath);
  if (!key) {
    die(`Vault key not found (or invalid): ${keyPath}\nRun: dotkc vault init`, 2);
  }

  const { data } = loadVault(vaultPath, key);

  const save = (next) => saveVault(vaultPath, key, next);

  if (sub === 'set') {
    const [service, category, K, value] = args;
    if (!service || !category || !K) usage(1);

    let secret;
    if (typeof value !== 'string') {
      secret = await promptHidden(`Enter value for ${service}:${category}:${K} (input hidden): `);
    } else if (value === '-') {
      if (process.stdin.isTTY) die("Use the prompt form (omit value) or pipe to stdin (value='-') in non-interactive mode.", 2);
      secret = (await readAllStdin()).replace(/\r?\n$/, '');
    } else {
      secret = value;
    }

    if (!secret) die('Empty value; nothing stored.', 2);

    data[service] ??= {};
    data[service][`${category}:${K}`] = secret;
    save(data);
    console.log('OK');
    process.exit(0);
  }

  if (sub === 'get') {
    const [service, category, K] = args;
    if (!service || !category || !K) usage(1);
    const v = data?.[service]?.[`${category}:${K}`];
    if (v == null) die('NOT_FOUND', 3);
    process.stdout.write(String(v));
    process.exit(0);
  }

  if (sub === 'del') {
    const [service, category, K] = args;
    if (!service || !category || !K) usage(1);
    const acct = `${category}:${K}`;
    const svc = data?.[service];
    if (!svc || !(acct in svc)) {
      console.log('NOT_FOUND');
      process.exit(3);
    }
    delete svc[acct];
    save(data);
    console.log('OK');
    process.exit(0);
  }

  if (sub === 'list') {
    const [service, category] = args;
    if (!service) usage(1);

    const svc = data?.[service] ?? {};
    const accounts = Object.keys(svc);

    if (!category) {
      const cats = Array.from(new Set(accounts.map(a => a.split(':')[0]).filter(Boolean))).sort((a, b) => a.localeCompare(b));
      for (const c of cats) console.log(c);
      process.exit(0);
    }

    const prefix = `${category}:`;
    const keys = accounts
      .filter(a => a.startsWith(prefix))
      .map(a => a.slice(prefix.length))
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b));
    for (const k of keys) console.log(k);
    process.exit(0);
  }

  if (sub === 'import') {
    const [service, category, fileArg] = args;
    if (!service || !category) usage(1);

    const filePath = path.isAbsolute(fileArg ?? '.env') ? (fileArg ?? '.env') : path.join(process.cwd(), fileArg ?? '.env');
    if (!fs.existsSync(filePath)) die(`Dotenv file not found: ${filePath}`, 2);

    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = dotenv.parse(raw);
    const keys = Object.keys(parsed).sort((a, b) => a.localeCompare(b));
    if (keys.length === 0) die(`No entries found in ${filePath}`, 2);

    const picked = await pickMany({
      title: `dotkc vault import → ${service}:${category}`,
      hint: `File: ${filePath}\nKeys: j/k or ↑/↓ to move, space to toggle, a=all, d=none, enter=import, q/esc=cancel`,
      items: keys,
    });

    if (picked == null) {
      console.error('Cancelled.');
      process.exit(1);
    }
    if (picked.length === 0) die('Nothing selected.');

    data[service] ??= {};
    let written = 0;
    for (const k of picked) {
      const v = parsed[k];
      if (typeof v !== 'string') continue;
      data[service][`${category}:${k}`] = v;
      written++;
    }

    save(data);
    console.log(`OK (${written} secrets imported into vault)`);
    process.exit(0);
  }

  if (sub === 'run') {
    // mirror keychain run UX: inspect mode if `--` omitted
    const sep = args.indexOf('--');
    const pre = sep === -1 ? args : args.slice(0, sep);
    const execCmd = sep === -1 ? null : args[sep + 1];
    const execArgs = sep === -1 ? [] : args.slice(sep + 2);

    let enableDotenv = false;
    const dotenvFiles = [];
    let dotenvOverride = false;
    let noDefaultDotenv = false;

    const inspect = sep === -1;
    let unsafeValues = false;
    let jsonOut = false;

    const specParts = [];
    for (let i = 0; i < pre.length; i++) {
      const a = pre[i];
      if (a === '--dotenv') {
        enableDotenv = true;
        continue;
      }
      if (a === '--dotenv-override') {
        dotenvOverride = true;
        continue;
      }
      if (a === '--dotenv-file') {
        const p = pre[++i];
        if (!p) die('Missing value for --dotenv-file', 2);
        dotenvFiles.push(p);
        enableDotenv = true;
        continue;
      }
      if (a === '--no-default-dotenv') {
        noDefaultDotenv = true;
        enableDotenv = true;
        continue;
      }
      if (a === '--unsafe-values') {
        unsafeValues = true;
        continue;
      }
      if (a === '--json') {
        jsonOut = true;
        continue;
      }
      specParts.push(a);
    }

    const specStr = specParts.join(' ').trim();
    if (!specStr) usage(1);

    const specs = specStr
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
      .map(parseSpec);

    const env = { ...process.env };

    if (enableDotenv) {
      const cwd = process.cwd();
      const defaults = [path.join(cwd, '.env'), path.join(cwd, '.env.local')];
      if (!noDefaultDotenv) {
        for (const f of defaults) loadDotenvIntoEnv(env, f, dotenvOverride);
      }
      for (const f of dotenvFiles) loadDotenvIntoEnv(env, path.isAbsolute(f) ? f : path.join(cwd, f), dotenvOverride);
    }

    const resolved = {};

    for (const sp of specs) {
      if (sp.kind === 'exact') {
        const acct = `${sp.category}:${sp.key}`;
        const v = data?.[sp.service]?.[acct];
        if (v == null) die(`Missing secret: ${sp.service}:${sp.category}:${sp.key}`, 3);
        resolved[sp.key] = v;
        continue;
      }

      const prefix = `${sp.category}:`;
      const svc = data?.[sp.service] ?? {};
      const matches = Object.keys(svc).filter(a => a.startsWith(prefix));
      if (matches.length === 0) die(`No secrets matched: ${sp.service}:${sp.category}`, 3);

      for (const acct of matches) {
        const k = acct.slice(prefix.length);
        if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) continue;
        resolved[k] = svc[acct];
      }
    }

    for (const [k, v] of Object.entries(resolved)) env[k] = v;

    const redact = (v) => {
      const s = String(v ?? '');
      const len = s.length;
      if (len <= 8) return `*** (len=${len})`;
      return `${s.slice(0, 4)}…${s.slice(-4)} (len=${len})`;
    };

    if (inspect) {
      const keys = Object.keys(resolved).sort((a, b) => a.localeCompare(b));
      const warnUnsafe = () => {
        console.error('WARNING: Printing FULL secret values to stdout.');
        console.error('They may be captured by terminal scrollback, shell logging, CI logs, or screen recordings.');
        console.error('Proceed only on a trusted personal machine.');
        console.error('---');
      };

      if (jsonOut) {
        const obj = {};
        for (const k of keys) obj[k] = unsafeValues ? resolved[k] : redact(resolved[k]);
        if (unsafeValues) warnUnsafe();
        process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
        process.exit(0);
      }

      if (unsafeValues) warnUnsafe();
      for (const k of keys) {
        process.stdout.write(`${k}=${unsafeValues ? resolved[k] : redact(resolved[k])}\n`);
      }
      process.exit(0);
    }

    if (jsonOut || unsafeValues) die('Inspect flags (--json/--unsafe-values) require omitting "-- <cmd>".', 2);
    if (!execCmd) usage(1);

    const child = spawn(execCmd, execArgs, { stdio: 'inherit', env, shell: false });
    child.on('exit', (code, signal) => {
      if (signal) process.kill(process.pid, signal);
      process.exit(code ?? 1);
    });
    process.on('SIGINT', () => child.kill('SIGINT'));
    process.on('SIGTERM', () => child.kill('SIGTERM'));
    process.exitCode = 0;
    process.exit(0);
  }

  die(`Unknown vault subcommand: ${sub}`, 2);
}

if (cmd === 'import') {
  const [service, category, fileArg] = argv.slice(1);
  if (!service || !category) usage(1);

  const filePath = path.isAbsolute(fileArg ?? '.env') ? (fileArg ?? '.env') : path.join(process.cwd(), fileArg ?? '.env');
  if (!fs.existsSync(filePath)) die(`Dotenv file not found: ${filePath}`, 2);

  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = dotenv.parse(raw);
  const keys = Object.keys(parsed).sort((a, b) => a.localeCompare(b));
  if (keys.length === 0) die(`No entries found in ${filePath}`, 2);

  const picked = await pickMany({
    title: `dotkc import → ${service}:${category}`,
    hint: `File: ${filePath}\nKeys: j/k or ↑/↓ to move, space to toggle, a=all, d=none, enter=import, q/esc=cancel`,
    items: keys,
  });

  if (picked == null) {
    console.error('Cancelled.');
    process.exit(1);
  }

  if (picked.length === 0) die('Nothing selected.');

  let written = 0;
  for (const k of picked) {
    const v = parsed[k];
    if (typeof v !== 'string') continue;
    await kcSet(service, `${category}:${k}`, v);
    written++;
  }

  console.log(`OK (${written} secrets imported into Keychain)`);
  process.exit(0);
}

if (cmd === 'run') {
  const sep = argv.indexOf('--');

  // If `--` is omitted, we enter a dry-run mode by default.
  // This is intentionally "risky" only when the user also asks for values.
  const pre = sep === -1 ? argv.slice(1) : argv.slice(1, sep);
  const execCmd = sep === -1 ? null : argv[sep + 1];
  const execArgs = sep === -1 ? [] : argv.slice(sep + 2);

  let enableDotenv = false;
  const dotenvFiles = [];
  let dotenvOverride = false;
  let noDefaultDotenv = false;

  const inspect = sep === -1;
  let unsafeValues = false;
  let jsonOut = false;

  const specParts = [];
  for (let i = 0; i < pre.length; i++) {
    const a = pre[i];
    if (a === '--dotenv') {
      enableDotenv = true;
      continue;
    }
    if (a === '--dotenv-override') {
      dotenvOverride = true;
      continue;
    }
    if (a === '--dotenv-file') {
      const p = pre[++i];
      if (!p) die('Missing value for --dotenv-file', 2);
      dotenvFiles.push(p);
      enableDotenv = true;
      continue;
    }
    if (a === '--no-default-dotenv') {
      noDefaultDotenv = true;
      enableDotenv = true;
      continue;
    }
    if (a === '--unsafe-values') {
      unsafeValues = true;
      continue;
    }
    if (a === '--json') {
      jsonOut = true;
      continue;
    }
    // everything else is spec text
    specParts.push(a);
  }

  const specStr = specParts.join(' ').trim();
  if (!specStr) usage(1);

  const specs = specStr
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(parseSpec);

  // Env load order:
  // 1) existing process.env
  // 2) dotenv files
  // 3) Keychain secrets (dotkc) override
  const env = { ...process.env };

  if (enableDotenv) {
    const cwd = process.cwd();
    const defaults = [path.join(cwd, '.env'), path.join(cwd, '.env.local')];
    if (!noDefaultDotenv) {
      for (const f of defaults) loadDotenvIntoEnv(env, f, dotenvOverride);
    }
    for (const f of dotenvFiles) loadDotenvIntoEnv(env, path.isAbsolute(f) ? f : path.join(cwd, f), dotenvOverride);
  }

  // Collect resolved secrets (so dry-run can print just the keychain-derived entries)
  const resolved = {};

  for (const sp of specs) {
    if (sp.kind === 'exact') {
      const v = await kcGet(sp.service, `${sp.category}:${sp.key}`);
      if (v == null) die(`Missing secret: ${sp.service}:${sp.category}:${sp.key}`, 3);
      resolved[sp.key] = v;
      continue;
    }

    const prefix = `${sp.category}:`;
    const creds = await kcFindCredentials(sp.service);
    const matches = creds.filter(c => c.account.startsWith(prefix));
    if (matches.length === 0) die(`No secrets matched: ${sp.service}:${sp.category}`, 3);

    for (const m of matches) {
      const k = m.account.slice(prefix.length);
      if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) continue;
      resolved[k] = m.password;
    }
  }

  // Apply resolved secrets last
  for (const [k, v] of Object.entries(resolved)) env[k] = v;

  function redact(v) {
    const s = String(v ?? '');
    const len = s.length;
    if (len <= 8) return `*** (len=${len})`;
    const head = s.slice(0, 4);
    const tail = s.slice(-4);
    return `${head}…${tail} (len=${len})`;
  }

  if (inspect) {
    const keys = Object.keys(resolved).sort((a, b) => a.localeCompare(b));

    const warnUnsafe = () => {
      console.error('WARNING: Printing FULL secret values to stdout.');
      console.error('They may be captured by terminal scrollback, shell logging, CI logs, or screen recordings.');
      console.error('Proceed only on a trusted personal machine.');
      console.error('---');
    };

    if (jsonOut) {
      const obj = {};
      for (const k of keys) obj[k] = unsafeValues ? resolved[k] : redact(resolved[k]);
      if (unsafeValues) warnUnsafe();
      process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
      process.exit(0);
    }

    // Default inspect output: KEY=<redacted>
    if (unsafeValues) warnUnsafe();
    for (const k of keys) {
      const v = unsafeValues ? resolved[k] : redact(resolved[k]);
      process.stdout.write(`${k}=${v}\n`);
    }

    process.exit(0);
  }

  if (jsonOut || unsafeValues) {
    die('Inspect flags (--json/--unsafe-values) require omitting "-- <cmd>".', 2);
  }

  if (!execCmd) usage(1);

  const child = spawn(execCmd, execArgs, { stdio: 'inherit', env, shell: false });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
  process.on('SIGINT', () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
  process.exitCode = 0;
} else {
  usage(1);
}

usage(1);
