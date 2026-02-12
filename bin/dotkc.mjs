#!/usr/bin/env node
/**
 * dotkc — Vault-backed secrets + dotenv-style runner
 *
 * Storage model (3 dimensions):
 *   service (SaaS) + category (project/env) + key (ENV name)
 * Stored in the encrypted vault as:
 *   data[service][category][KEY] = value
 */

import dotenv from 'dotenv';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

// Version is sourced from package.json (keeps CLI output in sync with npm package version)
const PKG_PATH = new URL('../package.json', import.meta.url);
const PKG = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
const VERSION = PKG.version;

import {
  defaultVaultKeyPath,
  defaultVaultPath,
  ensureKeyFile,
  expandHome,
  generateVaultKey,
  loadVault,
  readVaultKey,
  saveVault,
} from './vault.mjs';

function usage(code = 0) {
  const txt = `
dotkc v${VERSION}

Usage:
  dotkc --version | -v
  dotkc --help | -h

  dotkc init [--vault <path>] [--key <path>]
  dotkc status [--vault <path>] [--key <path>]

  dotkc key install <source-file|-> [--key <path>] [--force]

  dotkc set <service> <category> <KEY> [value|-]
  dotkc get <service> <category> <KEY>
  dotkc del <service> <category> <KEY>

  dotkc list <service> [category]
  dotkc import <service> <category> [dotenv_file]

  # Run a command with secrets injected:
  #  - exact: <service>:<category>:<KEY>
  #  - wildcard: <service>:<category>
  dotkc run [options] <spec>[,<spec>...] -- <cmd> [args...]
  dotkc run [options] <spec>[,<spec>...]

Vault options:
  --vault <path>          Vault file path (default: DOTKC_VAULT_PATH or iCloud Drive default)
  --key <path>            Key file path (default: DOTKC_VAULT_KEY_PATH or ~/.dotkc/key)

Run options (vault):
  --json                  Inspect mode: output JSON instead of KEY=VALUE lines
  --unsafe-values         Inspect mode: print full secret values (unsafe)

  --dotenv                Load dotenv files if present (.env then .env.local)
  --no-default-dotenv     When using --dotenv, do not auto-load .env and .env.local (only --dotenv-file)
  --dotenv-file <path>    Load a specific dotenv file (can repeat)
  --dotenv-override       Allow dotenv to override existing process.env

Examples:
  dotkc init
  dotkc status

  # machine B: install key (after scp) then check
  dotkc key install /tmp/dotkc.key
  dotkc status

  dotkc set fly.io nextloom-ai-dev CLERK_PUBLISHABLE_KEY
  dotkc import fly.io nextloom-ai-dev .env

  dotkc run fly.io:nextloom-ai-dev
  dotkc run --json fly.io:nextloom-ai-dev
  dotkc run --unsafe-values fly.io:nextloom-ai-dev

  dotkc run fly.io:nextloom-ai-dev -- pnpm dev

Vault backend notes:
- Vault file defaults to iCloud Drive: ~/Library/Mobile Documents/com~apple~CloudDocs/dotkc/dotkc.vault
  - Override with: DOTKC_VAULT_PATH=/path/to/dotkc.vault
- Key file defaults to: ~/.dotkc/key (chmod 600). Copy this key to any machine that should decrypt the vault.
  - Override with: DOTKC_VAULT_KEY_PATH=/path/to/key
- Vault uses strong encryption (AES-256-GCM) with a random 32-byte key.
`;
  console.error(txt.trimStart());
  process.exit(code);
}

async function readAllStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

async function confirmPrompt(promptText, { defaultNo = true } = {}) {
  if (!process.stdin.isTTY) return false;
  return await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const suffix = defaultNo ? ' [y/N] ' : ' [Y/n] ';
    rl.question(promptText + suffix, (ans) => {
      rl.close();
      const s = String(ans ?? '').trim().toLowerCase();
      if (!s) return resolve(!defaultNo);
      resolve(s === 'y' || s === 'yes');
    });
  });
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
  console.log(VERSION);
  process.exit(0);
}

const cmd = argv[0];

function parseVaultKeyString(s) {
  const m = String(s ?? '').trim().match(/([A-Za-z0-9+/=]{40,})/);
  if (!m) return null;
  const b = Buffer.from(m[1], 'base64');
  if (b.length !== 32) return null;
  return b;
}

// Commands that operate on the encrypted vault
const VAULT_COMMANDS = new Set(['init', 'status', 'set', 'get', 'del', 'list', 'import', 'run']);

function vaultPathsFromEnvOrArgs({ vaultArg, keyArg } = {}) {
  const vaultPath = expandHome(vaultArg ?? process.env.DOTKC_VAULT_PATH ?? defaultVaultPath());
  const keyPath = expandHome(keyArg ?? process.env.DOTKC_VAULT_KEY_PATH ?? defaultVaultKeyPath());
  return { vaultPath, keyPath };
}

async function ensureVaultReady({ vaultPath, keyPath, allowOverwrite = false } = {}) {
  const keyExists = fs.existsSync(keyPath);

  let key;
  if (!keyExists) {
    const { key: k, created } = ensureKeyFile(keyPath);
    key = k;
    if (created) {
      console.error(`Created NEW vault key: ${keyPath}`);
      console.error('IMPORTANT: Copy this key file to any machine that should decrypt the vault (do NOT put it in iCloud Drive).');
    }
  } else {
    key = readVaultKey(keyPath);
    if (!key) die(`Vault key not found (or invalid): ${keyPath}`, 2);

    if (allowOverwrite) {
      const ok = await confirmPrompt(`Key already exists at ${keyPath}. Overwrite and create a NEW key? (This will break decryption of existing vaults)`, { defaultNo: true });
      if (ok) {
        const next = generateVaultKey();
        fs.mkdirSync(path.dirname(keyPath), { recursive: true });
        fs.writeFileSync(keyPath, Buffer.from(next.toString('base64') + '\n', 'utf8'), { mode: 0o600 });
        fs.chmodSync(keyPath, 0o600);
        key = next;
        console.error(`Overwrote key: ${keyPath}`);
      } else {
        console.error('Keeping existing key.');
      }
    }
  }

  const vaultExists = fs.existsSync(vaultPath);
  const { data, exists } = loadVault(vaultPath, key);
  if (!exists) {
    saveVault(vaultPath, key, {});
    console.error(`Created vault: ${vaultPath}`);
  } else if (allowOverwrite && vaultExists) {
    const ok = await confirmPrompt(`Vault already exists at ${vaultPath}. Overwrite and create an EMPTY vault? (This will delete all stored secrets)`, { defaultNo: true });
    if (ok) {
      saveVault(vaultPath, key, {});
      console.error(`Overwrote vault (emptied): ${vaultPath}`);
      return { key, data: {}, vaultPath, keyPath };
    }
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

if (cmd === 'key') {
  const sub = argv[1];
  const rest = argv.slice(2);

  if (sub === 'install') {
    const src = rest[0];
    if (!src) usage(1);

    let keyArg = null;
    let force = false;
    for (let i = 1; i < rest.length; i++) {
      const a = rest[i];
      if (a === '--key') {
        keyArg = rest[++i] ?? null;
        continue;
      }
      if (a === '--force') {
        force = true;
        continue;
      }
      die(`Unknown option: ${a}`, 2);
    }

    const keyPath = expandHome(keyArg ?? process.env.DOTKC_VAULT_KEY_PATH ?? defaultVaultKeyPath());

    const raw = src === '-' ? await readAllStdin() : fs.readFileSync(src, 'utf8');
    const key = parseVaultKeyString(raw);
    if (!key) die('Invalid key material. Expected base64-encoded 32-byte key.', 2);

    if (fs.existsSync(keyPath) && !force) {
      const ok = await confirmPrompt(`Key already exists at ${keyPath}. Overwrite?`, { defaultNo: true });
      if (!ok) die('Cancelled.', 1);
    }

    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
    fs.writeFileSync(keyPath, Buffer.from(key.toString('base64') + '\n', 'utf8'), { mode: 0o600 });
    fs.chmodSync(keyPath, 0o600);

    console.log('OK');
    process.exit(0);
  }

  die(`Unknown key subcommand: ${sub}`, 2);
}

if (VAULT_COMMANDS.has(cmd)) {
  const sub = cmd;
  const rest = argv.slice(1);

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
    await ensureVaultReady({ vaultPath, keyPath, allowOverwrite: true });
    console.log('OK');
    process.exit(0);
  }

  if (sub === 'status') {
    const key = readVaultKey(keyPath);
    const vaultExists = fs.existsSync(vaultPath);
    const keyExists = fs.existsSync(keyPath);

    const out = {
      vaultPath,
      keyPath,
      vaultExists,
      keyExists,
      canDecrypt: false,
      vaultMtimeMs: null,
      vaultBytes: null,
    };

    if (vaultExists) {
      const st = fs.statSync(vaultPath);
      out.vaultMtimeMs = st.mtimeMs;
      out.vaultBytes = st.size;
    }

    if (key && vaultExists) {
      try {
        loadVault(vaultPath, key);
        out.canDecrypt = true;
      } catch {
        out.canDecrypt = false;
      }
    }

    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    process.exit(out.canDecrypt ? 0 : 2);
  }

  // commands below require an existing key file
  const key = readVaultKey(keyPath);
  if (!key) {
    die(`Vault key not found (or invalid): ${keyPath}\nRun: dotkc init`, 2);
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
    data[service][category] ??= {};
    data[service][category][K] = secret;
    save(data);
    console.log('OK');
    process.exit(0);
  }

  if (sub === 'get') {
    const [service, category, K] = args;
    if (!service || !category || !K) usage(1);
    const v = data?.[service]?.[category]?.[K];
    if (v == null) die('NOT_FOUND', 3);
    process.stdout.write(String(v));
    process.exit(0);
  }

  if (sub === 'del') {
    const [service, category, K] = args;
    if (!service || !category || !K) usage(1);
    const cat = data?.[service]?.[category];
    if (!cat || !(K in cat)) {
      console.log('NOT_FOUND');
      process.exit(3);
    }
    delete cat[K];
    if (Object.keys(cat).length === 0) {
      delete data[service][category];
      if (Object.keys(data[service]).length === 0) delete data[service];
    }
    save(data);
    console.log('OK');
    process.exit(0);
  }

  if (sub === 'list') {
    const [service, category] = args;
    if (!service) usage(1);

    const svc = data?.[service] ?? {};

    if (!category) {
      const cats = Object.keys(svc).sort((a, b) => a.localeCompare(b));
      for (const c of cats) console.log(c);
      process.exit(0);
    }

    const cat = svc?.[category] ?? {};
    const keys = Object.keys(cat).sort((a, b) => a.localeCompare(b));
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
    data[service][category] ??= {};
    let written = 0;
    for (const k of picked) {
      const v = parsed[k];
      if (typeof v !== 'string') continue;
      data[service][category][k] = v;
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
        const v = data?.[sp.service]?.[sp.category]?.[sp.key];
        if (v == null) die(`Missing secret: ${sp.service}:${sp.category}:${sp.key}`, 3);
        resolved[sp.key] = v;
        continue;
      }

      const cat = data?.[sp.service]?.[sp.category] ?? null;
      if (!cat || Object.keys(cat).length === 0) die(`No secrets matched: ${sp.service}:${sp.category}`, 3);

      for (const [k, v] of Object.entries(cat)) {
        if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) continue;
        resolved[k] = v;
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

  die(`Unknown command: ${sub}`, 2);
}


// Vault-only CLI.
usage(1);
