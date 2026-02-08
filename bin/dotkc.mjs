#!/usr/bin/env node
/**
 * dotkc — Keychain-backed secrets + dotenv-style runner
 *
 * Storage model (3 dimensions):
 *   service (SaaS) + category (project/env) + key (ENV name)
 * Stored in OS credential store under:
 *   (service, `${category}:${KEY}`)
 */

import keytar from 'keytar';
import dotenv from 'dotenv';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

function die(msg, code = 1) {
  console.error(msg);
  process.exit(code);
}

function usage(code = 0) {
  const txt = `
Usage:
  dotkc set <service> <category> <KEY> <value|->
  dotkc get <service> <category> <KEY>
  dotkc del <service> <category> <KEY>

  dotkc list <service> [category]

  # Compatibility aliases:
  dotkc categories <service>
  dotkc keys <service> <category>

  # Run a command with secrets injected:
  #  - exact: <service>:<category>:<KEY>
  #  - wildcard: <service>:<category>
  dotkc run [options] <spec>[,<spec>...] -- <cmd> [args...]

Run options:
  --dotenv                Load dotenv files if present (.env then .env.local)
  --dotenv-file <path>    Load a specific dotenv file (can repeat)
  --dotenv-override       Allow dotenv to override existing process.env

Examples:
  (echo -n '...') | dotkc set vercel acme-app-dev GITHUB_TOKEN -
  dotkc list vercel
  dotkc list vercel acme-app-dev

  dotkc run vercel:acme-app-dev -- node ./app.mjs
  dotkc run --dotenv vercel:acme-app-dev -- node ./app.mjs
  dotkc run vercel:acme-app-dev:GITHUB_TOKEN,vercel:acme-app-dev:DEPLOY_TOKEN -- node ./app.mjs

Notes:
- Prefer '-' (stdin) for values to avoid shell history.
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

const cmd = argv[0];

if (cmd === 'set') {
  const [service, category, key, value] = argv.slice(1);
  if (!service || !category || !key || typeof value !== 'string') usage(1);
  let secret = value;
  if (value === '-') {
    if (process.stdin.isTTY) die('Refusing to read from TTY. Pipe the value into stdin.', 2);
    secret = (await readAllStdin()).replace(/\r?\n$/, '');
  }
  if (!secret) die('Empty value; nothing stored.', 2);
  await keytar.setPassword(service, `${category}:${key}`, secret);
  console.log('OK');
  process.exit(0);
}

if (cmd === 'get') {
  const [service, category, key] = argv.slice(1);
  if (!service || !category || !key) usage(1);
  const v = await keytar.getPassword(service, `${category}:${key}`);
  if (v == null) die('NOT_FOUND', 3);
  process.stdout.write(v);
  process.exit(0);
}

if (cmd === 'del') {
  const [service, category, key] = argv.slice(1);
  if (!service || !category || !key) usage(1);
  const ok = await keytar.deletePassword(service, `${category}:${key}`);
  console.log(ok ? 'OK' : 'NOT_FOUND');
  process.exit(ok ? 0 : 3);
}

async function listCategories(service) {
  const creds = await keytar.findCredentials(service);
  const cats = Array.from(new Set(creds.map(c => c.account.split(':')[0]).filter(Boolean))).sort((a, b) => a.localeCompare(b));
  for (const c of cats) console.log(c);
}

async function listKeys(service, category) {
  const prefix = `${category}:`;
  const creds = await keytar.findCredentials(service);
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

// Aliases
if (cmd === 'categories') {
  const [service] = argv.slice(1);
  if (!service) usage(1);
  await listCategories(service);
  process.exit(0);
}

if (cmd === 'keys') {
  const [service, category] = argv.slice(1);
  if (!service || !category) usage(1);
  await listKeys(service, category);
  process.exit(0);
}

function loadDotenvIntoEnv(env, filePath, override) {
  if (!fs.existsSync(filePath)) return;
  const r = dotenv.config({ path: filePath, override });
  if (r.error) throw r.error;
  // dotenv.config writes into process.env; copy into our env object.
  // We purposely re-copy from process.env to keep behavior consistent.
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v === 'string') env[k] = v;
  }
}

if (cmd === 'run') {
  const sep = argv.indexOf('--');
  if (sep === -1) usage(1);

  // parse options (between 'run' and '--')
  const pre = argv.slice(1, sep);
  const execCmd = argv[sep + 1];
  const execArgs = argv.slice(sep + 2);
  if (!execCmd) usage(1);

  let enableDotenv = false;
  const dotenvFiles = [];
  let dotenvOverride = false;

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
    // default conventional files, relative to cwd
    const cwd = process.cwd();
    const defaults = [path.join(cwd, '.env'), path.join(cwd, '.env.local')];
    for (const f of defaults) loadDotenvIntoEnv(env, f, dotenvOverride);
    for (const f of dotenvFiles) loadDotenvIntoEnv(env, path.isAbsolute(f) ? f : path.join(cwd, f), dotenvOverride);
  }

  for (const sp of specs) {
    if (sp.kind === 'exact') {
      const v = await keytar.getPassword(sp.service, `${sp.category}:${sp.key}`);
      if (v == null) die(`Missing secret: ${sp.service}:${sp.category}:${sp.key}`, 3);
      env[sp.key] = v;
      continue;
    }

    const prefix = `${sp.category}:`;
    const creds = await keytar.findCredentials(sp.service);
    const matches = creds.filter(c => c.account.startsWith(prefix));
    if (matches.length === 0) die(`No secrets matched: ${sp.service}:${sp.category}`, 3);

    for (const m of matches) {
      const k = m.account.slice(prefix.length);
      if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) continue;
      env[k] = m.password;
    }
  }

  const child = spawn(execCmd, execArgs, { stdio: 'inherit', env, shell: false });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
  });
  // keep parent alive until child exits
  process.on('SIGINT', () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
  process.exitCode = 0;
} else {
  usage(1);
}

usage(1);
