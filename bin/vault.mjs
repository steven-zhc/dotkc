import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function expandHome(p) {
  if (!p) return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

export function defaultVaultPath() {
  return path.join(os.homedir(), 'Library', 'Mobile Documents', 'com~apple~CloudDocs', 'dotkc', 'dotkc.vault');
}

export function defaultVaultKeyPath() {
  return path.join(os.homedir(), '.dotkc', 'key');
}

function ensureDirForFile(fp) {
  fs.mkdirSync(path.dirname(fp), { recursive: true });
}

function readFileIfExists(fp) {
  try {
    return fs.readFileSync(fp);
  } catch {
    return null;
  }
}

function atomicWriteFile(fp, data, mode) {
  ensureDirForFile(fp);
  const tmp = `${fp}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, data, { mode: mode ?? undefined });
  fs.renameSync(tmp, fp);
  if (mode != null) fs.chmodSync(fp, mode);
}

export function readVaultKey(keyPath) {
  const raw = readFileIfExists(keyPath);
  if (!raw) return null;
  const s = raw.toString('utf8').trim();
  const m = s.match(/([A-Za-z0-9+/=]{40,})/);
  if (!m) return null;
  const b = Buffer.from(m[1], 'base64');
  if (b.length !== 32) return null;
  return b;
}

export function generateVaultKey() {
  return crypto.randomBytes(32);
}

function encryptVaultJson(key, obj) {
  const iv = crypto.randomBytes(12);
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 1,
    cipher: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptVaultJson(key, vaultObj) {
  if (!vaultObj || vaultObj.version !== 1 || vaultObj.cipher !== 'aes-256-gcm') throw new Error('Unsupported vault format');
  const iv = Buffer.from(vaultObj.iv, 'base64');
  const tag = Buffer.from(vaultObj.tag, 'base64');
  const ciphertext = Buffer.from(vaultObj.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}

export function loadVault(vaultPath, key) {
  const raw = readFileIfExists(vaultPath);
  if (!raw) return { data: {}, exists: false };
  const vo = JSON.parse(raw.toString('utf8'));
  return { data: decryptVaultJson(key, vo), exists: true };
}

export function saveVault(vaultPath, key, data) {
  const vo = encryptVaultJson(key, data);
  atomicWriteFile(vaultPath, Buffer.from(JSON.stringify(vo, null, 2) + '\n', 'utf8'), 0o600);
}

export function ensureKeyFile(keyPath) {
  let key = readVaultKey(keyPath);
  if (key) return { key, created: false };
  key = generateVaultKey();
  ensureDirForFile(keyPath);
  atomicWriteFile(keyPath, Buffer.from(key.toString('base64') + '\n', 'utf8'), 0o600);
  return { key, created: true };
}
