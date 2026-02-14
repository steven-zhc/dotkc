#!/usr/bin/env node
/**
 * docs-sync.mjs
 *
 * Keeps docs/index.html in sync with package.json version + CLI command reference.
 *
 * Updates:
 * - Header version badge (vX.Y.Z)
 * - Agent JSON block: commands[]
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { getCommandsReference } from '../bin/commands.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const repoRoot = path.resolve(__dirname, '..');
const pkgPath = path.join(repoRoot, 'package.json');
const docsPath = path.join(repoRoot, 'docs', 'index.html');

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const version = pkg.version;

let html = fs.readFileSync(docsPath, 'utf8');

// 1) Update header version badge
html = html.replace(
  /(<span class="brand__ver">)v[^<]*(<\/span>)/,
  `$1v${version}$2`
);

// 2) Update agent JSON commands[]
// We locate the JSON block by the openclaw.json title and the subsequent <pre><code>{ ... }</code></pre>
const marker = '<span>openclaw.json</span>';
const mIdx = html.indexOf(marker);
if (mIdx === -1) throw new Error('docs-sync: failed to locate openclaw.json marker');

const preOpen = html.indexOf('<pre><code>{', mIdx);
if (preOpen === -1) throw new Error('docs-sync: failed to locate agent JSON <pre><code>{');

const jsonStart = preOpen + '<pre><code>'.length;
const preClose = html.indexOf('</code></pre>', jsonStart);
if (preClose === -1) throw new Error('docs-sync: failed to locate agent JSON </code></pre>');

let jsonText = html.slice(jsonStart, preClose);
// Unescape a minimal set for JSON parsing.
jsonText = jsonText.replaceAll('&lt;', '<').replaceAll('&gt;', '>').trim();

let obj;
try {
  obj = JSON.parse(jsonText);
} catch (e) {
  throw new Error('docs-sync: failed to parse agent JSON block: ' + e.message);
}

obj.commands = getCommandsReference();

let nextJson = JSON.stringify(obj, null, 2);
// Escape angle brackets so HTML doesn’t treat them as tags.
nextJson = nextJson.replaceAll('<', '&lt;').replaceAll('>', '&gt;');

html = html.slice(0, jsonStart) + nextJson + '\n' + html.slice(preClose);

fs.writeFileSync(docsPath, html);
console.log(`docs-sync: updated docs/index.html (version v${version}, commands=${obj.commands.length})`);
