# dotkc roadmap

This roadmap focuses on **dotkc itself** (vault backend + CLI semantics). OpenClaw-specific policy and tool-surface concerns live in the plugin roadmap.

## Principles

- **JSON-first** when used by agents/tools.
- **Default safe**: no values unless explicitly requested.
- **SSOT**: command reference and docs should not drift.

## P0 — Agent-safe consistency

### 1) OpenClaw envelope coverage (all commands)
**Goal:** make output shape predictable for tools.

- Extend `--openclaw` envelope behavior beyond help/version/status/run to:
  - `doctor`, `list`, `search`, `export`, `copy`, `move`, `import`, `set`, `del`
- Ensure errors use a stable code + message format.

Deliverables:
- One output schema doc section (in README + docs)
- Golden examples for each command

### 2) No-leak mode (hard safety switch)
**Status:** ✅ implemented (env-only)

**Goal:** make it easy to guarantee “no secrets printed”.

Option:
- Env: `DOTKC_NO_LEAK=1`

Behavior (enforced):
- Block `get` (prints raw values)
- Block `--unsafe-values` (for `run` inspect and `export`)
- `export` remains redacted by default

### 3) Stronger redaction primitives
**Goal:** redaction is consistent and explicit.

- Standardize redaction markers (e.g. `{ redacted: true, length: N }`)
- Ensure *no* command prints values in JSON mode unless explicitly enabled

## P1 — Reliability & ergonomics

### 4) Spec-file parsing/validation improvements
- Strict parsing (line numbers, error codes)
- Path/format diagnostics in `doctor`

### 5) Better machine-readable diagnostics
- `doctor --openclaw`: structured suggestions (action + command)
- Add `data.suggestions[]` for common fixes

### 6) Docs automation
**Status:** 🟡 partial

- ✅ Keep `docs/index.html` agent JSON + version in sync (`npm run docs:sync`)
- ⬜ Add CI check: fail if `npm run docs:sync` changes files

## P2 — Packaging & discoverability

### 7) Optional library mode
- Extract vault engine to a small internal module for reuse

### 8) Release polish
- Changelog automation
- More explicit exit codes per failure mode

### 9) SEO / indexing (docs site)
**Status:** ✅ baseline shipped

- robots.txt + sitemap.xml
- Canonical + OG/Twitter meta + JSON-LD
- Basic OG image (`/og.png`)
- A few crawlable subpages added to sitemap

Next:
- Submit sitemap in Google Search Console and request indexing
