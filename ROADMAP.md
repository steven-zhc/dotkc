# dotkc roadmap

This roadmap focuses on **dotkc itself** (vault backend + CLI semantics). OpenClaw-specific policy and tool-surface concerns live in the plugin roadmap.

## Product framing

dotkc’s core promise:

- Keep secrets **off the model transcript** (and ideally off stdout/stderr entirely)
- Provide **agent-friendly** structured outputs when asked
- Keep workflows reproducible: allowlists + deterministic parsing + stable error codes

## Principles

- **Default safe**: no plaintext values unless explicitly “break-glass”.
- **JSON-first** when used by tools/agents.
- **SSOT**: command reference and docs should not drift.
- **Explicitness**: prefer clear breaking changes over hidden aliases.

---

## P0 — Agent-safe correctness (highest ROI)

### 1) OpenClaw envelope coverage (all commands)
**Status:** 🟡 partial

Motivation:
- Tool outputs are often persisted to session transcripts; stable structured output lets plugins enforce fail-closed policies reliably.

What’s done:
- ✅ Added OpenClaw envelope for: `help`, `version`, `status`, `run` (inspect), and now: `doctor`, `list`, `search`, `export`, `copy`, `move`, `import`, `set`, `del`, `init`
- ✅ `get --openclaw` is intentionally blocked to avoid returning raw values to models

Remaining:
- ⬜ Standardize error codes/messages across all commands (stable `code` + machine-readable `errors[]`)
- ⬜ Consider envelope for `key install` (still must be stdin-only)

Deliverables:
- One schema section in README + HTML manual
- Golden examples for each command

### 2) No-leak mode (hard safety switch)
**Status:** ✅ implemented (env-only)

- Env: `DOTKC_NO_LEAK=1`
- Enforced:
  - blocks `get`
  - blocks `--unsafe-values` (inspect + export)

Next:
- ⬜ Add `status` field like `data.noLeak: true/false` (observability)
- ⬜ Ensure all “would-print-values” paths route through a single gate

### 3) “Break-glass” unsafe output (intentional, loud)
**Status:** ⬜ not yet

Motivation:
- Prompt injection / operator error can trick agents into unsafe modes; break-glass should be hard to enable accidentally.

Pain point:
- Today unsafe is a flag, but it’s still easy to accidentally misuse.

Proposal:
- Require **two-step** unsafe enabling (e.g. `--unsafe-values` + `DOTKC_BREAK_GLASS=1`)
- Print warnings to stderr with a fixed prefix (so plugins can detect)

---

## P1 — UX & reliability

### 4) Spec file parsing: better diagnostics

Motivation:
- Spec allowlists are the main policy boundary; when they fail, users need precise fixes (line numbers, suggestions) without dumping values.
- Line numbers + specific errors
- Better `doctor` hints when spec files are missing/invalid

### 5) Concurrency / integrity
- Improve conflict messages for optimistic locking (fingerprint mismatch)
- Add guidance for iCloud sync races

### 6) CI: docs sync guard
**Status:** 🟡 partial

- ✅ `npm run docs:sync`
- ⬜ CI check: fail if `docs:sync` changes files

---

## P2 — Packaging & discoverability

### 7) Optional library mode
- Extract vault engine into a reusable internal module

### 8) Release polish
- Changelog automation
- Clear exit codes per failure mode

### 9) SEO / indexing (docs site)
**Status:** ✅ baseline shipped

Next:
- Submit sitemap in Google Search Console + request indexing
