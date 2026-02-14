// Shared command reference for dotkc.
// Keep this as the single source of truth for:
// - dotkc --help --openclaw (data.commands)
// - docs agent JSON (commands[])

export function getCommandsReference() {
  return [
    { name: 'init', usage: 'dotkc init [--vault <path>] [--key <path>]', desc: 'Initialize vault + local key (prompts before overwriting).' },
    { name: 'status', usage: 'dotkc status [--vault <path>] [--key <path>]', desc: 'Print JSON status (paths + canDecrypt).' },
    { name: 'doctor', usage: 'dotkc doctor [--vault <path>] [--key <path>] [--json]', desc: 'Run diagnostics and suggest fixes.' },
    { name: 'key install', usage: 'cat ~/.dotkc/key | dotkc key install [--key <path>] [--force]', desc: 'Install key from stdin (refuses overwrite unless --force).' },
    { name: 'set', usage: 'dotkc set <service> <category> <KEY> [value|-]', desc: 'Set a secret (prompt hidden if value omitted).' },
    { name: 'get', usage: 'dotkc get <service> <category> <KEY>', desc: 'Print secret value to stdout.' },
    { name: 'del', usage: 'dotkc del <service> <category> <KEY>', desc: 'Delete a secret.' },
    { name: 'list', usage: 'dotkc list <service> [category]', desc: 'List categories or keys.' },
    { name: 'search', usage: 'dotkc search <query> [--json]', desc: 'Search keys by substring (no values).' },
    { name: 'export', usage: 'dotkc export <spec>[,<spec>...] [--unsafe-values]', desc: 'Export dotenv lines (redacted by default).' },
    { name: 'copy', usage: 'dotkc copy <srcService>:<srcCategory> <dstService>:<dstCategory> [--force]', desc: 'Copy a category.' },
    { name: 'move', usage: 'dotkc move <srcService>:<srcCategory> <dstService>:<dstCategory> [--force]', desc: 'Move a category.' },
    { name: 'import', usage: 'dotkc import <service> <category> [dotenv_file]', desc: 'Interactive import from .env.' },
    { name: 'run', usage: 'dotkc run [options] <spec>[,<spec>...] [-- <cmd> ...]', desc: 'Inspect (redacted) or execute with injected env.' },
  ];
}
