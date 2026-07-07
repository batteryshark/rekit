# Skill contract

A skill is a directory under `skills/<id>/` with this shape:

```
skills/<id>/
  skill.json     machine manifest (required)
  SKILL.md       agent/human-facing doc (required)
  bin/           self-contained tool payloads (bundled binaries/scripts)
  scripts/       runner + build scripts (wrapper.mjs, build.sh, run.py, ...)
```

The dispatcher (`bin/skillpack`) discovers skills by scanning `skills/*/skill.json`.
Nothing else is registered anywhere — dropping a folder in is registration.

## `skill.json`

```json
{
  "id": "js-deobfuscate",
  "name": "JavaScript Deobfuscator",
  "version": "0.1.0",
  "description": "One line: what it does and, crucially, that it does NOT execute the input.",
  "capabilities": ["deobfuscate-js", "unpack-js-bundle"],

  "prerequisites": [
    {
      "tool": "node",
      "min_version": "18",
      "check": ["node", "--version"],
      "install_hint": "Install Node.js >= 18 (https://nodejs.org)"
    }
  ],

  "safety": {
    "executes_input": false,
    "network": "none",
    "tier": 1,
    "notes": "static AST transforms only; run with no network, writes only to the out dir"
  },

  "entry": {
    "command": ["node", "bin/webcrack.mjs"],
    "args": [
      {"name": "input",  "type": "file", "required": true,  "desc": "path to the input"},
      {"name": "outdir", "type": "dir",  "required": true,  "desc": "output directory"}
    ],
    "result": {
      "channel": "stdout",
      "format": "json",
      "fields": {"ok": "bool", "outputFile": "string", "notes": "string"}
    }
  }
}
```

### Field notes

- **`capabilities`** — stable capability strings a caller matches against (e.g.
  `unmask-re` maps `deobfuscate-js` onto its `deobfuscate` work item). Keep them
  boring and reusable across skills.
- **`prerequisites`** — external tools the skill needs on `PATH`. `check` is run
  verbatim; the first `\d+(\.\d+)*` in its output is compared to `min_version`.
  Prereqs are the *only* thing that can make a skill unavailable.
- **`safety`** — `executes_input` (`"no"` | `"sandboxed"` | `"full"`) and `network`
  let a caller pick a sandbox tier. Analysis skills should be `"no"` / `network:
  "none"` where possible; use `"sandboxed"` when the skill runs a narrow slice of the
  input inside an isolated VM (e.g. a deobfuscator decoding an encoded string array),
  and `"full"` only when dynamic execution is the whole point (then say so loudly).
- **`entry.command`** — argv prefix, resolved relative to the skill dir. The
  dispatcher appends the caller's positional args in `entry.args` order.
- **`entry.result`** — the runner SHOULD print a single JSON object to stdout as its
  machine result (`{"ok": true, ...}` / `{"ok": false, "error": "..."}`), so callers
  don't have to scrape logs.

## Invocation

Agent-agnostic, three equivalent ways:

```bash
# via dispatcher (checks prereqs first, then runs)
bin/skillpack run <id> <arg1> <arg2> ...

# direct (a caller that already knows the entry)
node skills/<id>/bin/<payload> <arg1> <arg2> ...

# programmatic (Python): read skill.json, check prereqs, exec entry.command + args
```

The dispatcher refuses to run a skill whose prerequisites are missing and prints the
install hint instead — that is the honest-degradation path.

## Building a skill's payload

Tools are vendored at **build time**, never at analysis time. A skill's
`scripts/build.sh` produces its `bin/` payload from pinned sources (e.g. bundle an
npm tool to one self-contained `.mjs` with esbuild). Commit the built payload so the
skill is offline and reproducible; re-run `build.sh` to refresh + re-pin.

## Adding a skill

1. `mkdir skills/<id>` with `skill.json` + `SKILL.md`.
2. Put the payload in `bin/` (and a `scripts/build.sh` that reproduces it).
3. `bin/skillpack doctor <id>` to confirm prereq detection.
4. Done — discovery is automatic.
