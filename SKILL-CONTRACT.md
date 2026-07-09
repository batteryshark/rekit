# Skill contract

A skill is a directory under `skills/<id>/` with this shape:

```
skills/<id>/
  SKILL.md       agent/human-facing doc (required) — name + description frontmatter + Markdown body
  scripts/       runner + build scripts + vendored deps (run.py, run.mjs, build.sh, site/, node_modules/, ...)
  bin/           committed native binaries / bundled data payloads     (optional)
  references/    docs loaded on demand                                  (optional)
  assets/        bundled data files the runner reads, templates, rules  (optional)
```

The machine manifest for **every** skill lives in ONE central file, `registry.json`,
keyed by skill id — *not* inside the skill folders. A skill's folder holds only its doc
(`SKILL.md`) and its payload (`scripts/`, `bin/`, …). `SKILL.md`'s frontmatter carries
just `name` + `description`, which keeps it a valid
[Agent Skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills); those two
fields are a synced projection of the registry (regenerate with `rekit sync-docs`). The
folder names (`scripts/`, `references/`, `assets/`, `bin/`) follow the Agent Skill
conventions.

The dispatcher (`bin/rekit`) is **pure stdlib**: it reads `registry.json` (plain JSON)
and pairs each entry with its `skills/<id>/` directory. Registration is a registry
entry — `rekit doctor` flags any skill dir with no entry (and any entry with no dir) so
the two can't silently drift.

## `registry.json`

One JSON object, `{ "<id>": { …manifest… }, … }`. The `<id>` key is the skill's
directory name; the value is its manifest:

```json
{
  "js-deobfuscate": {
    "name": "JavaScript Deobfuscator",
    "description": "One line: what it does and, crucially, whether it executes the input.",
    "version": "0.1.0",
    "capabilities": ["deobfuscate-js", "unpack-js-bundle"],
    "kind": "analyze",
    "prerequisites": [
      {"tool": "node", "min_version": "18", "check": ["node", "--version"],
       "install_hint": "Install Node.js >= 18 (https://nodejs.org)"}
    ],
    "safety": {"executes_input": "no", "network": "none", "tier": 1,
               "notes": "static AST transforms only; writes only to the out dir"},
    "entry": {
      "command": ["node", "scripts/run.mjs"],
      "args": [
        {"name": "input",  "type": "file", "required": true, "desc": "path to the input"},
        {"name": "outdir", "type": "dir",  "required": true, "desc": "output directory"}
      ],
      "result": {"channel": "stdout", "format": "json",
                 "fields": {"ok": "bool", "outputFile": "string", "notes": "string"}}
    }
  }
}
```

The dispatcher builds each skill dict as: `id` from the key, everything else from the
entry (`name`, `description`, `capabilities`, `entry`, …), plus the resolved `_dir`.

## `SKILL.md` frontmatter

`SKILL.md` MUST begin with YAML frontmatter carrying `name` (kebab-case, == the id/dir,
<= 64 chars) and `description` (<= 1024 chars, one line, no angle brackets `<`/`>`).
These are the Agent-Skill trigger fields; the description should cover both *what it
does* and *when to reach for it*. They mirror the registry — `rekit sync-docs`
regenerates them from `registry.json`, and `rekit sync-docs --check` fails on drift.

```markdown
---
name: js-deobfuscate
description: "Deobfuscate and unpack obfuscated JavaScript with webcrack. Use when JS reads as machine-generated noise (_0x names, packed string arrays). AST transforms only; never executes the input."
---

# JavaScript Deobfuscator
...
```

### Manifest field notes (each key of a `registry.json` entry)

- **`capabilities`** — stable capability strings a caller matches against (e.g.
  `unmask-re` maps `deobfuscate-js` onto its `deobfuscate` work item). Keep them
  boring and reusable across skills.
- **`kind`** *(optional, default `"analyze"`)* — the axis of what the skill *does to the
  world*. `"analyze"` skills READ/observe a target (the vast majority). `"construct"`
  skills PRODUCE an artifact (compile a PoC, assemble shellcode, build a stub) — their
  input is usually your own trusted source, not a sample, so they sit low on the risk
  scale. Orthogonal to `safety`: `kind` is read-vs-write, `executes_input` is
  runs-the-target-or-not. `list`/`search` mark construct skills 🔨 (dynamic wins the glyph
  if a skill is somehow both); `search --construct` / `--analyze` filter on it.
- **`prerequisites`** — external tools the skill needs on `PATH`. `check` is run
  verbatim; the first `\d+(\.\d+)*` in its output is compared to `min_version`.
  Prereqs are the *only* thing that can make a skill unavailable.
- **`safety`** — `executes_input` (`"no"` | `"sandboxed"` | `"full"`) and `network`
  let a caller pick a sandbox tier. Analysis skills should be `"no"` / `network:
  "none"` where possible; use `"sandboxed"` when the skill runs a narrow slice of the
  input inside an isolated VM (e.g. a deobfuscator decoding an encoded string array),
  and `"full"` only when dynamic execution is the whole point (then say so loudly).
  **Dynamic tier:** `executes_input: "full"` skills are gated — the dispatcher requires
  `rekit run --allow-dynamic <skill>` (consent, *not* a sandbox requirement; it passes
  `REKIT_ALLOW_DYNAMIC=1` to the runner) and marks them ⚡ in `list`. Such a runner should
  also refuse a direct call lacking that consent. Isolation (VM/container/OpenShell/Frida)
  is a separate, optional axis — native execution is fine on a box you don't mind risking.
- **`entry.command`** — argv prefix, resolved relative to the skill dir. The
  dispatcher appends the caller's positional args in `entry.args` order.
- **`entry.args`** — declared args drive the dispatcher's positional ordering AND
  the `rekit mcp` JSON Schema export. `type` is one of `file`/`dir`/`path`/`str`
  (→ string), `int` (→ integer), `enum` (→ string with a fixed set of choices),
  `flag` (→ boolean; `true` emits the bare switch). Names with a `--`/`-` prefix
  are options; bare names are positionals. For `enum` args, declare the allowed
  values in a machine-readable **`choices`** array (e.g. `["text", "json"]`) so
  consumers like `rekit mcp` emit a real JSON Schema `enum` instead of scraping
  the human `desc`. `required` only applies to positionals; options are optional.
- **`entry.result`** — the runner SHOULD print a single JSON object to stdout as its
  machine result (`{"ok": true, ...}` / `{"ok": false, "error": "..."}`), so callers
  don't have to scrape logs.

## Invocation

Agent-agnostic, three equivalent ways:

```bash
# via dispatcher (checks prereqs first, then runs)
bin/rekit run <id> <arg1> <arg2> ...

# direct (a caller that already knows the entry)
node skills/<id>/scripts/<payload> <arg1> <arg2> ...

# programmatic (Python): read the skill's registry.json entry, check prereqs, exec entry.command + args
```

The dispatcher refuses to run a skill whose prerequisites are missing and prints the
install hint instead — that is the honest-degradation path.

## Building a skill's payload

Tools are vendored at **build time**, never at analysis time. A skill's
`scripts/build.sh` produces its vendored payload alongside the runner in `scripts/`
(e.g. `scripts/site/` via `uv pip install --target`, or `scripts/node_modules/` from a
pinned npm tree). Committed native binaries and bundled data payloads live in `bin/`.
Commit the built payload so the skill is offline and reproducible; re-run `build.sh`
to refresh + re-pin.

## Adding a skill

1. Add a `"<id>": { … }` entry to `registry.json` (name, description, capabilities,
   prerequisites, safety, entry — see the shape above).
2. `mkdir skills/<id>` with a `SKILL.md` (Markdown body) and put the runner in
   `scripts/` (plus a `scripts/build.sh` if it vendors deps); commit native binaries /
   data payloads to `bin/` and any templates or rule packs to `assets/`.
3. `bin/rekit sync-docs` to write the `name` + `description` frontmatter into SKILL.md
   from the registry, then `bin/rekit doctor <id>` to confirm prereqs (and that the
   entry and directory line up).
4. Done — `registry.json` is the registration.
