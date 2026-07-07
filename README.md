# skillpacks

A library of **self-contained analysis skills** that any agent (or tool) can call.

Each skill is a folder that carries everything it needs — a bundled binary or
script under `bin/`, its runner under `scripts/`, a machine-readable `skill.json`,
and an agent-facing `SKILL.md`. A skill declares its external prerequisites (e.g.
`node`, `java`, `dotnet`) and its safety properties (does it execute the input? does
it touch the network?). If a prerequisite is missing, the agent is told exactly
what to install — or it can skip the skill and record the target as *not analysed*.

This is deliberately **not** coupled to any one agent. [`unmask-re`](../mcd) is the
first consumer (it wraps these skills as RE providers), but the contract is generic:
a skill is a directory + a manifest + a documented invocation. Point any harness at
`skillpacks/skills/` and go.

```bash
bin/skillpack list                       # what skills exist
bin/skillpack doctor                      # which prerequisites are present
bin/skillpack run js-deobfuscate in.js out/   # run one
```

## Layout

```
skillpacks/
  SKILL-CONTRACT.md          the spec every skill follows
  bin/skillpack              agent-agnostic dispatcher (list / doctor / run / info)
  scripts/skillpack.py       dispatcher implementation (pure stdlib Python)
  skills/
    js-deobfuscate/          reference skill: static JS deobfuscation (webcrack)
      SKILL.md  skill.json  bin/  scripts/
```

## Design rules

- **Self-contained.** A skill ships its own tool (bundled to a single file where
  possible). No install step at analysis time.
- **Pinned & offline.** Tools are pinned and vendored at build time, never fetched
  mid-analysis — this is analysis tooling for hostile inputs; installing packages
  during a scan is the one thing it must not do.
- **Honest degradation.** Missing prerequisite → the skill reports `missing` with an
  install hint; the caller asks the human or records a coverage blind spot.
- **Safety is declared.** Every skill states whether it executes the input and
  whether it needs network, so a caller can sandbox appropriately.

Status: spike. One reference skill (`js-deobfuscate`) is real and runnable; more
(hex-view, jvm/dotnet/native decompile) follow the same contract.

Apache-2.0
