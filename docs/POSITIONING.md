# Positioning & Architecture — rekit

Status: positioning draft (for discussion)

## TL;DR

**`rekit` is a curated, harness-agnostic set of skills and tools that agents use to do
reverse-engineering work** — deobfuscate, decompile, extract, triage, scan, carve, pull
IOCs, and (later) run/observe. It is **not a runtime.** Orchestration — the loop, the
ledger, goals, the human channel — is a *separate* concern owned by the agent/harness
(or a dedicated runtime project), not by rekit. This toolset (built as "rekit") **is**
rekit. It splits into a **static tier** (today) and a **dynamic tier** (growth).
`unmask`/MCD is a **completely separate project** and stays that way.

## 1. What rekit is

A kit. Each capability is a **self-contained skill**: a folder with a `skill.json`
manifest (id, capabilities, prerequisites, safety, entry), a `SKILL.md`, and its own
runner — a pure-stdlib script or a vendored tool. Plus a thin **dispatcher** for
discovery and use: `list` / `doctor` / `run` / `info` / `install` / `caps`.

Properties that make it a *kit*, not a framework:
- **Self-contained.** Skills carry their own tools (vendored) or declare a BYO tool with
  an install hint. No runtime carries the capabilities.
- **Harness-agnostic.** Any brain uses it — Claude Code, pi, codex, opencode, a human at
  a shell, or another program. A skill is a directory + a manifest + a documented
  invocation; the `caps` index maps capability → skill for discovery.
- **Honest.** Read-only or explicitly-sandboxed; missing prerequisite → the skill says so
  with an install hint (it never silently skips). Skills emit a uniform atom/finding
  shape so a caller can reason over results.

## 2. rekit is NOT the runtime

This is the sharpening: **separate rekit from the runtime.**

- rekit provides *capabilities*. It does **not** own the ralph loop, the project ledger,
  goal selection, or the agent brain. Those belong to whatever **drives** rekit — the
  agent/harness the operator is using, or a dedicated orchestration project.
- So an agent (or a script, or a person) picks skills off the shelf and runs them; rekit
  doesn't schedule, resume, or decide completion. That's the caller's job.
- **Name reclaim:** the existing `runner-lab/rekit` repo is currently a *runtime kernel*
  (loop / ledger / harness adapters / human channel / goalpacks). Under this definition
  the **"rekit" name moves to this toolset**, and that runtime kernel is **separated out**
  — parked or renamed to something that says "runtime," freeing `rekit` to mean the kit.
  (Open question below.)

## 3. Two tiers: static and dynamic

Every skill declares `safety.executes_input` (`no` | `sandboxed` | `full`) and a `tier`.
That field *is* the bifurcation.

### Static tier — today (21 skills)
- `executes_input: no` (or `sandboxed` for a narrow slice, e.g. webcrack's decoder VM),
  tier 0–1. Read-only; runs anywhere; safe over hostile input.
- Source covert-scan (JS/Py), secrets, YARA, binary triage (PE/ELF/Mach-O/.NET), hex,
  deobfuscate/decompile (webcrack, sourcemap, pyc, jvm/dotnet/native/ghidra), extract
  (unpack incl. asar/ar·deb, pyinstaller, binwalk), IOC extraction.

### Dynamic tier — growth
- `executes_input: full`, tier 3: **runs the target to observe behavior** — syscall /
  network / file / registry activity, runtime unpacking, instrumentation, emulation.
- **Isolation is the operator's choice, not a gate.** Running dynamic analysis inside a
  VM you already control is a first-class, expected workflow. rekit's job is to make
  execution **explicit and consented** — the skill declares it executes the target; the
  caller opts in (e.g. `--allow-dynamic`) — *not* to refuse unless a sandbox is bound.
- Sandbox / isolation providers (a VM driver, a container, OpenShell, Frida-on-host) are
  an **option** the caller can route dynamic skills through when configured, for automated
  or higher-assurance isolation. "I'm in a disposable VM, go" is honored.
- Candidate dynamic skills: sandboxed/VM **detonation** (behavioral trace), **Frida**
  instrumentation, **Unicorn** emulation of fragments, **network capture** (± sinkhole),
  debugger-driven unpacking, live memory dump + scan.

Contract-wise this needs nothing new — the `safety` fields already carry it; a caller
just keys its consent policy off them.

## 4. Boundary: `unmask` / MCD is a separate project

Stated plainly so it doesn't drift:

- `unmask`/MCD is **its own project and its own effort** — its own graph + SQLite ledger
  runtime and its own scanner. **It is not a goalpack. It is not "rekit's runtime." Its
  runtime is not merged with anything.** It stays exactly as it works today.
- rekit (the RE kit) and unmask (MCD) are **independent siblings**. unmask *may*, by
  explicit opt-in, reach for a rekit tool someday — but there is no architectural
  coupling, and rekit is not "for" unmask.

## 5. Open questions (for the discussion)

1. **Do the rename now?** `rekit` → `rekit` (repo/dir), and the `rekit` CLI →
   `rekit`. The `skill.json` contract stays; it just becomes *the* rekit contract.
2. **The existing rekit runtime kernel** (`runner-lab/rekit`): rename it to a
   runtime-y name (and keep it as a separate, optional orchestrator), or park it?
3. **Dynamic-tier consent UX** — per-run `--allow-dynamic`, per-skill acknowledgment, or
   an environment assertion ("I'm in a disposable VM")?
4. **First isolation provider** for the *optional* automated path — plain container, a VM
   driver, OpenShell, or Frida-on-host?
