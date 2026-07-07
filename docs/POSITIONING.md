# Positioning & Architecture — the RE skill toolset

Status: positioning draft (for discussion)

## TL;DR

This toolset is **general reverse-engineering tooling**, not a malicious-code-detection
feature. Its natural home is **`rekit`** — which is already *"a harness-agnostic
reverse-engineering runtime"* whose explicit design is "the runtime orchestrates;
parsers, decompilers, and tree-sitter live inside *skills*, never in the runtime."
These skills are exactly that. The library splits into a **static tier** (today) and a
**dynamic tier** (growth). `unmask`/MCD is a **separate project** and stays that way.

## 1. What this is (and isn't)

- **Is:** a library of self-contained RE skills — deobfuscate, decompile, extract,
  triage, scan, carve, pull IOCs. Each skill is a folder with a `skill.json` manifest,
  a `SKILL.md`, and its own vendored tool or pure-stdlib runner. Agent-agnostic; useful
  to any harness or human.
- **Isn't:** an MCD component. MCD was just the work that surfaced the need. Nothing in
  the toolset is coupled to `unmask`; the "MCD" label should come off.

## 2. Home: `rekit` (convergence, not rebrand)

`rekit` already *is* the "RE kit" — a harness-agnostic runtime with:

- a persistent project **ledger**, discovery/artifact tracking, a ralph loop, a human
  channel, and **`rekit/skills`** = "filesystem skill discovery, scoping, and a
  searchable registry";
- the scope rule: **runtime carries nothing; capabilities live in skills**.

That is the same philosophy this toolset was built on (self-contained skills, vendored
deps, runtime-depends-on-nothing). So the move is a **homecoming**: this toolset becomes
**rekit's skill library**. Physical packaging is a detail — the toolset can stay a repo
that rekit *discovers* on the filesystem (rekit already does filesystem skill discovery),
or fold into rekit — either way the skill contract is what matters.

**The one real integration task:** two skill contracts exist today —
- this toolset's `skill.json` + `bin/skillpack` dispatcher (self-contained, honest
  prereq degradation, `caps` index), and
- rekit's native skill protocol (`rekit/skills` — scoping, gating, sandboxing,
  derivation-fold into the ledger via `run_skill`).

They're philosophically identical; reconciling the two manifests (map `skill.json` ↔
rekit's skill protocol, or give rekit an adapter that loads these) is the first concrete
step whenever convergence happens.

## 3. Two tiers: static and dynamic

Every skill already declares `safety.executes_input` (`no` | `sandboxed` | `full`) and a
`tier`. That field *is* the bifurcation — the runtime keys off it.

### Static tier — today (21 skills)
- `executes_input: no` (or `sandboxed` for a narrow slice, e.g. webcrack's decoder VM).
- Read-only; runs anywhere; no isolation required; safe to run over hostile input.
- Covers: source covert-scan (JS/Py), secrets, YARA, binary triage (PE/ELF/Mach-O/.NET),
  hex, deobfuscate/decompile (webcrack, sourcemap, pyc, jvm/dotnet/native/ghidra),
  extract (unpack incl. asar/ar·deb, pyinstaller, binwalk), IOC extraction.

### Dynamic tier — growth
- `executes_input: full`, tier 3: **runs the target to observe behavior** — syscall /
  network / file / registry activity, runtime unpacking, instrumentation, emulation.
- **Isolation is the operator's choice, not a hard gate.** Running dynamic analysis
  inside a VM you already control is a first-class, expected workflow. The runtime's job
  is to make execution **explicit and consented** — the skill declares it executes the
  target, and the runtime surfaces that and requires an opt-in (e.g. `--allow-dynamic`),
  *not* to refuse unless a sandbox provider is bound.
- Sandbox / isolation providers (a VM, a container, OpenShell, Frida-instrumented host)
  are an **option** the runtime can route dynamic skills through when configured — for
  automated or higher-assurance isolation — but the operator saying "I'm in a VM, go" is
  honored.
- Candidate dynamic skills: sandboxed/VM **detonation** (behavioral trace), **Frida**
  instrumentation/hooking, **Unicorn** emulation of code fragments, **network capture**
  (with optional sinkhole), debugger-driven unpacking, live memory dump + scan.

Contract-wise this needs almost nothing new: the `safety` metadata is already there. The
runtime adds a policy — "dynamic skills require explicit consent; route through an
isolation provider if one is configured."

## 4. Boundary: `unmask` / MCD is a separate project

Stated plainly so it doesn't drift:

- `unmask`/MCD is **its own project and its own effort**, with its own graph + SQLite
  ledger runtime and its own scanner. **It is not a goalpack. It is not a rekit
  consumer. Its runtime is not merged with rekit's.** It stays exactly as it works today.
- rekit (RE runtime) and unmask (MCD) are **independent siblings**. They may, someday and
  by explicit opt-in, share the odd capability — but there is no architectural coupling,
  and "MCD as a lens over rekit" is explicitly **not** the model.

## 5. Naming

`rekit` = the umbrella RE system ("RE kit"): a harness-agnostic runtime + a skill library
spanning a **static tier** (now) and a **dynamic tier** (next). This toolset is that skill
library. Drop the MCD framing.

## 6. Open questions (for the discussion)

1. Packaging: does this toolset **fold into `rekit`**, or stay a sibling repo that rekit
   **discovers** on the filesystem? (Both preserve the skill contract.)
2. Skill-contract reconciliation: adapt `skill.json` to rekit's native protocol, or add a
   rekit adapter that loads `skill.json` skills as-is?
3. Dynamic-tier consent UX: a per-run `--allow-dynamic` flag, a per-skill acknowledgment,
   or an environment assertion ("I'm in a disposable VM")?
4. Isolation providers: which to support first for the *optional* automated path — plain
   container, a VM driver, OpenShell, Frida-on-host?
