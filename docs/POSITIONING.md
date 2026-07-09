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

A kit. Each capability is a **skill**: a folder with a `SKILL.md` doc + its own runner
(a pure-stdlib script or a vendored tool). The machine manifests (capabilities,
prerequisites, safety, entry) live in one central `registry.json`. Plus a thin
**dispatcher** for
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

## 5. MCP: rekit exports, the harness hosts

The MCP question resolves cleanly once you name the axis rekit is built on. A
rekit skill is a **stateless one-shot** — one `entry.command` + argv → one JSON
result, process dies. An MCP server is a **live session** — a long-lived
JSON-RPC process exposing N tools that share state (open a DB → query → close;
`open_database` → `wait_for_analysis` → `decompile_function` → `get_xrefs_to`).
Those are *different axes*, not competitors: rekit is the capability axis
(one-shot, declared safety, offline, vendored); MCP is the session axis
(stateful, multi-turn, huge surface). A 200-tool IDA server is only valuable
because its tools share one live IDA process — flatten it into 200 rekit skills
and each re-opens IDA (minutes each); collapse it into one skill and the tool
surface becomes an opaque blob.

So the stance is: **rekit speaks MCP as an *output*, and the harness
(rekit-factory) imports third-party MCP *servers* — rekit does neither host nor
client third-party servers itself.**

- **`rekit mcp` is the sole export adapter.** It exposes the whole skill catalog
  as ONE MCP server — one tool per skill, JSON Schema derived from
  `entry.args` (positionals → required string props; `--opt int/str/enum` → typed
  props, enums parsed from `desc`; `--flag` → boolean). A tool call is literally
  `rekit run <id> <args>` under the hood, so the prereq gate and the
  dynamic-consent gate are IDENTICAL to the CLI — zero drift. The adapter is
  pure stdlib and adds no MCP-*client* plumbing to rekit. This lets any
  MCP-native harness (rekit-factory, Claude, opencode) consume the entire kit as
  progressive-disclosure tools with zero per-skill wiring.
- **Third-party MCP servers are wired by the harness, never vendored into rekit.**
  MCP-client plumbing (a stdio multiplexer, server lifecycle, schema cache,
  connection pooling) is transport for *live sessions* — a runtime concern, and
  rekit-factory owns the runtime. rekit has no reason to carry it. When you
  depend on an upstream server (e.g. the IDA MCP), you run it as an MCP server
  at the harness layer alongside `rekit mcp`, and the agent composes both.
- **Convert-to-skill rule:** convert a third-party MCP server to a rekit skill
  **iff it's thin and stateless** (one CLI call captures its full value) — then
  pin it at build time and re-run the converter on upstream bumps, exactly like
  any `scripts/build.sh`. **Never convert** a stateful / large-surface server
  (IDA, a debugger, browser automation, a DB session) — there is no
  skill-shaped representation that preserves its value.
- **Tool search needs no unification.** rekit searches skills (`rekit search` /
  `caps`, tens→hundreds); a server like IDA searches its own tools. The
  200-tool problem only exists *inside* one server, where progressive disclosure
  is already native. Each layer searches itself; the agent asks the right layer.
  There is no 200+N federated catalog to build.
- **Consent and honest degradation carry through unchanged.** A ⚡ dynamic skill
  is consent-gated over MCP exactly as on the CLI: `rekit mcp` hides nothing
  (the tool is listed so the agent knows the capability exists) but a call
  returns an `isError` pointing to `rekit mcp --allow-dynamic` until the operator
  consents — mirroring `rekit run --allow-dynamic`. A skill whose prereq is
  missing is still listed, but its tool description is annotated
  `[unavailable on this host — missing prereq: …]` and a call returns the
  install hint — rekit never silently skips.

## 6. Status & decisions

- **Rename — DONE.** `skillpacks` → `rekit` (dir + `rekit` CLI); the old runtime kernel
  → **`rekit-factory`**. The `registry.json` + `SKILL.md` contract is now *the* rekit contract.
- **Dynamic-tier consent — DONE.** A skill with `safety.executes_input: full` is gated:
  `rekit run --allow-dynamic <skill>` (the dispatcher passes consent to the runner via
  `REKIT_ALLOW_DYNAMIC=1`; runners also refuse direct calls without it). `rekit list`
  marks dynamic skills with ⚡. First dynamic skill: **`exec-observe`** (run the target;
  capture exit / stdout / stderr / files-created / timing).
- **Isolation — optional axis; native is first-class.** RE often runs on a box you don't
  mind risking, so *no isolation* is a legitimate default. Providers (a VM driver, a
  container, **OpenShell**, Frida-on-host) are opt-in, for when you want automated
  isolation. None is required and none is wired yet — OpenShell is the leading candidate
  but undecided.
- **Boundary holds:** `unmask`/MCD stays a completely separate project.
- **MCP stance — DECIDED + built.** `rekit mcp` is the sole export adapter (one
  MCP tool per skill, pure-stdlib JSON-RPC-over-stdio in `scripts/rekit_mcp.py`).
  rekit neither hosts nor clients third-party MCP servers — that session-axis
  wiring belongs to the harness (rekit-factory). Convert-to-skill rule:
  thin/stateless only. See §5 above.
- **Enum `choices` — DONE.** `entry.args` of `type: enum` now carry a
  machine-readable `choices` array (documented in `SKILL-CONTRACT.md`), so
  `rekit mcp` emits real JSON Schema `enum`s from the manifest instead of parsing
  `desc` strings. All 34 enum args across the 31 skills are populated; the
  adapter keeps a best-effort `desc` parser as a fallback for future skills.

### Still open
- Which isolation provider to wire first (if any) — deferred until there's a concrete need.
- Deeper `rekit-factory` cleanup (its internal Python package is still named `rekit`).
- Next dynamic skills: `strace`/`dtruss` trace, Frida hooking, network capture, Unicorn.
