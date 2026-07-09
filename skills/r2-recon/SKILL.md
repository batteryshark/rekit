---
name: r2-recon
description: "Cross-format static recon of a native binary with radare2: drives r2 headless (-q -c, JSON commands) in one session for binary info, sections + per-section entropy, imports, exports, entry points, analysed functions, and decoded strings (incl. UTF-16). r2 auto-detects ELF/PE/Mach-O/DEX/..., so one skill covers them all and reports the relational view r2 is good at. Classifies imports by capability (inject/exec/network/anti-debug — Windows AND POSIX) and surfaces interesting strings. Emits BINARY.* atoms. Static: r2 analyses structure; it never runs or emulates the target."
---

# radare2 Recon

Cross-format static recon of a native binary with [radare2](https://radare.org).

## When to use

A native executable/library (ELF / PE / Mach-O / DEX / …) where you want one
cross-format pass that also reports the *relational* view r2 is good at —
analysed functions, entry points, decoded strings (incl. UTF-16) — not just a
structural parse of one format. Triages with `bin-triage` first, or jump
straight in; pair with `native-decompile` (rizin `pdg`) to read the
interesting functions.

## What it does

Opens **one** `r2` headless session (`-q -e scr.color=0 -c …`), runs analysis
(`aaa` by default; `--analysis none` for a fast structural-only pass), and dumps
every JSON command (`ij`, `iSj`, `iij`, `iEj`, `iej`, `aflj`, `izj`) separated
by `?e` echo markers — the runner splits on the markers and `json.loads` each
chunk, so a shape difference on one command degrades quietly instead of failing
the whole skill. Sections get per-section entropy computed from the file bytes
(the packed/compressed signal). Imports are classified by capability across
**both** Windows (VirtualAlloc, CreateProcess, …) and POSIX (execve, ptrace,
dlopen, socket …). Strings are scanned for URLs / IPs / paths / shell /
exec-API indicators. Emits `BINARY.*` atoms shared with `pe/elf/macho-analyze`
and `bin-triage`.

## Prerequisites

- **python3** (runner) and **`r2`** (radare2) on PATH. radare2 is a large native
  toolchain, so it is **not bundled** — install via `brew install radare2`
  (macOS), `apt install radare2` (Debian/Ubuntu), from <https://radare.org>, or
  `r2pm`. Until it's present, `doctor` marks the skill not-ready and `run`
  reports the honest gap.

## Usage

```bash
rekit run r2-recon ./suspicious.elf                      # human-readable + atoms
rekit run r2-recon ./unknown --format json | jq .        # machine result
rekit run r2-recon ./huge.bin --analysis none            # fast, structural only
```

## Notes

- r2 auto-detects the format, so this is the *one skill* for "I have a native
  blob of unknown format" — `pe/elf/macho-analyze` stay preferable when you know
  the format and want their format-specific atoms (TLS callbacks, RELRO, …).
- This is a **batch** skill: one stateless pass that emits a JSON result + atoms.
  To go deeper on a specific function, pair it with `native-decompile` (rizin
  `pdg`) — recon here, decompile there.
