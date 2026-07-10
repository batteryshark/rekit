---
name: yara-scan
description: "Scan a file or directory with YARA rules (classic yara or the newer yara-x). Ships a small high-signal starter rule pack; point --rules at a real corpus (YARA-Rules, signature-base, your own) for serious coverage. Read-only — matches patterns, never runs the target. Prereq-gated on the yara CLI with honest degradation."
---

# YARA Scanner

Scan a file or directory with [YARA](https://virustotal.github.io/yara/) rules — the
standard way to match known malware patterns/families.

## When to use

Any triage where you want signature coverage: run it over a package, an extracted
archive, a dropped sample, or a whole tree. Complements the behavioural covert-scan
skills (which look at *tactics*) with *signature* matching.

## What it does

Runs `yara` (or `yara-x`/`yr`) with your rules over the target and reports each match
as `{rule, target}`. Read-only — YARA matches patterns; it never runs the target.

Ships a small **starter rule pack** (`assets/starter.yar`): embedded/base64-encoded
PE, UPX packing, PHP webshell eval, Windows exec/download cradles, and `curl|sh`
droppers. **This is a starting point, not a corpus** — for real coverage point
`--rules` at [YARA-Rules](https://github.com/Yara-Rules/rules),
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base), or your own set.

## Usage

```bash
rekit run yara-scan ./package                       # starter rules over a tree
rekit run yara-scan ./sample.bin --rules ~/rules    # your own corpus
rekit run yara-scan ./x --format json
```

## Prerequisites

- **python3** (runner) and the **`yara`** CLI (or `yara-x`) on PATH — a native tool,
  not bundled. Until it's installed, `doctor` marks the skill not-ready and `run`
  reports the honest gap with an install hint. (The starter rules ship with the skill.)
