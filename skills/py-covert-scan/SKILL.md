# Python Covert-Tactics Scanner

The Python sibling of `js-covert-scan`: detect the tactics Python code uses to hide
what it does, and emit atoms. Static, read-only, pure-stdlib.

## When to use

A `.py` (or a package, or source recovered by `pyc-decompile`) that might be a
dropper or be behaving differently under analysis. This surfaces the *tactics*; it
doesn't decide intent.

## What it detects — three families of atoms

**OBF** — hidden code execution (the hallmark of Python malware):
- `OBF.DECODE_EXEC` — decode-then-execute: `exec`/`eval`/`compile` fed by
  `base64`/`hex`/`zlib`/`gzip`/`lzma`/`marshal` output. **The strongest single tell.**
- `OBF.EXEC` — `exec()` / `eval()`.
- `OBF.MARSHAL` — `marshal.loads` (marshalled code object).
- `OBF.PICKLE` — `pickle.load(s)` (deserialization can execute code).
- `OBF.DYNIMPORT` — `__import__()` / `getattr(__builtins__, …)` / `importlib`.
- `OBF.CHARCODE` — strings built from `chr()` / long `\xNN` escapes.

**EVADE** — environment-keyed / anti-analysis:
- `EVADE.PLATFORM` — `sys.platform` / `platform.system()` branching.
- `EVADE.SANDBOX` — VM/sandbox/analyst detection (`gethostname`, `getpass.getuser`,
  `/sys/class/dmi`, VMware/VirtualBox/QEMU markers).
- `EVADE.TIMEZONE` — `time.tzname` / `locale.getlocale` / `ZoneInfo`.
- `EVADE.ANTIDEBUG` — `sys.gettrace()` / `ptrace` / `IsDebuggerPresent`.

**STEGO** — invisible/zero-width/bidi chars and confusable-homoglyph
punctuation/letters (same detection as the JS scanner — it's about the source bytes).

**Combination is the signal.** Decode-then-exec next to a sandbox check is an evasive
dropper; the scan reports a co-occurrence `assessment` across families.

## Usage

```bash
rekit run py-covert-scan ./setup.py
rekit run py-covert-scan ./package --format json
```

JSON: `{filesScanned, findingCount, summary, families, assessment, findings:[{atom,
family, confidence, file, line, col, snippet}]}` — maps onto the XFRM/EVADE lenses.

## Prerequisites

- **python3 ≥ 3.8** — pure stdlib, nothing to vendor.
