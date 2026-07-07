# skillpacks — capability roadmap

The pile of analysis capabilities. Each becomes a self-contained skill under
`skills/<id>/` following `SKILL-CONTRACT.md`. Order is loose — build whatever's most
useful next.

## Built ✅

| Skill | Capability | Pattern | Prereq |
|---|---|---|---|
| `js-deobfuscate` | unpack obfuscated JS (webcrack) | vendored `node_modules` | node |
| `pyc-decompile` | `.pyc` → source (decompyle3) | `uv pip --target` | python3 |
| `hex-view` | hex dump + sha256 | pure stdlib | python3 |
| `js-covert-scan` | STEGO/OBF/EVADE atoms in JS/TS | pure stdlib | python3 |
| `elf-analyze` | ELF triage → `BINARY.*` atoms | `uv pip --target` (pyelftools) | python3 |
| `pe-analyze` | PE triage → `BINARY.*` atoms | `uv pip --target` (pefile) | python3 |
| `macho-analyze` | Mach-O triage → `BINARY.*` atoms | `uv pip --target` (macholib) | python3 |
| `dotnet-analyze` | .NET/CLR triage + P/Invoke → `DOTNET.*` atoms | `uv pip --target` (dnfile) | python3 |

**PE/ELF/Mach-O/.NET static triage: complete.**

## Queued — binary analysis

- **`bin-triage`** — format-agnostic pure-stdlib: magic ID + Shannon entropy
  (packed/encrypted) + string extraction (ascii + utf-16le, surface URLs/IPs/APIs).
  A fast first-look that routes to the format-specific analyzer.

## Queued — source analysis

- **`py-covert-scan`** — Python analog of js-covert-scan: `marshal`/`exec`/`compile`,
  base64/hex-decode-then-exec, `os.environ`/timezone evasion, Unicode stego → atoms.
- **`secrets-scan`** — API keys / tokens / private keys (high-signal regex + entropy).

## Queued — containers / decompilers (prereq-gated, exercise honest degradation)

- **`unpack`** — zip/tar/asar/whl/nupkg recursive extraction to a fixpoint.
- **`pyinstaller-extract`** — carve `.pyc` out of PyInstaller bundles (feeds `pyc-decompile`).
- **`jvm-decompile`** — jadx / CFR (→ `java`).
- **`dotnet-decompile`** — ilspycmd (→ `dotnet`).
- **`native-decompile`** — ghidra headless / rizin (→ `java` / bundled).

## Later

Wire skills into `unmask-re` as providers (atoms/artifacts → skill → rescan). Not
now — capabilities first.
