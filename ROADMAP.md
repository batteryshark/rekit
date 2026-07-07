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

## Queued — binary analysis

- **`pe-analyze`** — Windows PE/DLL: headers, arch, imports/exports, sections +
  entropy, signing, suspicious API imports → `BINARY.*` atoms. Lib: **pefile**.
- **`elf-analyze`** — Linux ELF: header/arch, sections + entropy, dynamic
  symbols/needed libs, RELRO/NX/PIE hardening → `BINARY.*` atoms. Lib: **pyelftools**.
- **`macho-analyze`** — macOS Mach-O: load commands, arch/fat, linked dylibs,
  code-signature presence. Lib: macholib (or lief).
- **`bin-triage`** — format-agnostic pure-stdlib: magic ID + Shannon entropy
  (packed/encrypted) + string extraction (ascii + utf-16le, surface URLs/IPs/APIs).

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
