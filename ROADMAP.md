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

## Queued — binary analysis

- **`macho-analyze`** — macOS Mach-O: arch/fat, file type, load commands, linked
  dylibs, RPATH, code-signature + encryption (`LC_ENCRYPTION_INFO`) → `BINARY.*`
  atoms. Lib: **macholib** (pure-python).
- **`dotnet-analyze`** — .NET / CLR managed assemblies (a PE with a CLR header):
  runtime version, referenced assemblies, **P/Invoke (`DllImport`) native-API
  surface** (the real capability signal for .NET malware), types/methods, entry
  point → `DOTNET.*`/`BINARY.*` atoms. Lib: **dnfile** (pure-python, static).
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
