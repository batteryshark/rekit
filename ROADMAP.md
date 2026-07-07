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
| `bin-triage` | format ID + entropy + strings + embedded scan | pure stdlib | python3 |
| `unpack` | recursive safe archive extraction | pure stdlib (+7z/unar CLI) | python3 |
| `py-covert-scan` | STEGO/OBF/EVADE atoms in Python | pure stdlib | python3 |
| `secrets-scan` | leaked credentials (redacted) → `SECRET.*` | pure stdlib | python3 |
| `pyinstaller-extract` | carve .pyc from PyInstaller exes | pure stdlib | python3 |
| `js-sourcemap-extract` | recover original sources from a JS source map | pure stdlib | python3 |
| `jvm-decompile` | apk/dex/jar/class → Java | jadx (BYO) |
| `dotnet-decompile` | .NET IL → C# | ilspycmd (BYO) |
| `native-decompile` | ELF/PE/Mach-O → C (rizin `pdg`) | rizin (BYO) |

**17 skills.** Static analysis + extraction (`unpack` incl. asar + ar/deb,
`pyinstaller-extract`) + prereq-gated decompilers (jvm/dotnet/native — honest
degradation) + **packaging** (`skillpack install`/`caps`, doctor summary, README).
**Chains verified end-to-end:** Electron (unpack→asar→js-deobfuscate/sourcemap→
js-covert-scan) and Python (pyinstaller-extract→pyc-decompile→py-covert-scan).

## Queued — remaining

- **`binwalk-carve`** — firmware / embedded-file carving & extraction (filesystems,
  bootloaders, nested archives) via **binwalk** (v3 is a Rust single-binary → its own
  prereq). The heavy sibling of `bin-triage`'s embedded-signature scan; still widely
  used for IoT/firmware. (`unpack` already covers zip/tar/gz/bz2/xz/asar/ar/deb +
  7z/rar via CLI; `bin-triage` previews embedded signatures.)

## Later

Wire skills into `unmask-re` as providers (atoms/artifacts → skill → rescan) — deferred:
the `unmask` scanner is being rebuilt natively in parallel, so integrating now would
collide. Capabilities first.
