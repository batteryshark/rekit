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

**Static analysis layer complete:** JS/Py covert-scan, PE/ELF/Mach-O/.NET triage,
`bin-triage`, `unpack`, `secrets-scan`. 12 skills. All emit atoms / route cleanly.

## Queued — containers / carving / decompilers

- **`unpack` follow-ups** — done: zip/tar/gz/bz2/xz + 7z/RAR (CLI) + **asar** (Electron,
  pure-python, base=8+u32@4, verified). Still to add: **ar/deb** extraction.
  (py7zr was rejected — native, python-ABI-locked deps; use the `7z` CLI instead.)
- **`binwalk-carve`** — firmware / embedded-file carving & extraction (filesystems,
  bootloaders, nested archives) via **binwalk** (v3 is a Rust single-binary → its own
  prereq). The heavy sibling of `bin-triage`'s embedded-signature scan; still widely
  used for IoT/firmware.
- **`pyinstaller-extract`** — carve `.pyc` out of PyInstaller bundles (feeds `pyc-decompile`).
- **`jvm-decompile`** — jadx / CFR (→ `java`).
- **`dotnet-decompile`** — ilspycmd (→ `dotnet`).
- **`native-decompile`** — ghidra headless / rizin (→ `java` / bundled).

## Later

Wire skills into `unmask-re` as providers (atoms/artifacts → skill → rescan). Not
now — capabilities first.
