# rekit — capability roadmap

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
| `binwalk-carve` | firmware / embedded-file extraction | binwalk (BYO) |
| `ghidra-decompile` | full Ghidra headless decompile (hard targets) | analyzeHeadless (BYO) |
| `yara-scan` | YARA signature scan + starter rule pack | yara (BYO) |
| `ioc-extract` | defanged IOCs (urls/ips/hashes/…) from any file | pure stdlib · python3 |

**21 skills.** Source detection + binary triage + extraction + decompilers
(`native-decompile` = rizin's Ghidra decompiler, no JVM; `ghidra-decompile` = full
Ghidra headless) + `yara-scan` signatures + `ioc-extract` reporting + **packaging**.
**15 run out of the box**; 6 BYO-tool (jadx/ilspycmd/rizin/binwalk/ghidra/yara) degrade
honestly.
**Chains verified end-to-end:** Electron (unpack→asar→js-deobfuscate/sourcemap→
js-covert-scan) and Python (pyinstaller-extract→pyc-decompile→py-covert-scan).

## Queued — remaining

Nothing queued — the toolset is feature-complete for now (18 skills). New skills just
drop into `skills/<id>/` following `SKILL-CONTRACT.md`.

## Later

Wire skills into `unmask-re` as providers (atoms/artifacts → skill → rescan) — deferred:
the `unmask` scanner is being rebuilt natively in parallel, so integrating now would
collide. Capabilities first.
