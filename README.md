# skillpacks

A library of **self-contained analysis skills** that any agent (or tool) can call —
built for reverse-engineering and malicious-code triage, but coupled to nothing.

Each skill is a folder that carries everything it needs: a bundled tool or pure-stdlib
script under `runtime/`, a machine-readable `skill.json`, and an agent-facing
`SKILL.md`. A skill declares its external prerequisites and its safety properties
(does it execute the input? touch the network?). If a prerequisite is missing, the
caller is told exactly what to install — or it skips the skill and records the target
as *not analysed*. Nothing is ever silently skipped.

[`unmask`](../mcd) is the first consumer (it will wrap these as RE providers), but the
contract is generic: a skill is a directory + a manifest + a documented invocation.

```bash
bin/skillpack list                    # what skills exist
bin/skillpack doctor                  # which prerequisites are present  (X/Y ready)
bin/skillpack caps                    # capability → skills index
bin/skillpack install [--<id>]        # vendor skill runtimes (runs each build.sh)
bin/skillpack run <id> <args...>      # run one (checks prereqs first)
bin/skillpack info <id>               # manifest + SKILL.md
```

## The skills (17)

**Source detection** (pure stdlib, read-only, emit atoms)
| Skill | What | Prereq |
|---|---|---|
| `js-covert-scan` | STEGO/OBF/EVADE tactics in JS/TS (Unicode stego, XOR hiding, env-evasion) | python3 |
| `py-covert-scan` | STEGO/OBF/EVADE in Python (decode-then-exec, marshal/pickle, sandbox/anti-debug) | python3 |
| `secrets-scan` | leaked API keys / tokens / private keys (redacted) | python3 |

**Binary triage** (emit `BINARY.*`/`DOTNET.*` atoms)
| Skill | What | Prereq |
|---|---|---|
| `bin-triage` | format ID + entropy + strings + embedded-signature scan (mini-binwalk) | python3 |
| `pe-analyze` | PE/EXE/DLL (pefile) | python3 |
| `elf-analyze` | ELF (pyelftools) | python3 |
| `macho-analyze` | Mach-O (macholib) | python3 |
| `dotnet-analyze` | .NET/CLR + P/Invoke surface (dnfile) | python3 |
| `hex-view` | hex dump + sha256 | python3 |

**Deobfuscate / decompile**
| Skill | What | Prereq |
|---|---|---|
| `js-deobfuscate` | unpack obfuscated JS (webcrack, sandboxed) | node |
| `js-sourcemap-extract` | recover original sources from a JS source map | python3 |
| `pyc-decompile` | `.pyc` → source (decompyle3, 3.7–3.8) | python3 |
| `jvm-decompile` | `.apk`/`.dex`/`.jar`/`.class` → Java (jadx) | jadx (BYO) |
| `dotnet-decompile` | .NET IL → C# (ilspycmd) | ilspycmd (BYO) |
| `native-decompile` | ELF/PE/Mach-O → C (rizin `pdg`) | rizin (BYO) |

**Extract**
| Skill | What | Prereq |
|---|---|---|
| `unpack` | recursive, safe: zip/tar/gz/bz2/xz/**asar**/**ar·deb** (+7z/rar via CLI) | python3 |
| `pyinstaller-extract` | carve `.pyc` out of PyInstaller executables | python3 |

### Chains

- **Electron:** `unpack` (zip → asar) → `js-deobfuscate` / `js-sourcemap-extract` → `js-covert-scan`
- **Python:** `pyinstaller-extract` → `pyc-decompile` → `py-covert-scan`
- **Binary:** `bin-triage` → `pe`/`elf`/`macho`/`dotnet-analyze` → the matching decompiler

## Getting started

```bash
bin/skillpack install          # vendor runtimes for the skills that need it
bin/skillpack doctor           # confirm what's ready; install BYO tools for the rest
bin/skillpack run bin-triage ./unknown.bin
```

## Design rules

- **Self-contained.** A skill ships its own tool (bundled to one file where possible).
  No install step at analysis time.
- **Pinned & offline.** Tools are vendored at build time, never fetched mid-analysis —
  this is tooling for hostile inputs.
- **Honest degradation.** Missing prerequisite → the skill reports `missing` with an
  install hint; the caller asks the human or records a coverage blind spot.
- **Safety is declared.** Every skill states whether it executes the input and whether
  it needs network. Most are read-only and offline.
- **Three packaging patterns:** pure-stdlib (no runtime), vendored `node_modules`
  (native ok), vendored `pip --target site` (pure-python). Native-ABI-locked python
  deps are avoided; such tools go through an external CLI instead.

See `SKILL-CONTRACT.md` for the manifest spec and `ROADMAP.md` for what's next.

Apache-2.0
