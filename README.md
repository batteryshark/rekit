# rekit

A library of **self-contained analysis skills** that any agent (or tool) can call —
built for reverse-engineering and malicious-code triage, but coupled to nothing.

Each skill is a folder that carries everything it needs: a bundled tool or pure-stdlib
runner under `scripts/`, and an agent-facing `SKILL.md` (`name` + `description`
frontmatter). The machine manifest for every skill lives in one central
[`registry.json`](registry.json), keyed by id. A skill declares its external prerequisites and its safety properties
(does it execute the input? touch the network?). If a prerequisite is missing, the
caller is told exactly what to install — or it skips the skill and records the target
as *not analysed*. Nothing is ever silently skipped.

The contract is consumer-agnostic: a skill is a directory, a manifest entry in
`registry.json`, and a documented invocation — any agent or tool can call it.

```bash
bin/rekit list                    # what skills exist
bin/rekit doctor                  # rekit's own reqs (base/build/recommended) + which skills are ready  (X/Y)
bin/rekit caps                    # capability → skills index
bin/rekit install [--<id>]        # vendor skill runtimes (runs each build.sh)
bin/rekit run <id> <args...>      # run one (checks prereqs first)
bin/rekit setup [--tier all]      # print install commands for missing base/build/recommended tools (never runs them)
bin/rekit info <id>               # manifest + SKILL.md
bin/rekit mcp [--allow-dynamic]   # serve the whole catalog over MCP (one tool per skill; export only)
```

## The skills

Grouped by what they do; `rekit list` and `rekit caps` are the authoritative catalog.

**Source detection** (pure stdlib, read-only, emit atoms)
| Skill | What | Prereq |
|---|---|---|
| `js-covert-scan` | STEGO/OBF/EVADE tactics in JS/TS (Unicode stego, XOR hiding, env-evasion) | python3 |
| `py-covert-scan` | STEGO/OBF/EVADE in Python (decode-then-exec, marshal/pickle, sandbox/anti-debug) | python3 |
| `secrets-scan` | leaked API keys / tokens / private keys (redacted) | python3 |
| `yara-scan` | YARA signature scan (+ starter rule pack) | yara (BYO) |
| `ioc-extract` | defanged IOCs (urls/ips/domains/hashes/CVEs/…) from any file | python3 |

**Binary triage** (emit `BINARY.*`/`DOTNET.*` atoms)
| Skill | What | Prereq |
|---|---|---|
| `bin-triage` | format ID + entropy + strings + embedded-signature scan (mini-binwalk) | python3 |
| `pe-analyze` | PE/EXE/DLL (pefile) | python3 |
| `elf-analyze` | ELF (pyelftools) | python3 |
| `macho-analyze` | Mach-O (macholib) | python3 |
| `dotnet-analyze` | .NET/CLR + P/Invoke surface (dnfile) | python3 |
| `hex-view` | hex dump + sha256 | python3 |
| `r2-recon` | cross-format native recon (ELF/PE/Mach-O/DEX…) — r2 headless: info/sections+entropy/imports/funcs/strings → `BINARY.*` atoms | r2 (BYO) |

**Deobfuscate / decompile**
| Skill | What | Prereq |
|---|---|---|
| `js-deobfuscate` | unpack obfuscated JS (webcrack, sandboxed) | node |
| `js-string-decode` | statically decode constant-key XOR / charCode string obfuscation in JS | python3 |
| `js-sourcemap-extract` | recover original sources from a JS source map | python3 |
| `pyc-decompile` | `.pyc` → source (decompyle3, 3.7–3.8) | python3 |
| `jvm-decompile` | `.apk`/`.dex`/`.jar`/`.class` → Java (jadx) | jadx (BYO) |
| `dotnet-decompile` | .NET IL → C# (ilspycmd) | ilspycmd (BYO) |
| `native-decompile` | ELF/PE/Mach-O → C (rizin `pdg`, no JVM) | rizin (BYO) |
| `ghidra-decompile` | ELF/PE/Mach-O → C (full Ghidra headless) | analyzeHeadless (BYO) |

**Extract**
| Skill | What | Prereq |
|---|---|---|
| `unpack` | recursive, safe: zip/tar/gz/bz2/xz/**asar**/**ar·deb** (+7z/rar via CLI) | python3 |
| `pyinstaller-extract` | carve `.pyc` out of PyInstaller executables | python3 |
| `binwalk-carve` | carve/extract embedded files from firmware images | binwalk (BYO) |

**PE repair** (Windows — reconstruct dumped or packed PEs)
| Skill | What | Prereq |
|---|---|---|
| `pe-unmap` | convert PE alignment: memory dump → loadable EXE (pe_unmapper) | python3 · Windows binary |
| `pyscylla` | rebuild a dumped PE's Import Address Table (libscylla) | python3 · Windows binary |
| `ord-lookup` | resolve Windows DLL ordinal imports → symbol names | python3 |

**Mobile** (dump from a live device)
| Skill | What | Prereq |
|---|---|---|
| `dex-dump` | dump decrypted DEX from a running Android app | adb (BYO device) |
| `ios-dump` | dump a decrypted iOS app binary (FairPlay) from a jailbroken device | frida (BYO device) |

**Dynamic** ⚡ (run the target to observe behavior; consent-gated via `rekit run --allow-dynamic`)
| Skill | What | Prereq |
|---|---|---|
| `exec-observe` | run target, capture exit/stdout/stderr/files-created/timing | python3 |
| `emulate-code` | contained: run raw shellcode/blob on a virtual CPU (no OS) | unicorn · python3 |
| `qiling-emulate` | contained: emulate a FULL binary (PE/ELF/Mach-O) w/ emulated OS syscalls | qiling + BYO rootfs · python3 |
| `syscall-trace` ⚡ | kernel-syscall trace (strace/dtruss) → histogram + files/net/exec | strace/dtruss (BYO) · python3 |
| `net-capture` ⚡ | run target + sniff wire (tcpdump) → talkers/DNS + pcap | tcpdump (BYO, root) · python3 |
| `frida-trace` ⚡ | Frida-hook network/exec/file/crypto API calls | frida-trace (BYO) · python3 |

**Construct** 🔨 (produce an artifact; never run it)
| Skill | What | Prereq |
|---|---|---|
| `cc-build` | compile C/C++/ObjC → native (exe/.o/.s/IR), cross-compile | clang/cc/gcc (BYO) · python3 |
| `asm-assemble` | assemble asm → bytes (hex/C-array/raw) — x64/x86/arm64/arm | clang/LLVM (BYO) · python3 |
| `shellcode-stub` | wrap raw shellcode → runnable native PoC (`--os posix` mmap/mprotect \| `--os windows` VirtualAlloc+ExitProcess) | clang (BYO) · python3 |

**Workflow** (not RE — a harness convenience)
| Skill | What | Prereq |
|---|---|---|
| `gitops` | drive git through plain verbs (clone/commit/branch/stash/push/worktree/…) for harnesses that don't grok git | git |

### Chains

- **Electron:** `unpack` (zip → asar) → `js-deobfuscate` / `js-sourcemap-extract` → `js-covert-scan`
- **Python:** `pyinstaller-extract` → `pyc-decompile` → `py-covert-scan`
- **Binary:** `bin-triage` → `pe`/`elf`/`macho`/`dotnet-analyze` → the matching decompiler
- **Construct → analyze:** `asm-assemble` → `shellcode-stub` → `exec-observe` (native) or `qiling-emulate` (cross-arch/cross-OS); `cc-build` → any decompiler (or `--emit asm|ir`)

## Getting started

rekit needs a baseline to run at all: **python3 ≥ 3.8** and **bash** (the dispatcher is
pure stdlib). Vendoring skill runtimes (`rekit install`) additionally needs **npm** (one
skill) and **uv** (seven skills). A fresh analysis box also benefits from `rg`, `git`,
`curl`, `jq`, `file`. These tiers live in [`requirements.json`](requirements.json) —
**distinct from per-skill prerequisites** (which live in `registry.json`).

```bash
bin/rekit setup                   # print install commands for any missing BASE tools (never runs them)
bin/rekit setup --tier all        # base + build + recommended
bin/rekit install                 # vendor runtimes for the skills that need it
bin/rekit doctor                  # confirm what's ready; install BYO tools for the rest
bin/rekit run bin-triage ./unknown.bin
```

`rekit setup` **prints** platform-appropriate install commands (auto-detects macOS/Linux;
on Windows, run them inside WSL2) — it never runs a package manager itself. Pipe it if you
want: `rekit setup --tier all | bash`. See [`docs/PLATFORMS.md`](docs/PLATFORMS.md) for the
tier table and the platform/WSL2 stance.

## Design rules

- **Self-contained.** A skill ships its own tool (bundled to one file where possible).
  No install step at analysis time.
- **Pinned & offline.** Tools are vendored at build time, never fetched mid-analysis —
  this is tooling for hostile inputs.
- **Honest degradation.** Missing prerequisite → the skill reports `missing` with an
  install hint; the caller asks the human or records a coverage blind spot.
- **Safety is declared.** Every skill states whether it executes the input and whether
  it needs network. Most are read-only and offline.
- **Three packaging patterns:** pure-stdlib (no vendored deps), vendored
  `scripts/node_modules` (native ok), vendored `pip --target scripts/site`
  (pure-python). Native-ABI-locked python deps are avoided; such tools go through an
  external CLI instead.

See [`SKILL-CONTRACT.md`](SKILL-CONTRACT.md) for the manifest spec.

## License

Apache-2.0 — see [LICENSE](LICENSE).
