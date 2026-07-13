<p align="center">
  <img src="rekit-logo.png" alt="rekit reverse engineering system" width="360">
</p>

# rekit

rekit is a catalog and dispatcher for reverse-engineering skills that agents,
automation, and analysts can invoke through one CLI or MCP server. It covers static
triage, extraction, decompilation, emulation, dynamic observation, and native artifact
construction.

Every skill has a human-readable `SKILL.md`, an executable runner, and a machine entry
in [`registry.json`](registry.json). The registry declares prerequisites, inputs,
outputs, capabilities, and whether the skill executes its target or uses the network.
Missing tools produce an explicit availability result instead of silently reducing
coverage.

## Quickstart

rekit's dispatcher requires Python 3.8+ and Bash. Clone the repository, inspect the
catalog, then run a pure-stdlib skill:

```bash
git clone https://github.com/batteryshark/rekit.git
cd rekit

bin/rekit list
bin/rekit doctor bin-triage
bin/rekit run bin-triage ./unknown.bin ./out --format json
```

Skills with local Python or Node.js runtimes need a one-time build. The setup command
prints required package-manager commands without running them; `install` builds the
selected runtimes from the committed manifests and lockfile. Native builds that need
an external SDK, such as `dex-dump`, run only when explicitly selected.

```bash
bin/rekit setup --tier all
bin/rekit install              # or: bin/rekit install js-deobfuscate
bin/rekit doctor
```

## How it fits together

| Path | Responsibility |
|---|---|
| [`bin/rekit`](bin/rekit) | Stable CLI entry point |
| [`scripts/rekit.py`](scripts/rekit.py) | Discovery, prerequisite checks, dispatch, setup, and docs sync |
| [`scripts/rekit_mcp.py`](scripts/rekit_mcp.py) | MCP transport over the same CLI execution path |
| [`registry.json`](registry.json) | Machine-readable source of truth for the skill catalog |
| [`skills/`](skills) | One directory per skill, optionally grouped by registry `path`: documentation, runner, and optional payload |
| [`SKILL-CONTRACT.md`](SKILL-CONTRACT.md) | Manifest and packaging contract for contributors |
| [`SERVER-CONTRACT.md`](SERVER-CONTRACT.md) | Storage convention for third-party MCP servers; discovery and hosting are not implemented |

The execution path stays short: `bin/rekit` delegates to `scripts/rekit.py`, the
dispatcher resolves one registry entry, checks its prerequisites and safety gate, then
invokes that skill's runner. The MCP server calls the same path rather than maintaining
a second implementation.

## CLI

| Command | Purpose |
|---|---|
| `bin/rekit list` | List the catalog and declared capabilities |
| `bin/rekit search <query>` | Find skills by name, capability, prerequisite, or description |
| `bin/rekit info <id>` | Show one manifest entry and its `SKILL.md` |
| `bin/rekit doctor [<id>]` | Check host requirements, skill prerequisites, and local payloads |
| `bin/rekit run <id> <args...>` | Run a skill after prerequisite and safety checks |
| `bin/rekit setup [--tier all]` | Print commands for missing host tools; never install them |
| `bin/rekit install [<id>]` | Build optional local runtimes |
| `bin/rekit caps` | Map capabilities to skills |
| `bin/rekit mcp [--allow-dynamic]` | Export one MCP tool per skill |

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
| `protection-survey` | anti-debug/VM, runtime-resolution, executable-memory, early-init, custom-section, inline-asm, flattening, stack-string, and obfuscating-build patterns across native and managed source | python3 |

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
| `native-disassemble` | ELF/PE/Mach-O → assembly listing (objdump; rizin/r2 fallback) | llvm-objdump/objdump/rizin/r2 (BYO) |
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
| `pyscylla` | rebuild a dumped PE's Import Address Table (libscylla adapter) | python3 · BYO libscylla |
| `ord-lookup` | resolve Windows DLL ordinal imports → symbol names | python3 |

**Mobile** (dump from a live device)

| Skill | What | Prereq |
|---|---|---|
| `dex-dump` | dump decrypted DEX from a running Android app | adb (BYO device) |
| `frida-android-instrument` ⚡ | enumerate Java classes/methods or observe method calls in an Android app | frida-tools + BYO device |
| `ios-dump` | dump a decrypted iOS app binary (FairPlay) from a jailbroken device | frida (BYO device) |

**Dynamic** ⚡ (run the target to observe behavior; consent-gated via `rekit run --allow-dynamic`)

| Skill | What | Prereq |
|---|---|---|
| `exec-observe` | run target, capture exit/stdout/stderr/files-created/timing | python3 |
| `emulate-code` | contained: run raw shellcode/blob on a virtual CPU (no OS) | unicorn · python3 |
| `emulation-session` | contained: persistent stepping, registers, memory, hooks, traces, and snapshots across calls | unicorn/qiling · python3 |
| `qiling-emulate` | contained: emulate a FULL binary (PE/ELF/Mach-O) w/ emulated OS syscalls | qiling + BYO rootfs · python3 |
| `syscall-trace` ⚡ | kernel-syscall trace (strace/dtruss) → histogram + files/net/exec | strace/dtruss (BYO) · python3 |
| `net-capture` ⚡ | run target + sniff wire (tcpdump) → talkers/DNS + pcap | tcpdump (BYO, root) · python3 |
| `frida-trace` ⚡ | Frida-hook network/exec/file/crypto API calls | frida-trace (BYO) · python3 |
| `frida-api-trace` ⚡ | signature-aware Frida tracing from a local, gitignored API Monitor XML tree | frida-tools + BYO definitions · python3 |

**Construct** 🔨 (produce an artifact; never run it)

| Skill | What | Prereq |
|---|---|---|
| `cc-build` | compile C/C++/ObjC → native (exe/.o/.s/IR), cross-compile | clang/cc/gcc (BYO) · python3 |
| `asm-assemble` | assemble asm → bytes (hex/C-array/raw) — x64/x86/arm64/arm | clang/LLVM (BYO) · python3 |
| `shellcode-stub` | wrap raw shellcode → runnable native PoC (`--os posix` mmap/mprotect \| `--os windows` VirtualAlloc+ExitProcess) | clang (BYO) · python3 |
| `minimal-executable` | emit deterministic no-runtime ELF/PE or static arm64 Mach-O research artifacts with structural proof | python3 |

**Workflow** (not RE — a harness convenience)

| Skill | What | Prereq |
|---|---|---|
| `gitops` | drive git through plain verbs (clone/commit/branch/stash/push/worktree/…) for harnesses that don't grok git | git |

### Chains

- **Electron:** `unpack` (zip → asar) → `js-deobfuscate` / `js-sourcemap-extract` → `js-covert-scan`
- **Python:** `pyinstaller-extract` → `pyc-decompile` → `py-covert-scan`
- **Binary:** `bin-triage` → `pe`/`elf`/`macho`/`dotnet-analyze` → the matching decompiler
- **Construct → analyze:** `asm-assemble` → `shellcode-stub` → `exec-observe` (native) or `qiling-emulate` (cross-arch/cross-OS); `cc-build` → any decompiler (or `--emit asm|ir`)
- **Protection research:** `protection-survey` → inspect flagged sites → build a controlled fixture with `cc-build` or `minimal-executable` → analyze the artifact
- **Windows API behavior:** `frida-trace` for quick globs; `frida-api-trace` when local signatures and typed arguments matter
- **Android runtime discovery:** `jvm-decompile` → `frida-android-instrument` for loaded classes/method calls → `dex-dump` when runtime-loaded DEX is absent on disk

## Requirements and runtimes

[`requirements.json`](requirements.json) separates rekit's host requirements from the
prerequisites declared by individual skills:

- **Base:** Python 3.8+ and Bash, required by the dispatcher.
- **Build:** npm and uv, used by `bin/rekit install` to create optional local runtimes.
- **Recommended:** command-line tools useful on an analysis workstation.
- **Per skill:** tools such as YARA, Ghidra, jadx, or radare2, checked only when relevant.

Generated `scripts/site/` and `scripts/node_modules/` trees are local and ignored by
Git. Their direct dependencies are versioned in requirements files or `package-lock.json`.
After installation, runners use those local copies and do not fetch packages while
analyzing a target. See [`docs/PLATFORMS.md`](docs/PLATFORMS.md) for platform support and
the full tier table.

## Safety model

Each registry entry declares `executes_input`, network behavior, and a safety tier.

- Static skills read or transform input without executing it.
- Contained skills run narrow code or whole binaries inside an emulator or sandbox.
- Dynamic skills execute the target on the host or a connected device. Host execution
  requires `--allow-dynamic`; that flag records consent but does not create a sandbox.
- Construct skills produce artifacts and do not run what they build.

Run dynamic skills only in an environment whose isolation and network policy match the
target's risk. Missing prerequisites remain visible in `doctor` and MCP tool metadata.

## License

Apache-2.0 — see [LICENSE](LICENSE).
