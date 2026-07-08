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
| `exec-observe` ⚡ | DYNAMIC: run target, capture exit/stdout/stderr/files | pure stdlib · python3 |
| `emulate-code` | contained: run raw shellcode/blob on a virtual CPU (no OS) | `uv pip --target` (unicorn) · python3 |
| `qiling-emulate` | contained: emulate a FULL binary (PE/ELF/Mach-O) w/ emulated OS syscalls | `uv pip --target` (qiling) + BYO rootfs · python3 |
| `syscall-trace` ⚡ | DYNAMIC: kernel-syscall trace (strace/dtruss) → histogram + files/net/exec | strace/dtruss (BYO) · python3 |
| `net-capture` ⚡ | DYNAMIC: run target + sniff wire (tcpdump) → talkers/DNS + pcap | tcpdump (BYO, root) · python3 |
| `frida-trace` ⚡ | DYNAMIC: Frida-hook network/exec/file/crypto API calls | frida-trace (BYO) · python3 |
| `cc-build` 🔨 | CONSTRUCT: compile C/C++/ObjC → native (exe/.o/.s/IR), cross-compile | clang/cc/gcc (BYO) · python3 |
| `asm-assemble` 🔨 | CONSTRUCT: assemble asm → bytes (hex/C-array/raw) — x64/x86/arm64/arm | clang/LLVM (BYO) · python3 |

**29 skills**, two axes. **`kind`** = *what it does to the world*: **analyze** (read a
target — 27) vs **construct** 🔨 (produce an artifact — 2: `cc-build`, `asm-assemble`).
**`safety.executes_input`** = *does it run the target*: 21 **static** (read-only) + 2
**contained** (`emulate-code` = Unicorn raw bytes/no OS; `qiling-emulate` = Qiling full
binary w/ emulated OS syscalls vs a BYO rootfs — both run on an emulated CPU not the
host, *not* consent-gated) + 4 **dynamic** ⚡ (`exec-observe`, `syscall-trace`,
`net-capture`, `frida-trace` — execute the target natively, consent-gated) + the 2
construct skills (`executes_input: no` — they build, never run the result). Source
detection + binary triage + extraction + decompilers (`native-decompile` = rizin's
Ghidra decompiler, no JVM; `ghidra-decompile` = full Ghidra headless) + `yara-scan`
signatures + `ioc-extract` reporting + **packaging** + **dynamic tier** (consent-gated
`rekit run --allow-dynamic`, ⚡ in `list`; isolation an optional axis, native
first-class) + **construct tier** (🔨, build PoCs/shellcode/stubs).

The **emulation/execution family** is a three-rung ladder: `emulate-code` (no OS) →
`qiling-emulate` (emulated OS, contained, cross-arch/cross-OS) → `exec-observe`/tracers
(native host execution, consent-gated). The **construct → analyze loops** close it:
`asm-assemble → emulate-code` (write shellcode, run it contained) and `cc-build → any
decompiler / --emit asm|ir` (build a PoC, inspect the codegen).

Dispatcher commands: `list · search · doctor · info · run · install · caps`.
**`rekit search <query>`** (keyword/capability, `--dynamic|--static|--tier|--capability`,
`--json`) is the find-a-skill entry point as the roster grows toward hundreds.
**~22 run out of the box** (host-dependent — construct skills need clang); BYO-tool
skills (jadx/ilspycmd/rizin/binwalk/ghidra/yara + tracers
strace-or-dtruss/tcpdump/frida-trace) degrade honestly via the prereq gate.

> **Packaging note:** `asm-assemble` is clang/LLVM-backed, *not* keystone —
> `keystone-engine` ships no arm64-macOS wheel (the same native-packaging trap as
> py7zr). The LLVM assembler `cc-build` already uses covers x64/x86/arm64/arm and
> works wherever clang does.
**Chains verified end-to-end:** Electron (unpack→asar→js-deobfuscate/sourcemap→
js-covert-scan) and Python (pyinstaller-extract→pyc-decompile→py-covert-scan).

## Queued — remaining

Static tier is feature-complete (21). Dynamic tier built: kernel view
(`syscall-trace`), API/library view (`frida-trace`), network view (`net-capture`),
plus contained `emulate-code` (Unicorn) and plain `exec-observe`. Behavioral coverage
now spans kernel + library + network. Remaining dynamic ideas as needed:
debugger-driven trace (gdb/x64dbg), memory-dump/runtime-YARA, headless-browser
detonation for web payloads. New skills drop into `skills/<id>/` per
`SKILL-CONTRACT.md`.

## Later

Wire skills into `unmask-re` as providers (atoms/artifacts → skill → rescan) — deferred:
the `unmask` scanner is being rebuilt natively in parallel, so integrating now would
collide. Capabilities first.
