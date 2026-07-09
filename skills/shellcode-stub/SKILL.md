---
name: shellcode-stub
description: "CONSTRUCT: wrap a raw shellcode blob into a runnable native PoC — a tiny C loader compiled with clang, whose exit code is the shellcode's return value. --os picks the loader: posix (mmap RW → memcpy → mprotect RX → call, default) or windows (VirtualAlloc RWX → memcpy → call → ExitProcess). --emit c dumps just the loader source. The last link in the write chain: asm-assemble → shellcode-stub → exec-observe (native) or qiling-emulate (cross-arch/cross-OS). Builds the exe; does NOT run it."
---

# Shellcode Stub Wrapper

**🔨 Construct tier — builds a runnable PoC around shellcode; does not run it.**

## Why this exists

Closes the write-side chain. `asm-assemble` makes bytes; `shellcode-stub` turns those
bytes into a **native executable** you can actually detonate or emulate:

```
asm-assemble ──→ sc.bin ──→ shellcode-stub ──→ poc ──→ exec-observe (native, ⚡ consent)
                                                    └──→ qiling-emulate (cross-arch/OS, contained)
```

## What it does

Drops the shellcode into a tiny C loader and compiles it with clang. **The loader's exit
code is the shellcode's return value**, so a `mov w0, #42; ret` PoC exits `42` — trivial
to assert.

Two loader templates, picked by `--os`:

| `--os` | loader | OS | default target |
|---|---|---|---|
| `posix` (default) | `mmap` RW → `memcpy` → `mprotect` RX → call as `int(void)` | Linux / macOS | host |
| `windows` | `VirtualAlloc` RWX → `memcpy` → call as `int(void)` → `ExitProcess(r)` | Windows PE | `x86_64-w64-mingw32` |

- `--emit exe` (default) — the compiled PoC (needs clang).
- `--emit c` — just the loader source, to inspect/tweak or hand to `cc-build`. Needs no
  compiler at all — works even when the toolchain for the target OS isn't installed.
- `--arch` / `--target` — build a stub for **another** arch, to run under
  `qiling-emulate`. Native host-arch is the guaranteed path; a cross-**OS** `--target`
  needs a cross sysroot/toolchain — pass it via `--cflags "--sysroot=… -fuse-ld=lld"`,
  else the link fails honestly.
- Input from a `.bin` file or `--hex "48c7c0…"`.

## Safety

`executes_input: no` — it BUILDS the exe, never runs it. Running the result is the
dynamic tier's job (`exec-observe`, consent-gated) or a contained emulator
(`qiling-emulate`).

## Usage — the full loop (POSIX)

```bash
rekit run asm-assemble --arch arm64 --code "mov w0, #42; ret" --out sc.bin
rekit run shellcode-stub sc.bin --out poc
./poc; echo $?          # → 42   (or: rekit run --allow-dynamic exec-observe ./poc)

rekit run shellcode-stub --hex "48c7c0370100... " --emit c --out loader.c   # inspect first
```

## Cross-OS — Windows PoCs

The Windows loader lets you build a `.exe` on a non-Windows box and then detonate it
**contained** under Qiling with a Windows rootfs (no Windows host required):

```bash
rekit run asm-assemble --arch x64 --code "mov eax, 42; ret" --out sc.bin
rekit run shellcode-stub sc.bin --os windows --out poc.exe
rekit run qiling-emulate poc.exe --rootfs ./rootfs/x8664_windows    # contained cross-OS
```

⚠️ **Honest failure mode.** Building a Windows PE needs the **mingw-w64** headers + sysroot,
which are NOT shipped with clang on macOS/Linux. Without them, the link fails cleanly
(e.g. `'windows.h' file not found`) and the runner prints the install hint:

```
→ brew install mingw-w64                       # macOS
→ apt install gcc-mingw-w64-x86-64             # Debian/Ubuntu
# then point the build at the toolchain sysroot:
   --cflags "--sysroot=/opt/homebrew/Cellar/mingw-w64/<ver>/toolchain-x86_64/x86_64-w64-mingw32 -fuse-ld=lld"
```

`--emit c --os windows` works **without any compiler** — it just emits the loader source
for inspection or hand-off to `cc-build` on a Windows/mingw host.
