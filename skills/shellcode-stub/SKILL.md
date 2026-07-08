# Shellcode Stub Wrapper

**🔨 Construct tier — builds a runnable PoC around shellcode; does not run it.**

## Why this exists

Closes the write-side chain. `asm-assemble` makes bytes; `shellcode-stub` turns those
bytes into a **native executable** you can actually detonate or emulate:

```
asm-assemble ──→ sc.bin ──→ shellcode-stub ──→ poc ──→ exec-observe (native, ⚡ consent)
                                                    └──→ qiling-emulate (cross-arch, contained)
```

## What it does

Drops the shellcode into a tiny C loader — `mmap` RW → `memcpy` → `mprotect` RX →
call as `int(void)` — and compiles it with clang. **The loader's exit code is the
shellcode's return value**, so a `mov w0, #42; ret` PoC exits `42` — trivial to assert.

- `--emit exe` (default) — the compiled PoC (needs clang).
- `--emit c` — just the loader source, to inspect/tweak or hand to `cc-build`.
- `--arch` / `--target` — build a stub for **another** arch, to run under
  `qiling-emulate`. Native host-arch is the guaranteed path; a cross-**OS** `--target`
  needs a cross sysroot/toolchain — pass it via `--cflags "--sysroot=… -fuse-ld=lld"`,
  else the link fails honestly.
- Input from a `.bin` file or `--hex "48c7c0…"`.

## Safety

`executes_input: no` — it BUILDS the exe, never runs it. Running the result is the
dynamic tier's job (`exec-observe`, consent-gated) or a contained emulator
(`qiling-emulate`). POSIX loader (Linux/macOS).

## Usage — the full loop

```bash
rekit run asm-assemble --arch arm64 --code "mov w0, #42; ret" --out sc.bin
rekit run shellcode-stub sc.bin --out poc
./poc; echo $?          # → 42   (or: rekit run --allow-dynamic exec-observe ./poc)

rekit run shellcode-stub --hex "48c7c0370100... " --emit c --out loader.c   # inspect first
```
