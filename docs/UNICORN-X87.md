# Unicorn x87 capability on macOS ARM64

## Reproducer and root cause

`scripts/unicorn_x87_probe.py` runs x87 execution and x87-register access in separate
child processes. A host signal therefore becomes a structured `tooling-capability`
failure rather than terminating Rekit. `tests/reproducers/unicorn_x87_sigill.c` is the
minimal binding-free form used to establish ownership in Unicorn core.

On the affected lane, `uc_open(UC_ARCH_X86, UC_MODE_32)` succeeds. The first operation
that completes Unicorn's engine initialization then fails:

| probe | exact failing operation | result |
|---|---|---|
| x87 execution | `uc_mem_map(code)` | host `SIGILL` |
| x87 register access | `uc_reg_write(FPCW)` | host `SIGILL` |

Both paths enter Unicorn's `init_cache_info`. Unicorn 2.1.4 first calls
`sysctlbyname("hw.cachelinesize")`; if policy denies that query, its generic AArch64
fallback executes `mrs CTR_EL0`. macOS does not permit that fallback instruction in
this context and raises `SIGILL`. The illegal instruction was located at
`init_cache_info+0x3c` (dylib offset `0xec84`). The same logic remains in upstream
master commit `7c5db94191defc1e04a4f66f4eb1220903cba837`.

Primary upstream source:

- [Unicorn 2.1.4 cache discovery](https://github.com/unicorn-engine/unicorn/blob/2.1.4/qemu/util/cacheinfo.c)
- [Unicorn 2.1.4 release](https://github.com/unicorn-engine/unicorn/releases/tag/2.1.4)

This is not an x87 semantic mismatch, a Python/Rust/C binding defect, a compiler CPU
baseline issue, or Rekit register initialization. The C reproducer fails without a
binding, both the published wheel and local source build contain the same fallback,
and both execute x87 correctly when the sysctl is available.

The minimal upstream-core repair was also verified against the 2.1.4 tag commit
`8028ec436f2d9376525352dd38ed9ed6b9f6be10`:

```diff
-#if defined(__aarch64__)
+#if defined(__aarch64__) && !defined(__APPLE__)
```

This prevents macOS from entering the Linux-oriented `CTR_EL0` fallback and lets
Unicorn's existing conservative cache-line fallback run when the sysctl is denied.
An ARM64 release build made with Apple clang 21.0.0 passed `uc_mem_map`, `FPCW`
access, and `FLD1` execution under the restrictive policy (test dylib SHA-256
`fc2fc87ff646193308eee7c9ce4829def2fde5ed7db51ce37669d174fd95697d`). Rekit does
not silently replace its pinned upstream library with an unpublished local fork;
until that change is accepted upstream and released, the explicit Rosetta lane is
the packaged fallback.

## Qualified environment

| item | value |
|---|---|
| host | Apple Silicon ARM64 (`Darwin 25.5.0`) |
| macOS | 26.5.1 (25F80) |
| native Python | Homebrew 3.14.6, ARM64 |
| Unicorn | 2.1.4 Python binding and C core |
| published ARM64 dylib | SHA-256 `7207c8e3d7a63118fb0bca73e01816797fd51b1d8a39a4cbc7abfd562ee59c85`; wheel tag `cp37-abi3-macosx_11_0_arm64`; setuptools 75.3.2 |
| local ARM64 dylib | SHA-256 `85bc37a56b96d2de60586416d8f9d84f29475b37156641ecbbe6636d6b40ed96`; source-built with Apple clang 21.0.0, CMake 4.3.2, macOS 26.5 SDK |
| Rosetta dylib | Unicorn 2.1.4 x86_64, SHA-256 `51c4a6f3ce22628ecd3acd1c49b921a818ffb989ca2c473134cc7eb06094f256` |
| Rekit revision investigated | `31a68cdf7ae2292af348fa045d4c5815ba42da6c` (`agent/joern-slice`) |

Native ARM64 and Rosetta x86_64 are reported separately. Running native ARM64 outside
the restrictive policy passed `FLD1`, `FNOP`, `FPCW`, `FPSW`, `FPTAG`, and 80-bit
`FP0` reads/writes. Under the restrictive policy, the native cache probe fails before
guest execution. The Rosetta x86_64 lane passes both x87 capability probes under the
same policy.

## Rekit behavior

`rekit doctor emulate-code` and `rekit doctor emulation-session` report x87 execution
and x87-register access as separate prerequisites. Each run selects a backend only
after both probes pass:

1. Prefer the installed native Unicorn runtime.
2. On Apple Silicon, retry the pinned x86_64 runtime under Rosetta.
3. If neither passes, return `errorType: tooling-capability`; never run the target and
   never represent the result as a corpus or differential mismatch.

Machine-readable emulation results include the backend, Unicorn version, host and
process architectures, native/Rosetta mode, library path, and library SHA-256. The
Rosetta payload is installed only during `rekit install`; Rekit never downloads it at
analysis time. If Rosetta is not installed, the build reports that fact and doctor
requires the native capability to pass.
