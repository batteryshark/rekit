# Binary Emulator (Qiling)

**Contained tier — the binary runs on Qiling's *emulated* OS, not the host.** Like
`emulate-code`, it is *not* behind the `--allow-dynamic` gate.

## When to use — and why it's different from the others

The emulation/execution family now has three rungs:

| Skill | What runs the code | OS | Consent |
|---|---|---|---|
| `emulate-code` | Unicorn — raw bytes on a virtual CPU | **none** (memory only) | contained, no gate |
| **`qiling-emulate`** | **Qiling — a full binary, OS syscalls emulated** | **emulated (BYO rootfs)** | contained, no gate |
| `exec-observe` / tracers | the **host** runs it natively | real host OS | ⚡ consent-gated |

Reach for `qiling-emulate` when you have a **whole binary** (not just shellcode) that you
want to detonate **without native execution and without a VM** — including **cross-arch /
cross-OS** targets (run a Windows PE or an ARM ELF on your x86 macOS box). Qiling
implements the syscalls itself, so they hit the emulator, not your kernel.

## What it does

Loads the target with Qiling against a rootfs, runs it under a wall-clock timeout
(`emu_stop` watchdog), and reports the outcome (`completed` / `timeout` / `error`),
detected arch, a best-effort syscall histogram, and the raw Qiling log tail (syscall/API
traces — the format varies by version, so the raw tail is always returned too).

## Prerequisites

- **Qiling** (vendored): `rekit install qiling-emulate` → `scripts/build.sh` vendors it
  into `runtime/site`. Heavier than Unicorn (pulls capstone/keystone/pefile/…).
- **A rootfs** (BYO): grab one matching the target's OS/arch from
  [qilingframework/rootfs](https://github.com/qilingframework/rootfs). Its libraries/DLLs
  back the emulation. Without `--rootfs` the runner refuses with that hint (exit 3).

## Safety note

Contained **by default**: file/network effects are emulated against the rootfs. Qiling
*can* be configured for syscall/network passthrough — that widens the blast radius and is
the operator's explicit choice, not what this skill does out of the box.

## Usage

```bash
rekit install qiling-emulate                       # one-time: vendor Qiling
rekit run qiling-emulate ./sample.exe --rootfs ./rootfs/x8664_windows
rekit run qiling-emulate ./malware.elf --rootfs ./rootfs/x8664_linux --format json
```

Feed shellcode carved by `bin-triage` or a full sample; pair the recovered syscalls/IOCs
with `ioc-extract`.
