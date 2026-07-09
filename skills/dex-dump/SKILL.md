---
name: dex-dump
description: "Dump decrypted DEX files from a RUNNING Android app's memory via the vendored panda-dex-dumper (ptrace attach on a rooted device). Defeats class-loading packers: the real DEX only exists in memory after the packer decrypts it, so this reads it live. Does NOT execute a sample on the host — attaches to an app the operator already launched on a connected device. BYO rooted device + adb."
---

# dex-dump — Android DEX Dumper

Dump decrypted DEX files from a **running** Android app's memory using the vendored
`panda-dex-dumper` (ptrace attach on a rooted device).

## What it does

Android packers that encrypt/load DEX at runtime only materialize the *real* DEX in
memory after their class loader decrypts it — so the on-disk APK holds an encrypted
stub, not the real code. This skill pushes a device-side dumper, ptrace-attaches to
the already-running app, and reads the decrypted DEX out of memory.

**Does not execute a sample on the host.** Invasive only on the connected device.

## Prerequisites

- `adb` on PATH (Android Platform Tools).
- A **rooted** Android device connected via USB (panda-dex-dumper uses `ptrace`;
  `adb root` or `su` is needed).
- The target app must be **running and past its splash screen** — the packer must
  have decrypted the real DEX. Launch the app and navigate past any splash/loader
  before running.

## Usage

```bash
# explicit package
rekit run dex-dump com.example.app ./out

# auto-detect the foreground app
rekit run dex-dump auto ./out

# specific device serial (multiple devices connected)
rekit run dex-dump com.example.app ./out --device 1234567890abcdef
```

Result is a single JSON object on stdout: `{ok, package, pid, dexFiles, fileCount,
outputDir}`. Multiple DEX files are normal for packed apps — pull all of them.

## Notes

- `--keep-tool` leaves `panda-dex-dumper` on the device (default cleans up both the
  tool and the dumped files after pulling).
- If `pidof` returns empty, the runner tries to launch the app via `monkey`.
- Pair the pulled DEX with your Android decompiler (jadx / dex2jar) and any class
  deobfuscation step.
