---
name: ios-dump
description: "Dump a decrypted iOS app binary (FairPlay 砸壳) from a jailbroken device via frida-ios-dump: attaches to the running app with Frida and writes the decrypted Mach-O from memory so it can be loaded into IDA/Ghidra/Hopper. BYO the frida-ios-dump toolchain + a jailbroken device with frida-server. Does NOT execute a sample on the host — attaches to an app the operator already launched on a connected device."
---

# ios-dump — iOS App Decryptor (砸壳)

Dump a decrypted iOS application binary from a jailbroken device using
`frida-ios-dump`. App Store binaries are FairPlay-encrypted; this attaches to the
running app with Frida and writes the decrypted Mach-O from memory so it can be
loaded into IDA/Ghidra/Hopper.

**Does not execute a sample on the host.** Invasive only on the connected device.

## Prerequisites

- `frida` / `frida-tools` on the host (prereq-gated on `frida-ps`). The host frida
  major version **must match** the on-device `frida-server`.
- A **jailbroken** iOS device with `frida-server` running and **SSH access**.
- The **frida-ios-dump** toolchain, cloned and built (BYO — like ilspycmd for
  dotnet-decompile):
  ```bash
  git clone https://github.com/AloneMonkey/frida-ios-dump
  cd frida-ios-dump
  pip3 install -r requirements.txt
  npm install --ignore-scripts
  npx frida-compile dump.ts -o dist/dump.js   # required before dump.py runs
  ```
  Point the runner at it via `--dump-tool PATH` or the `FRIDA_IOS_DUMP` env var.

## Usage

```bash
# dump a known bundle id (USB-connected device)
rekit run ios-dump app.ish.iSH ./out

# auto-detect a running app
rekit run ios-dump auto ./out

# network-connected device
rekit run ios-dump app.ish.iSH ./out --host 192.168.1.100 --user mobile --password alpine
```

Keep the target app in the foreground during the dump. Result is a single JSON
object on stdout: `{ok, bundleId, ipa, outputDir, decrypted}`.

## Verify decryption

```bash
unzip -o <app>.ipa -d dumped/
otool -l dumped/Payload/<App>.app/<Binary> | grep -A4 LC_ENCRYPTION_INFO
# cryptid 0  -> successfully decrypted
```

## Notes

- Apps with jailbreak detection may terminate before the dump completes — bypass
  jailbreak detection first.
- For apps with multiple frameworks, frida-ios-dump dumps all encrypted frameworks.
- Pair with the Mach-O analyzers, class-dump, and string analysis on the decrypted
  binary.
