---
name: native-lift
description: "Lift a bounded raw x86, amd64, or aarch64 machine-code region into LLVM IR or bitcode with pinned Remill. Use for semantic analysis of an isolated function, shellcode, or decoder stub. Static and offline: never executes the bytes; rejects whole executable containers."
---

# Native Code Lifter

Lift one bounded raw machine-code region into LLVM IR or bitcode using Remill. This
adds an instruction-semantics representation between Rekit's assembly listing and its
decompilation or emulation tools.

## When to use

Use `native-lift` for an extracted function, decoder stub, shellcode region, or a
small compiler-output fixture when you want explicit register and memory semantics.
The skill accepts at most 64 KiB and requires the architecture and virtual address.

Do not pass an ELF, PE, or Mach-O file. Remill's example trace lifter does not recover
a whole program, its loader, imports, or complete interprocedural control flow. Use
`native-disassemble`, `native-decompile`, or `ghidra-decompile` for complete native
containers. A future Anvill or McSema integration would be a separate capability.

## Install

The pinned Remill and LLVM runtime is intentionally not built on the analysis host.
Install the published multi-platform image explicitly:

```bash
rekit install native-lift
rekit doctor native-lift
```

Installation pulls the immutable image and therefore uses the network. Analysis never
pulls or builds an image; it fails clearly when Docker, the daemon, the expected image,
or the runtime health check is unavailable.

## Usage

```bash
rekit run native-lift ./function.bin ./out --arch amd64 --address 0x401000
rekit run native-lift ./stub.bin ./out --arch aarch64 --emit both --format json
```

Inputs are `x86`, `amd64`, or `aarch64`; representative OS choices are `linux`,
`macos`, `windows`, and `solaris`. The entry address defaults to the base address and
must point inside the supplied region. The default timeout is 300 seconds and may be
set from 1 through 3600 seconds.

Outputs are written atomically as `lifted.ll`, `lifted.bc`, or both. The JSON result
records the input digest, addresses, target, immutable image reference, runtime
identity, and artifact paths.

## Safety and reproducibility

The target bytes are copied into a temporary read-only mount. The pinned image runs
without networking, Linux capabilities, privilege escalation, or a writable root
filesystem, and with CPU, memory, process, wall-clock, and temporary-storage bounds.
Only the temporary output mount is writable. Remill translates the bytes but never
executes or emulates them.

## Offline use and troubleshooting

After one successful `rekit install native-lift`, disconnect the host or deny Docker
networking and repeat the same `rekit run` command. The analysis container always uses
`--network none`; no registry request occurs during a run.

`rekit doctor native-lift` reports the failed layer explicitly:

- **Docker is not installed**: install Docker Engine or Docker Desktop.
- **Docker daemon is unavailable**: start Docker and rerun doctor.
- **Unsupported Docker platform**: use a `linux/amd64` or `linux/arm64` daemon.
- **Immutable image is missing**: run `rekit install native-lift` while online.
- **Image health check failed**: remove the damaged local copy, reinstall the pinned
  digest, and rerun doctor.

Runtime updates are deliberate rather than automatic. Rekit records the Remill commit,
LLVM package revision, base-image digest, installer checksum, platform manifest digest,
provenance, and SBOM for each published image; the update procedure lives in
`containers/native-lift/README.md`.
