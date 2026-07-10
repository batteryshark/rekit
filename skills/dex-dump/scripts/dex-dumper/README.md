# rekit dex-dumper source

This is rekit's clean-room, dependency-free Android memory scanner. The source is
licensed under the repository's Apache-2.0 license. It does not incorporate or
depend on panda-dex-dumper code or binaries.

## Clean-room provenance and license

This implementation was designed solely from rekit's documented behavioral
requirements and independently known DEX/CompactDex and Linux/Android interface
contracts. During its development, the pre-existing unlicensed payload and its
upstream source were not inspected, executed, decompiled, fetched, copied, or
otherwise used. All source in this directory and the binary produced from it are
original rekit work distributed under the repository's Apache License 2.0.

The device binary attaches to a positive PID with `ptrace`, reads the target's
readable `/proc/PID/maps` ranges with `process_vm_readv`, recognizes supported
DEX and CompactDex magic, validates header and section bounds, and writes unique
images using SHA-256 content identities and an atomic no-overwrite publication
step. The target remains stopped while its memory is read and is detached on all
normal and error paths.

## Host tests

Requirements: stable Rust 1.74 or newer. No Android SDK or third-party crates are
needed.

```sh
cargo test --manifest-path skills/dex-dump/scripts/dex-dumper/Cargo.toml
```

The host tests cover magic scanning, DEX/CompactDex header validation, bounds and
overflow rejection, Linux maps parsing, CLI validation, and SHA-256 vectors. A
host binary is intentionally unable to attach to macOS or Windows processes.

## Android aarch64 build

Requirements:

- stable Rust with `rustup target add aarch64-linux-android`
- Android NDK r25 or newer
- `ANDROID_NDK_HOME` set to the NDK root
- optional `ANDROID_API` (defaults to 24)

```sh
ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.2.12479018" \
  skills/dex-dump/scripts/build.sh
```

The script builds a release binary and installs it at
`skills/dex-dump/bin/dex-dumper`. Run it on a rooted aarch64 Android device:

```sh
dex-dumper -p 1234 -o /data/local/tmp/rekit-dex-dump
```
