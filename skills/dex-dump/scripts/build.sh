#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 rekit contributors
# Reproducibly build the aarch64 Android device tool from the locked Rust crate.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SKILL_DIR=$(dirname -- "$SCRIPT_DIR")
CRATE_DIR="$SCRIPT_DIR/dex-dumper"
TARGET=aarch64-linux-android
ANDROID_API=${ANDROID_API:-24}

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
    echo "error: set ANDROID_NDK_HOME to an Android NDK installation" >&2
    exit 2
fi
NDK=${ANDROID_NDK_HOME:-$ANDROID_NDK_ROOT}

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)
        PREBUILT_CANDIDATES="darwin-aarch64 darwin-x86_64"
        ;;
    Darwin-*)
        PREBUILT_CANDIDATES="darwin-x86_64"
        ;;
    Linux-aarch64)
        PREBUILT_CANDIDATES="linux-aarch64 linux-x86_64"
        ;;
    Linux-*)
        PREBUILT_CANDIDATES="linux-x86_64"
        ;;
    *)
        echo "error: unsupported build host: $(uname -s)-$(uname -m)" >&2
        exit 2
        ;;
esac

TOOLCHAIN=
for candidate in $PREBUILT_CANDIDATES; do
    path="$NDK/toolchains/llvm/prebuilt/$candidate"
    if [ -d "$path" ]; then
        TOOLCHAIN=$path
        break
    fi
done
if [ -z "$TOOLCHAIN" ]; then
    echo "error: no compatible LLVM toolchain under $NDK/toolchains/llvm/prebuilt" >&2
    exit 2
fi

LINKER="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang"
if [ ! -x "$LINKER" ]; then
    echo "error: Android API $ANDROID_API linker not found: $LINKER" >&2
    exit 2
fi

TARGET_LIBDIR=$(rustc --print target-libdir --target "$TARGET")
if [ ! -d "$TARGET_LIBDIR" ]; then
    echo "error: Rust target $TARGET is not installed" >&2
    echo "install it with: rustup target add $TARGET" >&2
    exit 2
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$LINKER
cargo build --locked --release --target "$TARGET" --manifest-path "$CRATE_DIR/Cargo.toml"

mkdir -p "$SKILL_DIR/bin"
cp "$CRATE_DIR/target/$TARGET/release/dex-dumper" "$SKILL_DIR/bin/dex-dumper"
chmod 755 "$SKILL_DIR/bin/dex-dumper"
echo "built $SKILL_DIR/bin/dex-dumper"
