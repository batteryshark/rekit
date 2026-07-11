#!/usr/bin/env bash
# Vendor both emulation backends into scripts/site. Native wheels make the resulting
# tree platform-specific; rebuild it after copying the skill to another platform.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"
PYTHON="$(command -v python3)"
rm -rf "$RT/site"
echo "vendoring Unicorn, Capstone, and Qiling into scripts/site..."
if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  # Unicorn's published 2.1.x macOS arm64 wheel can terminate with SIGILL when
  # emulation starts on some Apple Silicon hosts. A local source build uses the
  # current machine baseline and avoids that wheel-specific failure.
  uv pip install --python "$PYTHON" --target "$RT/site" --no-binary unicorn -r "$RT/requirements.txt" -q

  # keystone-engine 0.9.2 publishes Python bindings but no Apple Silicon
  # dynamic library. Qiling imports Keystone for architecture setup, so build
  # the pinned upstream core locally and place only the generated dylib beside
  # those bindings. The source tree and build products stay in a temp dir.
  command -v git >/dev/null || { echo "git is required to build Keystone on macOS arm64" >&2; exit 3; }
  command -v cmake >/dev/null || { echo "cmake is required to build Keystone on macOS arm64" >&2; exit 3; }
  KS_COMMIT="dc7932ef2b2c4a793836caec6ecab485005139d6"
  KS_TMP="$(mktemp -d)"
  trap 'rm -rf "$KS_TMP"' EXIT
  git clone --quiet --depth 1 --branch 0.9.2 \
    https://github.com/keystone-engine/keystone.git "$KS_TMP/src"
  if [[ "$(git -C "$KS_TMP/src" rev-parse HEAD)" != "$KS_COMMIT" ]]; then
    echo "Keystone tag 0.9.2 did not resolve to the pinned commit" >&2
    exit 3
  fi
  sed -i.bak 's/cmake_policy(SET CMP0051 OLD)/cmake_policy(SET CMP0051 NEW)/' \
    "$KS_TMP/src/CMakeLists.txt" "$KS_TMP/src/llvm/CMakeLists.txt"
  KS_LOG="$KS_TMP/keystone-build.log"
  if ! cmake -S "$KS_TMP/src" -B "$KS_TMP/build" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_LIBS_ONLY=ON \
    -DLLVM_TARGETS_TO_BUILD='AArch64;ARM;Mips;PowerPC;Sparc;SystemZ;X86' \
    >"$KS_LOG" 2>&1; then
    tail -80 "$KS_LOG" >&2
    exit 3
  fi
  if ! cmake --build "$KS_TMP/build" --target keystone -j 8 >>"$KS_LOG" 2>&1; then
    tail -80 "$KS_LOG" >&2
    exit 3
  fi
  cp "$KS_TMP/build/llvm/lib/libkeystone.dylib" "$RT/site/keystone/libkeystone.dylib"
else
  uv pip install --python "$PYTHON" --target "$RT/site" -r "$RT/requirements.txt" -q
fi
echo "done: scripts/site ($(du -sh "$RT/site" | cut -f1))"
echo "note: Qiling sessions still need a matching BYO rootfs"
