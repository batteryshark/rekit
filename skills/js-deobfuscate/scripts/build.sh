#!/usr/bin/env bash
# Build the local webcrack runtime under scripts/node_modules.
#
# Why node_modules and not a single .js: webcrack depends on isolated-vm, a NATIVE
# addon (it runs the obfuscated string-array decoder inside a secure isolated VM).
# Native .node addons can't be inlined by a JS bundler, so a "single file" bundle
# can't find its native build. isolated-vm ships PREBUILT binaries for
# darwin-arm64/x64, linux-x64/arm64 (glibc+musl) and win32-x64, so this vendored
# tree is portable across the common platforms with no compiler. The user's RUN-time
# prerequisite stays just `node`.
#
# Build-time only (needs npm + network). With no override, npm installs the exact
# dependency graph in package-lock.json. Set WEBCRACK_VERSION to update and re-pin.
#
#   WEBCRACK_VERSION=2.16.0 scripts/build.sh
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"
cd "$RT"
rm -rf node_modules
if [ -n "${WEBCRACK_VERSION:-}" ]; then
  echo "updating webcrack to ${WEBCRACK_VERSION} (production deps only)..."
  npm install --save-exact --omit=dev --no-audit --no-fund --loglevel=error \
    "webcrack@${WEBCRACK_VERSION}"
else
  echo "installing webcrack from package-lock.json (production deps only)..."
  npm ci --omit=dev --no-audit --no-fund --loglevel=error
fi

RESOLVED="$(node -e "console.log(require('./node_modules/webcrack/package.json').version)")"
echo "webcrack@${RESOLVED}" > "$RT/webcrack.version"

echo "vendored isolated-vm prebuilt platforms:"
if [ -d "$RT/node_modules/isolated-vm/prebuilds" ]; then
  ( cd "$RT/node_modules/isolated-vm/prebuilds" && ls -1d */ 2>/dev/null | sed 's#/$##;s/^/  - /' )
else
  echo "  (none — isolated-vm will build from source at install; needs a C++ toolchain)"
fi
echo "done: scripts/node_modules (webcrack@${RESOLVED}, $(du -sh node_modules | cut -f1))"
