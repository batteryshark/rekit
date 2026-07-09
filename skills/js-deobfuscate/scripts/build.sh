#!/usr/bin/env bash
# Vendor webcrack into scripts/node_modules (offline, self-contained, committed).
#
# Why node_modules and not a single .js: webcrack depends on isolated-vm, a NATIVE
# addon (it runs the obfuscated string-array decoder inside a secure isolated VM).
# Native .node addons can't be inlined by a JS bundler, so a "single file" bundle
# can't find its native build. isolated-vm ships PREBUILT binaries for
# darwin-arm64/x64, linux-x64/arm64 (glibc+musl) and win32-x64, so this vendored
# tree is portable across the common platforms with no compiler. The user's RUN-time
# prerequisite stays just `node`.
#
# Build-time only (needs npm + network). Re-run to refresh + re-pin. Commit scripts/.
#
#   WEBCRACK_VERSION=2.16.0 scripts/build.sh
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"
WEBCRACK_VERSION="${WEBCRACK_VERSION:-latest}"

cd "$RT"
rm -rf node_modules package-lock.json
echo "installing webcrack@${WEBCRACK_VERSION} (production deps only)..."
npm install --omit=dev --no-audit --no-fund --loglevel=error "webcrack@${WEBCRACK_VERSION}"

RESOLVED="$(node -e "console.log(require('./node_modules/webcrack/package.json').version)")"
echo "webcrack@${RESOLVED}" > "$RT/webcrack.version"

echo "vendored isolated-vm prebuilt platforms:"
if [ -d "$RT/node_modules/isolated-vm/prebuilds" ]; then
  ( cd "$RT/node_modules/isolated-vm/prebuilds" && ls -1d */ 2>/dev/null | sed 's#/$##;s/^/  - /' )
else
  echo "  (none — isolated-vm will build from source at install; needs a C++ toolchain)"
fi
echo "done: scripts/node_modules (webcrack@${RESOLVED}, $(du -sh node_modules | cut -f1))"
