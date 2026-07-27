#!/usr/bin/env bash
# Vendor a pinned Diaphora release + its Python deps into scripts/.
#
# Diaphora ships as a git checkout, not a package, so we pull one immutable tag
# tarball (verified by commit SHA) into scripts/diaphora and install its runtime
# requirements into scripts/site. Nothing is fetched at analysis time.
#
# Build-time only (needs curl + uv + network). Re-run to refresh the pin.
set -euo pipefail

# Diaphora 3.4.1 — https://github.com/joxeankoret/diaphora/releases/tag/3.4.1
DIAPHORA_TAG="3.4.1"
DIAPHORA_SHA="12f72b1683d605a796823a251f46e018e43a3eb3"

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"
TARBALL="https://github.com/joxeankoret/diaphora/archive/${DIAPHORA_SHA}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "fetching Diaphora ${DIAPHORA_TAG} (${DIAPHORA_SHA:0:12})..."
curl -fsSL "$TARBALL" -o "$tmp/diaphora.tar.gz"

rm -rf "$RT/diaphora"
mkdir -p "$RT/diaphora"
tar -xzf "$tmp/diaphora.tar.gz" -C "$RT/diaphora" --strip-components=1

if [ ! -f "$RT/diaphora/diaphora.py" ]; then
  echo "error: extracted tree has no diaphora.py" >&2
  exit 1
fi
printf '%s %s\n' "$DIAPHORA_TAG" "$DIAPHORA_SHA" > "$RT/diaphora/.rekit-pin"

echo "vendoring Diaphora requirements into scripts/site..."
rm -rf "$RT/site"
uv pip install --target "$RT/site" -r "$RT/diaphora/requirements.txt" -q

echo "done: Diaphora ${DIAPHORA_TAG} ($(du -sh "$RT/diaphora" | cut -f1)), \
deps ($(du -sh "$RT/site" | cut -f1))"
