#!/bin/sh
set -eu

if [ "${1:-}" = "--version" ]; then
  binary_version=$("remill-lift-${LLVM_VERSION}" --version 2>&1 | sed -n '1p')
  printf 'native-lift remill=%s commit=%s llvm=%s binary=%s\n' \
    "${REMILL_VERSION}" "${REMILL_COMMIT}" \
    "$(llvm-config-${LLVM_VERSION} --version)" "$binary_version"
  exit 0
fi

input=
arch=
os=linux
address=0
entry_address=0
ir_out=
bc_out=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --input) input=$2; shift 2 ;;
    --arch) arch=$2; shift 2 ;;
    --os) os=$2; shift 2 ;;
    --address) address=$2; shift 2 ;;
    --entry-address) entry_address=$2; shift 2 ;;
    --ir-out) ir_out=$2; shift 2 ;;
    --bc-out) bc_out=$2; shift 2 ;;
    *) printf 'native-lift: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

if [ -z "$input" ] || [ -z "$arch" ]; then
  printf 'native-lift: --input and --arch are required\n' >&2
  exit 2
fi
if [ -z "$ir_out" ] && [ -z "$bc_out" ]; then
  printf 'native-lift: at least one output is required\n' >&2
  exit 2
fi
if [ ! -f "$input" ]; then
  printf 'native-lift: input is not a regular file\n' >&2
  exit 2
fi

bytes=$(od -An -v -tx1 "$input" | tr -d ' \n')
set -- "remill-lift-${LLVM_VERSION}" \
  --arch "$arch" \
  --os "$os" \
  --address "$address" \
  --entry_address "$entry_address" \
  --bytes "$bytes"

if [ -n "$ir_out" ]; then
  set -- "$@" --ir_out "$ir_out"
fi
if [ -n "$bc_out" ]; then
  set -- "$@" --bc_out "$bc_out"
fi

exec "$@"
