#!/bin/sh
set -eu

INSTALLER="$(dirname "$0")/install-unix.sh"

assert_order() {
  actual="$(sh "$INSTALLER" --compare-testnet-versions "$1" "$2")"
  if [ "$actual" != "$3" ]; then
    printf '%s\n' "Expected version order $1 vs $2 to be $3, got $actual" >&2
    exit 1
  fi
}

assert_order 0.1.0-testnet.12 0.1.0-testnet.13 -1
assert_order 0.1.0-testnet.13 0.1.0-testnet.13 0
assert_order 0.1.0-testnet.14 0.1.0-testnet.13 1
assert_order 0.1.0-testnet.0 0.1.0-testnet.1 -1
assert_order 0.1.0-testnet.2147483647 0.1.0-testnet.2147483646 1
assert_order 0.1.1-testnet.1 0.1.0-testnet.99 1
assert_order 0.1.1 0.1.0 1
assert_order 0.1.0 0.2.0 -1
assert_order 1.0.0 0.99.99 1
assert_order 0.1.0-testnet.99 0.1.1-testnet.0 -1
assert_order 0.1.0-testnet.99 0.1.0  -1
assert_order 0.1.0 0.1.0-testnet.99 1

assert_invalid() {
  if sh "$INSTALLER" --compare-testnet-versions "$1" 0.1.0-testnet.13 >/dev/null 2>&1; then
    printf '%s\n' "Invalid installed version must be rejected: $1" >&2
    exit 1
  fi
  if sh "$INSTALLER" --compare-testnet-versions 0.1.0-testnet.12 "$1" >/dev/null 2>&1; then
    printf '%s\n' "Invalid candidate version must be rejected: $1" >&2
    exit 1
  fi
}

for invalid in \
  0.1 \
  v0.1.0 \
  0.1.0-preview.1 \
  0.1.0-testnet.foo \
  00.1.0 \
  0.01.0 \
  0.1.00 \
  0.1.0-testnet.013 \
  2147483648.0.0 \
  0.1.0-testnet.2147483648 \
  18446744073709551616.0.0; do
  assert_invalid "$invalid"
done

printf '%s\n' 'Unix installer semantic-version ordering and fail-closed checks passed'
