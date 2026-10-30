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
assert_order 0.1.1-testnet.1 0.1.0-testnet.99 1
assert_order 0.1.0-testnet.99 0.1.0  -1
assert_order 0.1.0 0.1.0-testnet.99 1

if sh "$INSTALLER" --compare-testnet-versions 0.1.0-testnet.013 0.1.0-testnet.13 >/dev/null 2>&1; then
  printf '%s\n' 'Leading-zero prerelease identifiers must be rejected' >&2
  exit 1
fi
if sh "$INSTALLER" --compare-testnet-versions 0.1.0-preview.1 0.1.0-testnet.13 >/dev/null 2>&1; then
  printf '%s\n' 'Unknown prerelease identifiers must be rejected' >&2
  exit 1
fi

printf '%s\n' 'Unix installer semantic-version downgrade checks passed'
