#!/usr/bin/env bash
# The Rust checks a change must pass, listed once for CI (.github/workflows/test.yml)
# and the release gate (scripts/release.sh). informdump turns on serde_json's
# preserve_order, so it is tested on its own: the other crates are tested with the
# features the shipped binary is built with. informdump's MongoDB import is behind a
# feature; the last check keeps it compiling and linted.
#
#   scripts/check.sh          # runs them in order, stopping at the first failure
#   scripts/check.sh --list   # prints them, one per line
set -euo pipefail

checks=(
  "cargo test --workspace --exclude informdump --locked"
  "cargo test -p informdump --locked"
  "cargo clippy --workspace --all-targets --locked -- -D warnings"
  "cargo clippy -p informdump --features mongo --all-targets --locked -- -D warnings"
)

if [ "${1:-}" = --list ]; then
  printf '%s\n' "${checks[@]}"
  exit 0
fi
cd "$(dirname "$0")/.."
for check in "${checks[@]}"; do
  echo "== $check"
  $check
done
