#!/usr/bin/env bash
# The checks a change must pass, listed once for CI (.github/workflows/test.yml) and
# the release gate (scripts/release.sh).
#
# Rust: informdump turns on serde_json's preserve_order, so it is tested on its own:
# the other crates are tested with the features the shipped binary is built with.
# informdump's MongoDB import is behind a feature; the last check keeps it compiling
# and linted.
#
# Web: lint (eslint, no warnings), type-check and build web/, in the Node image the
# Dockerfile builds it with, run by $APCTL_ENGINE, else docker, else podman (the rule
# scripts/image-check.sh follows). npm's download cache is $HOME/.npm, mounted into the
# container. What it writes (web/node_modules, web/dist, the cache) is the caller's:
# rootful Docker runs it as the caller's user; rootless engines (podman, rootless
# Docker) already map the container's root to the caller.
#
#   scripts/check.sh                                # runs the Rust checks in order, stopping at the first failure
#   scripts/check.sh --list                         # prints them, one per line
#   [APCTL_ENGINE=podman] scripts/check.sh --web    # runs the web check
set -euo pipefail

checks=(
  "cargo test --workspace --exclude informdump --locked"
  "cargo test -p informdump --locked"
  "cargo clippy --workspace --all-targets --locked -- -D warnings"
  "cargo clippy -p informdump --features mongo --all-targets --locked -- -D warnings"
)

case ${1:-} in
  --list)
    printf '%s\n' "${checks[@]}"
    exit 0 ;;
  --web)
    cd "$(dirname "$0")/.."
    engine=${APCTL_ENGINE:-$(command -v docker || command -v podman)} || { echo "the web check needs docker or podman" >&2; exit 1; }
    as_caller=()
    if [ "$(id -u)" != 0 ]; then
      # podman --version names podman, also behind a docker shim; rootless Docker lists
      # rootless among its security options.
      about="$("$engine" --version 2>&1 || true) $("$engine" info --format '{{.SecurityOptions}}' 2>/dev/null || true)"
      case $about in
        *podman* | *rootless*) ;;
        *) as_caller=(--user "$(id -u):$(id -g)" -e HOME=/tmp) ;;
      esac
    fi
    mkdir -p "$HOME/.npm"
    exec "$engine" run --rm ${as_caller[@]+"${as_caller[@]}"} -v "$PWD/web:/web:Z" -v "$HOME/.npm:/npm:Z" -e npm_config_cache=/npm -w /web \
      docker.io/library/node:26-slim@sha256:94816674c62774da0d099a947bf4613b9e1972a2733abd0d0cd80e795f8411d0 \
      sh -c "npm ci --no-fund --no-audit && npm run lint && npm run build" ;;
  "") ;;
  *) echo "usage: scripts/check.sh [--list | --web]" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
for check in "${checks[@]}"; do
  echo "== $check"
  $check
done
