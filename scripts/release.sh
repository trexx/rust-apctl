#!/usr/bin/env bash
# Builds, checks and publishes the apctl image, then removes the unnamed build
# stages every image build leaves behind (about 2.5 GB each).
#
#   scripts/release.sh 0.10.1                      # build, test, push
#   scripts/release.sh 0.10.1 --pin ~/flux/apctl/manifests/statefulset.yaml
#   scripts/release.sh 0.10.1 --no-push            # build and check only
#
# The version must match crates/controller/Cargo.toml. Stops at the first
# failure, so a stale image is never pushed under a new tag.
set -euo pipefail

IMAGE=${APCTL_IMAGE:-ghcr.io/trexx/apctl}
cd "$(dirname "$0")/.."

version=${1:?usage: scripts/release.sh <version> [--pin <manifest>] [--no-push] [--no-test]}
shift
pin=""
push=1
test=1
while [ $# -gt 0 ]; do
  case $1 in
    --pin) pin=${2:?--pin needs a file}; shift 2 ;;
    --no-push) push=0; shift ;;
    --no-test) test=0; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# Leftover build stages are removed however the script ends.
cleanup() { podman image prune -f >/dev/null 2>&1 || true; }
trap cleanup EXIT

crate=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/controller/Cargo.toml | head -1)
if [ "$crate" != "$version" ]; then
  echo "crates/controller/Cargo.toml says $crate, not $version" >&2
  exit 1
fi

if [ $test = 1 ]; then
  echo "== tests"
  cargo test -q --workspace 2>&1 | grep -E "^test result|FAILED|panicked" | grep -v " 0 failed" && { echo "tests failed" >&2; exit 1; } || true
fi

echo "== building $IMAGE:$version"
# --force-rm: a failed build must not leave working containers (they pin their images).
podman build -q --force-rm --target runtime -t "$IMAGE:$version" .
reported=$(podman run --rm "$IMAGE:$version" --version)
if [ "$reported" != "controller $version" ]; then
  echo "the image reports '$reported', expected 'controller $version'" >&2
  exit 1
fi

if [ $push = 0 ]; then
  echo "built $IMAGE:$version (not pushed)"
  exit 0
fi

digestfile=$(mktemp)
podman push -q --digestfile "$digestfile" "$IMAGE:$version"
digest=$(cat "$digestfile")
rm -f "$digestfile"
echo "pushed $IMAGE:$version@$digest"

if [ -n "$pin" ]; then
  sed -i -E "s|image: ${IMAGE}:[^@ ]+@sha256:[0-9a-f]+|image: ${IMAGE}:${version}@${digest}|" "$pin"
  grep -q "${IMAGE}:${version}@${digest}" "$pin" || { echo "could not pin $pin (no '${IMAGE}:...@sha256:...' image line?)" >&2; exit 1; }
  echo "pinned in $pin"
fi
