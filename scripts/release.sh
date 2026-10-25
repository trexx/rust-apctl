#!/usr/bin/env bash
# Builds and checks the apctl image locally, and with --pin writes the digest CI
# published for the release into a manifest. Removes the unnamed build stages the
# build left behind (about 2.5 GB each).
#
#   scripts/release.sh 0.10.1                      # test, build and check the image
#   git tag 0.10.1 && git push origin 0.10.1       # CI publishes :0.10.1 and :latest
#   scripts/release.sh 0.10.1 --pin ~/flux/apctl/manifests/statefulset.yaml
#
# CI (.github/workflows/build.yml, on the version tag) is the only publisher: this
# script never pushes, so one tag never names two different builds. --pin waits
# until CI has published $IMAGE:<version>, checks that image was built from HEAD,
# and pins its digest.
#
# The version must match crates/controller/Cargo.toml. Stops at the first failure.
set -euo pipefail

IMAGE=${APCTL_IMAGE:-ghcr.io/trexx/rust-apctl}
# How long --pin waits for CI to publish the image, in seconds.
WAIT=${APCTL_PIN_WAIT:-3600}

version=${1:?usage: scripts/release.sh <version> [--pin <manifest>] [--no-test]}
shift
pin=""
test=1
while [ $# -gt 0 ]; do
  case $1 in
    --pin)
      [ $# -ge 2 ] || { echo "--pin needs a file" >&2; exit 2; }
      # Resolved before the cd below, so a relative path means the caller's directory.
      pin=$(realpath -e -- "$2" 2>/dev/null) || { echo "--pin: no such file: $2" >&2; exit 2; }
      shift 2 ;;
    --no-test) test=0; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
cd "$(dirname "$0")/.."

if [ -n "$pin" ] && ! grep -Eq "image: ${IMAGE}:[^@ ]+@sha256:[0-9a-f]+" "$pin"; then
  echo "$pin has no '${IMAGE}:...@sha256:...' image line to pin" >&2
  exit 1
fi

# Leftover build stages are removed however the script ends: only the unnamed
# images that were not there before, not every dangling image on the host.
dangling() { podman images -q --filter dangling=true | sort -u; }
before=$(dangling)
manifest=""
cleanup() {
  comm -13 <(echo "$before") <(dangling) | xargs -r podman rmi >/dev/null 2>&1 || true
  rm -f "$manifest"
}
trap cleanup EXIT

crate=$(scripts/version.sh)
if [ "$crate" != "$version" ]; then
  echo "crates/controller/Cargo.toml says $crate, not $version" >&2
  exit 1
fi

# The image is built from the working tree, so that must be exactly a commit. This
# script does not tag: a tag of this version that already exists must name that
# commit, and --pin needs it (CI publishes from the tag).
if [ -n "$(git status --porcelain)" ]; then
  echo "the working tree has uncommitted changes; commit or stash them first" >&2
  exit 1
fi
head=$(git rev-parse HEAD)
if tagged=$(git rev-parse -q --verify "refs/tags/$version^{commit}"); then
  if [ "$tagged" != "$head" ]; then
    echo "tag $version names $tagged, not HEAD" >&2
    exit 1
  fi
elif [ -n "$pin" ]; then
  echo "HEAD is not tagged $version: tag and push it first (CI publishes from the tag)" >&2
  exit 1
else
  echo "note: HEAD is not tagged $version"
fi

if [ $test = 1 ]; then
  # The same checks as CI: scripts/check.sh lists the Rust ones and runs the web one;
  # run here one by one to keep each one's output and say which failed.
  mapfile -t checks < <(scripts/check.sh --list)
  [ ${#checks[@]} -gt 0 ] || { echo "scripts/check.sh lists no checks" >&2; exit 1; }
  checks+=("scripts/check.sh --web")
  log=$(mktemp)
  for check in "${checks[@]}"; do
    echo "== $check"
    if ! $check >"$log" 2>&1; then
      # No pipe into head: under pipefail, grep killed by SIGPIPE (or matching nothing)
      # would end the script before it says which check failed.
      grep -m 20 -E "FAILED|panicked|error|warning" "$log" >&2 || true
      echo "failed: $check (full output: $log)" >&2
      exit 1
    fi
  done
  rm -f "$log"
fi

# A local name only: CI builds the image it publishes on its own.
built="localhost/rust-apctl:$version"
echo "== building $built"
# --force-rm: a failed build must not leave working containers (they pin their images).
# OUI_MONTH: the manufacturer list is downloaded again once a month.
podman build -q --force-rm --target runtime --build-arg OUI_MONTH="$(date +%Y-%m)" -t "$built" .
APCTL_ENGINE=podman scripts/image-check.sh "$built"

if [ -z "$pin" ]; then
  exit 0
fi

# skopeo reads the registry without pulling; from a container when it is not installed.
skopeo() {
  if command -v skopeo >/dev/null; then
    command skopeo "$@"
  else
    podman run --rm quay.io/skopeo/stable:v1.20.0@sha256:47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4 "$@"
  fi
}

ref="docker://$IMAGE:$version"
manifest=$(mktemp)
echo "== waiting for CI to publish $IMAGE:$version (up to ${WAIT}s)"
deadline=$((SECONDS + WAIT))
until skopeo inspect --raw "$ref" >"$manifest" 2>/dev/null; do
  if [ $SECONDS -ge $deadline ]; then
    echo "$IMAGE:$version is not published after ${WAIT}s; was the tag pushed, and did CI pass?" >&2
    exit 1
  fi
  sleep 60
done
# The digest of the tag's own manifest (the index, for a multi-platform image).
digest="sha256:$(sha256sum "$manifest" | cut -d' ' -f1)"
revision=$(skopeo inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' "docker://$IMAGE@$digest")
case $revision in
  "$head") ;;
  "" | "<no value>") echo "note: $IMAGE:$version carries no revision label; not checked against HEAD" ;;
  *) echo "$IMAGE:$version was built from $revision, not HEAD ($head)" >&2; exit 1 ;;
esac
echo "published $IMAGE:$version@$digest"

sed -i -E "s|image: ${IMAGE}:[^@ ]+@sha256:[0-9a-f]+|image: ${IMAGE}:${version}@${digest}|" "$pin"
grep -q "${IMAGE}:${version}@${digest}" "$pin" || { echo "could not pin $pin" >&2; exit 1; }
echo "pinned in $pin"
