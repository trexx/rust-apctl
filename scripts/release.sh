#!/usr/bin/env bash
# Builds and checks the apctl image locally, and with --pin writes the digest CI
# published for the release into a manifest. Removes the unnamed build stages the
# build left behind (about 2.5 GB each).
#
#   scripts/release.sh 0.10.1                      # test, build and check the image
#   git tag 0.10.1 && git push origin 0.10.1       # CI publishes :0.10.1 and :latest (and the capture sidecar's)
#   scripts/release.sh 0.10.1 --pin ~/flux/apctl/manifests/statefulset.yaml
#
# CI (.github/workflows/build.yml, on the version tag) is the only publisher: this
# script never pushes, so one tag never names two different builds. --pin waits
# until CI has published $IMAGE:<version>, checks that image was built from HEAD,
# waits for the tag's Build run (which tests the published images) to pass, and pins
# its digest. The Build run is checked with gh; without gh that is left out, with a note.
#
# The version must match crates/controller/Cargo.toml, and README.md must name its
# image. Stops at the first failure.
set -euo pipefail

IMAGE=${APCTL_IMAGE:-ghcr.io/trexx/rust-apctl}
# How long --pin waits for CI to publish and check the image, in seconds.
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
err=""
cleanup() {
  comm -13 <(echo "$before") <(dangling) | xargs -r podman rmi >/dev/null 2>&1 || true
  rm -f "$manifest" "$err"
}
trap cleanup EXIT

crate=$(scripts/version.sh)
if [ "$crate" != "$version" ]; then
  echo "crates/controller/Cargo.toml says $crate, not $version" >&2
  exit 1
fi
# The README's Kubernetes example names the image of the latest release.
if ! grep -Eq "rust-apctl:${version//./\\.}([^0-9A-Za-z.-]|$)" README.md; then
  echo "README.md does not name rust-apctl:$version; update its image line" >&2
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
podman build -q --force-rm --target runtime -t "$built" .
APCTL_ENGINE=podman scripts/image-check.sh "$built"

if [ -z "$pin" ]; then
  exit 0
fi

# skopeo reads the registry without pulling; from a container when it is not installed
# (type -P: `command -v` would find this function itself), which gets the credentials
# `podman login` saved, read-only, for a private $IMAGE.
skopeo() {
  if type -P skopeo >/dev/null; then
    command skopeo "$@"
    return
  fi
  local auth opts=()
  for auth in "${REGISTRY_AUTH_FILE:-}" "${XDG_RUNTIME_DIR:-/run/user/$UID}/containers/auth.json" "$HOME/.config/containers/auth.json"; do
    if [ -n "$auth" ] && [ -f "$auth" ]; then
      opts=(--security-opt label=disable -v "$auth:/auth.json:ro" -e REGISTRY_AUTH_FILE=/auth.json)
      break
    fi
  done
  podman run --rm "${opts[@]}" quay.io/skopeo/stable:v1.22.3@sha256:2681eccb8b02c495b013c2669cbf7f41d5c0b0b0e644e7c69bd3ea9bcb20641f "$@"
}

ref="docker://$IMAGE:$version"
manifest=$(mktemp)
err=$(mktemp)
echo "== waiting for CI to publish $IMAGE:$version (up to ${WAIT}s)"
deadline=$((SECONDS + WAIT))
# Only "not published yet" is waited out. Any other failure stops at once with skopeo's
# own message: podman failing to run the skopeo image (125 and up), a registry refusing
# the credentials, a mistyped APCTL_IMAGE.
until rc=0; skopeo inspect --raw "$ref" >"$manifest" 2>"$err" || rc=$?; [ $rc = 0 ]; do
  if [ $rc -ge 125 ] || ! grep -qiE 'manifest unknown|not found' "$err"; then
    cat "$err" >&2
    if [ $rc -ge 125 ]; then
      echo "could not run skopeo (podman exited $rc)" >&2
    else
      echo "could not read $IMAGE:$version; for a private image, log in first: podman login ${IMAGE%%/*}" >&2
    fi
    exit 1
  fi
  if [ $SECONDS -ge $deadline ]; then
    cat "$err" >&2
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

# CI pushes the images before its check job tests them (scripts/image-check.sh on the published
# image, tcpdump in the capture sidecar), so the manifest exists while that check runs, or after
# it failed: pin only once the tag's Build run for HEAD has passed. Without gh that is left unchecked.
if type -P gh >/dev/null; then
  # "<status> <url> <conclusion>" of the newest run, or "null null null" before there is one.
  # The conclusion is last: it is empty while the run is going, and read would then shift the URL into it.
  build_run() {
    gh run list --workflow build.yml --branch "$version" --event push --commit "$head" -L 1 \
      --json status,conclusion,url -q '.[0] // {} | "\(.status) \(.url) \(.conclusion)"'
  }
  echo "== waiting for the Build run of $version to pass"
  until run=$(build_run) || { echo "could not list the Build runs with gh; is it logged in (gh auth status)?" >&2; exit 1; }
        read -r status url conclusion <<<"$run"; [ "$status" = completed ]; do
    if [ $SECONDS -ge $deadline ]; then
      echo "the Build run of $version has not finished after ${WAIT}s (${url/#null/no run found})" >&2
      exit 1
    fi
    sleep 15
  done
  if [ "$conclusion" != success ]; then
    echo "the Build run of $version ended '$conclusion', not success: $url" >&2
    exit 1
  fi
  echo "passed: $url"
else
  echo "note: gh is not installed; not checked that CI's Build run of $version passed"
fi

sed -i -E "s|image: ${IMAGE}:[^@ ]+@sha256:[0-9a-f]+|image: ${IMAGE}:${version}@${digest}|" "$pin"
grep -q "${IMAGE}:${version}@${digest}" "$pin" || { echo "could not pin $pin" >&2; exit 1; }
echo "pinned in $pin"
