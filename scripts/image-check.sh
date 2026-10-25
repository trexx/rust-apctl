#!/usr/bin/env bash
# Checks that an apctl image runs and reports the controller crate's version. Used by
# CI (.github/workflows/image.yml, build.yml) and the release gate (scripts/release.sh).
# It runs the image with $APCTL_ENGINE, else docker, else podman: a local image is only
# in the store of the engine that built it, so a caller that built with one of them on
# a host that has both names it.
#
#   [APCTL_ENGINE=podman] scripts/image-check.sh <image>
set -euo pipefail

image=${1:?usage: scripts/image-check.sh <image>}
version=$("$(dirname "$0")/version.sh")
engine=${APCTL_ENGINE:-$(command -v docker || command -v podman)} || { echo "the image check needs docker or podman" >&2; exit 1; }
reported=$("$engine" run --rm "$image" --version)
if [ "$reported" != "controller $version" ]; then
  echo "$image reports '$reported', expected 'controller $version'" >&2
  exit 1
fi
echo "$image reports controller $version"
