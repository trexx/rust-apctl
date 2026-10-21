#!/usr/bin/env bash
# Checks that an apctl image runs and reports the controller crate's version, with
# docker or podman. Used by CI (.github/workflows/image.yml, build.yml) and the release
# gate (scripts/release.sh).
#
#   scripts/image-check.sh <image>
set -euo pipefail

image=${1:?usage: scripts/image-check.sh <image>}
version=$("$(dirname "$0")/version.sh")
engine=$(command -v docker || command -v podman) || { echo "the image check needs docker or podman" >&2; exit 1; }
reported=$("$engine" run --rm "$image" --version)
if [ "$reported" != "controller $version" ]; then
  echo "$image reports '$reported', expected 'controller $version'" >&2
  exit 1
fi
echo "$image reports controller $version"
