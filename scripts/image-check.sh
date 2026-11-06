#!/usr/bin/env bash
# Checks that an apctl image runs and reports the controller crate's version, and that it
# carries the manufacturer list where the controller looks for it. Used by CI
# (.github/workflows/image.yml, build.yml) and the release gate (scripts/release.sh).
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

# The list at the --oui-file default, read as vendor.rs reads it: a header line, then
# MA-L lines of a six-digit hex prefix and a name. Without it apctl starts all the same,
# with a warning, and shows no manufacturers. The image has no shell, so the file is
# copied out of a container that never starts. The 2026 list has about 40 000 names.
container=$("$engine" create "$image")
trap '"$engine" rm "$container" >/dev/null' EXIT
names=$("$engine" cp "$container:/usr/share/apctl/oui.csv" - | tar -xO \
  | awk 'NR == 1 { header = /^Registry,Assignment,/; next } /^MA-L,[0-9A-F]{6},./ { n++ } END { print header ? n + 0 : -1 }')
if [ "$names" -lt 30000 ]; then
  if [ "$names" -lt 0 ]; then why="no header line"; else why="only $names manufacturer lines"; fi
  echo "$image: /usr/share/apctl/oui.csv has $why" >&2
  exit 1
fi
echo "$image carries $names manufacturer prefixes"
