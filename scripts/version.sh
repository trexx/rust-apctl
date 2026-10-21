#!/usr/bin/env bash
# Prints the controller crate's version (crates/controller/Cargo.toml): what a release
# tag must say and what the image reports.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/controller/Cargo.toml | head -n 1)
[ -n "$version" ] || { echo "crates/controller/Cargo.toml has no version" >&2; exit 1; }
echo "$version"
