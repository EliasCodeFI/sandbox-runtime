#!/usr/bin/env bash
# install-ripgrep.sh <version> <sha256 of the x86-64 archive> <sha256 of the arm64 one>
#
# Unpacks that ripgrep release into $RUNNER_TEMP/ripgrep-<version>, from the
# upstream release instead of whichever version the package archive serves
# that day. Each checksum is the one upstream publishes beside the archive,
# and a mismatch fails the step.
set -euo pipefail

version=$1
case "$(uname -m)" in
  x86_64) asset=ripgrep-$version-x86_64-unknown-linux-musl.tar.gz sha256=$2 ;;
  aarch64) asset=ripgrep-$version-aarch64-unknown-linux-gnu.tar.gz sha256=$3 ;;
  *)
    echo "::error::no ripgrep archive is pinned for $(uname -m)"
    exit 1
    ;;
esac
into=$RUNNER_TEMP/ripgrep-$version

curl -fsSL --retry 3 -o "$RUNNER_TEMP/$asset" "https://github.com/BurntSushi/ripgrep/releases/download/$version/$asset"
echo "$sha256  $RUNNER_TEMP/$asset" | sha256sum --check --strict
mkdir -p "$into"
tar -xzf "$RUNNER_TEMP/$asset" -C "$into" --strip-components=1
"$into/rg" --version
