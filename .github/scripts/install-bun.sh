#!/bin/sh
# install-bun.sh <sha256 of the x64 archive> <sha256 of the aarch64 one> [-musl]
#
# For a container: puts bun in /usr/local/bin, at the version the rest of the
# matrix runs (oven-sh/setup-bun). The tree carries a dozen workarounds for
# one bun version or another, so "whatever bun shipped this morning" is not
# the runtime under test. The release archive, by checksum, rather than an
# installer piped into a shell.
set -eu

case "$(uname -m)" in
  x86_64) zip=bun-linux-x64${3-} sha256=$1 ;;
  aarch64) zip=bun-linux-aarch64${3-} sha256=$2 ;;
  *)
    echo "no bun archive is pinned for $(uname -m)"
    exit 1
    ;;
esac

curl -fsSL --retry 3 -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/$zip.zip"
echo "$sha256  /tmp/bun.zip" | sha256sum -c -
unzip -q /tmp/bun.zip -d /tmp
install -m 0755 "/tmp/$zip/bun" /usr/local/bin/bun
bun --version
