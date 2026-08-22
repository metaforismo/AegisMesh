#!/usr/bin/env sh
# install.sh — install the aegismesh binary from a release tarball.
#
# Designed to be REVIEWED and then run, not piped blindly into a shell:
#   curl -fsSL https://raw.githubusercontent.com/metaforismo/aegismesh/master/scripts/install.sh -o install.sh
#   less install.sh
#   sh install.sh v0.1.0
#
# What it does: downloads the matching release archive + SHA256SUMS.txt,
# verifies the checksum, installs to ~/.local/bin (override with PREFIX).
set -eu

repo="metaforismo/aegismesh"
bin="aegismesh"

version="${1:-}"
[ -n "$version" ] || { echo "usage: $0 vX.Y.Z   (see https://github.com/$repo/releases)" >&2; exit 2; }

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

prefix="${PREFIX:-$HOME/.local/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

base="https://github.com/$repo/releases/download/$version"
asset="$bin-$os-$arch"

echo "install.sh: downloading $base/$asset"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$asset" "$base/$asset"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt"

expected=$(grep " $asset\$" "$tmp/SHA256SUMS.txt" | cut -d' ' -f1)
if [ -z "$expected" ]; then
  echo "checksum for $asset not found in SHA256SUMS.txt" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
elif command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
  echo "no sha256 tool available; cannot verify" >&2
  exit 2
fi

if [ "$actual" != "$expected" ]; then
  echo "CHECKSUM MISMATCH: want $expected, got $actual" >&2
  exit 1
fi

mkdir -p "$prefix"
install -m 0755 "$tmp/$asset" "$prefix/$bin"
echo "install.sh: installed $prefix/$bin ($version, checksum verified)"
command -v "$prefix" >/dev/null 2>&1 || true
echo "ensure $prefix is on your PATH"
