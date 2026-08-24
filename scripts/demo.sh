#!/usr/bin/env sh
# Compatibility wrapper for the self-contained CLI demo.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
make -C "$root" build >/dev/null
exec "$root/bin/aegismesh" demo "$@"
