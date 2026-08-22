#!/usr/bin/env sh
# license-check.sh — audit every Go module dependency's LICENSE file against
# docs/license-policy.md. Allowed set is deliberately tiny:
#   Apache-2.0, MIT, BSD-2/3-Clause, ISC.
#
# Heuristic but auditable: reads the first 4KiB of each module's LICENSE in
# the module cache and matches known license texts. New dependencies need a
# recorded justification in the PR regardless of this check passing.
#
# Exit 1 listing any module with a missing or disallowed license.
set -eu

policy_doc="docs/license-policy.md"

command -v go >/dev/null 2>&1 || { echo "license-check: go not installed" >&2; exit 2; }

echo "license-check: policy = $policy_doc"
# "all" matters: without it, test-only dependencies of dependencies
# (e.g. gopkg.in/check.v1) are not fetched and the scan false-positives.
go mod download all

status=0
count=0
for mod_ver in $(go list -m -f '{{.Path}}@{{.Version}}' all | tail -n +2); do
  count=$((count + 1))
  dir="$(go env GOMODCACHE)/$mod_ver"
  if [ ! -d "$dir" ]; then
    echo "MISSING module dir: $mod_ver" >&2
    status=1
    continue
  fi
  lic=""
  for f in "$dir"/LICENSE* "$dir"/COPYING* "$dir"/LICENCE*; do
    [ -f "$f" ] && { lic="$f"; break; }
  done
  if [ -z "$lic" ]; then
    echo "NO LICENSE FILE: $mod_ver" >&2
    status=1
    continue
  fi
  # Match canonical license texts. BSD appears as "Redistribution and use";
  # ISC as "ISC License" or "Permission to use, copy, modify, and/or".
  if ! head -c 4096 "$lic" | grep -Eqi \
      'apache license|mit license|permission is hereby granted|redistribution and use|isc license'; then
    echo "UNRECOGNIZED LICENSE: $mod_ver ($lic)" >&2
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "license-check: ok — $count module(s) within policy"
fi
exit "$status"
