#!/usr/bin/env sh
# license-check.sh — audit every Go module dependency's LICENSE file against
# docs/license-policy.md. Allowed set is deliberately tiny:
#   Apache-2.0, MIT, BSD-0/2/3-Clause, ISC.
#
# Heuristic but auditable: reads the first and last 4KiB of each module's LICENSE in
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
for module_record in $(go list -m -f '{{if not .Main}}{{.Path}}@{{.Version}}|{{.Dir}}{{end}}' all); do
  mod_ver=${module_record%%|*}
  count=$((count + 1))
  dir=${module_record#*|}
  if [ ! -d "$dir" ]; then
    echo "MISSING module dir: $mod_ver" >&2
    status=1
    continue
  fi
  lic=""
  for f in "$dir"/LICENSE* "$dir"/COPYING* "$dir"/LICENCE*; do
    [ -f "$f" ] && { lic="$f"; break; }
  done
  # This upstream test-only submodule embeds its 0BSD grant in the README.
  # Restrict the fallback to the reviewed module/version and exact license text.
  if [ -z "$lic" ] && [ "$mod_ver" = 'c2sp.org/CCTV/age@v0.0.0-20260829155415-4448f2097b2d' ]; then
    expected=fdbd4b06044f3803c72bdaf2df7681fdce3a45a326a2898e75640eae906606ad
    if command -v sha256sum >/dev/null 2>&1; then
      actual=$(sha256sum "$dir/README.md" | awk '{print $1}')
    else
      actual=$(shasum -a 256 "$dir/README.md" | awk '{print $1}')
    fi
    if [ "$actual" = "$expected" ]; then lic="$dir/README.md"; fi
  fi
  if [ -z "$lic" ]; then
    echo "NO LICENSE FILE: $mod_ver" >&2
    status=1
    continue
  fi
  # Match canonical license texts. BSD appears as "Redistribution and use";
  # ISC as "ISC License" or "Permission to use, copy, modify, and/or".
  if ! { head -c 4096 "$lic"; tail -c 4096 "$lic"; } | grep -Eqi \
      'apache license|mit license|permission is hereby granted|redistribution and use|isc license|permission to use, copy, modify, and/or'; then
    echo "UNRECOGNIZED LICENSE: $mod_ver ($lic)" >&2
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "license-check: ok — $count module(s) within policy"
fi
exit "$status"
