#!/usr/bin/env sh
# secrets-scan.sh — fail when likely secrets appear in tracked files.
#
# Deliberately simple and auditable: regexes over `git ls-files` output.
# This is a tripwire, not a guarantee; review diffs before committing.
#
# Exit 1 with the offending file:line list.
set -eu

command -v git >/dev/null 2>&1 || { echo "secrets-scan: git not available" >&2; exit 2; }

patterns='
AKIA[0-9A-Z]{16}
(?i)aws_secret_access_key.{0,10}[0-9a-zA-Z/+]{40}
-----BEGIN [A-Z ]*PRIVATE KEY-----
(?i)authorization["'"'"']?\s*[:=]\s*["'"'"']?bearer\s+[a-z0-9._~+/=-]{20,}
ghp_[a-zA-Z0-9]{36}
github_pat_[a-zA-Z0-9_]{82}
xox[baprs]-[a-zA-Z0-9-]{10,}
(?i)api[_-]?key["'"'"']?\s*[:=]\s*["'"'"']?[a-z0-9._-]{32,}
'

status=0
# shellcheck disable=SC2254
while IFS= read -r f; do
  [ -f "$f" ] || continue
  # -h: no filename duplication; we print it ourselves once per hit group.
  if grep -Ein "$patterns" "$f" 2>/dev/null | grep -v 'EXAMPLE\|example\|<[^>]*>\|REDACTED\|placeholder'; then
    echo "^^ possible secret in $f" >&2
    status=1
  fi
done <<EOF
$(git ls-files)
EOF

if [ "$status" -eq 0 ]; then
  echo "secrets-scan: ok"
fi
exit "$status"
