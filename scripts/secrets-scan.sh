#!/usr/bin/env sh
# secrets-scan.sh — fail when likely secrets appear in tracked files.
#
# Deliberately simple and auditable: fixed regexes over `git ls-files`
# output. This is a tripwire, not a guarantee; review diffs before committing.
#
# Portability notes:
#   - Patterns are passed as explicit -e arguments. A variable holding a
#     newline-separated list yields EMPTY patterns (leading/trailing newlines)
#     and an empty ERE matches every line — the scanner then flags everything.
#   - POSIX ERE has no inline (?i); case-insensitive rules use grep -i.
#   - \s is non-portable; [[:space:]] is used instead.
set -eu

command -v git >/dev/null 2>&1 || { echo "secrets-scan: git not available" >&2; exit 2; }

status=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  # The scanner necessarily contains secret-shaped literals (its own
  # patterns); scanning itself can only ever self-flag.
  [ "$f" = "scripts/secrets-scan.sh" ] && continue

  hits=$(
    {
      grep -En \
        -e 'AKIA[0-9A-Z]{16}' \
        -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
        -e 'ghp_[a-zA-Z0-9]{36}' \
        -e 'github_pat_[a-zA-Z0-9_]{82}' \
        -e 'xox[baprs]-[a-zA-Z0-9-]{10,}' \
        -- "$f" 2>/dev/null || true
      grep -Ein \
        -e 'aws_secret_access_key.{0,10}[0-9a-zA-Z/+]{40}' \
        -e 'authorization["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?bearer[[:space:]]+[a-z0-9._~+/=-]{20,}' \
        -e 'api[_-]?key["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[a-z0-9._-]{32,}' \
        -- "$f" 2>/dev/null || true
    }
  )
  # Filter obvious test fixtures and placeholders before judging a hit.
  # A line may carry `secret-scan:allow` to declare itself benign on review.
  report=$(printf '%s\n' "$hits" | grep -v 'EXAMPLE\|example\|REDACTED\|placeholder\|supersecret\|secret-scan:allow' || true)
  if [ -n "$report" ]; then
    printf '%s\n' "$report"
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
