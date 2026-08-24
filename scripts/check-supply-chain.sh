#!/usr/bin/env sh
# check-supply-chain.sh — enforce immutable build inputs in executable scopes.
#
# The optional repository argument exists for focused fixture tests; normal
# invocations inspect the current checkout.  This checker intentionally skips
# itself and its fixture test because those files contain the patterns they
# assert.  Comments are ignored for mutable-reference checks.
set -eu

case "$#" in
  0) root=. ;;
  1) root=$1 ;;
  *)
    echo "usage: $0 [REPOSITORY_ROOT]" >&2
    exit 2
    ;;
esac

if ! root=$(CDPATH= cd "$root" && pwd); then
  echo "supply-chain-check: repository root is not accessible" >&2
  exit 2
fi

[ -d "$root" ] || {
  echo "supply-chain-check: repository root is not a directory: $root" >&2
  exit 2
}

status=0

check_workflow_actions() {
  awk '
    function fail(message) {
      printf "%s:%d: %s\n", FILENAME, FNR, message
      failed = 1
    }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line == "" || line ~ /^#/ || line !~ /(^|[[:space:]])uses:[[:space:]]*/) {
        next
      }
      sub(/^.*uses:[[:space:]]*/, "", line)
      sub(/[[:space:]]+#.*$/, "", line)
      gsub(/^["\047]/, "", line)
      gsub(/["\047,][[:space:]]*$/, "", line)
      if (line ~ /^\.\//) {
        next
      }
      at = index(line, "@")
      if (at == 0) {
        fail("external workflow action must use a lowercase 40-hex commit SHA: " line)
        next
      }
      ref = substr(line, at + 1)
      if (length(ref) != 40 || ref !~ /^[0-9a-f]+$/) {
        fail("external workflow action must use a lowercase 40-hex commit SHA: " line)
      }
    }
    END { exit failed ? 1 : 0 }
  ' "$@"
}

check_docker_from() {
  awk '
    function fail(message) {
      printf "%s:%d: %s\n", FILENAME, FNR, message
      failed = 1
    }
    {
      if (toupper($1) != "FROM") {
        next
      }
      field = 2
      while ($(field) ~ /^--/) {
        field++
      }
      image = $(field)
      marker = index(image, "@sha256:")
      if (image == "" || marker == 0) {
        fail("Docker FROM must use an explicit @sha256:64 digest: " image)
        next
      }
      digest = substr(image, marker + 8)
      if (length(digest) != 64 || digest !~ /^[0-9a-f]+$/) {
        fail("Docker FROM must use an explicit lowercase @sha256:64 digest: " image)
      }
    }
    END { exit failed ? 1 : 0 }
  ' "$@"
}

check_mutable_refs() {
  awk '
    function fail(message) {
      printf "%s:%d: %s\n", FILENAME, FNR, message
      failed = 1
    }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line == "" || line ~ /^#/) {
        next
      }
      sub(/[[:space:]]+#.*$/, "", line)
      if (line ~ /@(latest|main|master)([^[:alnum:]_.-]|$)/) {
        fail("mutable @latest/@main/@master reference in executable scope")
      }
    }
    END { exit failed ? 1 : 0 }
  ' "$@"
}

check_go_tool_refs() {
  awk '
    function fail(message) {
      printf "%s:%d: %s\n", FILENAME, FNR, message > "/dev/stderr"
      failed = 1
    }
    function clean(token) {
      gsub(/^["\047]/, "", token)
      gsub(/["\047,;\\]+$/, "", token)
      return token
    }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line == "" || line ~ /^#/) {
        next
      }
      sub(/[[:space:]]+#.*$/, "", line)
      count = split(line, fields, /[[:space:]]+/)
      for (i = 1; i <= count - 2; i++) {
        if (clean(fields[i]) != "go") {
          continue
        }
        verb = clean(fields[i + 1])
        if (verb != "run" && verb != "install") {
          continue
        }
        for (j = i + 2; j <= count; j++) {
          candidate = clean(fields[j])
          if (candidate ~ /^-/) {
            continue
          }
          if (candidate ~ /^\.\.?\//) {
            break
          }
          if (candidate !~ /\//) {
            continue
          }
          at = index(candidate, "@")
          if (at == 0) {
            fail("external go " verb " tool must use an exact vMAJOR.MINOR.PATCH version: " candidate)
            break
          }
          ref = substr(candidate, at + 1)
          if (ref !~ /^v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$/) {
            fail("external go " verb " tool must use an exact vMAJOR.MINOR.PATCH version: " candidate)
          }
          break
        }
      }
    }
    END { exit failed ? 1 : 0 }
  ' "$@"
}

check_workflow_files() {
  find "$root/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_workflow_actions "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

check_workflow_mutable_refs() {
  find "$root/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_mutable_refs "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

check_workflow_go_tools() {
  find "$root/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_go_tool_refs "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

check_script_mutable_refs() {
  find "$root/scripts" -type f \
    ! -name 'check-supply-chain.sh' \
    ! -name 'check-supply-chain_test.sh' \
    -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_mutable_refs "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

check_script_go_tools() {
  find "$root/scripts" -type f \
    ! -name 'check-supply-chain.sh' \
    ! -name 'check-supply-chain_test.sh' \
    -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_go_tool_refs "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

check_docker_files() {
  find "$root" -type f -name 'Dockerfile*' ! -path '*/.git/*' -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_docker_from "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

check_docker_mutable_refs() {
  find "$root" -type f -name 'Dockerfile*' ! -path '*/.git/*' -print |
    (
      failed=0
      while IFS= read -r file; do
        if ! check_mutable_refs "$file"; then
          failed=1
        fi
      done
      exit "$failed"
    )
}

if [ -d "$root/.github/workflows" ]; then
  if ! check_workflow_files; then
    status=1
  fi
  if ! check_workflow_mutable_refs; then
    status=1
  fi
  if ! check_workflow_go_tools; then
    status=1
  fi
fi

if [ -d "$root/scripts" ]; then
  if ! check_script_mutable_refs; then
    status=1
  fi
  if ! check_script_go_tools; then
    status=1
  fi
fi

if [ -f "$root/Makefile" ]; then
  if ! check_mutable_refs "$root/Makefile"; then
    status=1
  fi
  if ! check_go_tool_refs "$root/Makefile"; then
    status=1
  fi
fi

if ! check_docker_files; then
  status=1
fi
if ! check_docker_mutable_refs; then
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "supply-chain-check: ok"
fi
exit "$status"
