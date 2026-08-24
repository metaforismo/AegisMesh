#!/usr/bin/env sh
# Focused positive/negative fixtures for check-supply-chain.sh.
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
checker="$script_dir/check-supply-chain.sh"
repo_dir=$(CDPATH= cd "$script_dir/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/aegismesh-supply-chain-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

new_fixture() {
  fixture=$(mktemp -d "$tmp/fixture.XXXXXX")
  mkdir -p "$fixture/.github/workflows" "$fixture/scripts" "$fixture/deploy"
  printf '%s\n' \
    'name: fixture' \
    'on: workflow_dispatch' \
    'jobs:' \
    '  build:' \
    '    runs-on: ubuntu-latest' \
    '    steps:' \
    '      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567' \
    '      - uses: ./.github/actions/local' \
    '      - run: echo safe' \
    > "$fixture/.github/workflows/fixture.yml"
  printf '%s\n' '#!/usr/bin/env sh' 'echo safe' > "$fixture/scripts/build.sh"
  printf '%s\n' 'all:' '	printf "%s\\n" safe' > "$fixture/Makefile"
  printf '%s\n' \
    'FROM alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'RUN printf "%s\\n" safe' \
    > "$fixture/deploy/Dockerfile"
}

expect_pass() {
  if ! "$checker" "$fixture"; then
    echo "check-supply-chain_test: expected PASS" >&2
    return 1
  fi
}

expect_fail() {
  report="$fixture/report.txt"
  if "$checker" "$fixture" > "$report" 2>&1; then
    echo "check-supply-chain_test: expected FAIL" >&2
    return 1
  fi
  grep -Eq 'supply-chain-check|must use|mutable' "$report"
}

new_fixture
expect_pass

new_fixture
printf '%s\n' \
  'name: mutable-action' \
  'jobs:' \
  '  build:' \
  '    runs-on: ubuntu-latest' \
  '    steps:' \
  '      - uses: actions/checkout@main' \
  > "$fixture/.github/workflows/fixture.yml"
expect_fail

new_fixture
printf '%s\n' \
  'FROM alpine:latest' \
  > "$fixture/deploy/Dockerfile"
expect_fail

new_fixture
printf '%s\n' \
  '#!/usr/bin/env sh' \
  'go install example.invalid/tool@master' \
  > "$fixture/scripts/build.sh"
expect_fail

new_fixture
printf '%s\n' \
  '#!/usr/bin/env sh' \
  'go run example.invalid/tool@v1 ./...' \
  > "$fixture/scripts/build.sh"
expect_fail

new_fixture
printf '%s\n' \
  '#!/usr/bin/env sh' \
  'go install example.invalid/tool@release-branch' \
  > "$fixture/scripts/build.sh"
expect_fail

new_fixture
printf '%s\n' \
  '#!/usr/bin/env sh' \
  'go run example.invalid/tool@v1.2.3 ./...' \
  > "$fixture/scripts/build.sh"
expect_pass

# Regression: a tracked filename beginning with '-' must be passed to grep
# after `--`, otherwise grep interprets the filename as an option.
secret_fixture="$tmp/secrets"
mkdir -p "$secret_fixture/scripts"
cp "$repo_dir/scripts/secrets-scan.sh" "$secret_fixture/scripts/secrets-scan.sh"
printf '%s\n' 'safe fixture content' > "$secret_fixture/--safe"
git -C "$secret_fixture" init -q
git -C "$secret_fixture" add -- scripts/secrets-scan.sh --safe
if ! (cd "$secret_fixture" && ./scripts/secrets-scan.sh); then
  echo "check-supply-chain_test: secrets filename regression failed" >&2
  exit 1
fi

echo "check-supply-chain_test: ok"
