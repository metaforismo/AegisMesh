#!/usr/bin/env sh
# sbom.sh — generate a CycloneDX SBOM for the aegismesh binary/module.
#
# Prefers syft (image/directory SBOM) and falls back to the pure-Go
# CycloneDX generator from the Go toolchain ecosystem when available.
# If neither tool is installed, prints exact setup instructions and exits 2 —
# it never fabricates an SBOM.
set -eu

out="${1:-dist/sbom-aegismesh.cdx.json}"
mkdir -p "$(dirname "$out")"

if command -v syft >/dev/null 2>&1; then
  echo "sbom.sh: using syft"
  syft dir:. -o cyclonedx-json="$out"
  echo "sbom.sh: wrote $out"
  exit 0
fi

if command -v cyclonedx-gomod >/dev/null 2>&1; then
  echo "sbom.sh: using cyclonedx-gomod"
  cyclonedx-gomod mod -json -output "$out" ./go.mod
  echo "sbom.sh: wrote $out"
  exit 0
fi

cat >&2 <<'EOF'
sbom.sh: no supported SBOM tool found.

Install one of:
  syft:            https://github.com/anchore/syft (brew install syft)
  cyclonedx-gomod: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

CI generates SBOMs automatically on release tags; this script exists for
local verification. Exiting 2 (tool unavailable, nothing produced).
EOF
exit 2
