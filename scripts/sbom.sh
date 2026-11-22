#!/usr/bin/env sh
# sbom.sh — generate the deterministic CycloneDX application SBOM.
#
# The generator is deliberately invoked through an exact Go module version:
# there is no PATH fallback or floating @latest dependency. The output is
# first written beside the requested destination and then renamed atomically.
set -eu

case "$#" in
  0) out='dist/sbom-aegismesh.cdx.json' ;;
  1) out=$1 ;;
  *)
    echo "usage: $0 [OUTPUT]" >&2
    exit 2
    ;;
esac

[ -n "$out" ] || {
  echo "sbom.sh: output path must not be empty" >&2
  exit 2
}

out_dir=$(dirname "$out")
mkdir -p "$out_dir"
tmp=$(mktemp "$out.tmp.XXXXXX")
tooldir=$(mktemp -d "${TMPDIR:-/tmp}/aegismesh-sbom.XXXXXX")
cleanup() {
  rm -f "$tmp"
  rm -rf "$tooldir"
}
trap cleanup EXIT HUP INT TERM

go_version=$(awk '/^go / {print $2; exit}' go.mod)
[ -n "$go_version" ] || { echo "sbom.sh: go.mod has no go directive" >&2; exit 2; }
export GOTOOLCHAIN="go$go_version"

goos=${GOOS:-$(go env GOOS)}
goarch=${GOARCH:-$(go env GOARCH)}
cgo_enabled=${CGO_ENABLED:-$(go env CGO_ENABLED)}

# Build the generator for the host, then run it with the target's build
# constraints. `go run` would honor GOOS/GOARCH and cross-compile the generator
# itself, which cannot execute when the target differs from the host.
GOPROXY=https://proxy.golang.org \
GOSUMDB=sum.golang.org \
GONOSUMDB= \
GOOS= \
GOARCH= \
GOBIN="$tooldir" \
GOFLAGS=-mod=readonly \
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0

GOPROXY=https://proxy.golang.org \
GOSUMDB=sum.golang.org \
GONOSUMDB= \
GOOS="$goos" \
GOARCH="$goarch" \
CGO_ENABLED="$cgo_enabled" \
GOFLAGS=-mod=readonly \
"$tooldir/cyclonedx-gomod" \
  app \
  -main ./cmd/aegismesh \
  -licenses \
  -std \
  -json \
  -noserial \
  -notimestamp \
  -output-version 1.6 \
  -output "$tmp" \
  .

[ -s "$tmp" ] || {
  echo "sbom.sh: generator produced an empty output" >&2
  exit 1
}
mv "$tmp" "$out"
rm -rf "$tooldir"
trap - EXIT HUP INT TERM
echo "sbom.sh: wrote $out (${goos}/${goarch}, cgo=${cgo_enabled})"
