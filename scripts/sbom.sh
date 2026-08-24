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
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT HUP INT TERM

goos=${GOOS:-$(GOTOOLCHAIN=go1.25.14 go env GOOS)}
goarch=${GOARCH:-$(GOTOOLCHAIN=go1.25.14 go env GOARCH)}
cgo_enabled=${CGO_ENABLED:-$(GOTOOLCHAIN=go1.25.14 go env CGO_ENABLED)}

GOTOOLCHAIN=go1.25.14 \
GOPROXY=https://proxy.golang.org \
GOSUMDB=sum.golang.org \
GONOSUMDB= \
GOOS="$goos" \
GOARCH="$goarch" \
CGO_ENABLED="$cgo_enabled" \
GOFLAGS=-mod=readonly \
go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0 \
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
trap - EXIT HUP INT TERM
echo "sbom.sh: wrote $out (${goos}/${goarch}, cgo=${cgo_enabled})"
