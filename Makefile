# Makefile — AegisMesh developer entrypoints
# Keep targets boring and explicit. CI mirrors these commands.

BINARY  := bin/aegismesh
MODULE  := github.com/metaforismo/aegismesh
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.Date=$(DATE)

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-14s %s\n", $$1, $$2}'

.PHONY: build
build: ## build ./bin/aegismesh
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/aegismesh

.PHONY: test
test: ## run all tests with race detector
	go test -race ./...

.PHONY: lint
lint: ## gofmt check + go vet (+ golangci-lint when available)
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; skipped (vet+fmt ran)"

.PHONY: helm-contract
helm-contract: ## verify Helm chart contract (guarded test; needs local helm v4)
	@command -v helm >/dev/null 2>&1 || { echo "helm-contract: BLOCKED - helm binary not found in PATH"; exit 1; }
	AEGISMESH_HELM_CONTRACT_TEST=1 go test ./deploy/helm/aegismesh -count=1 -v

.PHONY: fuzz-seed
fuzz-seed: ## run bounded real fuzzing without post-discovery minimization
	go test -run '^$$' -fuzz=FuzzParseConfig ./internal/config -fuzztime=15s -fuzzminimizetime=0
	go test -run '^$$' -fuzz=FuzzDecodeEventEnvelope ./internal/event -fuzztime=15s -fuzzminimizetime=0
	go test -run '^$$' -fuzz=FuzzMatchTCPLine ./internal/sensor/tcpsensor -fuzztime=15s -fuzzminimizetime=0
	go test -run '^$$' -fuzz=FuzzSSHMetadataHelpers ./internal/sensor/sshsensor -fuzztime=15s -fuzzminimizetime=0
	go test -run '^$$' -fuzz=FuzzGenerateObservation ./internal/recommend -fuzztime=15s -fuzzminimizetime=0
	go test -run '^$$' -fuzz=FuzzImportBeelzebubDoc ./internal/migrate/beelzebub -fuzztime=15s -fuzzminimizetime=0

.PHONY: fuzz-short
fuzz-short: ## short real fuzzing pass (~1m/target); CI runs fuzz-seed instead
	go test -run '^$$' -fuzz=FuzzParseConfig ./internal/config -fuzztime=60s -fuzzminimizetime=0

.PHONY: vuln
vuln: ## run the pinned govulncheck release
	GOTOOLCHAIN=go1.25.14 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOFLAGS=-mod=readonly go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

.PHONY: secrets-scan
secrets-scan: ## heuristic secret scan over tracked files
	./scripts/secrets-scan.sh

.PHONY: license-check
license-check: ## verify dependency licenses against policy
	./scripts/license-check.sh

.PHONY: sbom
sbom: ## emit the application SBOM to dist/
	@mkdir -p dist
	./scripts/sbom.sh dist/sbom-aegismesh.cdx.json

.PHONY: sbom-check
sbom-check: ## validate an existing application SBOM without acquisition
	test -s dist/sbom-aegismesh.cdx.json
	GOTOOLCHAIN=go1.25.14 GOFLAGS=-mod=readonly go run ./tools/sbomcheck dist/sbom-aegismesh.cdx.json

.PHONY: supply-chain-check
supply-chain-check: ## verify immutable workflow, image, and tool references
	./scripts/check-supply-chain.sh

.PHONY: demo
demo: build ## scripted end-to-end demo into a temp dir
	./scripts/demo.sh

.PHONY: release
release: ## cross-build release artifacts + checksums + sbom into dist/
	@set -eu; \
	mkdir -p dist; \
	GOTOOLCHAIN=go1.25.14 go mod download; \
	GOTOOLCHAIN=go1.25.14 go mod verify; \
	build() { \
		os=$$1; arch=$$2; \
		out="dist/aegismesh-$(VERSION)-$$os-$$arch"; \
		GOTOOLCHAIN=go1.25.14 GOPROXY=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -buildvcs=true -ldflags '$(LDFLAGS)' -o "$$out" ./cmd/aegismesh; \
		test -s "$$out"; \
	}; \
	generate_sbom() { \
		os=$$1; arch=$$2; \
		GOTOOLCHAIN=go1.25.14 GOOS="$$os" GOARCH="$$arch" CGO_ENABLED=0 ./scripts/sbom.sh "dist/sbom-aegismesh-$$os-$$arch.cdx.json"; \
	}; \
	validate_sbom() { \
		os=$$1; arch=$$2; \
		GOTOOLCHAIN=go1.25.14 GOFLAGS=-mod=readonly go run ./tools/sbomcheck "dist/sbom-aegismesh-$$os-$$arch.cdx.json"; \
	}; \
	build linux amd64; \
	build linux arm64; \
	build darwin amd64; \
	build darwin arm64; \
	generate_sbom linux amd64; \
	generate_sbom linux arm64; \
	generate_sbom darwin amd64; \
	generate_sbom darwin arm64; \
	validate_sbom linux amd64; \
	validate_sbom linux arm64; \
	validate_sbom darwin amd64; \
	validate_sbom darwin arm64; \
	if command -v sha256sum >/dev/null 2>&1; then \
		(cd dist && sha256sum \
			aegismesh-$(VERSION)-linux-amd64 \
			aegismesh-$(VERSION)-linux-arm64 \
			aegismesh-$(VERSION)-darwin-amd64 \
			aegismesh-$(VERSION)-darwin-arm64 \
			sbom-aegismesh-linux-amd64.cdx.json \
			sbom-aegismesh-linux-arm64.cdx.json \
			sbom-aegismesh-darwin-amd64.cdx.json \
			sbom-aegismesh-darwin-arm64.cdx.json > SHA256SUMS.txt); \
	elif command -v shasum >/dev/null 2>&1; then \
		(cd dist && shasum -a 256 \
			aegismesh-$(VERSION)-linux-amd64 \
			aegismesh-$(VERSION)-linux-arm64 \
			aegismesh-$(VERSION)-darwin-amd64 \
			aegismesh-$(VERSION)-darwin-arm64 \
			sbom-aegismesh-linux-amd64.cdx.json \
			sbom-aegismesh-linux-arm64.cdx.json \
			sbom-aegismesh-darwin-amd64.cdx.json \
			sbom-aegismesh-darwin-arm64.cdx.json > SHA256SUMS.txt); \
	else \
		echo "release: sha256sum or shasum is required" >&2; exit 2; \
	fi

.PHONY: clean
clean:
	rm -rf bin dist coverage
