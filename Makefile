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
	go test -run '^$$' -fuzz=FuzzImportBeelzebubDoc ./internal/migrate/beelzebub -fuzztime=15s -fuzzminimizetime=0

.PHONY: fuzz-short
fuzz-short: ## short real fuzzing pass (~1m/target); CI runs fuzz-seed instead
	go test -run '^$$' -fuzz=FuzzParseConfig ./internal/config -fuzztime=60s -fuzzminimizetime=0

.PHONY: vuln
vuln: ## govulncheck if installed
	@command -v govulncheck >/dev/null 2>&1 && govulncheck ./... || echo "govulncheck not installed; skipped"

.PHONY: secrets-scan
secrets-scan: ## heuristic secret scan over tracked files
	./scripts/secrets-scan.sh

.PHONY: license-check
license-check: ## verify dependency licenses against policy
	./scripts/license-check.sh

.PHONY: sbom
sbom: ## emit module inventory to dist/
	@mkdir -p dist && ./scripts/sbom.sh > dist/sbom-modules.txt

.PHONY: demo
demo: build ## scripted end-to-end demo into a temp dir
	./scripts/demo.sh

.PHONY: release
release: ## cross-build release artifacts + checksums + sbom into dist/
	@mkdir -p dist
	go build -trimpath -buildvcs=true -ldflags '$(LDFLAGS)' -o dist/aegismesh-$(VERSION)-darwin-arm64 ./cmd/aegismesh
	GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true -ldflags '$(LDFLAGS)' -o dist/aegismesh-$(VERSION)-linux-amd64 ./cmd/aegismesh
	GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=true -ldflags '$(LDFLAGS)' -o dist/aegismesh-$(VERSION)-linux-arm64 ./cmd/aegismesh
	cd dist && shasum -a 256 aegismesh-* > checksums.txt
	$(MAKE) sbom

.PHONY: clean
clean:
	rm -rf bin dist coverage
