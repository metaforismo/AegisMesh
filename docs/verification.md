# Verification ledger

Current evidence is kept first. The detailed cumulative ledger through
2026-08-24 is preserved in
[`verification-history-through-2026-08-24.md`](verification-history-through-2026-08-24.md).

Vocabulary: **PASS** means the named command or external check actually ran and
succeeded; **FAIL** means it ran and failed; **BLOCKED** means the required tool,
checkout, permission or environment was unavailable; **NOT RUN** means the
check or external action was deliberately not executed. Evidence from hosted CI
does not turn an unavailable local command into a local PASS.

## 2026-11-14 — whole-repository Go security refresh

Baseline: clean `security/go-toolchain-vuln-fixes` at `01579d3`. Local host:
macOS arm64. Selected Go **1.27.4**, `golang.org/x/crypto` **v0.59.0** and
`golang.org/x/sys` **v0.50.0**. The public Go proxy returned these latest
module releases; x/crypto selects x/net v0.62.0, x/term v0.48.0 and x/text
v0.44.0. Both upgraded modules retain BSD-3-Clause licenses. No runtime
module was added. The SSH advisories
[GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) were fixed in v0.56.0.
[Go release history](https://go.dev/doc/devel/release#go1.27.4) identifies
the selected security patch. No fallback to Go 1.26 was made.

Make and the standalone SBOM script derive their exact toolchain from the
module's `go` directive. Formatting uses that toolchain's gofmt. Every CI and
release `setup-go` step already uses `go-version-file: go.mod`; those workflows
need no duplicate version edit. Extension fixture modules use the same version.
Govulncheck v1.7.0 and CycloneDX GoMod v1.10.0 remain pinned.

| Command / check | Result and captured output |
|---|---|
| Baseline `make vuln` before edits | **FAIL**, make exit 2 (scanner exit 3): `Your code is affected by 14 vulnerabilities from 1 module and the Go standard library.` Also reported 1 imported-package and 3 module-only findings. |
| Docker Hub registry index resolution | **PASS**: authenticated GET of `https://registry-1.docker.io/v2/library/golang/manifests/1.27.4-alpine` returned an OCI multi-platform index; `Docker-Content-Digest` matched SHA-256 of the response bytes: `sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf`. Index includes Linux amd64 and arm64. |
| `GOTOOLCHAIN=go1.27.4 go version` | **PASS**, exit 0: `go version go1.27.4 darwin/arm64`. |
| `GOTOOLCHAIN=go1.27.4 go get golang.org/x/crypto@v0.59.0 golang.org/x/sys@v0.50.0` | **PASS**, exit 0: upgraded x/crypto v0.55.0 to v0.59.0 and x/sys v0.47.0 to v0.50.0. |
| `go mod tidy` | **PASS**, exit 0; module graph and checksums refreshed under Go 1.27.4. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `make lint test` | **PASS**, exit 0: gofmt, `go vet ./...` and `go test -race ./...` across all packages; `golangci-lint` is not installed locally (documented fallback). One earlier run under heavy concurrent host load failed `TestHostHandshakeFailures/echoes_wrong_frame_type` on its fixed 2 s handshake timeout; the test passed 6/6 in isolation (`-race -count=6`) and in the clean full rerun. Recorded as a pre-existing load-sensitive test, not changed here. |
| `make vuln` | **PASS**, exit 0: `No vulnerabilities found.` (govulncheck v1.7.0 under Go 1.27.4). |
| `make fuzz-seed` | **PASS**, exit 0: all eight bounded targets. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `./scripts/check-supply-chain_test.sh` | **PASS**, exit 0. Checker and fixtures needed no version-specific change. |
| `make license-check secrets-scan` | **PASS**, exit 0: `license-check: ok — 7 module(s) within policy` / `secrets-scan: ok`. |
| `make helm-contract` | **PASS**, exit 0 with Helm `v4.2.2`. |
| `make sbom sbom-check` | **BLOCKED** locally: the pinned CycloneDX generator fails with `failed to determine version of main module: git: reference not found` inside a linked `git worktree`, which is where this change was prepared. Hosted CI on the pull-request head is the acceptance evidence for this gate. |
| `sh -n scripts/sbom.sh` / `git diff --check` | **PASS**, exit 0. |

An earlier attempt in the same session was interrupted by a full disk; every
gate above was rerun afterwards. No tests or gates were weakened. Historical
ledgers were left intact. No tag, release publication, container
build/publication or deployment was performed.

## 2026-08-31 — storage `max_event_bytes` enforcement

| Check | Command / evidence | Status |
|---|---|---|
| Isolated source and toolchain | exact `master` source snapshot with temporary branch-only workflow removed; `/mnt/data/aegismesh-workspace/toolchain/x64/bin/go version` | PASS — source matches public `52b6ead` outside the removed temporary workflow; Go `1.25.14 linux/amd64` |
| Red implementation audit | compare config default/validation, `runtime.Build` and `storage.Options` | FAIL before fix — `storage.max_event_bytes` was never passed to or enforced by the store |
| Focused storage regressions | `go test ./internal/storage -run 'Test(MaxEventBytes|OversizeEventRejected|AppendAndReadBack)' -count=1 -v` | PASS |
| Runtime wiring regression | `go test ./internal/runtime -run TestBuildWiresStorageMaxEventBytes -count=1 -v` | PASS |
| Affected race suite | `go test -race -count=1 ./internal/storage ./internal/runtime` | PASS |
| Repository-wide local gate | two `make lint test` attempts, the second with a warm cache | BLOCKED — `go vet ./...` passed and the race run completed through 23 packages before this execution wrapper terminated the still-running aggregate command; affected packages and additional sensor packages passed separately, and exact-head PR CI remains the authoritative aggregate gate |
| Dependency and egress change | `git diff -- go.mod go.sum`; runtime destination review | PASS — no dependency, secret, provider, webhook, extension or destination changed |
| Module, supply-chain, license and secret checks | `go mod verify`; `make supply-chain-check`; offline cached `make license-check`; `make secrets-scan` | PASS — seven resolved modules remained within policy; no module graph changed |
| Helm contract locally | `make helm-contract` | BLOCKED — no Helm binary is installed in this environment; the unchanged chart remains covered by required PR CI |
| Release and repository administration | publication, tag, signing, settings and cluster actions | NOT RUN |

## 2026-08-31 — repository ground truth and PR #54 truth-sync

| Check | Command / evidence | Status |
|---|---|---|
| Requested local checkout | `test -d /Users/francescogiannicola/Documents/ChatGPT/AegisMesh`; search mounted work areas | BLOCKED — the macOS path is not mounted in this Linux execution environment and no alternate AegisMesh checkout was present |
| Local toolchain | `go version` | BLOCKED for repository gates — available Go is `go1.23.2 linux/amd64`, below the module requirement `go 1.25.14`; no source checkout is available to test |
| Public repository identity | GitHub repository metadata and branch/commit queries | PASS — `metaforismo/AegisMesh`, default branch `master`, baseline `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4` |
| Process-isolation merge | PR #54 metadata | PASS — PR #54 is merged; head `6ded0223235fbb383f65accf762aa67fe481e316`, merge commit `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4` |
| PR #54 hosted CI | workflow run `32717789361` | PASS — `fmt, vet, build, test (-race)` including Linux/Darwin cross-build; eight bounded fuzz targets; Helm contract; pinned `govulncheck`; dependency-license and secret checks; deterministic CycloneDX generation and validation all concluded `success` |
| Exa connector probe | one `web_search_exa` call and one `web_fetch_exa` call | PASS — both connector functions returned results; historical blocked entries remain archived as historical environment facts |
| Public maintenance queue | GitHub open PR and issue queries | PASS — no open issues; open Dependabot PRs #48 and #49 require policy-aware review |
| Local `make lint test` | unavailable checkout and insufficient local Go version | BLOCKED — not run in this environment; PR #54 hosted CI remains independent evidence for its exact head only |
| Documentation-only dependency/egress review | compare proposed truth-sync paths with runtime/module files | PASS — no `go.mod`, `go.sum`, runtime destination, provider, webhook or extension behavior changes in this block |
| Release, tag, signing, image and cluster actions | external-state review | NOT RUN — no release publication, tag, signature, attestation execution, image publication, repository-setting change or Kubernetes deployment was performed |

## Required evidence for the next implementation slice

Optional evidence-at-rest encryption is not complete until the exact PR head has:

- focused config, storage, reader and CLI tests;
- wrong-key, corruption, truncation, restart, rotation, retention and recovery
  integration cases;
- affected-package `go test -race`;
- `make lint test` and applicable bounded fuzzing;
- `go mod verify`, dependency-license, secret, vulnerability and deterministic
  CycloneDX checks;
- documentation, ADR, threat-model, backlog and handoff truth-sync;
- all required hosted jobs green before merge.

Release publication and real-cluster operation remain separate `NOT RUN` actions
unless explicitly authorized at action time.
