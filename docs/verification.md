# Verification ledger

Every claim in this repository maps to a command run locally (macOS 26.5.2,
arm64; host Go 1.25.5 and project-required Go 1.25.14) or to CI. Vocabulary: **PASS** = ran, exit 0; **FAIL** =
ran, non-zero (fixed or documented); **BLOCKED** = tool/environment missing,
fallback noted; **NOT RUN** = deliberately skipped, reason given.

## 2026-08-24 — deterministic dry-run recommendations

| check | command | result |
|---|---|---|
| Isolated baseline | `git status --short --branch`; `git rev-parse HEAD`; `git log --oneline -5` | PASS — `codex/dry-run-recommendations` started at supply-chain merge `7d0e59113c699857b256cac7db31f8fc030fc946`; the primary checkout was not modified |
| HTTP/TCP finding persistence | `GOCACHE=/tmp/aegismesh-go-cache go test -race ./internal/sensor/httpsensor ./internal/sensor/tcpsensor -count=3` | PASS — real loopback interactions persisted deterministic typed findings, omitted benign detection blocks, retained integrity, and did not leak the synthetic credential marker |
| Core recommendation contract | `GOCACHE=/tmp/aegismesh-go-cache go test ./internal/recommend -count=1`; repeated focused and race runs | PASS — static attacker-independent prose, exact evidence links, deterministic IDs/order, canary-only proposals, correlation resolution, conflict/false-positive metadata, rule-family/schema checks, metadata and collection caps, and filter-before-limit behavior |
| CLI golden and adversarial matrix | `GOCACHE=/tmp/aegismesh-go-cache go test ./internal/cli -run 'TestRecommend' -count=1`; exact human/JSON files under `internal/cli/testdata` | PASS — byte-stable output plus omitted, explicit-empty, whitespace, padded, repeated, comma, missing, invalid, positional, double-dash, unknown, limit-boundary, no-match, malformed-line, invalid-envelope/hash, duplicate-ID, incompatible-block, and over-cap cases; every input failure left stdout empty |
| Streaming reader red regression | `GOCACHE=/tmp/aegismesh-go-cache go test ./internal/storage -run TestReaderStreamsBeforeTrailingScannerFailure -count=1` | PASS — callback termination occurs before a trailing overlong line is materialized; segment open/scanner errors still propagate |
| Sandbox-only focused attempt | `GOCACHE=/tmp/aegismesh-go-cache go test ./internal/storage ./internal/recommend ./internal/cli -count=3` | BLOCKED — unprivileged sandbox denied existing doctor/healthcheck loopback listeners with `operation not permitted`; storage and recommendation passed before the CLI listener boundary |
| Repeated focused suite with loopback access | same command with scoped loopback execution | PASS — storage, recommendation and complete CLI packages passed three repetitions |
| Final affected-package race suite | `GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go test -race ./internal/storage ./internal/recommend ./internal/cli ./internal/event ./internal/sensor/httpsensor ./internal/sensor/tcpsensor -count=1` | PASS |
| Independent adversarial review | read-only Sol review of the complete diff, followed by re-review | PASS after fixes — the review found whole-segment buffering, unbounded/unescaped sensor metadata, a vacuous fuzz target and cap test, and missing golden contracts; streaming reads, pre-retention validation, strict metadata bounds, real fuzz coverage and exact goldens closed every blocking finding |
| Final formatting, vet and all-package race suite | `GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make lint test` | PASS — all packages passed; `golangci-lint` unavailable, so the documented gofmt/vet fallback ran |
| Final six-target fuzz suite | `GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make fuzz-seed` | PASS — config, event, TCP, SSH, recommendation and Beelzebub-import targets each ran 15 seconds with minimization disabled; recommendation executed 1,697,775 cases in the final run |
| Helm, supply-chain and repository hygiene | `make helm-contract`; `make supply-chain-check`; `go mod verify`; `./scripts/license-check.sh`; `./scripts/secrets-scan.sh`; `git diff --check` | PASS — Helm positive/adversarial contract, immutable references, all seven modules, license policy, secret tripwire and patch whitespace passed; no dependency changed |
| Local pinned vulnerability scan | `GOCACHE=/tmp/aegismesh-go-cache make vuln`; scoped retry | BLOCKED — the exact `govulncheck@v1.7.0` tool was not cached, sandbox DNS could not reach `proxy.golang.org`, and the external download retry required separate action-time approval; PR CI must pass the identical pinned gate |
| PR #51 independent CI | `gh pr checks 51 --repo metaforismo/AegisMesh --watch` at `1c036c0` | PASS — full race suite 1m10s, six-target bounded fuzz 2m9s, pinned govulncheck 32s, Helm contract 23s, dependency-license/secret checks 16s, and supply-chain contracts 45s |
| Runtime actions, release writes and new egress | firewall/credential/process/production mutation; tag/release/signing/attestation; webhook/extension correlation fan-out | NOT RUN — no such path was implemented or invoked; each remains a separate architecture and approval boundary |

## 2026-08-24 — supply-chain release-evidence hardening

| check | command | result |
|---|---|---|
| Isolated baseline | `git status --short --branch`; `git rev-parse HEAD` | PASS — `codex/supply-chain-hardening` based on SSH merge `150a305e074f03f2d25dd1c3a0e3f63f1a0f5ece`; the unrelated primary checkout was not modified |
| Container index identity | `docker buildx imagetools inspect golang:1.25.14-alpine`; `docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot` | PASS — verified multiarch index digests `sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59` and `sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` before pinning |
| SBOM validator focused tests | `GOCACHE=/tmp/aegismesh-go-cache go test ./tools/sbomcheck -count=1`; `go vet ./tools/sbomcheck` | PASS — bounded 16 MiB strict JSON/CycloneDX 1.6 parser rejects duplicate fields, trailing data, duplicate/dangling references, empty root graphs, and oversized input |
| Shell and immutable-reference fixtures | `sh -n scripts/sbom.sh scripts/check-supply-chain.sh scripts/check-supply-chain_test.sh scripts/secrets-scan.sh`; `./scripts/check-supply-chain_test.sh`; `./scripts/check-supply-chain.sh` | PASS — exact action SHAs, Docker digests, and external Go `vMAJOR.MINOR.PATCH` tool refs enforced; negative fixtures include partial semantic versions, branches, mutable tags, and dash-prefixed tracked filenames |
| Workflow syntax and expression check | `actionlint .github/workflows/ci.yml .github/workflows/release.yml` | PASS |
| Independent security review | read-only Sol review of the complete supply-chain diff | PASS after fixes — review found publication-wide artifact merging, partial Go version acceptance, incomplete provenance verification, and a local toolchain mismatch; exact named downloads, stricter fixtures, source tag/commit binding, and explicit Go 1.25.14 selection closed them before commit |
| First full-suite attempt | `GOCACHE=/tmp/aegismesh-go-cache make lint test` | FAIL — sandbox denied loopback binds with `operation not permitted`; package failures were environmental, not accepted as product evidence |
| Full formatting, vet and race suite with loopback access | same command with scoped execution outside the bind-restricted sandbox | PASS — all packages, including `tools/sbomcheck`; `golangci-lint` unavailable, documented gofmt/vet fallback used |
| Bounded parser fuzzing | `GOCACHE=/tmp/aegismesh-go-cache make fuzz-seed` | PASS — config, event, TCP, SSH, and Beelzebub-import targets each ran 15 seconds with minimization disabled |
| Helm contract | `GOCACHE=/tmp/aegismesh-go-cache make helm-contract` | PASS — all positive and adversarial chart cases |
| Module, license, secret and patch integrity | `GOTOOLCHAIN=go1.25.14 go mod verify`; `./scripts/license-check.sh`; `./scripts/secrets-scan.sh`; `git diff --check` | PASS — seven modules verified and within policy; no dependency graph change or secret-shaped diff |
| Cross-platform offline compile path | `GOCACHE=/tmp/aegismesh-go-cache make release VERSION=v0.2.0-test`; `file dist/aegismesh-v0.2.0-test-*` | FAIL at the subsequent SBOM acquisition boundary — module verification and all four offline static builds completed with the expected Linux/Darwin amd64/arm64 formats; no checksum file was emitted after the generator failed closed |
| Local CycloneDX generation and determinism | `make sbom`; repeat generation plus `cmp`; `make sbom-check` | BLOCKED — the exact `cyclonedx-gomod@v1.10.0` module was not cached, sandbox DNS could not reach `proxy.golang.org`, and scoped escalation was rejected because this download lacked separate action-time approval; no SBOM PASS is inferred |
| Local pinned vulnerability scan | `GOTOOLCHAIN=go1.25.14 GOFLAGS=-mod=readonly go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...` | BLOCKED — the exact tool was not cached and sandbox DNS could not reach the Go proxy; PR CI must pass the identical pinned target |
| Local Docker build | `docker version`; scoped daemon retry | BLOCKED — client 29.1.3 is installed, but the Docker Desktop daemon did not return server state; no image-build PASS is inferred |
| PR #47 independent CI | `gh pr checks 47 --repo metaforismo/AegisMesh --watch`; `gh run view 32680525563 --job 97296305774 --log` | PASS at `d7fbc6f` — race/full 1m21s, five-target fuzz 1m54s, govulncheck 28s, Helm 29s, license/secrets 18s, supply-chain 43s; the latter acquired CycloneDX GoMod v1.10.0, emitted a real CycloneDX 1.6 application SBOM, printed `SBOM valid`, and passed a byte-for-byte second-generation `cmp` |
| Release, attestation and signing writes | tag/release creation, GitHub provenance generation, checksum publication, cosign/GPG signing | NOT RUN — no tag or release workflow was executed; publication/signing remains a separate approval boundary |

## 2026-08-24 — SSH authentication-deception sensor

| check | command | result |
|---|---|---|
| Isolated baseline | `git status --short --branch`; `git rev-parse HEAD` | PASS — `codex/ssh-auth-sensor` worktree based on `d548d57ceb6ead7ba44b8a697e2f4676897735e9`; unrelated checkout state was not modified |
| GitHub public state before the SSH PR | `gh auth status`; `gh pr list --state open --limit 50 --json number,title,headRefName,baseRefName,isDraft,url`; `gh issue list --state open --limit 50 --json number,title,labels,url` | PASS — authenticated as `metaforismo`; one unrelated open Dependabot PR (#2), no open issues; default branch separately verified as `master` |
| Exa availability and primary-source research | one small `web_search_exa` probe, then multi-pass search/fetch of official repositories, RFC 4252/4254, Go release notes and `x/crypto/ssh` documentation | PASS — connector search/fetch tools were exposed; upstream claims were kept separate from repository facts and engineering inferences |
| Pre-fix vulnerability gate | `go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...` with host Go 1.25.5 | FAIL — exit 3; 17 reachable standard-library findings, including GO-2026-5972 through `sshsensor → ssh.NewServerConn → asn1.Unmarshal`; this blocked the slice until the Go floor was raised |
| Intermediate security-fixed toolchain | `env GOTOOLCHAIN=go1.25.13+auto GOCACHE=/tmp/aegismesh-go-cache go version` | PASS — `go version go1.25.13 darwin/arm64`; this removed the reachable findings before the final current-patch refresh |
| Current patch toolchain | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go version` | PASS — `go version go1.25.14 darwin/arm64`; official Go release history and Docker Hub were rechecked before advancing the final floor |
| Container builder reference | official Docker Hub tag listing for `golang:1.25.14-alpine` | PASS — the official multi-platform tag exists; immutable digest pinning remains the next supply-chain slice |
| Local container build | `docker version --format '{{.Client.Version}} {{.Server.Version}}'` | BLOCKED — client 29.1.3 is installed, but the local daemon socket was unavailable and the scoped retry did not return a server version; no build result inferred |
| Pinned vulnerability scan | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -show verbose ./...` | PASS — 0 reachable symbol vulnerabilities and 0 imported-package vulnerabilities; module-only GO-2026-5932 concerns unused `x/crypto/openpgp`, which is not imported |
| Focused SSH/config repeat | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go test ./internal/config ./internal/sensor/sshsensor -count=3` | PASS — real password/public-key loopback handshakes, invalid proof, channel/request rejection, strict explicit-zero/empty config, connection/deadline caps and shutdown races |
| Affected-package race suite | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go test -race ./internal/sensor/sshsensor ./internal/runtime ./internal/config ./internal/cli ./internal/ecsexport ./internal/migrate/beelzebub -count=1` | PASS |
| SSH fuzz smoke | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go test -run '^$' -fuzz FuzzSSHMetadataHelpers -fuzztime 5s ./internal/sensor/sshsensor` | PASS — 86,309 executions; no failure |
| Module integrity and license graph | `go list -m all`; `go mod verify`; `./scripts/license-check.sh` under Go 1.25.14 | PASS — seven non-main modules resolved, all checksums verified and all licenses within policy |
| First full-suite attempt | `env GOTOOLCHAIN=go1.25.13+auto GOCACHE=/tmp/aegismesh-go-cache make lint test` | FAIL — existing extension negative-handshake case timed out under full race-suite load; all SSH/config/runtime packages passed |
| Extension timeout diagnosis | `go test -race ./internal/ext -run TestHostHandshakeFailures -count=10 -v` | PASS — all 30 subtests passed; no SSH dependency or runtime regression found |
| Pre-fix runtime readiness repeat | affected-package race command above after the final test additions | FAIL — the extension integration test timed out waiting for the HTTP listener; review showed `/readyz` counted configured sensors before their listeners started |
| Runtime readiness regression repeat | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache go test -race ./internal/runtime -run 'TestSystemEndToEndLifecycle|TestSystemDeliversObservationsToExtension|TestSystemStreamsEvidenceToWebhook' -count=5 -v` | PASS — five cycles each; `/readyz` now becomes ready only after all four sensor listeners start |
| Final formatting, vet and all-package race suite | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make lint test` | PASS — all 30 packages evaluated after the readiness fix; `golangci-lint` unavailable, documented `gofmt`/`go vet` fallback used |
| Initial concurrent fuzz attempt | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make fuzz-seed` while Helm and vulnerability checks ran concurrently | FAIL — config fuzzing returned `context deadline exceeded` after 92,709 executions; no crashing input was produced |
| Fuzz deadline diagnosis | config fuzz with default minimization, one worker, and `-fuzzminimizetime=0` variants | PASS — the stall was Go's independent 60-second post-discovery minimization under contention, not a reproduced parser loop; disabling minimization sustained 923,359 executions in 15 seconds |
| Repository fuzz suite, clean rerun | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make fuzz-seed` | PASS — config, event, TCP-line, SSH-metadata and Beelzebub-import targets ran for 15 seconds each; the final bounded rerun after adding `-fuzzminimizetime=0` is recorded below |
| Final bounded fuzz rerun | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make fuzz-seed` | BLOCKED — the Codex execution reviewer rejected the local command after the session reached its usage limit; no local PASS is inferred. The PR fuzz job runs the same five commands with `-fuzzminimizetime=0` and is required before merge |
| PR #46 independent CI | `gh pr checks 46 --repo metaforismo/AegisMesh --watch` at `31c9e395d67ff9b98d854cf1761bdcf661ae8f06` | PASS — full race suite (1m19s), five-target bounded fuzz (1m55s), Helm contract, pinned govulncheck, and dependency-license/secret checks all completed successfully |
| Helm SSH packaging contract | `env GOTOOLCHAIN=go1.25.14+auto GOCACHE=/tmp/aegismesh-go-cache make helm-contract` | PASS — positive SSH sensor/schema render plus existing positive and adversarial cases |
| Secret and patch hygiene | `./scripts/secrets-scan.sh`; `git diff --check` | PASS |

## 2026-08-23 — Batch 2 R3 and shutdown correctness

| check | command | result |
|---|---|---|
| Repository baseline | `git status --short --branch`; `git rev-parse HEAD`; `git remote -v` | PASS — clean `master`, HEAD `cf8bdee19625e78ee82e399f9531331e78173b94`, origin points to `metaforismo/AegisMesh` before the isolated worktree was created |
| Baseline suite | `make lint test` | PASS — `go vet` and `go test -race ./...`; `golangci-lint` unavailable, documented fallback used |
| ECS mapping and strict CLI matrix | `go test ./internal/ecsexport ./internal/cli -run 'TestMarshal\|TestInspectExport\|TestInspectShowRejects' -count=1` | PASS |
| Final export security review | `go test ./internal/storage ./internal/cli -run 'TestInspectExportRejectsStructurallyInvalidNativeEnvelope\|TestInspectExportRejectsEvidenceSegmentDestination\|TestInspectExportNativeProfileOmittedIsByteCompatible' -count=1` | PASS — native schema validation plus direct/symlink/hardlink source-segment rejection |
| Export failure regressions before fix | `go test ./internal/cli -run 'TestInspectExportRejectsUnexpectedArgumentsWithoutTouchingOutput\|TestInspectExportVerifyFailsClosedWithoutTouchingOutput' -count=1` | FAIL — reproduced positional-argument target replacement and verified-export success despite tampering; fixed in this batch |
| Bus regression before fix | `go test ./internal/event -run TestBusSubmitAfterCloseReturnsFalse -count=1` | FAIL — reproduced `panic: send on closed channel`; fixed in this batch |
| Concurrent lifecycle stress | `go test -race ./internal/event ./internal/webhook ./internal/extmanager -run 'TestBusSubmitAfterCloseReturnsFalse\|TestBusConcurrentSubmitAndClose\|TestOfferConcurrentWithClose\|TestDeliverConcurrentWithStop' -count=10`; extension test repeated separately with `-count=3` | PASS |
| Global shutdown idempotence | `go test -race ./internal/runtime -run TestSystemStopConcurrentIsIdempotent -count=10` | PASS |
| Runtime extension readiness after full-suite timeout diagnosis | `go test -race ./internal/runtime -run 'TestSystemDeliversObservationsToExtension\|TestSystemStopConcurrentIsIdempotent' -count=3` | PASS at that snapshot — the test wait was lengthened; the later SSH slice fixed the underlying premature `/readyz` status |
| Final formatting, vet, build and all package races | `make lint test` | PASS — 29 packages enumerated by `go list ./...`; scoped loopback permission was required for integration listeners |
| Parser fuzz seeds | `make fuzz-seed` | PASS — config, event, TCP-line and Beelzebub-import fuzz targets, 15 seconds each |
| Helm packaging contract | `make helm-contract` | PASS — positive and adversarial chart cases |
| Dependency license policy | `./scripts/license-check.sh` | PASS — 2 modules within policy; this batch added no dependency |
| Secret tripwire | `./scripts/secrets-scan.sh` | PASS |
| Patch hygiene | `git diff --check` | PASS |

## 2026-08-24 — evidence reader fail-closed hotfix

| check | command | result |
|---|---|---|
| Red segment-read regression | `go test ./internal/cli -run TestInspectExportFailsClosedOnSegmentReadError -count=1` | FAIL before fix — export returned 0 and reported `exported 0 event(s)` after a segment read failure |
| Focused reader/export regression | `go test ./internal/storage ./internal/cli -run 'TestInspectExportFailsClosedOnSegmentReadError\|TestInspectExportVerifyFailsClosedWithoutTouchingOutput' -count=1` | PASS |
| Focused reader/export race repeat | `go test -race ./internal/storage ./internal/cli -run 'TestInspectExportFailsClosedOnSegmentReadError\|TestInspectExportVerifyFailsClosedWithoutTouchingOutput' -count=5` | PASS |
| First full-suite attempt | `make lint test` | FAIL — two extension-host tests hit their handshake timeout under load; the changed storage/CLI packages passed |
| Extension timeout diagnosis | `go test -race ./internal/ext -run 'TestHostHandshakeFailures\|TestHostCallDeadlineRevokesProcess' -count=3 -v` | PASS — all six test cases passed three consecutive runs |
| Final formatting, vet and full race suite | `make lint test` | PASS — unchanged retry; `golangci-lint` unavailable, documented `go vet` fallback used |
| License, secret and patch hygiene | `./scripts/license-check.sh`; `./scripts/secrets-scan.sh`; `git diff --check` | PASS — no dependency change |

Current evidence boundaries:

- **BLOCKED:** local `golangci-lint`, CycloneDX tooling and cosign are unavailable. The Makefile's documented formatting/vet fallback and pinned `govulncheck` through `go run` were used; no SBOM or signature result was inferred.
- **BLOCKED:** the local Docker daemon was unavailable, so this environment did
  not produce a container build; the official builder tag was verified and CI
  remains the executable container gate.
- **NOT RUN:** release publication/signing, real-cluster deployment, repository-setting changes, new egress and correlation-signal fan-out were outside this batch's authority.

## Prior captured full-suite evidence (through `cf8bdee`)

| check | command | result |
|---|---|---|
| Formatting | `gofmt -l .` | PASS (empty output) |
| Vet | `go vet ./...` | PASS |
| Build | `go build ./...` | PASS |
| Unit + integration | `go test ./...` | PASS (historical snapshot) |
| Race detector | `go test -race ./...` | PASS (historical snapshot) |
| Repeated race runs (sensor/runtime stability) | `go test -race -count=2 ./internal/sensor/... ./internal/runtime/` | PASS |
| Ext host stability | `go test -race -count=3 ./internal/ext/` | PASS |
| Correlation engine determinism/race | `go test -race ./internal/correlate/ && go test -count=5 ./internal/correlate/` | PASS |
| Correlation CLI surface | `go test ./internal/cli/ -run 'TestDoctorCorrelation|TestValidateEffectiveIncludes'` | PASS |

## Fuzz smoke (bounded sessions on this machine)

| target | command | result |
|---|---|---|
| config parser | `go test -run '^$' -fuzz FuzzParseConfig -fuzztime 10s ./internal/config/` | PASS (earlier 10s + final 5s) |
| event envelope decode | `go test -run '^$' -fuzz FuzzDecodeEventEnvelope -fuzztime 5s ./internal/event/` | PASS |
| TCP line reader | `go test -run '^$' -fuzz FuzzMatchTCPLine -fuzztime 5s ./internal/sensor/tcpsensor/` | PASS (~389k execs) |
| SSH metadata bounds | `go test -run '^$' -fuzz FuzzSSHMetadataHelpers -fuzztime 5s ./internal/sensor/sshsensor/` | PASS (86,309 execs) |
| Beelzebub importer | `go test -run '^$' -fuzz FuzzImportBeelzebubDoc -fuzztime 8s ./internal/migrate/beelzebub/` | PASS (~224k execs, 300 corpus entries) |

CI runs all five targets at 15s each on every push.

## End-to-end behavior

| scenario | command | result |
|---|---|---|
| Demo walkthrough (HTTP+TCP+MCP decoys, metrics, SIGTERM shutdown, verified evidence) | `./scripts/demo.sh` | PASS — 3 events recorded, `INTEGRITY true`, counters incremented before shutdown |
| Dry-run binding proof | `go run ./cmd/aegismesh run --config examples/demo/mesh.yaml --dry-run` | PASS — 3 sensors bound and stopped cleanly |
| Strict validation of demo config | `go run ./cmd/aegismesh validate --config examples/demo/mesh.yaml` | PASS |
| Effective-policy preview (validate --effective, human + pure-JSON) | `go test -run 'TestValidateEffective' ./internal/cli/` | PASS |
| inspect --finding filter (match, empty match, invalid rule id, verified JSON rows) | `go test -run TestInspectFindingFilter ./internal/cli/` | PASS |
| init provider profiles load through strict loader; doctor credential-reference states | `go test -run 'TestInitProfiles|TestInitRejectsUnknownProfile|TestDoctorRemoteProfileKeyFileStates' ./internal/cli/` | PASS |
| Importer refuses inline credential material with non-zero exit; references reported, never carried or echoed | `go test -run 'TestMigrateRefuses|TestMigrateReports' ./internal/cli/` | PASS |
| Example migration fixtures round-trip through the strict loader | `go test -run TestMigrateExampleFixturesRoundTrip ./internal/cli/` | PASS |
| Race detector on touched packages | `go test -race -count=1 ./internal/cli/ ./internal/migrate/beelzebub/` | PASS |
| Extension observer supervisor (slow/failing/crashing/backpressured synthetic extensions, revocation, bounded shutdown, drop accounting) | `go test -race -count=1 ./internal/extmanager/` | PASS |
| Runtime wiring: observations delivered to a real observer subprocess; fail-closed on missing manifest / respond-only extension | `go test -race -count=1 -run 'TestSystemDelivers|TestBuildFailsClosedOnMissing|TestBuildFailsClosedOnRespond' ./internal/runtime/` | PASS |
| Webhook config schema: egress-validated destinations, secret references, bounds, defaults | `go test -run 'TestWebhookSectionValidation|TestResolveWebhookSecret' ./internal/config/` | PASS |
| Webhook delivery engine: signed batches, retry+jitter, redirect refusal, dial-time egress re-classification, bounded shutdown | `go test -race -count=3 ./internal/webhook/` | PASS |
| Runtime fan-out: decoy → store AND signed webhook batch end-to-end; unresolvable secret fails startup | `go test -race -run 'TestSystemStreamsEvidenceToWebhook|TestBuildFailsClosedOnUnresolvableWebhookSecret' ./internal/runtime/` | PASS |
| Webhook readiness in doctor/validate --effective (no contact) + opt-in signed probe | `go test -race -run 'TestValidateEffectiveShowsWebhook|TestDoctorWebhook|TestDoctorWarnsOnUnsigned' ./internal/cli/` | PASS |
| inspect --finding filter (match, empty match, invalid rule id, verified JSON rows) | `go test -run TestInspectFindingFilter ./internal/cli/` | PASS |
| Importer refuses inline credential material with non-zero exit; references reported, never carried or echoed | `go test -run 'TestMigrateRefuses|TestMigrateReports' ./internal/cli/` | PASS |
| Example migration fixtures round-trip through the strict loader | `go test -run TestMigrateExampleFixturesRoundTrip ./internal/cli/` | PASS |
| Importer output passes strict loader (in-test round trip) | `go test -run TestEmitConfigRoundTripsThroughStrictLoader ./internal/migrate/beelzebub/` | PASS |
| Extension contract incl. real subprocess handshake/call/revocation | `go test -race ./internal/ext/` | PASS |
| License policy scan | `./scripts/license-check.sh` | PASS (2 modules within policy) |
| Secret tripwire scan | `./scripts/secrets-scan.sh` | PASS |
| Shell scripts syntax | `sh -n scripts/*.sh` | PASS |

## Known failures found and fixed during development

Tests were written to expose behavior first; the following production fixes
resulted (root causes fixed, not assertions bent):

1. MCP `writeRPC` dropped parse-error objects → responses were `{}` with
   HTTP 200 instead of JSON-RPC error objects. Rewritten; protocol-error test
   now pins the contract.
2. Extensions inherited the operator's full environment → untrusted child
   processes could read secrets like `AEGISMESH_LLM_API_KEY`. Now spawned with
   a fixed minimal env (`AEGISMESH_EXTENSION=1`) and cwd pinned to the
   manifest directory.
3. `ext verify` panicked (nil deref) when a pubkey was supplied for an
   unsigned manifest. Presence is now checked before any dereference;
   regression test added.
4. Redaction: universal `$1=` replacement left artifacts for groupless
   patterns, and JSON-style keys (`"password":"hunter2"`) escaped scrubbing.
   Per-pattern replacements + a JSON-key rule added; redaction tests extended.
5. `migrate beelzebub` never parsed flags (files always "missing", flags
   ignored). Interleaved positional/flag parsing implemented; CLI tests pin it.
6. Sensor listeners raced across goroutines (`Addr()` vs `Close()`); guarded
   with mutexes across sensor implementations.
7. Runtime maintenance goroutine leaked after Stop; now halts via closed
   channel.
8. Port `0` rejected by validation although ephemeral binds are legitimate;
   documented and allowed.
9. Verified export truncated or replaced its target before validation and
   returned success after skipping tampered events. Export now stages locally,
   refuses partial verified output and atomically replaces the target only on success.
10. Event, webhook and extension producers could race channel closure. Lifecycle
    locks now cover the closed-state check through each non-blocking send; runtime
    shutdown is whole-sequence idempotent.
11. Runtime readiness previously counted every configured sensor before any
    listener started. `SensorsStarted` now advances only after successful
    starts, so `/readyz` is the integration tests' authoritative startup gate.
12. Native export trusted a matching payload hash without structural validation,
    and `--out` could resolve to an authoritative source segment. All profiles now
    validate envelopes, and segment identity checks cover direct, symbolic and hard links.

## BLOCKED / NOT RUN (honest limits)

| item | status |
|---|---|
| golangci-lint local run | BLOCKED (not installed). Fallback: gofmt + go vet green; CI lint slot reserved. |
| govulncheck current local supply-chain rerun | BLOCKED (exact v1.7.0 tool absent from cache and sandbox Go-proxy DNS unavailable). PR #47 CI passed the pinned scan; the local boundary remains BLOCKED rather than rewritten as PASS. |
| SBOM generation local run | BLOCKED (exact CycloneDX GoMod v1.10.0 tool absent from cache and sandbox Go-proxy DNS unavailable); `scripts/sbom.sh` fails closed and leaves no fabricated output. PR #47 CI generated, validated, and reproduced the application SBOM. |
| cosign keyless signing | NOT RUN (roadmap; attestations provide tamper-evidence meanwhile). Documented in docs/RELEASE.md. |
| Real-cluster Kubernetes smoke | NOT RUN; the Helm chart contract is PASS, but no cluster-support claim is made. |
| Docker image build/push | BLOCKED for local build because the Docker Desktop daemon did not return server state; image publication remains NOT RUN and belongs to a separately approved release flow. |
