# Verification ledger

Every claim in this repository maps to a command run locally (macOS 26.5.2,
arm64, Go 1.25.5) or to CI. Vocabulary: **PASS** = ran, exit 0; **FAIL** =
ran, non-zero (fixed or documented); **BLOCKED** = tool/environment missing,
fallback noted; **NOT RUN** = deliberately skipped, reason given.

## 2026-08-23 — Batch 2 R3 and shutdown correctness

| check | command | result |
|---|---|---|
| Repository baseline | `git status --short --branch`; `git rev-parse HEAD`; `git remote -v` | PASS — clean `master`, HEAD `cf8bdee19625e78ee82e399f9531331e78173b94`, origin points to `metaforismo/AegisMesh` before the isolated worktree was created |
| Baseline suite | `make lint test` | PASS — `go vet` and `go test -race ./...`; `golangci-lint` unavailable, documented fallback used |
| ECS mapping and strict CLI matrix | `go test ./internal/ecsexport ./internal/cli -run 'TestMarshal\|TestInspectExport\|TestInspectShowRejects' -count=1` | PASS |
| Export failure regressions before fix | `go test ./internal/cli -run 'TestInspectExportRejectsUnexpectedArgumentsWithoutTouchingOutput\|TestInspectExportVerifyFailsClosedWithoutTouchingOutput' -count=1` | FAIL — reproduced positional-argument target replacement and verified-export success despite tampering; fixed in this batch |
| Bus regression before fix | `go test ./internal/event -run TestBusSubmitAfterCloseReturnsFalse -count=1` | FAIL — reproduced `panic: send on closed channel`; fixed in this batch |
| Concurrent lifecycle stress | `go test -race ./internal/event ./internal/webhook ./internal/extmanager -run 'TestBusSubmitAfterCloseReturnsFalse\|TestBusConcurrentSubmitAndClose\|TestOfferConcurrentWithClose\|TestDeliverConcurrentWithStop' -count=10`; extension test repeated separately with `-count=3` | PASS |
| Global shutdown idempotence | `go test -race ./internal/runtime -run TestSystemStopConcurrentIsIdempotent -count=10` | PASS |
| Runtime extension readiness after full-suite timeout diagnosis | `go test -race ./internal/runtime -run 'TestSystemDeliversObservationsToExtension\|TestSystemStopConcurrentIsIdempotent' -count=3` | PASS — readiness wait now matches the 15-second production startup deadline plus test margin |
| Final formatting, vet, build and all package races | `make lint test` | PASS — 29 packages enumerated by `go list ./...`; scoped loopback permission was required for integration listeners |
| Parser fuzz seeds | `make fuzz-seed` | PASS — config, event, TCP-line and Beelzebub-import fuzz targets, 15 seconds each |
| Helm packaging contract | `make helm-contract` | PASS — positive and adversarial chart cases |
| Dependency license policy | `./scripts/license-check.sh` | PASS — 2 modules within policy; this batch added no dependency |
| Secret tripwire | `./scripts/secrets-scan.sh` | PASS |
| Patch hygiene | `git diff --check` | PASS |

Current evidence boundaries:

- **BLOCKED — Exa connector tools are not exposed to this task.** Native web research used official sources instead.
- **BLOCKED:** `gh pr list` and `gh issue list` could not connect to `api.github.com`, including a scoped network retry. Authentication status was available, but public PR/issue state remains unverified.
- **BLOCKED:** the first full-suite attempt could not bind loopback listeners inside the sandbox. The identical scoped retry ran; one runtime readiness test then exposed a real load-sensitive timeout, which was fixed and followed by a green final suite.
- **BLOCKED:** local `golangci-lint`, `govulncheck`, CycloneDX tooling and cosign are unavailable. No result was inferred for those tools.
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
| Beelzebub importer | `go test -run '^$' -fuzz FuzzImportBeelzebubDoc -fuzztime 8s ./internal/migrate/beelzebub/` | PASS (~224k execs, 300 corpus entries) |

CI runs all four targets at 15s each on every push.

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
   with mutexes in all three sensors.
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
11. The extension integration readiness wait was shorter than the production
    startup deadline and failed under full race-suite load. The test now derives
    its bound from `startTimeout` and the focused repeated run is green.

## BLOCKED / NOT RUN (honest limits)

| item | status |
|---|---|
| golangci-lint local run | BLOCKED (not installed). Fallback: gofmt + go vet green; CI lint slot reserved. |
| govulncheck local run | BLOCKED (not installed). CI runs it on every push. |
| SBOM generation local run | BLOCKED (syft/cyclonedx-gomod not installed); `scripts/sbom.sh` exits 2 with setup instructions rather than fabricating one. CI generates per-release SBOMs. |
| cosign keyless signing | NOT RUN (roadmap; attestations provide tamper-evidence meanwhile). Documented in docs/RELEASE.md. |
| Real-cluster Kubernetes smoke | NOT RUN; the Helm chart contract is PASS, but no cluster-support claim is made. |
| Docker image build/push | NOT RUN locally this batch (Docker available but image publishing belongs to CI/tag flow); compose file mirrors the tested demo config. |
