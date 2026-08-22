# Verification ledger

Every claim in this repository maps to a command run locally (macOS 26.5.2,
arm64, Go 1.25.5) or to CI. Vocabulary: **PASS** = ran, exit 0; **FAIL** =
ran, non-zero (fixed or documented); **BLOCKED** = tool/environment missing,
fallback noted; **NOT RUN** = deliberately skipped, reason given.

## Full-suite evidence (final state of this batch)

| check | command | result |
|---|---|---|
| Formatting | `gofmt -l .` | PASS (empty output) |
| Vet | `go vet ./...` | PASS |
| Build | `go build ./...` | PASS |
| Unit + integration | `go test ./...` | PASS (14 packages) |
| Race detector | `go test -race ./...` | PASS (all 14 packages) |
| Repeated race runs (sensor/runtime stability) | `go test -race -count=2 ./internal/sensor/... ./internal/runtime/` | PASS |
| Ext host stability | `go test -race -count=3 ./internal/ext/` | PASS |

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

## BLOCKED / NOT RUN (honest limits)

| item | status |
|---|---|
| golangci-lint local run | BLOCKED (not installed). Fallback: gofmt + go vet green; CI lint slot reserved. |
| govulncheck local run | BLOCKED (not installed). CI runs it on every push. |
| SBOM generation local run | BLOCKED (syft/cyclonedx-gomod not installed); `scripts/sbom.sh` exits 2 with setup instructions rather than fabricating one. CI generates per-release SBOMs. |
| cosign keyless signing | NOT RUN (roadmap; attestations provide tamper-evidence meanwhile). Documented in docs/RELEASE.md. |
| Kubernetes manifests | NOT RUN by design — docs/deploy/kubernetes.md is a labeled direction document. |
| Docker image build/push | NOT RUN locally this batch (Docker available but image publishing belongs to CI/tag flow); compose file mirrors the tested demo config. |
