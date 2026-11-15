# Verification ledger

Current evidence is kept first. The detailed cumulative ledger through
2026-08-24 is preserved in
[`verification-history-through-2026-08-24.md`](verification-history-through-2026-08-24.md).

Vocabulary: **PASS** means the named command or external check actually ran and
succeeded; **FAIL** means it ran and failed; **BLOCKED** means the required tool,
checkout, permission or environment was unavailable; **NOT RUN** means the
check or external action was deliberately not executed. Evidence from hosted CI
does not turn an unavailable local command into a local PASS.

## 2026-11-15 — stack status

**Status record, not a new test run.** The work of 2026-11-14/15 is committed and
pushed as a stack of open, unmerged pull requests against `master` (`01579d3`).
Each PR is stacked on the previous one. Older entries below that say "uncommitted"
or name a candidate describe the state when they were written.

| PR | Branch | Content | Hosted CI on PR head | Merged? |
|---|---|---|---|---|
| #72 | `security/go-toolchain-vuln-fixes` | Go 1.27.4, x/crypto v0.59.0 | **PASS**, all 6 jobs | no |
| #73 | `feat/evidence-at-rest-encryption` (on #72) | opt-in age/X25519 evidence encryption | **PASS**, all 6 jobs | no |
| #74 | `feat/console-api` (on #73) | operator console API | **PASS**, all 6 jobs | no |
| #75 | `feat/console-ui-embed` (on #74) | embedded console UI, design system, landing page | **PASS**, all 6 jobs, including the Node UI tests step | no |
| pending | `feat/fleet-enrollment` (on #75) | experimental fleet inventory | **NOT RUN** | no |

No release, tag, image, signature, deployment or repository-setting change
happened. Dependabot PRs #68 and #70 are superseded by #72 but still open; #71
(pinned Action bumps) is untriaged.

**Manual browser verification, 2026-11-15.**

- Console against the real server started by `aegismesh demo --console`: login,
  overview, events, recommendations, node, audit and investigation creation.
- Fleet with two real processes on loopback: a token minted through the operator
  API; an agent enrolled and appeared `online`; interaction counters propagated;
  after the agent stopped it became `stale` once three 10 s heartbeats were
  missed; a token created from the Fleet screen was recorded in the audit trail.
- Fleet token revocation was **not** re-run in the browser. It was verified by
  the backend two-process run and automated tests.

## 2026-11-15 — fleet review: abuse resistance and heartbeat write coalescing

**PASS — local fixes and requested gates.** Base is the local draft `ad53dc7`
(`wip(fleet): draft before review`), branch `feat/fleet-enrollment`. These changes
were uncommitted when the entry was written; they are now committed on
`feat/fleet-enrollment` (PR pending). No commit, push, branch switch or `gh`
command was run during the recorded checks.
`docs/architecture/console-api.md` and the operator-facing response shapes are
unchanged. No module files, dependencies or configuration knobs were added.
This entry supersedes the earlier candidate's rejection-audit, replay-budget and
per-heartbeat durability claims; the earlier verification record is historical.

All suites ran sequentially on macOS arm64 / Apple M3, Go 1.27.4, with
`GOTOOLCHAIN=go1.27.4 GOFLAGS=-p=1 GOMAXPROCS=2`. The `vuln` target itself
sets `GOFLAGS=-mod=readonly`, as printed in the captured command output.
[Raw command output](fleet-review-verification.log) includes the initial expected
regression failures, all benchmark samples, and the final complete gate outputs.
[Decision trail](fleet-review-decisions.tsv) records the main tradeoffs.

| Check | Exact command | Result |
| --- | --- | --- |
| Formatting, vet and complete race suite | `make lint test` | **PASS**, exit 0; all packages passed. Optional `golangci-lint` was not installed and was skipped explicitly; gofmt/vet ran. |
| Fresh affected-package race suite | `go test -race -count=1 ./internal/fleet/... ./internal/console/... ./internal/runtime` | **PASS**, exit 0; all 10 packages passed. |
| Bounded real fuzzing | `make fuzz-seed` | **PASS**, exit 0; all 12 targets passed at 15 seconds each. Fleet protocol: 680703 executions, 44 new interesting inputs, no failure. |
| Pinned vulnerability check | `make vuln` | **PASS**, exit 0; `No vulnerabilities found.` |
| Heartbeat benchmark | `go test ./internal/fleet/hub -run '^$' -bench '^BenchmarkHeartbeat1000$' -benchmem -benchtime=200x -count=3` | **PASS**, exit 0; before/after samples below. |
| Patch whitespace | `git diff --check` | **PASS**, exit 0; no output, repeated after this ledger update. |
| Fleet Go line lengths | `awk 'length($0) > 140 {n++} END {print n+0}' $(rg --files internal/fleet -g '*.go')` | **PASS**, exit 0; **0**, including all new Go files. |
| Protected API document | `git diff --exit-code -- docs/architecture/console-api.md` | **PASS**, exit 0; no output. |

The new regression tests drove the three reported defects before implementation:
100 invalid requests wrote 100 audit records; an immediate second heartbeat
returned 200 instead of 429; accepted heartbeats changed the snapshot immediately.
Those expected pre-fix failures are retained in the raw log, separately from the
passing final gates. Final review also extended the reuse fixture's token TTL
past the ten-second retry spacing, so the cross-key refusal proves single-use
consumption rather than expiration. The complete and focused race suites were
rerun afterward; production code did not change after fuzz/vuln/benchmark checks.

**Implemented evidence:**

- A 100-request malformed burst increments 100 rejection metrics and produces
  exactly five audit samples plus one summary with count 95 after the injected
  minute boundary. The real concurrent HTTP test also keeps a legitimate signed
  heartbeat successful during four workers' 400-request invalid burst.
- Stateless rejection tests hold the hub mutex and still complete method, path,
  content-type, header, body-cap, skew and enrollment-signature failures. Stored
  heartbeat public-key lookup is the necessary short state dependency; crypto,
  body parsing and response writes hold no hub mutex.
- Source-IP throttling returns 429/Retry-After, aggregates changing ports and
  ignores forwarded headers. More than 4096 distinct remotes leave exactly 4096
  buckets; expiry/pruning restores admission. Fixed 8192 requests/minute supports
  the maximum ten-second fleet behind one NAT, with documented collateral risk.
- A rogue key's 155 attempts over 31 injected seconds admit exactly four
  heartbeats at its ten-second interval while the second node's four heartbeats
  succeed. A filled 64-nonce window affects only its node; expiry reclaims it.
  Revoked and rate-limited requests leave the snapshot, dirty flag and nonce count
  unchanged. Signed re-enrollment retries cannot bypass the write throttle.
- Snapshot-byte tests verify no synchronous heartbeat rewrite, no flush before
  five seconds, one snapshot containing both nodes at the deadline, no clean
  rewrite, synchronous revocation, and orderly shutdown flushing. A real worker
  test verifies an injected-clock advance triggers the background flush.
- Abrupt-restart tests reopen the real last on-disk snapshot without Close's
  soft-state flush: last flushed inventory and replay protection survive; an
  unflushed nonce can be accepted again inside the skew window, then expires.
  A real stale temporary file proves background write failure latches unavailable
  and Close reports the failure. Legacy oversized live nonce windows fail closed;
  startup succeeds after expiry without discarding live replay protection.

**Benchmark comparison.** The identical final benchmark harness seeds a valid
1000-node enrolled registry, then times signing, request construction, ServeHTTP,
verification, replay handling and acknowledgement. Empty sensor lists are used;
setup and shutdown are excluded. Each node reports at 30-second intervals when
cycled; per-node synthetic source IPs keep remote throttling out of this workload.
The controlled 200-operation samples finish before the worker's first wake, so
these are request-path measurements, **not amortized background flush cost or
production throughput**. Coalescing correctness is tested separately above.

The draft was measured with the same final `benchmark_test.go` using
`go test -overlay=/tmp/fleet-baseline/overlay.json` plus the benchmark flags above.
The overlay substitutes `hub.go`, `requests.go`, `nodes.go`, `tokens.go`,
`state.go`, and `server.go` from `git show ad53dc7:internal/fleet/hub/<file>`;
new `limits.go` and `abuse_test.go` are replaced with `package hub` stubs.
No working source replacement or branch switch was needed.

| Version | Median ns/op | Median B/op | Median allocs/op | Time range, 3 samples |
| --- | ---: | ---: | ---: | --- |
| Draft `ad53dc7` | 9276050 | 2458381 | 1294 | 9205144..10794933 ns/op |
| Fixed worktree | 63871 | 15441 | 165 | 61161..80244 ns/op |

Medians are computed per metric. The measured request path is about 145 times
faster, with about 87% fewer allocations, for this bounded synthetic workload.

**Residual risks and durability:** durable enrollment/key/interval/revocation and
token changes remain synchronous. Normally a crash loses at most the latest
five-second soft-state interval; scheduler/IO stalls can extend elapsed loss.
Restart displays the last flushed inventory until the next heartbeat. Unflushed
nonces can reopen within signed timestamp ±120 seconds (up to 240 seconds after
initial receipt for a future-dated request). No process-start timestamp floor is
imposed. Pending rejection samples/counts can also be lost on crash. Flushed
nonces, consumed tokens and revocation remain durable. Shared NAT throttling,
remote-table saturation, bounded audit quota exhaustion and distributed CPU/disk
pressure remain possible; no DDoS/host isolation or prospective performance
claim is made. The full registry is still rewritten under the mutex at the
coalesced cadence, plus synchronous durable changes.

## 2026-11-15 — experimental fleet inventory candidate

**PASS — local implementation and required verification.** Branch
`feat/fleet-enrollment`, base HEAD `20a2dbb`, stacking the operator console.
All changes were uncommitted when this entry was written; they are now committed
on `feat/fleet-enrollment` (PR pending, unmerged). No commit, push, branch
switch, `gh`, merge, publication or deployment occurred during the recorded checks. macOS arm64, `go version go1.27.4 darwin/arm64`.
No module files or dependencies changed. All suites ran sequentially with
`GOTOOLCHAIN=go1.27.4 GOFLAGS=-p=1 GOMAXPROCS=2`; Makefile pins that toolchain.

The candidate is experimental fleet inventory with authenticated enrollment and
heartbeats. It is not multi-tenant, not a managed service, and forwards no
evidence. The hub cannot command nodes. ADR-0018 and `architecture/fleet-protocol.md`
define the implemented boundaries and proposed work.

| Check | Exact command | Final local result / captured output |
| --- | --- | --- |
| Formatting, vet, complete race suite | `make lint test` | PASS, exit 0; `go vet ./...`, `go test -race ./...`; all packages passed. Optional `golangci-lint` was not installed and was explicitly skipped. (49.80 s) |
| Fresh affected-package race suite | `go test -race -count=1 ./internal/fleet/... ./internal/console/... ./internal/runtime ./internal/config ./internal/cli` | PASS, exit 0; fleet agent/hub/identity/protocol, console and its subpackages, runtime, config and CLI all passed with `-count=1`. (49.26 s) |
| Bounded real fuzzing | `make fuzz-seed` | PASS, exit 0; all 12 targets passed at 15 seconds/target. New `FuzzFleetProtocol`: 692619 executions, 65 new interesting inputs; no failure. Target added to Makefile and CI lists. (198.29 s) |
| Pinned vulnerability check | `make vuln` | PASS, exit 0; `No vulnerabilities found.` (3.57 s) |
| Dependency licenses and tracked-file secret scan | `make license-check secrets-scan` | PASS, exit 0; `license-check: ok — 14 module(s) within policy`; `secrets-scan: ok`. (2.00 s) |
| Immutable supply-chain references | `make supply-chain-check` | PASS, exit 0; `supply-chain-check: ok`. (0.09 s) |
| Module checksum verification | `go mod verify` | PASS, exit 0; `all modules verified`. (0.56 s) |
| Patch whitespace | `git diff --check` | PASS, exit 0; empty output. Repeated after the final documentation update. (0.02 s) |
| Built binary for manual verification | `make build` | PASS, exit 0; built `bin/aegismesh` with the Makefile version/commit flags. (2.28 s) |
| New Go line-length count | `git ls-files --others --exclude-standard '*.go'` piped to `awk 'length($0) > 140 {count++} END {print count+0}'` | PASS, exit 0; **0** overlong lines across 25 new Go files. |
| Supplemental secret scan | Existing scanner with its file inventory extended to `git ls-files --cached --others --exclude-standard`, temporary helper outside the repo | PASS, exit 0; `secrets-scan: ok`; includes the untracked new files. |

Captured focused-suite output includes:

```text
ok  github.com/metaforismo/aegismesh/internal/fleet/agent
ok  github.com/metaforismo/aegismesh/internal/fleet/hub
ok  github.com/metaforismo/aegismesh/internal/fleet/identity
ok  github.com/metaforismo/aegismesh/internal/fleet/protocol
ok  github.com/metaforismo/aegismesh/internal/console
ok  github.com/metaforismo/aegismesh/internal/console/audit
ok  github.com/metaforismo/aegismesh/internal/console/auth
ok  github.com/metaforismo/aegismesh/internal/console/investigations
ok  github.com/metaforismo/aegismesh/internal/console/stateio
ok  github.com/metaforismo/aegismesh/internal/runtime
ok  github.com/metaforismo/aegismesh/internal/config
ok  github.com/metaforismo/aegismesh/internal/cli
```

Integration evidence uses real loopback listeners and the real hub/agent:
enrollment → heartbeat → online, injected-clock stale/offline, token reuse and
concurrent single-use consumption, expiry/wrong token, proof failure, tampered
body/path/timestamp/nonce, replay across hub restart, out-of-window skew,
revocation and refused re-enrollment, oversized body, registry/identity restart,
TLS with a generated CA and unknown-CA refusal, redirect/proxy refusal and safe
response bounds. Runtime tests send a real sensor request and verify stored
evidence while the hub is down. Config tests cover every new field and override,
unknown/inline fields, unsafe egress/TLS and credential references. A hub can run
without sensors; ordinary nodes/agents still require sensors. Dry-run startup
binds listeners without agent egress/token consumption; an explicit live send
from the same preflighted agent then succeeds.

The route-driven authorization matrix now covers all 30 registered routes with
210 exact-status cases (none, malformed, wrong, expired, viewer, analyst, admin).
An additional enabled-fleet matrix exercises 28 role cases across all seven new
routes, plus cookie CSRF/Origin, strict bodies/queries, token secrecy and audit.
Initial development runs exposed missing matrix fixtures, an invalid HTTP test
fixture, a wrong session-field reference and formatting-helper comma errors;
all were corrected. The final receipts above supersede those intermediate
failures. The dry-run egress issue and hub-only sensor requirement found during
review were fixed and the complete/focused/fuzz gates rerun afterward.
The timestamp-tamper fixture was then strengthened to change the header by one
second, inside the allowed skew window, so signature verification must reject
it. `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/fleet/hub -run
TestAuthenticatedRequestFailuresAndReplayAcrossRestart` passed (exit 0,
`ok .../internal/fleet/hub 2.165s`), followed by another passing `make lint test`.
This final edit changed test coverage only; the manually exercised production
binary was unchanged.

Manual built-binary receipt (**PASS**, separate processes and private temp data
roots, loopback HTTP development transport, ten-second reporting interval):

1. Started a sensor-free hub with console. Authenticated `GET /api/v1/fleet`
   returned 200 with hub enabled.
2. Admin `POST /api/v1/fleet/enrollment-tokens` returned 201. Token **REDACTED**;
   supplied through a 0600 file, never a command argument or inline config.
3. Started a second process as agent. One node appeared `online`; the token
   disappeared from outstanding metadata and agent status reported enrolled.
4. Agent sensor returned HTTP 200. The next heartbeat carried interaction=1;
   the hub's evidence endpoint still returned an empty event list.
5. Stopped the agent with SIGTERM (exit 0). Inventory became `stale` **30.0 s**
   after stop. Restart reused the same node ID and returned to `online` with
   exactly one inventory record.
6. Admin revoked the node (200, status `revoked`). Its next live heartbeat was
   refused: agent reported the fixed HTTP-403 category
   `fleet: node revoked; operator review required`. Last-seen did not advance.
   Audit contained token.create, node.enroll, node.revoke and node.rejected.
7. Both processes stopped cleanly, exit 0. Disposable state/token/key directories
   were removed. Only redacted summaries are retained here; no raw transcript or
   helper script was added to the repository.

Offline-after-ten-intervals was verified with the injected clock in integration
tests, not by waiting 100 seconds in this manual run. Public-network deployment,
scale/load validation, UI acceptance, hosted CI, merge and production operation
are **NOT RUN**. The inventory is authenticated self-report, not host attestation.
Optional `fleet status` and `demo --fleet` were omitted. Evidence forwarding,
rotation, mTLS/attestation, remote configuration, upgrades, tenancy and SSO remain
proposed, not implemented; no hub-to-agent control channel is reserved.

## 2026-11-15 — embedded operator console UI

Worktree branch `feat/console-ui-embed` on top of `feat/console-api`, macOS arm64,
Go **1.27.4**, Node.js v25.8.2. Local commits only: no push, `gh`, hosted CI,
merge or deployment. The runtime now passes `consoleui.FS()` to the console, so the
UI is embedded, has no build step and no third-party code, and is served only
when `console.enabled` is true. Makefile targets `ui-test`/`ui-dev` and a Node.js
CI step were added; the CI step has not run on hosted CI.

| Command / check | Result |
|---|---|
| `make ui-test` | **PASS**: 63 tests, 0 failures (DOM safety, routing, API client, stream, charts, components, mock server, site checks). |
| `go test -race -count=1 ./internal/consoleui ./internal/console/... ./internal/runtime ./internal/cli` | **PASS**: all eight packages, including the new `TestConsoleServesEmbeddedUI` (real runtime on loopback: `/` is 200 `text/html` with the exact CSP and `no-store`, the entry script is served as JavaScript, unauthenticated `/api/v1/overview` is 401). |
| `make lint` | **PASS**: gofmt clean, `go vet ./...`; `golangci-lint` not installed, skipped by the Makefile. |
| `make supply-chain-check` and `./scripts/check-supply-chain_test.sh` | **PASS**: no new action was added; the CI step uses the runner's Node.js. |
| `make license-check secrets-scan` | **PASS**: 14 modules within policy; no secrets found. |
| `git diff --check` | **PASS** after stripping trailing whitespace from the staged UI scripts. |
| Full `make test`, fuzzing, `make vuln` | **NOT RUN** in this change; covered by hosted CI on PR #75. |
| Hosted CI for the new Node.js step | **NOT RUN** when this entry was written; later **PASS** on PR #75 (see the stack status entry). |

**Manual browser evidence (recorded separately from the implementer's checks).** Run in
a browser against the real server started by `aegismesh demo --console`: login,
overview, events, recommendations, node, audit trail, and creating an
investigation (cookie session plus CSRF) all worked, with no CSP violations. The
mock-based walk-through of all 13 screens in both themes and at 375px is recorded
in `docs/design-system.md`.

## 2026-11-15 — console backend review fixes

Worktree `feat/console-api`, continuing local draft `4976522` without committing,
pushing, switching branches, or running `gh`. macOS arm64 / Go 1.27.4. Verification
suites ran sequentially with `GOFLAGS=-p=1 GOMAXPROCS=2` to constrain build and
fuzz concurrency. No dependencies or module files changed.

Resource handlers and HTTP tests are separated by responsibility; console state,
authentication, and listener lifetime retain one owner. Construction helpers use
one deferred error cleanup. The new packages document their trust boundaries and
exported API. Multi-field literals, local names, and logical steps are expanded
for review. The sole Go line over 140 characters is the fixed CSP string constant.

Summaries now project stored HTTP, MCP, SSH, TCP, and correlation fields with a
160-character cap and control-character sanitization. Fuzzing exercises each
sensor kind. Cross-endpoint cursors are rejected even with matching filters.
Literal/encoded traversal returns 404 before ServeMux can normalize a path.
Investigation startup rejects JSON null and reports the state filename plus
inspection/recovery guidance for corrupt snapshots.

The HTTP authorization matrix derives from all 23 route registrations and has
161 exact-status cases: no credentials, malformed Authorization, wrong token,
expired session, viewer, analyst, admin. Missing success fixtures fail the test
when a route is added. Expected roles are declared independently in the fixtures,
so a changed authorization policy also fails the matrix. Loopback tests cover
CSRF/Origin, bearer mutations,
Host/port/localhost/IPv6 authority, exact 64 KiB and 64 KiB+1 bodies, strict JSON,
bodyless routes, cursor tampering/truncation/scope, static files and headers,
login throttling/Retry-After, session rotation/logout/TTL/eviction, SSE capacity
and shutdown, investigation field limits and quota status mapping, and TLS login
and logout Secure cookies. TTL tests use an injected atomic clock, without sleeps.

Auth tests fill the 4096-remote throttle registry directly and prove reclamation
at its clock boundary. Store tests cover every investigation field/count limit,
32 MiB encoded-state refusal without mutation, successful restart, failed atomic
replacement preserving the prior snapshot, and corrupt/stale state failing closed.
Audit tests modify, remove an interior record, and reorder records, each reporting
`first_invalid_seq: 2`; rotation/restart keeps the verified chain continuous.
These file/state tests exercise the owning packages directly; HTTP policy and
quota mapping tests use real loopback listeners and the actual runtime snapshot
provider. Runtime tests retain sensor → storage → index → API/SSE, backfill,
encrypted live-only indexing, correlation provenance, and shutdown wiring.

The user reported the integrated embedded UI browser flow accepted during review;
that browser run was not repeated here. The one-off smoke script and transcript
were deleted; the historical manual receipt remains a short entry below. CLI help
now describes available UI assets without assuming whether this build embeds them.

| Command / check | Result and captured output |
|---|---|
| `make lint test` | **PASS**, exit 0: gofmt clean; `go vet ./...`; `go test -race ./...` passed across all 36 tested packages. Optional `golangci-lint` is absent; Make printed `golangci-lint not installed; skipped (vet+fmt ran)`. |
| `go test -race -count=1 ./internal/console/... ./internal/evidenceindex ./internal/runtime ./internal/cli ./internal/config` | **PASS**, exit 0, all nine packages: console 7.708 s; audit 1.551 s; auth 1.474 s; investigations 6.491 s; stateio 1.383 s; evidenceindex 6.045 s; runtime 14.408 s; CLI 3.637 s; config 1.651 s. |
| `make fuzz-seed` | **PASS**, exit 0: all eleven bounded real fuzz targets emitted `PASS`; `FuzzObservationProjection` executed 555260 cases in 15 s, and `FuzzCursorFilter` passed. Two fuzz workers, sequential targets. |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0 printed `No vulnerabilities found.` |
| `git diff --check` | **PASS**, exit 0, no output; supplemental untracked-file whitespace scan found 0 issues. |
| `awk 'length($0) > 140'` over all 48 new Go files, including draft files and untracked additions | **PASS**, 1 line: `internal/console/server.go:24`, the 189-character fixed CSP string. All other lines are at most 140 characters. |
| Exported Go documentation audit | **PASS**, 0 missing declaration, field, or interface-method comments in the new production Go files. |

## 2026-11-14 — first operator console backend candidate

Worktree `feat/console-api`, base `e82df977c4119629b3bd87b8496428615ff1b865`,
macOS arm64 / Go **1.27.4**. All changes were uncommitted when this entry was written, including the supplied
console contract; they are now committed in PR #74 (open, unmerged). No commit,
push, branch switch, `gh`, hosted CI, merge, publication or deployment occurred
during the recorded checks. UI embedding and browser QA were **NOT RUN** in this
entry (later done in PR #75); at this point the runtime passed a nil UI and `/`
served a notice.

**Architecture.** `runtime.indexedSink` serializes successful storage append →
`evidenceindex.Index` for both bus observations and direct correlation signals.
The existing observer/webhook fan-out receives no new signal path. The index
owns envelope copies, bounded defensive summaries, signed pagination, aggregates,
provenance lookup and non-blocking bounded SSE subscriptions. `console.Server`
receives runtime node/sensor snapshots through a read-only interface; auth,
audit, investigations and private rooted state I/O are separate packages.
`storage.SnapshotMetadata` bounds node directory reads without reading payloads.
All new implementation dependencies are standard library; module files unchanged.

**Contract safety clarifications.** The contract now records the additional
64 MiB accounted-envelope budget, latest-4096 recommendation input, 65536-entry
node metadata bound (503 beyond), 1000 investigations / 100 notes per case /
32 MiB encoded state, 4 MiB audit rotation / 128-file quota, bearer session empty
CSRF/zero expiry, strict bodyless routes, and separate investigation/audit
transactions. Encrypted evidence is live-only with `history: "unavailable"`;
no evidence read identity enters the runtime. Audit and notes remain plaintext.
The audit chain proves internal consistency, not writer identity or external
anchoring. A successful investigation snapshot can precede a failed final audit
append; the API explicitly reports that state may already be saved.

**Behavioral evidence.** Real loopback HTTP tests cover 21 authenticated routes ×
six states (anonymous, invalid token, a genuinely expired 60-second cookie, viewer,
analyst, admin), public meta/session behavior, cookie/CSRF/Origin/Host checks,
strict/oversized bodies and queries, cursor tampering, a real sensor event through
storage/index/API/SSE, actual correlation-engine signals with three provenance
links, plaintext backfill, encrypted live-only indexing, failed-store exclusion,
TLS Secure cookies, session rotation/revocation, login rate/audit records,
investigation persistence and limits, and chain verification. Sixteen real SSE
streams are accepted, the seventeenth is 503, and shutdown closes the sixteen.
Static tests inject an FS through a real server and verify CSP, types, caching,
index-only-root behavior and traversal/listing refusal. Bounded metadata is
compared with real segment files and rejects excessive entry counts.

**Fixed regression.** `go test ./internal/console/audit -run
'^TestIncompleteJSONLRecordRejected$' -count=1` first reproduced **FAIL**, exit 1:
"unterminated JSONL record accepted; a later append would concatenate two records".
The scanner now rejects a missing final newline before accepting or extending a
chain. The regression and full audit race suite subsequently passed. No repair,
truncation or deletion of existing audit data is performed.

| Command | Final result and captured output |
|---|---|
| `make lint test` | **PASS**, exit 0: gofmt clean, `go vet ./...`, complete `go test -race ./...`; runtime `ok` (78.382 s), audit `ok` (1.969 s). |
| `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/console/... ./internal/evidenceindex ./internal/storage` | **PASS**, exit 0, all seven packages; console 7.920 s, audit 1.929 s, auth 1.672 s, investigations 3.061 s, stateio 3.395 s, evidenceindex 11.765 s, storage 5.377 s. |
| `make fuzz-seed` | **PASS**, exit 0, eleven bounded real fuzz targets; each emitted `PASS`, including `FuzzObservationProjection` and `FuzzCursorFilter`. Makefile and CI lists both include them. |
| `make vuln` | **PASS**, exit 0, pinned govulncheck v1.7.0: `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0: `14 module(s) within policy`; `secrets-scan: ok`. The script scans tracked files; supplemental scan below covers untracked additions. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `make build` | **PASS**, exit 0; built `bin/aegismesh` with the project toolchain and metadata. |
| `GOTOOLCHAIN=go1.27.4 go test -race ./internal/console/audit -count=1` | **PASS**, exit 0 (1.607 s), including the reproduced/fixed incomplete-JSONL regression. |
| `git diff --check` | **PASS**, exit 0, no output. |
| Optional `golangci-lint` | **BLOCKED**, not installed; the Make target explicitly reported its skip. Gofmt/vet and the race suite did run and pass. |

Complete successful command output and the built binary checksum are preserved in
[console-verification.log](console-verification.log). Supplemental fixed-pattern secret scan: 33 untracked files, 0 findings. Untracked whitespace scan: 0 findings.


Historical manual run (2026-11-14): the built binary was exercised with curl
through login, reads, operator mutations, audit, and live SSE; both processes
exited on SIGINT. The one-off script and transcript were removed during review;
the Go integration tests are the maintained reproduction path.

## 2026-11-14 — steady-traffic encryption segment review

Candidate was uncommitted when written (now committed in PR #73), on `feat/evidence-at-rest-encryption`, based on
`c64b58f29373ac475ec6a44ce692722062c5dfba`, macOS arm64 / Go **1.27.4**.
This entry supersedes the unconditional flush/seal policy in the earlier recovery
receipt below. No commit, push, branch switch, `gh`, staging, hosted CI, merge,
publication or deployment was performed.

**Changed behavior.** Ordinary flushes publish buffered ciphertext to the OS and
keep the segment open. The fixed `maxEncryptedSegmentAge = 5 * time.Minute`
starts at the first successful event append; only size rotation, close or a flush
at that age seals. Empty segments never age out, repeated aged flushes leave the
sealed bytes unchanged, and a successor opens only on the next accepted append.
Five minutes balances near-live read delay with at most 288 age-driven seals/day
under steady traffic instead of 17,280. Size rotation and restarts add files.
This preserves the existing non-`fsync` flush contract; power-loss durability is
not claimed. No runtime timer or configuration field changed.

**Regression evidence.** Injected-clock tests cover 60 interleaved appends/flushes
inside the age window with exactly one segment, observable ciphertext bytes after
each flush, active-reader/count "not sealed" errors, an exact-boundary seal that
verifies every event and footer, repeated seals producing no additional bytes or
files, successor age reset, empty idle flushes across 100 minutes, first append
after idle, and byte-for-byte plaintext output across age bounds. Existing
size-rotation, active-retention, restart, corruption/truncation and concurrent
append/flush/retention tests remain in the race suite. Runtime wiring now proves
that flush leaves evidence unsealed and close makes it readable.

**Related resource review.** An unfit encrypted frame could previously rotate a
populated/sealed segment before rejection. Such frames now fail the fresh-segment
header/frame/footer fit check before any seal/rotation; a regression checks ten
rejections both before and after an age seal without creating a successor or
changing the original event count. Append/flush do no directory listing or
retention scan. The writer holds one segment descriptor and closes it before
opening the successor. Encryption is in memory; identity loading is bounded to
eight files and closes each read. Read/count/alias checks open segments one at a
time. CLI export creates one staged file per explicit export, removes it on error,
and syncs once per export, not once per event. There is no per-event `fsync`.

Retention still lists/sorts all segments and scans their frames every ten minutes;
it holds the store mutex, so a large pass can delay writes/flushes. Size rotation
is proportional to accepted bytes, retention can overshoot between passes, and a
damaged closed segment blocks count retention. These are documented limits, not
a hard disk quota or an absolute daily file cap. Active evidence is unreadable
until sealed, normally within five minutes of the first event plus the next
five-second flush (longer if maintenance stalls). Full-directory inspection can
still fail on a new active successor: stop the runtime or inspect a separate
sealed-only snapshot. Documentation, configuration reference, ADR-0016, threat
model, CLI/data-flow guidance, roadmap and handoff now describe these boundaries.

| Command | Result and captured output |
|---|---|
| `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/storage ./internal/runtime` | **PASS**, exit 0 after all code/test edits: storage `ok` (4.431 s), runtime `ok` (15.679 s). |
| `make lint test` | **PASS**, exit 0 after all code/test edits: gofmt check, `go vet ./...`, `go test -race ./...`; all packages passed. Storage `ok` (4.692 s), runtime `ok` (15.999 s). Make reported `golangci-lint not installed; skipped (vet+fmt ran)`; no separate lint execution is claimed. |
| `make fuzz-seed` | **PASS**, exit 0: all nine 15-second targets passed. `FuzzEncryptedFrameStructure`: 479969 executions, 20 new interesting inputs, no failure (`ok`, 16.372 s). |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0, `No vulnerabilities found.` |
| `git diff --check` | **PASS**, exit 0 after the final documentation/ledger update; no whitespace errors. |

## 2026-11-14 — evidence-at-rest encryption recovery and review

Candidate: `feat/evidence-at-rest-encryption` (uncommitted when written; now PR #73) on
`c64b58f29373ac475ec6a44ce692722062c5dfba` (reviewed but unmerged toolchain
upgrade). Host: macOS arm64, Go **1.27.4**. No commit, push, reset, branch
checkout, `gh`, hosted workflow, publication or deployment was performed.
The index is unchanged. PR number at the time: pending; now #73 (open, unmerged). PR #58 is closed/unmerged and
its patch is draft provenance, not review or exact-head CI evidence.

### Recovery and defects corrected

Fifteen `git show origin/codex/evidence-at-rest-age-v2:.codex/encryption-v2.partNN`
reads were concatenated outside the repository in `$TMPDIR`. Verified SHA-256:
`4fc51a53fe6e7aa89c3e9d7925d0afdff6fd84f47786861d5474093c753c26c7`.
Split sizes/digests also matched the source workflow:

| Patch | Bytes | SHA-256 |
|---|---:|---|
| `01-runtime.patch` | 56285 | `658a31a84f272994045376572b085f8e4de72e015572d758a3294f3093d5e992` |
| `02-tests.patch` | 49399 | `9455112109ecf3c3b9dd183e629ff91067edde2a8e8e3be79031f15b1d33f7be` |
| `03-docs.patch` | 42380 | `f6cfbc5933271b5e71707678c6f17da44d833b774b8486b8ef9b5d00f802de94` |

The runtime and tests applied without three-way conflicts. Module files were
resolved by retaining the current toolchain/x/* versions and acquiring age
v1.3.2. The docs patch conflicted in license-policy/verification; those files
were reconciled manually without importing historical PASS claims. Neither
`.codex` chunks nor the reconstruction workflow was added.

- **FAIL reproduced, then fixed:**
  `go test ./internal/storage -run TestEncryptedFrameBoundaryTruncationFailsClosed -count=1`
  exited 1 on the recovered implementation: it accepted truncation at byte 23
  (header only) and byte 605 (complete event boundary). Independent event
  ciphertexts did not establish segment completion. The v2 format adds an
  age-authenticated footer binding count and ordered framed-ciphertext digest.
  Initially flush/rotation/close sealed the segment; the steady-traffic review
  above supersedes the unconditional flush policy.
- Exact-match `inspect show` stopped early, bypassing later encrypted failures;
  it now consumes all input before emitting output. Authenticated but empty or
  malformed event JSON was silently skipped; encrypted records now fail closed.
- Identity diagnostics could echo an inline private value used as a filename
  or rejected flag value. Diagnostics now suppress identity values, and the
  loader rejects inline identities. The byte limit is enforced on actual file
  reads as well as metadata, covering concurrent growth and comment suffixes.
- Dedicated encryption configuration matrices were absent. Added YAML/JSON
  field/default/invalid/unknown/inline-identity cases and identity-flag matrices
  across all four read commands (including repetition and positional input), plus mixed ordering,
  counting, age/count retention, active-segment protection, concurrency,
  interrupted restart and real buffered-file failure regressions.
- The draft did not complete resolved-graph license review. All fourteen
  modules were reviewed; the scanner now uses Go-resolved module directories
  (including uppercase escaping), with a checksum-pinned README grant for the
  upstream CCTV test-only module's selected 0BSD option. No CC0/Unlicense grant
  is selected. See `license-policy.md` for versions, justification and hashes.
- Diff-scoped deslop review removed a redundant plaintext byte copy, obsolete
  early-stop handling and an unbounded guard-creation retry. It preserved
  trust-boundary validation and the existing plaintext representation.

### Commands executed on this candidate

| Command | Result and captured output |
|---|---|
| `go test ./internal/event ./internal/storage ./internal/config ./internal/cli ./internal/runtime ./internal/agekey -count=1` | **PASS**, exit 0; all six packages `ok`. Additional matrix/mixed-retention tests added later are included in the final race runs below. |
| `go test -race ./internal/storage ./internal/config ./internal/cli ./internal/runtime ./internal/agekey -count=1` | **PASS**, exit 0 on final runtime/test code; all five packages `ok` (output below). Includes concurrent encrypted append/flush/retention. |
| `make lint test` | **PASS**, exit 0, repeated after final code/test changes: formatting, `go vet ./...`, `go test -race ./...`; 30 test packages `ok`. `golangci-lint` is not installed; Make explicitly reported `skipped (vet+fmt ran)`. No unavailable tool was relabeled as run. |
| `make fuzz-seed` | **PASS**, exit 0, nine targets at 15 s each (158.97 s total). New `FuzzEncryptedFrameStructure` exercises framing/counting and age decryption with a valid sealed seed; 736929 executions, 220 new interesting inputs, no failure. Target is listed in both CI and Makefile. |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0, `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0: `license-check: ok — 14 module(s) within policy`; `secrets-scan: ok`. New untracked files were also checked separately for secret-shaped values; all identities in tests are generated, not literals. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `make sbom sbom-check` in the linked worktree | **BLOCKED by tool/layout**, make exit 2: pinned generator returned `failed to determine version of main module: git: reference not found`. The second target is not reached by this failed invocation. This reproduces the base branch's known limitation, not a successful local generation. |
| `make sbom sbom-check` in an identical-source ordinary temporary clone | **PASS**, exit 0: `sbom.sh: wrote dist/sbom-aegismesh.cdx.json (darwin/arm64, cgo=1)`; `SBOM valid`. An initial shared-object clone attempt exited 2 (`git: object not found`); materializing its objects with `git -C "$SNAPSHOT" repack -a` resolved that temporary-clone limitation. Original worktree Git metadata was untouched. |
| Repeat ordinary-clone `make sbom sbom-check` plus SHA-256 comparison | **PASS**, exit 0, identical JSON SHA-256 `20be56525e9fcc61fea0ddbf860f4e7d96cc63c0eb95df62604dfee593b907da`. Generator warned `no licenses detected module=std@go1.27.4`; heuristic license evidence remains distinct from the explicit dependency review. |
| `make sbom-check` in the worktree against the copied snapshot artifact | **PASS**, exit 0: `SBOM valid`. The artifact stays ignored under `dist/`; this does not relabel direct worktree generation as PASS. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `git diff --check` | **PASS**, exit 0, no output (repeated after documentation). |
| `make build` | **PASS**, exit 0; native binary built with existing Makefile version flags. |
| `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$TMPDIR/.../aegismesh-linux-arm64" ./cmd/aegismesh` | **PASS**, exit 0. |
| `CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "$TMPDIR/.../aegismesh-darwin-arm64" ./cmd/aegismesh` | **PASS**, exit 0. |
| `sh -n scripts/license-check.sh`; `./scripts/check-supply-chain_test.sh` | **PASS**, exits 0; `check-supply-chain_test: ok`. |
| Human review, exact-head hosted CI and merge | **NOT RUN** when written; hosted CI later **PASS** on the PR #73 head, human review and merge pending. |
| Explicit `make helm-contract` | **NOT RUN** in this encryption slice; chart behavior did not change. The normal guarded package tests ran under `make test`; they are not a live Helm receipt. |

Final focused race stdout:

```text
ok  	github.com/metaforismo/aegismesh/internal/storage	2.868s
ok  	github.com/metaforismo/aegismesh/internal/config	2.742s
ok  	github.com/metaforismo/aegismesh/internal/cli	5.396s
ok  	github.com/metaforismo/aegismesh/internal/runtime	15.332s
ok  	github.com/metaforismo/aegismesh/internal/agekey	2.123s
```

The SBOM fallback was created by a local shared/no-hardlink clone, then a
SHA-256-verified overlay of 232 tracked/untracked working-source files, then
materialization of Git objects in that temporary clone. Runtime, module and
check source matches the final worktree code; documentation receipts were
updated afterwards. No commit or fabricated version/tag was created. It uses
the unchanged pinned generator and validator. The application SBOM contains
age v1.3.2, hpke v0.4.0, x/crypto v0.59.0, yaml v3.0.1 and std go1.27.4.
Graph-only upstream test dependencies are separately covered by license review.

### Acceptance evidence map

| Contract | Behavioral evidence |
|---|---|
| Disabled filenames and bytes unchanged | `TestEncryptionDisabledPreservesPlaintextRecord` compares encoded bytes/newline and suffix; existing storage/CLI tests pass. |
| Recipient validation before readiness | `TestStorageEncryptionConfigMatrix` (YAML and JSON), `TestParseRecipient`, `TestBuildRejectsInvalidEncryptionBeforeCreatingDataDir`. |
| Read-only bounded identities, no inline secrets or diagnostic disclosure | `TestLoadIdentityFile`, FIFO rejection, config unknown-identity fields, duplicate/alias CLI tests, `TestIdentityArgumentsNeverEchoInlinePrivateKey`. File-only references are deliberately supported; no identity env-value or inline config surface exists. |
| Missing/wrong identities, corruption/truncation fail closed | Recovered storage/CLI matrices, new frame-boundary/footer/order tests and `TestEncryptedShowValidatesPastExactMatch`; failed exports leave targets untouched. |
| Restart, rotation and partial failures never downgrade | `TestEncryptedRestartCreatesIndependentSegments`, key-rotation tests, `TestEncryptedFlushSealsAndNextAppendRotates`, `TestEncryptedRestartAfterInterruptedWriteAndWriteFailure`, persistent guard/history checks. |
| Mixed history, retention, ordering and protected active segment | `TestMixedHistoryOrderingCountingAndRetention` checks unchanged plaintext, exact 2/2/1 counts, sorted output, count deletion, age deletion and old encrypted active preservation; concurrent append/flush/retention regression. |
| Bounded records/frames and concurrency | Exact stored-envelope boundary tests, length-prefix rejection, fuzz target and final affected/full race runs. |
| No added external destination, key service, captured-data path or exec | Source/diff review of agekey/config/runtime/storage/CLI wiring: only explicit operator data/identity/output paths and native X25519 library constructors. Manual traffic is loopback only. |

### Manual built-binary transcript summary

**PASS**, repeated after the final runtime edits. A private temporary workspace
was created; a small Go helper using age v1.3.2 generated two X25519 identities
into owner-only files without printing private values. Only the public recipient
entered `mesh.json`. A native built binary ran one HTTP sensor on an unprivileged
loopback port; two synthetic requests returned HTTP 200. SIGINT exited 0.

```text
aegismesh run --config TEMP/mesh.json
GET http://127.0.0.1:PORT/encryption-manual-marker-1 -> 200
GET http://127.0.0.1:PORT/encryption-manual-marker-2 -> 200
SIGINT -> exit 0; one .jsonl.age segment; zero .jsonl segments
inspect list --identity TEMP/identity.txt --verify --json -> exit 0, 2 events, both integrity_ok=true
inspect list [no identity] -> exit 1, empty stdout, requires at least one identity file
inspect list --identity TEMP/wrong.txt -> exit 1, empty stdout, did not match any supplied identity
inspect show --id EVENT --identity TEMP/identity.txt -> exit 0, verified=true
recommend --identity TEMP/identity.txt -> exit 0, dry-run report (0 recommendations)
inspect export [missing/wrong identity] -> exit 1, empty stdout, existing output unchanged
inspect export --identity TEMP/identity.txt -> exit 0, 2 events exported
run --config TEMP/mesh.json --dry-run [encryption enabled] -> exit 0; new encrypted segment
inspect list --identity TEMP/identity.txt --json -> exit 0, still 2 events
run --config TEMP/mesh.json --dry-run [encryption removed] -> exit 1, refusing plaintext writes
```

Every segment was checked for absent marker and envelope-schema plaintext bytes;
no plaintext `.jsonl` segment existed before or after restart/downgrade attempts.
Logs/transcript were checked against both generated private values. Temporary
private identity files were removed after the run. Exported synthetic NDJSON is
explicit plaintext outside the data directory.

### Remaining limits

Encryption protects contents on storage media, not a compromised runtime host or
stolen identity. Names, sizes, timing, logs and exports remain visible. Existing
plaintext is not migrated; lost keys cannot be recovered. The directory is for
one runtime writer; there is no cross-process lock. Readers require a completed
footer; live unfinished writes and crash-unsealed segments fail closed. There
is no automatic salvage or whole-file deletion/replacement detection, and anyone
holding the public recipient can create new ciphertext: this is confidentiality
and consistency, not writer provenance. Count retention validates framing without
private keys; it cannot authenticate ciphertext. The low-level reader may invoke
callbacks before a later failure; CLI outputs remain buffered/staged until the
complete read succeeds. Direct linked-worktree SBOM generation, human review and
exact-head CI/merge remain open as stated above.

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
