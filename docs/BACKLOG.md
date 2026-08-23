# Engineering backlog

This is the living, evidence-backed queue for work after the verified `cf8bdee`
baseline. An item is complete only after focused tests, relevant broader tests,
documentation truth-sync, and evidence in `docs/verification.md`.

## P0 — correctness, security, data loss, broken builds, dishonest claims

### P0-1 — make verified export fail closed — PASS

- **Evidence:** `internal/cli/inspect.go` opened/truncated `--out` before reading,
  ignored `flag.Parse` errors, accepted positional arguments, and skipped an
  integrity mismatch while returning success. The red tests
  `TestInspectExportRejectsUnexpectedArgumentsWithoutTouchingOutput` and
  `TestInspectExportVerifyFailsClosedWithoutTouchingOutput` reproduced both.
- **Affected:** `internal/cli`, `internal/storage`, `docs/cli.md`, verification.
- **Security/egress:** local read/write only; prevents a misleading or partial
  verified export. No new egress.
- **Dependencies:** none.
- **Acceptance:** invalid syntax and failed verification return non-zero without
  changing an existing target; stdout receives bytes only after validation;
  native successful output stays byte-for-byte compatible; an export target
  cannot resolve to a source segment through a direct path, symlink or hard link.
- **Verify:** `go test ./internal/cli -run 'TestInspectExport|TestInspectShowRejects' -count=1`;
  `go test -race ./internal/cli ./internal/storage`; `make lint test`.

### P0-2 — close producer/shutdown channel races — PASS

- **Evidence:** red review and tests showed `event.Bus.Submit`,
  `webhook.Sink.Offer`, and `extmanager.Manager.Deliver` could race channel
  closure. `Submit` after `Close` reproduced a send-on-closed panic before the fix.
- **Affected:** `internal/event`, `internal/webhook`, `internal/extmanager`,
  `internal/runtime`, data-flow and verification docs.
- **Security/egress:** a shutdown-time panic is availability loss. Webhook is an
  existing opt-in egress; the fix must not add destinations or deliver derived
  correlation signals.
- **Dependencies:** complete before any new signal fan-out or runtime consumer.
- **Acceptance:** repeated concurrent submit/deliver/offer and close/stop calls
  never panic under `-race`; drop counters and non-blocking semantics remain.
- **Verify:** focused concurrent lifecycle tests repeated under `-race`;
  `go test -race ./internal/runtime -run TestSystemStopConcurrentIsIdempotent -count=10`;
  `make lint test`.

### P0-3 — remove product claims ahead of implementation — PASS

- **Evidence:** README and PRODUCT said AegisMesh already recommends containment,
  while ROADMAP R4 and the absence of a recommendation package/CLI show it is
  proposed work. FAQ also said nothing leaves the machine although opt-in remote
  providers and webhooks are shipped.
- **Affected:** README, PRODUCT, FAQ, HANDOFF, configuration and roadmap docs.
- **Security/egress:** documentation must identify every opt-in outbound edge and
  must not imply enforcement or a shipped recommendation engine.
- **Dependencies:** none.
- **Acceptance:** implemented, proposed, and aspirational behavior are distinct;
  canary activations remain observations rather than incidents.
- **Verify:** `rg -n 'recommend|nothing leaves|remote adapters absent|not wired' README.md docs`;
  compare claims with `internal/runtime` and `internal/llm`; `make lint test`.

### P0-4 — propagate evidence segment read failures — PASS

- **Evidence:** `storage.readLines` returned an empty slice on open errors and
  discarded scanner errors. A red CLI regression exported zero events with exit
  0 after replacing a segment with an unreadable directory target.
- **Affected:** `internal/storage`, `internal/cli`, verification and handoff docs.
- **Security/egress:** local evidence correctness only; prevents incomplete
  evidence from being represented as a successful verified export. No egress.
- **Dependencies:** none.
- **Acceptance:** segment metadata, open and scan failures propagate; verified
  export remains fail closed and leaves an existing target unchanged.
- **Verify:** `go test ./internal/storage ./internal/cli -run
  'TestInspectExportFailsClosedOnSegmentReadError|TestInspectExportVerifyFailsClosedWithoutTouchingOutput'
  -count=1`; `make lint test`.

## P1 — Batch 2 and important architecture gaps

### P1-1 — ECS-compatible evidence export — PASS

- **Evidence:** before this block, `inspect export` emitted only the native
  envelope and had no `--profile`; ROADMAP R3 explicitly requested the slice.
- **Affected:** new `internal/ecsexport`, `internal/cli`, CLI/architecture/mapping
  docs, roadmap and verification.
- **Security/egress:** local transform only. The complete native envelope is
  preserved; the project does not claim full ECS compliance or upload anything.
- **Dependencies:** P0-1 fail-closed export boundary.
- **Acceptance:** stable documented mapping, deterministic golden, strict omitted/
  empty/whitespace/padded/repeated/comma/invalid/positional matrix, and exact
  native compatibility when the flag is absent.
- **Verify:** `go test ./internal/ecsexport ./internal/cli -run 'TestMarshal|TestInspectExport' -count=1`;
  `go test -race ./internal/ecsexport ./internal/cli ./internal/event ./internal/storage`;
  `make lint test`.

### P1-2 — SSH deception sensor — TODO

- **Evidence:** config and runtime accept only `http`, `tcp`, and `mcp`; there is
  no `internal/sensor/sshsensor`. Migration reports SSH fully unsupported.
- **Affected:** config schema/validation/scaffold, runtime sensor construction,
  new sensor package, migration, docs and deployment examples.
- **Security/egress:** inbound listener only. Synthetic authentication must never
  validate/reuse real credentials or expose shell, PTY, host filesystem, or exec.
- **Dependencies:** choose and license-review a maintained SSH implementation;
  finish P0-2 lifecycle hardening first.
- **Acceptance:** Ed25519 host-key lifecycle guidance, loopback/unprivileged
  defaults, connection/deadline/input caps, redaction, and real loopback tests.
- **Verify:** focused unit/integration/race/fuzz tests for `sshsensor` and config;
  `./scripts/license-check.sh`; `./scripts/secrets-scan.sh`; `make lint test`.

### P1-3 — dry-run recommendation engine — TODO

- **Evidence:** ROADMAP R4 is unchecked and no package or command emits typed,
  evidence-linked recommendations. Current `policy.Enforcer` changes decoy
  responses and is not the requested operator recommendation model.
- **Affected:** future recommendation package/CLI, rule catalog, docs and threat model.
- **Security/egress:** recommendations only; no firewall, credential, process, or
  production mutation. Any future action connector needs separate approval.
- **Dependencies:** architecture decision defining evidence links, conflicts,
  deterministic ordering, and false-positive semantics.
- **Acceptance:** every output is labeled `recommendation`, links immutable
  evidence IDs, remains deterministic, and passes conflicting-rule and
  false-positive tests without an enforcement seam.
- **Verify:** focused golden/property tests; CLI malformed-input matrix;
  `go test -race ./...`; `make lint test`.

### P1-4 — optional evidence-at-rest encryption — TODO

- **Evidence:** storage writes plaintext JSONL and the threat model accepts this
  residual risk; no encryption dependency exists.
- **Affected:** storage/config/inspect, retention/rotation, key lifecycle docs,
  license policy and ADR.
- **Security/egress:** local confidentiality; fail closed when enabled and never
  downgrade to plaintext. No egress.
- **Dependencies:** age/X25519 dependency and license/maintenance review; key
  rotation/recovery design before code.
- **Acceptance:** wrong key, corruption, truncation, restart, rotation and
  retention tests; documented backup, recovery and rotation behavior.
- **Verify:** focused storage restart/failure tests; race tests; license and
  secret checks; `make lint test`.

### P1-5 — extension live-policy boundary — TODO

- **Evidence:** ADR-0006 and runtime ship only a bounded data-only observer path;
  extension responses cannot affect evidence, policy or decoy behavior.
- **Affected:** extension manifest/host/manager, policy/runtime and threat model.
- **Security/egress:** response influence is a security architecture change.
  Sending correlation signals to extensions or webhooks is new external egress
  and requires explicit approval. Never republish signals with `Bus.Submit`.
- **Dependencies:** P0-2; explicit operator-enable design and provenance schema;
  user approval for any new egress.
- **Acceptance:** strict typed/bounded output, auditable provenance, no execution,
  path selection, config mutation or enforcement, and no recursion/order races.
- **Verify:** adversarial schema/capability tests, shutdown saturation tests,
  runtime race tests and `make lint test`.

### P1-6 — `aegismesh demo` command — TODO

- **Evidence:** `scripts/demo.sh` and `make demo` exist, but the command dispatcher
  has no `demo` command.
- **Affected:** CLI, runtime/test harness, docs and examples.
- **Security/egress:** loopback-only, synthetic-only, no API key/cloud/privileged
  port. No external egress.
- **Dependencies:** a safe way to expose OS-assigned listener addresses without
  widening the public `sensor.Sensor` interface speculatively.
- **Acceptance:** meaningful HTTP/TCP/MCP-to-evidence flow, deterministic summary,
  bounded readiness, cleanup on failure/signal, repeatable parallel runs.
- **Verify:** focused CLI tests; repeated real loopback integration; `make lint test`.

## P2 — operational quality, observability, maintainability, documentation

### P2-1 — complete documentation truth-sync — PASS

- **Evidence:** PRODUCT understated MCP/provider support; HANDOFF stopped at Batch
  1; README understated observer wiring; configuration and FAQ called remote
  providers future work; ROADMAP called Helm future work despite a chart; the
  verification ledger counted 14 packages although the module now has 28.
- **Affected:** README and docs broadly, plus stale provider comments.
- **Security/egress:** accurately disclose remote-provider and webhook egress,
  unsigned-checksum/signing limits, plaintext storage and cluster support limits.
- **Dependencies:** current implementation and this block's verified results.
- **Acceptance:** every shipped/future claim matches code and current evidence;
  no production-readiness claim.
- **Verify:** targeted `rg`, `go list ./...`, workflow inspection, `make lint test`.

### P2-2 — supply-chain hardening — TODO

- **Evidence:** actions are immutable-SHA pinned and workflow permissions are
  scoped, but CI installs `govulncheck@latest`, local SBOM guidance uses
  `cyclonedx-gomod@latest`, and cosign signing is not implemented.
- **Affected:** CI/release workflows, scripts, release/license docs.
- **Security/egress:** build-time downloads only. Do not add signing credentials,
  publish artifacts, or change repository settings without action-time approval.
- **Dependencies:** select immutable tool versions/digests and validate artifacts.
- **Acceptance:** pinned tool acquisition; schema-valid CycloneDX inventory with
  direct/transitive relationships; verified provenance language; signing remains
  explicitly separate until implemented and verified.
- **Verify:** workflow static checks, SBOM schema validation, provenance verification,
  license/secret scans. Release publishing remains NOT RUN without approval.

### P2-3 — deployment evidence — TODO

- **Evidence:** Helm chart contract tests exist, but no real-cluster proof or
  published-image contract establishes supported Kubernetes operation.
- **Affected:** chart, deploy docs, release pipeline and verification ledger.
- **Security/egress:** cluster exposure and image publishing require explicit
  operator/release choices; no production-ready claim.
- **Dependencies:** published or locally loaded image, persistence, NetworkPolicy,
  security-context and upgrade/rollback tests.
- **Acceptance:** real-cluster smoke and failure-path evidence with exact platform
  boundary, or continued clearly labeled packaging-only status.
- **Verify:** `make helm-contract`; later kind/k3d smoke commands documented when run.

## P3 — later research and optional improvements

### P3-1 — per-sensor process isolation — TODO

- **Evidence:** ADR-0002 intentionally keeps first-party sensors in-process and
  the threat model accepts shared-process availability loss.
- **Affected:** runtime/sensor lifecycle, IPC, health/admin, packaging and ADR.
- **Security/egress:** fault containment only; untrusted bytes remain data. Avoid
  a large orchestrator without evidence.
- **Dependencies:** architecture/blast-radius analysis of IPC, resource caps,
  restart policy, readiness and shutdown.
- **Acceptance:** minimal auditable protocol, bounded resources, clear ownership,
  deterministic shutdown and proof that input cannot become behavior.
- **Verify:** process crash/restart/IPC fuzz/race tests and full suite.

### P3-2 — MCP/agentic threat model maintenance — PASS

- **Evidence:** the current threat model covers basic prompt injection/tool
  poisoning but not mutable definitions, shadowing, confused deputy, token
  passthrough, resource/audience/issuer binding, context over-sharing, or model
  and extension supply-chain compromise.
- **Affected:** threat model, canary model, ADRs and future authenticated MCP work.
- **Security/egress:** preserve observation-only semantics and data minimization;
  no authorization feature is implied as shipped.
- **Dependencies:** current OWASP and MCP specification sources.
- **Acceptance:** each threat names the present boundary, current mitigation,
  residual risk and whether it applies now or to a future authenticated surface.
- **Verify:** source links resolve; claims remain separated from implementation;
  `make lint test`.

### P3-3 — distributed mesh, web console and richer exports — TODO

- **Evidence:** ROADMAP labels these as later directions and no shipped code owns
  their trust, tenancy or authorization boundaries.
- **Affected:** future control plane/API/UI and deployment architecture.
- **Security/egress:** substantial new network and multi-tenant surface requiring
  separate threat models and explicit authorization.
- **Dependencies:** stable single-node runtime and evidence/export contracts.
- **Acceptance:** future ADRs and scoped vertical slices; no aspirational capability
  is described as implemented.
- **Verify:** defined with each future slice; currently NOT RUN.

## Current evidence boundaries

- **BLOCKED:** Exa connector tools are not exposed to this task; native web
  research was used.
- **BLOCKED:** GitHub PR/issue API calls could not connect, including a scoped
  escalated retry. Local authentication status alone does not prove public state.
- **BLOCKED:** the current sandbox cannot bind the demo loopback listeners; package
  integration tests that create real loopback listeners pass under `make lint test`.
- **NOT RUN:** release publication, signing, repository-setting changes, new
  external egress and real-cluster deployment were outside this block's authority.
