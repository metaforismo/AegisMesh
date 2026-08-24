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
  the shipped recommendation boundary is distinguished from autonomous
  enforcement; canary activations remain observations rather than incidents.
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

### P1-2 — SSH deception sensor — PASS

- **Evidence:** the baseline accepted only `http`, `tcp`, and `mcp`. The shipped
  `internal/sensor/sshsensor` performs real SSH handshakes with synthetic
  password/public-key authentication, emits bounded redacted observations, and
  rejects every channel and global request. Migration maps only kind, derived
  id, and safe listen address; unsupported behavior is reported, never copied.
- **Affected:** config schema/validation/scaffold, runtime sensor construction,
  new `internal/sensor/sshsensor` package, migration, docs and deployment
  examples, plus the resolved dependency graph.
- **Security/egress:** inbound listener only. Password and public-key
  authentication is synthetic; usernames and credential contents are omitted,
  not hashed. No shell, PTY, subsystem, SFTP, forwarding, filesystem,
  command-execution, or outbound-target path may exist. Loopback and
  unprivileged defaults remain the safe baseline.
- **Dependencies:** `golang.org/x/crypto/ssh` `v0.55.0` is pinned and
  BSD-3-Clause; the seven-module resolved graph passed the repository license
  gate and `go mod verify`. Go 1.25.14 is the minimum current 1.25 patch; the
  preceding 1.25.13 patch removed reachable standard-library vulnerabilities
  through the SSH stack. P0-2 lifecycle hardening is PASS. No new egress was
  added.
- **Acceptance:** Ed25519 host key generated and held in memory per sensor instance
  with no configured key path; strict bounded config for server version,
  handshake/session deadlines, and authentication attempts; fixed caps for
  concurrent connections and protocol metadata; synthetic auth only; all
  channels/global requests rejected; redaction and omission assertions; real
  loopback integration, restart/shutdown, adversarial input, and race tests.
  Startup/shutdown races and timeout paths preserve terminal lifecycle
  semantics, including when `Close` wins a concurrent bind.
- **Verify:** focused unit/integration tests for `internal/sensor/sshsensor`,
  config and runtime; real loopback client/server tests; `go test -race` on
  affected packages; `go mod verify`; `go list -m -json all`;
  `./scripts/license-check.sh`; `./scripts/secrets-scan.sh`; `make lint test`.
- **Status:** **PASS** — focused real-loopback tests, adversarial auth/config
  tests, affected-package race tests, SSH fuzz smoke, pinned vulnerability
  scan, dependency/license checks, full suite, Helm contract, and documentation
  truth-sync passed in the current environment; see `docs/verification.md`.

### P1-3 — dry-run recommendation engine — PASS

- **Evidence:** the prior baseline had no recommendation package or CLI, and
  `policy.Enforcer` changes only decoy responses. `internal/recommend` now owns a
  pure evidence-to-proposal boundary; `aegismesh recommend` performs a complete
  bounded, fail-closed local read before buffered human or JSON output.
- **Affected:** HTTP/TCP detection evidence, `internal/storage`, new
  `internal/recommend`, `internal/cli`, rule catalog, fuzz CI, architecture,
  product, CLI, threat-model, canary, handoff and verification docs.
- **Security/egress:** recommendations only. No firewall, credential, process,
  production mutation, runtime policy, bus, webhook, extension, LLM, command,
  or enforcement seam; no new egress. Any future action connector needs
  separate architecture and action-time approval.
- **Dependencies:** ADR-0012; typed findings persisted by HTTP/TCP/MCP; unified
  rule catalog; fail-closed streaming evidence reader.
- **Acceptance:** every output is labeled `recommendation`, `dry_run`,
  `proposed`, and `signal_not_incident`; links exact evidence IDs and payload
  hashes from envelopes that passed structural validation and observation-hash
  consistency checks; states that this is not signature or provenance
  authentication; remains deterministic; uses static guidance only; exposes
  conflicts/false-positive limits; filters before the final limit; and writes no
  stdout for malformed, incompatible, duplicate, oversized, or corrupt input.
- **Verify:** exact human/JSON goldens; exhaustive CLI empty/whitespace/padded/
  repeated/comma/missing/invalid/positional matrix; storage streaming regression;
  core caps/conflict/correlation/canary tests; recommendation fuzz target;
  affected-package race suite; `make lint test`; see `docs/verification.md`.
- **Status:** **PASS** — focused and full race suites, six-target fuzz suite,
  independent adversarial review, documentation truth-sync, local hygiene and
  PR #51 CI passed; merged as `86041b8`.

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

### P1-5 — extension live-policy boundary — PASS

- **Evidence:** the former v1alpha1 schema reserved `respond`, the host exposed a
  generic raw-result call, matching response bodies were discarded without a
  typed contract, and fan-out still occurred after a failed primary append.
- **Affected:** extension manifest/host/manager, runtime fan-out, CLI/reference
  observer, architecture, threat model and operator documentation.
- **Security/egress:** response influence is a security architecture change.
  Sending correlation signals to extensions or webhooks is new external egress
  and requires explicit approval. Never republish signals with `Bus.Submit`.
- **Dependencies:** P0-2; ADR-0014. No new egress or response authority was
  approved or added.
- **Acceptance:** observe-only strict manifests; identity-bound handshake;
  canonical event-bound acknowledgements; no extension-produced return value;
  failed primary append suppresses fan-out; bounded concurrent shutdown and
  terminal process revocation; no execution, path/config mutation, enforcement,
  signal recursion or ordering change.
- **Verify:** adversarial schema/capability tests, shutdown saturation tests,
  runtime race tests and `make lint test`.
- **Status:** **PASS** — focused and full race suites, parser fuzzing,
  independent review, truth-sync and PR #53 CI passed; merged as `ee54a63`.

### P1-6 — `aegismesh demo` command — PASS

- **Evidence:** the former shell walkthrough used fixed ports, external `curl`
  and `nc`, omitted SSH, exposed dynamic state and could not run in parallel.
  The shipped CLI now owns the complete scenario and the script is a thin
  compatibility wrapper.
- **Affected:** `internal/demo`, runtime endpoint discovery, CLI registration,
  completion, exact goldens, script, product/CLI/architecture/security docs.
- **Security/egress:** loopback-only, synthetic-only, no API key/cloud/privileged
  port, proxy, user path or destination. No external egress, exec or enforcement.
- **Dependencies:** runtime-owned immutable endpoint snapshots without widening
  `sensor.Sensor`; the merged recommendation engine; existing SSH dependency.
- **Acceptance:** meaningful HTTP/TCP/MCP/SSH-to-evidence flow, deterministic
  human/JSON summaries, bounded readiness/requests, complete cleanup, strict
  four-envelope/hash verification, one dry-run proposal, repeated parallel runs.
- **Verify:** exact CLI goldens and adversarial argument matrix; repeated and
  parallel real-loopback integration; affected race suite; `make lint test`;
  see `docs/verification.md`.
- **Status:** **PASS** — focused race tests passed three repetitions including
  three concurrent demos; independent review and post-fix re-review, final
  broader gates and PR #52 CI passed. Merge is the final delivery gate.

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

### P2-2 — supply-chain hardening — PASS

- **Evidence:** the previous release workflow granted OIDC authority to the
  build/SBOM job, scanned the workspace rather than the target application,
  merged every workflow artifact before publication, and used mutable
  container tags. Local SBOM guidance selected arbitrary installed tools or
  recommended `@latest`; no regression gate enforced these boundaries. The
  implementation now separates read-only build/SBOM jobs from exact-subject
  attestation, downloads eight named publication artifacts, pins tools/actions/
  image indexes, and validates deterministic CycloneDX 1.6 application graphs.
- **Affected:** CI/release workflows, Makefile, Docker build context, SBOM/static
  check scripts, `tools/sbomcheck`, release/license/threat/ADR/handoff docs.
- **Security/egress:** build-time downloads only. Do not add signing credentials,
  publish artifacts, or change repository settings without action-time approval.
  No runtime module, destination, or egress changed.
- **Dependencies:** Go 1.25.14; CycloneDX GoMod v1.10.0; govulncheck v1.7.0;
  exact Actions and multiarch image-index digests. PR #47 CI exercised tool
  acquisition because the local sandbox denied it.
- **Acceptance:** pinned tool acquisition; schema-valid CycloneDX inventory with
  direct/transitive relationships; publish bytes come only from exact named
  artifacts; OIDC exists only in the binary attestation job; provenance
  verification binds repository, workflow, source tag, and commit; checksums,
  inventories, provenance, and signing remain distinct claims.
- **Verify:** `go test ./tools/sbomcheck -count=1`; `sh -n scripts/*.sh`;
  `./scripts/check-supply-chain_test.sh`; `make supply-chain-check`; `make sbom`;
  `make sbom-check`; repeat SBOM generation plus `cmp`; `actionlint
  .github/workflows/{ci,release}.yml`; `make lint test`; `make fuzz-seed`;
  `make helm-contract`; `make vuln`; `go mod verify`; license/secret/diff gates.
  Release publication and provenance creation remain NOT RUN without approval.
  PR #47 independently passed the real SBOM validator and byte-for-byte second
  generation, pinned govulncheck, full race/fuzz, Helm, license and secret jobs.

### P2-3 — deployment evidence — PASS (packaging-only boundary)

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
- **Status:** **PASS for the v0.2 claim boundary** — the chart remains
  contract-tested packaging only; real-cluster support, published-image
  operation, upgrades and rollback remain explicitly unverified and are not
  presented as shipped support. No cluster or publication action was run.

## P3 — later research and optional improvements

### P3-1 — per-sensor process isolation — IN PROGRESS

- **Evidence:** the default remains the ADR-0002 in-process path; opted-in
  HTTP/TCP/MCP/SSH sensors now run behind one fixed same-binary worker each.
- **Affected:** runtime/sensor lifecycle, IPC, health/admin, packaging and ADR.
- **Security/egress:** fault containment only; untrusted bytes remain data. Avoid
  a large orchestrator without evidence.
- **Dependencies:** ADR-0015 and completed architecture/blast-radius analysis;
  no automatic restart in v0.2.
- **Acceptance:** minimal auditable protocol, bounded resources, clear ownership,
  deterministic shutdown and proof that input cannot become behavior.
- **Verify:** real sibling-worker crash containment; all-four-sensor loopback
  E2E; binary `body_file`; blocked-write, cancellation, shutdown and readiness
  lifecycle tests; IPC fuzz/race; cross-build; full suite.
- **Status:** **IN PROGRESS** — fixed executable/argv,
  minimal environment, private working directory, challenge-bound canonical
  IPC, parent-owned envelopes, allowlisted declaration-first metrics, bounded
  resources and direct-child reap are implemented; focused, race, full-suite,
  fuzz, cross-build, Helm and repository-hygiene gates pass locally. This
  remains fault containment, not a sandbox. PR CI and merge are still required
  before this item becomes PASS.

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

- **BLOCKED:** Exa connector tools are not exposed to this task. Native web
  research was the explicitly authorized fallback and used primary sources.
- **PASS:** loopback integration and race tests ran with scoped host access; no
  pass is inferred from the restricted sandbox's bind policy.
- **PASS:** scoped GitHub API access verified authentication, open pull requests
  and open issues before the SSH PR was created.
- **NOT RUN:** release publication, signing, repository-setting changes, new
  external egress and real-cluster deployment were outside this block's authority.
