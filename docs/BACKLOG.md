# Engineering backlog

Current local branch: `perf/console-hot-paths`, based on `feat/console-sso`
(`338eea7`). The measured backend performance/architecture changes remain
uncommitted. Inherited SSO via OIDC and logical tenant isolation remain
experimental as specified in ADR-0019/0020 and `architecture/console-api.md`.
Current local performance and verification evidence is dated 2026-11-16 in
`verification.md`; older branch receipts below are historical.


Updated: 2026-11-16. This is the living, evidence-backed queue. The cumulative
queue through merge commit `eef2b93` is preserved in
[`BACKLOG-history-through-eef2b93.md`](BACKLOG-history-through-eef2b93.md).

An item is complete only after implementation, focused tests, relevant broader
tests, documentation truth-sync and captured evidence. Status vocabulary is
`TODO`, `IN PROGRESS`, `PASS`, `FAIL`, `BLOCKED` and `NOT RUN`.

## 2026-11-16 — measured backend follow-up (`perf/console-hot-paths`)

These are scoped follow-ups from the local architecture pass, not capability
claims or release blockers invented from hypothetical load. Measurements and
limits are in `architecture/performance.md` and the dated verification entry.

- **TODO P1 — isolate doctor tests from live default listeners.**
  `internal/cli/cli_test.go:TestDoctorReportsChecksHumanAndJSON`, the correlation
  doctor tests and webhook doctor tests expect scaffold/default ports to be
  free. The first full local gate failed on occupied 8081/6399/8090/9110 while the
  backend changes left those processes and existing tests untouched. A later
  baseline control and full retry passed after the conflict cleared. Give these
  tests ephemeral listener fixtures in a separate change; preserve production
  doctor bind checks. See the dated verification entry for the baseline control.
- **TODO P1 — paired console/IO controls and accepting-hub overview.** The
  eight-tenant cookie overview did not improve in the short handler samples,
  despite lower allocation, and unchanged storage/session/heartbeat controls
  varied or regressed. Repeat with controlled machine load and interleaved
  baselines before attributing those timings. Add an accepting fleet hub and
  live registry-name resolution: `overview_handlers.go` adds `ByNode`, and
  `evidenceindex/overview.go:ByNode` currently resolves names per observation.
  The current handler benchmark has no hub and no live resolver. Keep this gap
  distinct from the independent hub ingestion benchmark.
- **TODO P1 — append codec ownership.** `storage.Store.Append`,
  `evidenceindex.Index.add` and `fleet/agent.Agent.Enqueue` each marshal the same
  envelope. Define a small trusted encoded-envelope seam before trying to share
  bytes: storage success must precede either tap, byte bounds must remain exact,
  and queue/index copies must outlive callers without aliasing. Benchmark taps
  separately from disk, including queue overflow and encrypted checkpoints.
- **TODO P1 — out-of-order append and contention workloads.**
  `evidenceindex/index.go` and `selectors.go` maintain chronological lists;
  substantially late arrivals walk backwards under the writer lock, including
  secondary lists. Add skewed timestamps and simultaneous append/read benchmarks
  before choosing a different ordered structure. Current timing is sequential
  chronological append and read-only queries, not lock-wait or saturation proof.
- **TODO P1 — source and filter cardinality.** `overview.go` still sorts all
  distinct source aggregates before returning the top ten/fifty; severity-only
  and free-text queries still scan retained candidates to provide exact
  `total_matched`. `index.go:GetNode` still scans when resolving an unscoped
  remote ID and rejecting collisions; the related benchmark uses a local signal.
  Measure high-cardinality sources, remote lookup, long rule sets and query
  mixes before adding heap selection or another maintained index. Keep exact
  ordering, inclusive query timestamps and half-open overview windows.
- **TODO P1 — explicit runtime monitor ownership and shutdown errors.**
  `runtime/lifecycle.go:Run` uses the caller context for sensor-monitor goroutines;
  an early return relies on sensor `Done`/caller cancellation for their exit.
  Give monitors their own cancellation/join scope, with a terminal-failure test.
  Separately decide how `System.Stop` can expose fleet/store shutdown failures:
  it currently returns no error and several close errors are discarded or logged.
  Changing that contract belongs in a lifecycle change, not this mechanical split.
- **TODO P2 — preserve runtime error causes deliberately.**
  `runtime/runtime.go` uses `fmt.Errorf("%w: %v", errRuntime, err)` at several
  construction boundaries. That retains text but discards `errors.Is`/`As`
  access to the provider/storage cause. Decide the error-inspection contract and
  safe diagnostic boundaries before replacing this with multiple wrapping or
  typed construction errors; add caller-level error assertions. Do not expose
  provider responses or secret-bearing configuration through richer diagnostics.
- **TODO P2 — move shared private state IO out of console.** Fleet hub and
  identity already reuse `console/stateio`; this is a package ownership problem,
  not duplicate atomic-write code. Move it to a neutral small internal package
  with import-only changes, preserving private modes, fixed names, stale-temp
  refusal, directory sync and the 32 MiB limit. Tenant migration and encrypted
  storage have different durability/format contracts and must stay separate.
- **TODO P2 — tenant fleet dispatch lookup.**
  `fleet/hub/tenants.go:routePartition` searches declared partitions for a node,
  and enrollment searches token digests. Current maximum is 32 partitions;
  existing hub benchmarks use one partition. Measure the eight/thirty-two-tenant
  registry path before adding an ownership directory; revocation, enrollment and
  restart must invalidate/update it atomically. Console evidence already uses
  separate per-tenant indexes, not post-filtering.
- **TODO P2 — shared SSE encoding.** `console/events_handlers.go:stream` encodes
  per subscriber (16 maximum). The paced benchmark includes real stream handlers
  but no sockets, cookie-revalidation churn or TLS. Only introduce shared frames
  with a tenant-owned broadcaster, explicit cancellation/join ownership, immutable
  bytes and slow-client tests. Current bounded drop/close behavior stays intact.

Reviewed and deliberately retained: constant-time scan of at most 32 operator
hashes (`console/auth`), separate session/fleet limiter policies, endpoint-specific
cursor keys/scopes, OIDC provider/JWKS refresh and allowlist boundaries, config
validation in `config/console.go`, `oidc.go` and `fleet.go`, and consumer-owned
runtime sink interfaces. They have different contracts or no demonstrated hot
cost in this workload. No enforcement, token policy, state format or config
surface was changed. Secondary lists/cursor anchors are removed on eviction;
static catalog metadata has no runtime registration/invalidation mechanism.

## Recorded earlier baseline

- Local `master` is `484bd65`, verified through local Git ancestry, with the
  merges of #72-#76 (toolchain, encryption, console API/UI and fleet inventory).
- Current worktree: `feat/evidence-forwarding`, initially clean at `25645c0`
  (v3 encrypted live-read / stacked PR #77). Evidence forwarding remains uncommitted;
  no remote operations or hosted-CI checks were run. Earlier references are historical receipts.
- No release, tag, image, signature, deployment or repository-setting change is
  part of this task; refresh remote dependency issue state before further triage.
- Manual browser checks of the console and of two-process fleet enrollment on
  loopback are recorded in `docs/verification.md`.
- PR #58 is closed/unmerged; its recovered draft and historical checks are not
  review, CI or merge evidence for #73.
- Other backlog items retain their prior recorded statuses; no release-readiness
  completion, repository administration or remote PR-state refresh is implied.

## P0 — correctness, security, data loss, broken builds, dishonest claims

### P0-1 — post-PR-54 documentation and evidence truth-sync — PASS

- **Evidence:** `docs/ROADMAP.md`, `docs/HANDOFF.md`,
  `docs/DELIVERY-PLAN.md`, this backlog and the top verification entry still
  described per-sensor process isolation as awaiting PR CI/merge although PR
  #54 merged as `eef2b93`. The old current-evidence section also said Exa was
  unavailable, while both Exa search and fetch are callable in this run.
- **Affected:** product, roadmap, handoff, backlog and verification documents.
- **Security/egress:** documentation-only. Accurate boundaries prevent operators
  from treating process containment as a sandbox or interpreting historical
  tool failures as current facts. No runtime egress.
- **Dependencies:** public GitHub state and PR #54 CI evidence.
- **Acceptance:** current docs record #54 as merged, preserve its sandbox limits,
  separate historical evidence into archives, disclose the unavailable local
  checkout, and state the future SaaS direction without claiming a shipped
  control plane or multi-tenancy.
- **Verify:** inspect the exact PR #54 head and hosted jobs; compare current docs
  with `master`; `git diff --check`; normal documentation PR CI.
- **Status:** **PASS** — PR #55 merged as `52b6ead`.

### P0-2 — unresolved code correctness/security defects — PASS

- **Evidence:** the prior queue closed fail-closed export, segment-read error
  propagation, producer/shutdown channel races, runtime readiness drift and
  process-worker lifecycle findings. PR #54 head passed full race, build,
  cross-build, fuzz, Helm, vulnerability, license/secret and SBOM gates.
- **Affected:** repository-wide.
- **Security/egress:** no known unresolved P0 defect was identified from the
  current source, public PR state or verification ledger. This is not a claim
  that defects cannot exist.
- **Dependencies:** continuous review and CI.
- **Acceptance:** any newly reproduced P0 preempts feature work and receives a
  red regression test before the fix.
- **Verify:** `make lint test`, focused red regressions, applicable fuzz/race and
  hosted vulnerability gates.
- **Status:** **PASS for the current audit snapshot**.

### P0-3 — enforce the configured storage event-size cap — PASS

- **Evidence:** `storage.max_event_bytes` was strictly decoded, defaulted and
  documented, but `runtime.Build` did not pass it to `storage.Options` and the
  store had no independent event-size field. An event larger than the declared
  cap was therefore accepted whenever it still fit inside `max_file_bytes`.
- **Affected:** `internal/storage`, `internal/runtime`, storage configuration,
  changelog and verification evidence.
- **Security/egress:** restores the promised local encoded-record and disk
  bound. No new destination, credential, dependency or egress.
- **Dependencies:** must land before encrypted framing derives ciphertext caps
  from the maximum plaintext event size.
- **Acceptance:** direct store construction defaults to 256 KiB, rejects values
  below 1024 bytes, rejects an encoded envelope above the configured cap before
  any append-count or segment mutation, and runtime construction wires the
  loaded value into the store.
- **Verify:** `go test ./internal/storage -run
  'Test(MaxEventBytes|OversizeEventRejected|AppendAndReadBack)' -count=1`;
  `go test ./internal/runtime -run TestBuildWiresStorageMaxEventBytes -count=1`;
  `go test -race ./internal/storage ./internal/runtime -count=1`;
  `make lint test`; hosted CI on the exact PR head.
- **Status:** **PASS** — merged to `master` as PR #56 (`8652ef5`) with hosted CI
  green on the merge commit.

## P1 — v0.2 completion and important architectural gaps

### P1-1 — optional evidence-at-rest encryption — baseline implemented; v3 local amendment

- **Scope:** public-recipient-only native age/X25519 writes and explicit local
  read identities; plaintext remains default in new directories, with a persistent
  anti-downgrade guard once encryption is enabled.
- **V3 result:** authenticated prefix checkpoints at existing busy flush cadence,
  no idle checkpoints, bounded control records counted against file size, seals
  on size/age/close or checkpoint space exhaustion, restart to a new file.
  CLI reads prefixes with stderr/JSON notices; older open files warn as interrupted
  and doctor reports structural status without keys. `--require-sealed` restores
  strict output failure. Console still cannot backfill encrypted history.
- **Compatibility:** plaintext/v2/v3 history; sealed v2 works, unfinished v2 fails
  with v3 guidance; no in-place migration, repair or new configuration knob.
- **Security boundary:** no new dependencies, egress, commands or enforcement.
  Complete corrupt records fail closed. Open prefixes permit tail rollback;
  even a removed seal truncated to a checkpoint appears open in permissive mode.
  Use strict reads for completion. Public-recipient holders can forge whole files.
- **Evidence:** record-sequence tables, every-byte crash truncation, key/alias
  failures, injected-clock age/flush/rotation/restart, mixed retention, snapshot
  mutation, CLI staging/golden tests and v2/v3 encrypted-frame fuzz seeds.
  Gate and live runtime receipts are in `docs/verification.md`.
- **Status:** encryption exists in the supplied master baseline. V3 is local
  uncommitted work on `feat/encrypted-live-read`; no commit, push, hosted-CI,
  merge or release action is part of this task.

### P1-2 — final v0.2 release-readiness audit — TODO (blocked)

- **Evidence:** the finite delivery plan requires every v0.2 slice plus a final
  audit. Process isolation is merged; the encryption slice is implemented in
  open PR #73 but not merged.
- **Affected:** entire repository, docs, release workflow and deployment claims.
- **Security/egress:** audit only. It must not publish a release, push an image,
  create a tag, sign artifacts, alter repository settings or deploy a cluster.
- **Dependencies:** PR stack #72-#75 and the fleet PR merged in order; dependency
  PR decisions recorded.
- **Acceptance:** clean `master`; no unresolved P0/P1/P2 milestone item; full
  race/fuzz/Helm/license/secret/vulnerability/SBOM gates on the exact commit;
  documentation and threat model match runtime; release and cluster actions are
  explicitly `NOT RUN` unless separately authorized.
- **Verify:** commands in `docs/DELIVERY-PLAN.md` and `docs/verification.md`.
- **Status:** **BLOCKED — not done; waiting for the PR stack to merge**.

### P1-3 — automated dependency PR triage — TODO

- **Evidence:** PR #48 proposed a Docker-only Go major upgrade. The
  2026-11-14 toolchain security refresh (open PR #72, hosted CI PASS) aligns the
  module, CI, releases, container builder and local tools on Go 1.27.4; local
  verification is in `docs/verification.md`. Dependabot PRs #68 and #70 are
  superseded by #72 but still open; #71 (pinned Action bumps) is untriaged.
  No PR closure or merge has happened.
- **Affected:** Dockerfile, CI/release workflows, immutable-reference fixtures,
  Go toolchain policy and verification.
- **Security/egress:** build-time supply chain. No credentials or runtime egress.
- **Dependencies:** official release notes, exact upstream tags/commits,
  compatibility review and green repository gates.
- **Acceptance:**
  - close or supersede partial toolchain upgrades that would make container,
    module and CI support claims inconsistent;
  - merge immutable Action updates only after upstream identity and permission
    review plus all checks on the exact head;
  - leave an explicit backlog item for a whole-repository Go major upgrade if
    it is desirable after v0.2.
- **Verify:** PR diff, upstream official release/tag evidence, `make
  supply-chain-check`, full CI and exact head status.
- **Status:** **TODO** — triage #71; close #68 and #70 after #72 merges.

## P2 — operational quality, maintainability and product definition

### P2-1 — integrated-branch cleanup — TODO

- **Evidence:** the repository exposes many historical `docs/*`, `feat/*` and
  `codex/*` branches after their work was merged or superseded.
- **Affected:** Git references only.
- **Security/egress:** deletion must be limited to branches proven merged or
  superseded; never delete `master`, active PR heads or branches with unique
  commits. No runtime effect.
- **Dependencies:** compare every candidate with `master`, inspect open PR heads,
  and retain any branch with unmerged work.
- **Acceptance:** delete only verified integrated/superseded branches; report
  branches retained and why; automated PR branches are handled with their PRs.
- **Verify:** per-branch compare, open-PR list before and after, final branch
  inventory.
- **Status:** **TODO**.

### P2-2 — competitive and standards research refresh — TODO

- **Evidence:** the competitive document was last refreshed on 2026-08-23 and
  contains blank Beelzebub source bullets. Upstream repositories, MCP guidance
  and supply-chain standards are mutable.
- **Affected:** `docs/research/competitive-landscape.md`, threat model, ADR links
  and later product planning.
- **Security/egress:** research only. Upstream marketing claims remain labeled as
  claims and no code/text is copied from incompatible projects.
- **Dependencies:** official repositories/docs/specifications and Exa/native web
  access.
- **Acceptance:** working primary-source links; current capability/license
  snapshots for Beelzebub, Cowrie, OpenCanary, T-Pot and Galah; current OWASP
  MCP/agent guidance, MCP authorization, Sigstore, SLSA and CycloneDX references;
  verified facts separated from upstream claims and engineering inferences.
- **Verify:** source links resolve and implementation claims are cross-checked
  against AegisMesh code.
- **Status:** **TODO**.

### P2-3 — SaaS/control-plane architecture brief — PARTIAL DESIGN

- **Evidence:** the operator intends AegisMesh to remain open source and become a
  commercial SaaS. ADR-0018 defines an inventory-only trust foundation; tenant,
  hosted authorization, billing and residency design remains proposed.
- **Affected:** future product/architecture/threat-model documents only; no
  runtime implementation is implied.
- **Security/egress:** a hosted control plane introduces major identity,
  authorization, tenancy, retention and network boundaries. It must not be
  smuggled into the single-node runtime as an implicit outbound edge.
- **Dependencies:** stable v0.2 storage/query contracts and explicit product
  decisions about hosted vs self-hosted responsibilities.
- **Acceptance:** define open-source/core boundary, data-plane/control-plane
  ownership, enrollment, tenant isolation, RBAC/SSO, audit, retention,
  region/residency, billing metering, offline behavior, upgrade channels and
  threat boundaries. Mark every capability as proposed until implemented.
- **Verify:** architecture review and threat-model traceability; no code or egress
  change in the documentation slice.
- **Status:** **PARTIAL DESIGN** — ADR-0018 inventory foundation implemented on
  `feat/fleet-enrollment` (PR #76, unmerged); managed-service acceptance
  remains open.

### P2-4 — real-cluster Kubernetes evidence — TODO (later support claim)

- **Evidence:** the Helm chart has positive/adversarial contract tests but no
  supported-cluster image, persistence, upgrade, rollback or failure-path run.
- **Affected:** deployment docs, chart, image/release process and support matrix.
- **Security/egress:** cluster exposure and image publication are separate
  operator actions. Current packaging-only wording is accurate.
- **Dependencies:** an approved image source or locally loaded image and a
  disposable kind/k3d environment.
- **Acceptance:** exact Kubernetes/container runtime matrix, persistence,
  NetworkPolicy, probes, resource limits, worker behavior, upgrade/rollback and
  failure evidence before any real-cluster support claim.
- **Verify:** documented cluster commands and retained logs; until then this is
  `NOT RUN` operational evidence, not a v0.2 packaging blocker.
- **Status:** **TODO — later milestone**.

## P3 — later research and optional improvements

### P3-1 — distributed mesh and managed fleet — INVENTORY MERGED; LOCAL EVIDENCE AMENDMENT

- **Evidence:** experimental fleet inventory with authenticated enrollment and
  heartbeats merged locally in #76 (`484bd65`); see ADR-0018 and
  `architecture/fleet-protocol.md`, with local receipts in `verification.md`.
- **Affected:** fleet identity/protocol/hub/agent packages, strict config,
  runtime status/counters/lifecycle and console inventory administration.
- **Security/egress:** explicit fixed outbound agent destination, TLS beyond
  loopback, shared egress classification, one-use tokens, per-request Ed25519,
  persistent replay cache, private atomic state, role/CSRF/audit and revocation.
  Hub never dials agents and cannot command nodes; this invariant is permanent.
- **Scope:** not multi-tenant or a managed service. Local opt-in evidence amendment below.
- **Remaining:** review/CI/merge of the separate evidence amendment; durable encrypted spool and offline guarantees,
  key rotation, attestation, hosted tenancy/SSO and upgrades are proposed,
  not implemented. P2-3 managed-service design remains partial.
- **Status:** **Inventory merge observed in local ancestry**. Current forwarding hosted CI NOT RUN. Manual
  two-process loopback check (enrollment, `online`, `stale` after three missed
  heartbeats, token creation and audit) is in `verification.md`; revocation was
  verified by a two-process run and automated tests, not in the browser. No
  publication or deployment.

### P3-2 — read-mostly operator console — IMPLEMENTED (PRs #74, #75, unmerged)

- **Evidence:** `internal/console` and `internal/evidenceindex`; fixed API v1 in
  `architecture/console-api.md`; local checks in `verification.md`.
- **Affected:** strict console config, runtime append tap/lifecycle, CLI token/hash
  opt-in persistent synthetic demo, embedded zero-dependency UI (no build step).
- **Security/egress:** token roles, Host/Origin/CSRF, bounded requests/index/SSE,
  private atomic investigations and hash-chained audit; no new egress/control.
- **Scope:** single-node, single-tenant. Encrypted storage is live-only; console
  notes/audit remain plaintext. SSO/logical isolation are added by ADR-0019/0020 on this branch; optional fleet
  inventory administration is the separate P3-1 item.
- **Remaining:** human review and merge of #74 and #75.
- **Status:** **IMPLEMENTED (API in #74, embedded UI in #75), UNMERGED**. Hosted
  CI PASS on both PR heads (6 of 6 jobs; #75 includes the Node UI tests step).
  Manual browser check against `aegismesh demo --console` passed. Complete
  product acceptance is not claimed; use the verification ledger for exact
  command receipts.

### P3-3 — continuous defensive simulation — TODO

- **Evidence:** `aegismesh demo` validates one owned scenario, not a configurable
  CI adversarial harness.
- **Affected:** future test harness and fixtures.
- **Security/egress:** may probe only explicit operator-owned loopback or approved
  decoy targets; never becomes exploitation or arbitrary scanning.
- **Dependencies:** stable sensor contracts.
- **Acceptance:** deterministic scenarios, target allowlist/ownership checks,
  bounded traffic and evidence assertions.
- **Verify:** future loopback/CI integration tests.
- **Status:** **TODO**.

### P3-4 — additional protocol sensors and local evidence intelligence — TODO

- **Evidence:** Telnet, database protocols and local clustering/TTP summaries are
  roadmap directions only.
- **Affected:** future sensor and analysis packages.
- **Security/egress:** no fake host shell, captured malware execution, autonomous
  action or model-derived behavior. Local model output remains untrusted data.
- **Dependencies:** demonstrated operator need and one protocol/threat model at a
  time.
- **Acceptance:** bounded, defensive vertical slices with honest fidelity claims.
- **Verify:** defined per slice.
- **Status:** **TODO**.

## Closed v0.2 foundations

The following are already `PASS` and are retained in the archived backlog and
verification history with exact commands and regressions:

- fail-closed verified export and segment-read propagation;
- producer/shutdown lifecycle race fixes;
- ECS-compatible local projection;
- authentication-only SSH deception;
- release/SBOM/provenance workflow hardening;
- deterministic dry-run recommendations;
- self-contained four-sensor demo;
- observe-only extension live-policy boundary;
- optional fixed-worker process isolation;
- MCP/agentic threat-model coverage;
- contract-tested Helm packaging with an explicit non-cluster-support boundary.

## Current evidence boundaries

- **PASS:** hosted CI on the heads of PRs #72–#75 (six jobs each); local gates
  recorded per change in `docs/verification.md`.
- **BLOCKED:** `make sbom sbom-check` inside a linked git worktree (the pinned
  generator cannot resolve the main-module version there); hosted CI covers it.
- **NOT RUN:** merges, release/tag/signing/image publication, repository
  settings, site publication, real-cluster deployment, durable offline forwarding and
  correlation-signal fan-out to webhooks or extensions.


### P3-1 evidence forwarding — experimental local implementation (2026-11-15)

`feat/evidence-forwarding` is stacked on the encrypted live-read branch / PR #77.
Best-effort forwarding with counted loss; local store authoritative. Both consent switches
default off. Queue, signature/replay, hostile parsing, bounded deduplication, per-node and
aggregate quotas, hub encryption, origin-scoped index/API and counters are implemented.
See architecture/fleet-protocol.md for exact limits and verification.md for local receipts.
Review/hosted CI/merge/deployment remain separate. Remaining: durable encrypted spool,
forwarded-history index backfill, cross-node correlation, historical forwarding, deletion
propagation and tenancy are not implemented. Hub-to-node traffic remains permanently forbidden.


## Console identity and isolation — local branch, 2026-11-15

`feat/console-sso`, stacked on `feat/evidence-forwarding` (PR #79), adds
**SSO via OIDC (experimental)** and **logical tenant isolation (experimental)**.
These are local uncommitted changes, not a merge, deployment, hosted CI or
operational acceptance claim. ADR-0019/0020 and console-api.md define the exact
contract; verification.md records executed checks and their limits.

OIDC is opt-in Authorization Code/S256, state/nonce/browser binding, library-owned
asymmetric token verification, explicit role and tenant mappings, bounded egress
and credential-capped sessions. Existing tokens remain break-glass by default;
`token_login: false` requires OIDC. Discovery outages retry without stopping
sensors. Logout remains local. No refresh-token persistence or provider logout.

One declared active tenant covers index queries, sources/overview/by_node,
SSE, investigations, audit, fleet registries, enrollment tokens and forwarded
evidence. Local runtime views belong to local_tenant. Per-tenant quotas and
recoverable legacy migration isolate logical state pressure; no admin all view.
At most 32 tenants share a process, OS user, data directory, hub encryption
recipient and signing/egress settings. Host/process compromise and shared disk/
CPU exhaustion cross tenants. Per-tenant keys, billing, rate plans, self-service
creation and a hard hosted isolation boundary remain outside scope.

Delivery polish includes bounded startup gzip, representation-specific strong
ETags/304/no-cache for non-index assets and aligned per-sensor overview buckets
(up to 64 sensor IDs). The existing UI is unchanged; it can consume the documented
meta/session additions. Remaining work includes external-IdP interoperability,
human review and independent deployment evidence; no release action is authorized.
