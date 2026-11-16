# Engineering backlog

Updated: 2026-11-16. This is the living, evidence-backed queue. The cumulative
queue through merge commit `eef2b93` is preserved in
[`BACKLOG-history-through-eef2b93.md`](BACKLOG-history-through-eef2b93.md).

An item is complete only after implementation, focused tests, relevant broader
tests, documentation truth-sync and captured evidence. Status vocabulary is
`TODO`, `IN PROGRESS`, `PASS`, `FAIL`, `BLOCKED` and `NOT RUN`.

## Current baseline

- `master` is `7ae0356` (merge of PR #81), **to be tagged v0.2.0 by a
  maintainer**. No tag, GitHub release, image, binary signature or provenance
  attestation exists.
- Merged to `master`, each through a pull request whose head passed the six
  hosted CI jobs: #72 (Go 1.27.4, `x/crypto` v0.59.0), #73 (evidence encryption),
  #74 (console API), #75 (embedded UI, design system, landing page), #76 (fleet
  inventory), #77 (encrypted container v3 checkpoints), #78 and #81 (console UI
  polish and UI for origin/SSO/tenants), #79 (evidence forwarding), #80 (SSO via
  OIDC and logical tenant isolation) and #82 (performance pass).
- Dependabot PRs #68 and #70 are closed as superseded by #72. PR #71 (pinned
  GitHub Action bumps) is open, rebased and CI-green, and is not yet reviewed or
  merged.
- Fleet inventory, evidence forwarding, SSO via OIDC and logical tenant
  isolation are implemented and merged as **experimental**, opt-in features.
- Not done and not verified: tag/release/image/signature/deployment; OIDC against
  a real external identity provider (local test providers only); UI outside
  Chromium; a real-cluster Kubernetes run; publication of the landing page;
  `golangci-lint` (not installed locally).
- PR #58 is closed/unmerged; its recovered draft and historical checks are not
  review, CI or merge evidence for #73.

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

### P1-1 — optional evidence-at-rest encryption — PASS

- **Scope:** public-recipient-only native age/X25519 writes and explicit local
  read identities; plaintext remains default in new directories, with a persistent
  anti-downgrade guard once encryption is enabled.
- **V3 result (#77):** authenticated prefix checkpoints at existing busy flush
  cadence, no idle checkpoints, bounded control records counted against file size,
  seals on size/age/close or checkpoint space exhaustion, restart to a new file.
  CLI reads prefixes with stderr/JSON notices; older open files warn as interrupted
  and doctor reports structural status without keys. `--require-sealed` restores
  strict output failure. Console still cannot backfill encrypted history.
- **Compatibility:** plaintext/v2/v3 history; sealed v2 works, unfinished v2 fails
  with v3 guidance; no in-place migration, repair or new configuration knob.
- **Security boundary:** the only new direct dependency is `filippo.io/age` v1.3.2
  (BSD-3-Clause, reviewed in `license-policy.md`); no new egress, commands or
  enforcement. Complete corrupt records fail closed. Open prefixes permit tail
  rollback; even a removed seal truncated to a checkpoint appears open in
  permissive mode. Use strict reads for completion. Public-recipient holders can
  forge whole files.
- **Evidence:** record-sequence tables, every-byte crash truncation, key/alias
  failures, injected-clock age/flush/rotation/restart, mixed retention, snapshot
  mutation, CLI staging/golden tests and v2/v3 encrypted-frame fuzz seeds.
  Gate and live runtime receipts are in `docs/verification.md`.
- **Status:** **PASS** — merged as PR #73 (`6d46429`) and PR #77 (`7b96af1`), hosted
  CI green on both heads.

### P1-2 — final v0.2 release-readiness audit — AUDIT PERFORMED; GATES AND TAG PENDING

- **Evidence:** the finite delivery plan requires every v0.2 slice plus a final
  audit. All slices are merged. The documentation and claims audit was performed
  on 2026-11-16 against `master` `7ae0356`; the dated entry in
  `docs/verification.md` records it.
- **Affected:** entire repository, docs, release workflow and deployment claims.
- **Security/egress:** audit only. It did not publish a release, push an image,
  create a tag, sign artifacts, alter repository settings or deploy a cluster.
- **Dependencies:** PR stack #72-#82 merged; dependency PR decisions recorded in
  P1-3.
- **Acceptance criteria and state (2026-11-16):**

  | Criterion | State |
  |---|---|
  | Every delivery-plan slice (1-8) merged, PR and merge commit recorded | MET — `DELIVERY-PLAN.md` |
  | Clean `master` | MET at audit start: the audit branch was cut from `7ae0356` with a clean tree |
  | Full race/fuzz/Helm/license/secret/vulnerability/SBOM gates on the exact commit | PENDING — the maintainer records them in the "Gates on `7ae0356`" table of `docs/verification.md`; hosted CI on earlier PR heads is not a substitute |
  | No unresolved P0/P1/P2 milestone item | NOT MET as written — P1-3 (#71 open) and P2-1, P2-2, P2-3 (partial design), P2-4 remain open. P2-4 is already recorded as a later milestone; the maintainer decides whether the others are deferred to the next milestone (DELIVERY-PLAN completion predicate 7) or closed before tagging |
  | Documentation and threat model match runtime | AUDITED — status-word sweep, link and cross-number checks done; `THREAT-MODEL.md` and the API/protocol contracts were checked for status and numbers, not re-derived from source; no independent human review |
  | Release, tag, signing, image and cluster actions explicitly `NOT RUN` unless authorized | MET — none performed |
  | Verification vocabulary separates `PASS`, `FAIL`, `BLOCKED`, `NOT RUN` | MET — see the verification entry |
  | Final handoff moves only genuinely later work | MET — `HANDOFF.md` "Next priorities after v0.2.0" |

- **Verify:** commands in `docs/DELIVERY-PLAN.md` and `docs/verification.md`.
- **Status:** audit performed 2026-11-16; gates on `7ae0356` recorded in
  docs/verification.md; tag pending maintainer action.

### P1-3 — automated dependency PR triage — PARTIAL

- **Evidence:** PR #48 proposed a Docker-only Go major upgrade. The
  2026-11-14 toolchain security refresh (#72, merged) aligns the module, CI,
  releases, container builder and local tools on Go 1.27.4. Dependabot PRs #68
  and #70 are closed as superseded by #72. PR #71 (pinned Action bumps) is open,
  rebased and CI-green, but not yet reviewed or merged.
- **Affected:** Dockerfile, CI/release workflows, immutable-reference fixtures,
  Go toolchain policy and verification.
- **Security/egress:** build-time supply chain. No credentials or runtime egress.
- **Dependencies:** official release notes, exact upstream tags/commits,
  compatibility review and green repository gates.
- **Acceptance:**
  - close or supersede partial toolchain upgrades that would make container,
    module and CI support claims inconsistent (done for #68, #70);
  - merge immutable Action updates only after upstream identity and permission
    review plus all checks on the exact head (open for #71);
  - leave an explicit backlog item for a whole-repository Go major upgrade if
    it is desirable after v0.2.
- **Verify:** PR diff, upstream official release/tag evidence, `make
  supply-chain-check`, full CI and exact head status.
- **Status:** **TODO** — review #71. #68 and #70 are closed.

## Post-v0.2 follow-ups from the measured performance pass (next milestone)

These are scoped follow-ups from the architecture pass merged as #82, not
capability claims or release blockers invented from hypothetical load.
Measurements and limits are in `architecture/performance.md` and the dated
verification entry.

- **TODO (high) — isolate doctor tests from live default listeners.**
  `internal/cli/cli_test.go:TestDoctorReportsChecksHumanAndJSON`, the correlation
  doctor tests and webhook doctor tests expect scaffold/default ports to be
  free. The first full local gate failed on occupied 8081/6399/8090/9110 while the
  backend changes left those processes and existing tests untouched. A later
  baseline control and full retry passed after the conflict cleared. Give these
  tests ephemeral listener fixtures in a separate change; preserve production
  doctor bind checks. See the dated verification entry for the baseline control.
- **TODO (high) — paired console/IO controls and accepting-hub overview.** The
  eight-tenant cookie overview did not improve in the short handler samples,
  despite lower allocation, and unchanged storage/session/heartbeat controls
  varied or regressed. Repeat with controlled machine load and interleaved
  baselines before attributing those timings. Add an accepting fleet hub and
  live registry-name resolution: `overview_handlers.go` adds `ByNode`, and
  `evidenceindex/overview.go:ByNode` currently resolves names per observation.
  The current handler benchmark has no hub and no live resolver. Keep this gap
  distinct from the independent hub ingestion benchmark.
- **TODO (high) — append codec ownership.** `storage.Store.Append`,
  `evidenceindex.Index.add` and `fleet/agent.Agent.Enqueue` each marshal the same
  envelope. Define a small trusted encoded-envelope seam before trying to share
  bytes: storage success must precede either tap, byte bounds must remain exact,
  and queue/index copies must outlive callers without aliasing. Benchmark taps
  separately from disk, including queue overflow and encrypted checkpoints.
- **TODO (high) — out-of-order append and contention workloads.**
  `evidenceindex/index.go` and `selectors.go` maintain chronological lists;
  substantially late arrivals walk backwards under the writer lock, including
  secondary lists. Add skewed timestamps and simultaneous append/read benchmarks
  before choosing a different ordered structure. Current timing is sequential
  chronological append and read-only queries, not lock-wait or saturation proof.
- **TODO (high) — source and filter cardinality.** `overview.go` still sorts all
  distinct source aggregates before returning the top ten/fifty; severity-only
  and free-text queries still scan retained candidates to provide exact
  `total_matched`. `index.go:GetNode` still scans when resolving an unscoped
  remote ID and rejecting collisions; the related benchmark uses a local signal.
  Measure high-cardinality sources, remote lookup, long rule sets and query
  mixes before adding heap selection or another maintained index. Keep exact
  ordering, inclusive query timestamps and half-open overview windows.
- **TODO (high) — explicit runtime monitor ownership and shutdown errors.**
  `runtime/lifecycle.go:Run` uses the caller context for sensor-monitor goroutines;
  an early return relies on sensor `Done`/caller cancellation for their exit.
  Give monitors their own cancellation/join scope, with a terminal-failure test.
  Separately decide how `System.Stop` can expose fleet/store shutdown failures:
  it currently returns no error and several close errors are discarded or logged.
  Changing that contract belongs in a lifecycle change, not this mechanical split.
- **TODO (medium) — preserve runtime error causes deliberately.**
  `runtime/runtime.go` uses `fmt.Errorf("%w: %v", errRuntime, err)` at several
  construction boundaries. That retains text but discards `errors.Is`/`As`
  access to the provider/storage cause. Decide the error-inspection contract and
  safe diagnostic boundaries before replacing this with multiple wrapping or
  typed construction errors; add caller-level error assertions. Do not expose
  provider responses or secret-bearing configuration through richer diagnostics.
- **TODO (medium) — move shared private state IO out of console.** Fleet hub and
  identity already reuse `console/stateio`; this is a package ownership problem,
  not duplicate atomic-write code. Move it to a neutral small internal package
  with import-only changes, preserving private modes, fixed names, stale-temp
  refusal, directory sync and the 32 MiB limit. Tenant migration and encrypted
  storage have different durability/format contracts and must stay separate.
- **TODO (medium) — tenant fleet dispatch lookup.**
  `fleet/hub/tenants.go:routePartition` searches declared partitions for a node,
  and enrollment searches token digests. Current maximum is 32 partitions;
  existing hub benchmarks use one partition. Measure the eight/thirty-two-tenant
  registry path before adding an ownership directory; revocation, enrollment and
  restart must invalidate/update it atomically. Console evidence already uses
  separate per-tenant indexes, not post-filtering.
- **TODO (medium) — shared SSE encoding.** `console/events_handlers.go:stream` encodes
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

## P2 — operational quality, maintainability and product definition

### P2-1 — integrated-branch cleanup — TODO

- **Evidence:** the repository exposes many historical `docs/*`, `feat/*`,
  `perf/*` and `codex/*` branches after their work was merged or superseded.
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
  commercial SaaS. ADR-0018 (fleet inventory, #76), ADR-0019/0020 (SSO and
  logical tenants, #80) define experimental, self-hosted foundations; hosted
  authorization, hard tenant isolation, billing and residency design remains
  proposed.
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
- **Status:** **PARTIAL DESIGN** — experimental self-hosted foundations are
  merged; managed-service acceptance remains open.

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

### P2-5 — publish the static landing page — TODO (needs approval)

- **Evidence:** `site/` holds a static landing page and design-system reference,
  merged in #75 and kept truthful through #80. It is not hosted anywhere.
- **Affected:** hosting configuration and DNS only; no runtime effect.
- **Security/egress:** publication is an external-state action requiring explicit
  owner approval; no tracking or third-party code is present.
- **Acceptance:** an approved host, a link check against the published origin and
  the existing `make ui-test` site tests.
- **Status:** **TODO — NOT RUN**, pending an owner decision.

## P3 — later research and optional improvements

### P3-1 — distributed mesh and managed fleet — INVENTORY AND FORWARDING MERGED (experimental)

- **Evidence:** experimental fleet inventory with authenticated enrollment and
  heartbeats merged in #76 (`484bd65`); experimental opt-in evidence forwarding
  merged in #79 (`777dcc9`). See ADR-0018 and `architecture/fleet-protocol.md`.
- **Affected:** fleet identity/protocol/hub/agent packages, strict config,
  runtime status/counters/lifecycle and console inventory administration.
- **Security/egress:** explicit fixed outbound agent destination, TLS beyond
  loopback, shared egress classification, one-use tokens, per-request Ed25519,
  persistent replay cache, private atomic state, role/CSRF/audit and revocation.
  Forwarding is separately opt-in on both ends. Hub never dials agents and cannot
  command nodes; this invariant is permanent.
- **Scope:** best-effort forwarding with counted loss; the local store is
  authoritative; memory-only agent queue (4,096 events / 16 MiB); not a managed
  service.
- **Remaining:** durable encrypted spool and offline guarantees, forwarded-history
  index backfill, cross-node correlation, historical forwarding, deletion
  propagation, key rotation, attestation and upgrades are proposed, not
  implemented. P2-3 managed-service design remains partial.
- **Status:** **IMPLEMENTED, MERGED, EXPERIMENTAL.** Manual two-process loopback
  check (enrollment, `online`, `stale` after three missed heartbeats, token
  creation, audit, forwarded counts and origin column) is in `verification.md`;
  revocation was verified by a two-process run and automated tests, not in the
  browser. No publication or deployment.

### P3-2 — read-mostly operator console — IMPLEMENTED AND MERGED

- **Evidence:** `internal/console` and `internal/evidenceindex`; fixed API v1 in
  `architecture/console-api.md`; local checks in `verification.md`.
- **Affected:** strict console config, runtime append tap/lifecycle, CLI token/hash
  opt-in persistent synthetic demo, embedded zero-dependency UI (no build step).
- **Security/egress:** token roles, Host/Origin/CSRF, bounded requests/index/SSE,
  private atomic investigations and hash-chained audit; no new egress/control
  except the opt-in OIDC edge in P3-5.
- **Scope:** encrypted storage is live-only; console notes/audit remain plaintext.
- **Remaining:** UI checks outside Chromium; human review beyond the PR gates.
- **Status:** **IMPLEMENTED, MERGED** (API #74, UI #75, polish #78 and #81). Hosted
  CI PASS on every PR head (six jobs; UI PRs include the Node UI tests step). Manual
  browser check against the real server passed (see `verification.md`). Complete
  product acceptance is not claimed.

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

- **Evidence:** Telnet, database protocols, multi-step synthetic MCP
  environments and local clustering/TTP summaries are roadmap directions only.
- **Affected:** future sensor and analysis packages.
- **Security/egress:** no fake host shell, captured malware execution, autonomous
  action or model-derived behavior. Local model output remains untrusted data.
- **Dependencies:** demonstrated operator need and one protocol/threat model at a
  time.
- **Acceptance:** bounded, defensive vertical slices with honest fidelity claims.
- **Verify:** defined per slice.
- **Status:** **TODO**.

### P3-5 — console SSO and logical tenant isolation — IMPLEMENTED, MERGED, EXPERIMENTAL

- **Evidence:** ADR-0019/0020 and `architecture/console-api.md`; implemented in #80,
  UI in #81; verification in `verification.md` (local test provider, built binary
  with two tenants, browser check with two tenants).
- **Scope:** opt-in Authorization Code/S256; role and tenant mappings; operator
  tokens remain break-glass unless `token_login: false`; logout is local. Up to 32
  declared tenants; one active tenant per session; independent quotas; recoverable
  migration into `tenants/default`.
- **Security boundary:** logical isolation only — one process, OS user, data
  directory and encryption recipient. Host/process compromise and shared
  disk/CPU exhaustion cross tenants.
- **Remaining:** interoperability with real external identity providers (NOT RUN),
  hard tenant separation (per-tenant keys or processes), refresh/provider logout,
  tenant self-service.
- **Status:** **IMPLEMENTED, MERGED, EXPERIMENTAL.**

### P3-6 — measured backend performance pass — PASS

- **Evidence:** #82; `architecture/performance.md`, `make bench`, the dated
  verification entry and `docs/performance/2026-11-15/`.
- **Scope:** secondary indexes and overview snapshots in the console evidence
  index; synthetic local measurements only, with noisy and unmeasured cases stated.
- **Status:** **PASS** for the pass itself; the follow-ups above are open.

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
- contract-tested Helm packaging with an explicit non-cluster-support boundary;
- Go 1.27.4 / `x/crypto` v0.59.0 security refresh (#72);
- optional evidence-at-rest encryption with v3 checkpoints (P1-1).

## Current evidence boundaries

- **PASS:** hosted CI (six jobs) on the head of every merged PR #72-#82; local
  gates recorded per change in `docs/verification.md`.
- **PENDING (maintainer):** the gate table on the exact `master` commit `7ae0356`
  in the 2026-11-16 audit entry of `docs/verification.md`.
- **BLOCKED:** `make sbom sbom-check` inside a linked git worktree (the pinned
  generator cannot resolve the main-module version there); run in an ordinary
  clone or rely on hosted CI.
- **NOT RUN:** tag, release, signing and image publication; repository settings;
  site publication; real-cluster deployment; OIDC against a real identity
  provider; UI outside Chromium; durable offline forwarding (not implemented);
  correlation-signal fan-out to webhooks or extensions (not implemented);
  `golangci-lint` (not installed locally).
