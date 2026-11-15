# Engineering backlog

Updated: 2026-11-15. This is the living, evidence-backed queue. The cumulative
queue through merge commit `eef2b93` is preserved in
[`BACKLOG-history-through-eef2b93.md`](BACKLOG-history-through-eef2b93.md).

An item is complete only after implementation, focused tests, relevant broader
tests, documentation truth-sync and captured evidence. Status vocabulary is
`TODO`, `IN PROGRESS`, `PASS`, `FAIL`, `BLOCKED` and `NOT RUN`.

## Current baseline

- Default branch: `master`, last recorded head `01579d3`. None of the work
  below is merged.
- The 2026-11-14/15 work is a stack of open, unmerged PRs against `master`, in
  merge order: #72 `security/go-toolchain-vuln-fixes` (Go 1.27.4, x/crypto
  v0.59.0); #73 `feat/evidence-at-rest-encryption`; #74 `feat/console-api`;
  #75 `feat/console-ui-embed` (embedded UI, design system, landing page). Each
  is stacked on the previous one and has hosted CI PASS (6 of 6 jobs) on its
  head. Human review and merge are pending.
- Current worktree: `feat/fleet-enrollment`, stacked on #75 (experimental fleet
  inventory). PR pending; hosted CI NOT RUN.
- No release, tag, image, signature, deployment or repository-setting change
  happened. Dependabot PRs #68 and #70 are superseded by #72 but still open;
  #71 (pinned Action bumps) is untriaged.
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

### P0-3 — enforce the configured storage event-size cap — IN PROGRESS

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
- **Status:** **IN PROGRESS** — focused and affected-package race tests passed
  locally. The enforcement shipped in the stacked work (#72 and later); hosted
  CI PASS on those heads, merge pending human review.

## P1 — v0.2 completion and important architectural gaps

### P1-1 — optional evidence-at-rest encryption — IMPLEMENTED (PR #73, unmerged)

- **Evidence:** this change adds native age/X25519 `.jsonl.age` segments,
  explicit read identities, rotation/recovery semantics and a persistent
  anti-downgrade guard while preserving plaintext as the default for data
  directories that have never enabled encryption.
- **Affected:** `internal/storage`, storage configuration and validation,
  runtime construction, `inspect`/`recommend` read paths, CLI contracts,
  examples, threat model, ADRs, release/license policy and verification.
- **Security/egress:** local confidentiality only. Enabling encryption must fail
  closed and must never silently downgrade writes to plaintext. No key service,
  remote KMS or other new destination is approved.
- **Dependencies:** exact-version maintenance/license/vulnerability review of
  `filippo.io/age`; an ADR defining X25519-only recipients/identities, restart,
  rotation, recovery and mixed plaintext/encrypted history semantics.
- **Acceptance:**
  - disabled mode preserves current filenames and bytes;
  - enabled mode creates only authenticated age/X25519 segments;
  - invalid or empty recipients fail before runtime readiness;
  - private identities are explicit read-time references, bounded, never logged
    and never accepted inline in checked-in configuration;
  - encrypted segments fail on missing identity, wrong identity, corruption and
    truncation rather than being skipped or interpreted as plaintext;
  - restart opens a new encrypted stream instead of appending to an incomplete
    previous stream;
  - rotation and count/age retention work across plaintext and encrypted
    segments without deleting the active segment;
  - existing plaintext remains explicitly plaintext until separately migrated;
  - verified export and recommendations preserve their fail-closed output rules.
- **Verify:** table-driven config and key parser tests; storage restart,
  wrong-key, corruption, truncation, rotation and retention integration tests;
  exact CLI omitted/empty/whitespace/padded/repeated/comma/positional matrices;
  affected-package race tests; `make lint test`; applicable fuzz; `go mod
  verify`; license, secret, vulnerability and SBOM gates.
- **Status:** **IMPLEMENTED — PR #73, unmerged**. Branch
  `feat/evidence-at-rest-encryption`, stacked on #72. Hosted CI PASS on the PR
  head (6 of 6 jobs); human review and merge pending. Local gate results are in
  `docs/verification.md`. The closed unmerged PR #58 supplies draft material
  only and is not acceptance evidence.

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
  `feat/fleet-enrollment` (PR pending, unmerged); managed-service acceptance
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

### P3-1 — distributed mesh and managed fleet — INVENTORY IMPLEMENTED (PR pending)

- **Evidence:** experimental fleet inventory with authenticated enrollment and
  heartbeats on `feat/fleet-enrollment`, stacked on #75; see ADR-0018 and
  `architecture/fleet-protocol.md`, with local receipts in `verification.md`.
- **Affected:** fleet identity/protocol/hub/agent packages, strict config,
  runtime status/counters/lifecycle and console inventory administration.
- **Security/egress:** explicit fixed outbound agent destination, TLS beyond
  loopback, shared egress classification, one-use tokens, per-request Ed25519,
  persistent replay cache, private atomic state, role/CSRF/audit and revocation.
  Hub never dials agents and cannot command nodes; this invariant is permanent.
- **Scope:** not multi-tenant, not a managed service; forwards no evidence.
- **Remaining:** open the PR, hosted CI, review and merge; evidence batches and bounded spool,
  key rotation, attestation, hosted tenancy/SSO and upgrades are proposed,
  not implemented. P2-3 managed-service design remains partial.
- **Status:** **IMPLEMENTED — PR pending, unmerged**. Hosted CI NOT RUN. Manual
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
  notes/audit remain plaintext. SSO/multi-tenancy remain absent; optional fleet
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

- **PASS:** Exa search and fetch connectors are callable in this run.
- **PASS:** GitHub API evidence confirms `master`, merge commit `eef2b93`, PR #54
  and its six successful CI jobs.
- **BLOCKED:** the requested macOS checkout is not mounted in this execution
  environment; local `git status`, `make lint test` and Go 1.25.14 runs are not
  available here.
- **NOT RUN:** release/tag/signing/image publication, repository settings,
  real-cluster deployment, new runtime egress and correlation-signal fan-out.
