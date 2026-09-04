# Engineering backlog

Updated: 2026-08-31. This is the living, evidence-backed queue. The cumulative
queue through merge commit `eef2b93` is preserved in
[`BACKLOG-history-through-eef2b93.md`](BACKLOG-history-through-eef2b93.md).

An item is complete only after implementation, focused tests, relevant broader
tests, documentation truth-sync and captured evidence. Status vocabulary is
`TODO`, `IN PROGRESS`, `PASS`, `FAIL`, `BLOCKED` and `NOT RUN`.

## Current baseline

- Default branch: `master`.
- Current public `master` at the start of this block:
  `52b6ead4fc5848d90e29eeb6de6b2c8272485d8d`.
- PR #54 and the subsequent product truth-sync PR #55 are merged.
- No open product issues were present at the start of this run.
- Two automated dependency PRs (#48 and #49) require policy-aware review.
- The operator's macOS checkout is not mounted in the current execution
  environment, so local Git and test commands here are `BLOCKED`; they are not
  relabeled from hosted CI evidence.

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
- **Status:** **IN PROGRESS** — focused and affected-package race tests pass
  locally; hosted CI and merge remain required.

### P0-4 — close reachable x/crypto/ssh channel DoS vulnerabilities — IN PROGRESS

- **Evidence:** hosted `govulncheck` on the encryption pre-merge gate reached
  `ssh.NewServerConn` and reported GO-2026-6354 and GO-2026-6355 against
  `golang.org/x/crypto v0.55.0`; both are fixed in v0.56.0.
- **Affected:** `go.mod`, `go.sum`, Docker builder, Makefile/SBOM/release
  toolchain selection, SSH dependency documentation and verification.
- **Security/egress:** availability fix for inbound SSH deception. Build-time
  dependency/tool acquisition only; no runtime destination or authority change.
- **Dependencies:** x/crypto v0.56.0 requires Go 1.26+, so this is a coordinated
  Go 1.26.8 repository-wide upgrade rather than a Docker-only bump.
- **Acceptance:** Go/toolchain/container references agree; SSH focused/race/fuzz,
  whole-repository race, Helm, vulnerability, license, secret, supply-chain and
  deterministic SBOM gates pass on one exact PR head.
- **Verify:** `make lint test`; `make fuzz-seed`; `make helm-contract`; `make
  vuln`; `make license-check secrets-scan`; `make supply-chain-check`; `make
  sbom sbom-check`; release cross-build smoke; exact-head normal CI.
- **Status:** **IN PROGRESS** — candidate is gated before PR; normal exact-head
  CI and merge remain required.

## P1 — v0.2 completion and important architectural gaps

### P1-1 — optional evidence-at-rest encryption — TODO

- **Evidence:** `internal/storage` writes plaintext `.jsonl` segments and the
  threat model explicitly accepts plaintext-at-rest risk. No encryption
  dependency or key lifecycle is currently wired.
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
- **Status:** **TODO**.

### P1-2 — final v0.2 release-readiness audit — BLOCKED

- **Evidence:** the finite delivery plan requires every v0.2 slice plus a final
  audit. Process isolation is merged, but P1-1 remains unfinished.
- **Affected:** entire repository, docs, release workflow and deployment claims.
- **Security/egress:** audit only. It must not publish a release, push an image,
  create a tag, sign artifacts, alter repository settings or deploy a cluster.
- **Dependencies:** P1-1 merged; dependency PR decisions recorded.
- **Acceptance:** clean `master`; no unresolved P0/P1/P2 milestone item; full
  race/fuzz/Helm/license/secret/vulnerability/SBOM gates on the exact commit;
  documentation and threat model match runtime; release and cluster actions are
  explicitly `NOT RUN` unless separately authorized.
- **Verify:** commands in `docs/DELIVERY-PLAN.md` and `docs/verification.md`.
- **Status:** **BLOCKED — depends on P1-1**.

### P1-3 — automated dependency PR triage — TODO

- **Evidence:** open PR #48 updates only the Docker Go image to a new Go major
  line, while the module, CI and release toolchain remain pinned to Go 1.25.14.
  Open PR #49 changes pinned GitHub Action commits. Neither should be merged
  merely because Dependabot opened it.
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
- **Status:** **TODO**.

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

### P2-3 — SaaS/control-plane architecture brief — TODO

- **Evidence:** the operator intends AegisMesh to remain open source and become a
  commercial SaaS, but no control-plane, tenant, authorization, billing or data
  residency design exists.
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
- **Status:** **TODO — schedule after v0.2**.

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

### P3-1 — distributed mesh and managed fleet — TODO

- **Evidence:** current runtime is single-node and owns no remote control channel.
- **Affected:** future sensor identity, enrollment, transport, buffering,
  reconciliation, authorization, upgrade and control-plane packages.
- **Security/egress:** substantial new outbound and multi-tenant surfaces.
- **Dependencies:** P2-3 architecture and stable evidence contracts.
- **Acceptance:** separate ADR/threat model and one bounded vertical slice; no
  generic remote command execution.
- **Verify:** defined with the future slice.
- **Status:** **TODO**.

### P3-2 — read-only web investigation console — TODO

- **Evidence:** no public query API or UI exists.
- **Affected:** future API/UI/auth/query layers.
- **Security/egress:** evidence may contain attacker-controlled and sensitive
  content; output encoding, tenant isolation and authorization are mandatory.
- **Dependencies:** stable read/query API and P2-3.
- **Acceptance:** read-only default, explicit scopes, bounded queries, safe
  rendering and auditability before any mutation capability is considered.
- **Verify:** future contract, integration, authorization and browser tests.
- **Status:** **TODO**.

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
