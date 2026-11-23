# AegisMesh roadmap

Updated: 2026-11-16. Checked items are implemented **and verified** in this
repository and merged to `master` (`7ae0356`, to be tagged v0.2.0). Intent,
research and product direction remain unchecked until an implementation and its
acceptance gates are complete.

## Batch 1 — foundation

- [x] Product brief, principles, non-goals, threat model, trust boundaries and data-flow diagrams
- [x] Competitive-landscape research with claims/evidence separation
- [x] Apache-2.0 governance, contribution, security, support and release policies
- [x] CLI: `init`, `doctor`, `validate`, `run`, `inspect`, `migrate beelzebub`, `version`, `completion`
- [x] Schema-versioned strict configuration with documented precedence
- [x] HTTP, TCP and MCP deception sensors
- [x] Static policy gate and deterministic local provider
- [x] Event envelope v1 and bounded JSONL storage with rotation and retention
- [x] Loopback admin listener: `/healthz`, `/readyz`, `/metrics`, `/version`
- [x] Verified out-of-process observer-extension contract
- [x] Clean-room Beelzebub configuration importer
- [x] Docker/Compose packaging and contract-tested Helm chart
- [x] Unit, integration, golden, fuzz and race coverage in pinned CI workflows

## Batch 1.5 — secure intelligence layer

- [x] Deterministic prompt-injection and abuse findings
- [x] Credential references and strict remote-provider construction
- [x] Local, Ollama and OpenAI-compatible provider profiles
- [x] MCP finding enforcement limited to decoy response behavior
- [x] Provider output treated as bounded, redacted, untrusted response data
- [x] Effective-policy preview, provider readiness and rule-oriented inspection
- [x] Import safety gate that refuses inline credential material

## Batch 2 — defensible single-node v0.2

1. [x] **SSH authentication deception.** Synthetic password/public-key
   authentication, ephemeral in-memory Ed25519 host key, bounded resources and
   unconditional rejection of channels and global requests. No shell, PTY,
   SFTP, forwarding, filesystem or command execution.
2. [x] **Remote providers.** Opt-in OpenAI-compatible and Ollama adapters with
   fail-closed startup, destination classification, redirect/proxy refusal,
   time and byte caps. Provider output remains untrusted data.
3. [x] **ECS-compatible local export.** Conservative deterministic projection
   that preserves the complete native envelope and adds no connector or egress.
4. [x] **Dry-run recommendations.** Deterministic evidence-linked proposals for
   operator review with no enforcement, asset mutation or runtime feedback path.
5. [x] **Optional evidence-at-rest encryption.** Merged in #73 and #77. Native
   age/X25519, explicit key rotation and a persistent plaintext downgrade guard.
   New segments use container v3 with authenticated busy-flush checkpoints, live
   CLI prefix reads, interrupted-segment/doctor warnings and `--require-sealed`;
   historical v2 stays seal-only. See ADR-0016 for the unavoidable rollback
   limit: a removed seal back to a checkpoint looks open unless strict completion
   is required.
6. [x] **Observe-only extension boundary.** Strict manifests and exact
   event-linked acknowledgements; extension output cannot affect evidence,
   policy, responses, paths, configuration or enforcement.
7. [x] **Self-contained demo.** Synthetic HTTP/TCP/MCP/SSH flow on OS-assigned
   loopback ports with verified evidence, eight dry-run proposals and cleanup (current
   local round 3 demo; see verification).
8. [x] **Optional per-sensor process isolation.** Merged in PR #54 as
   `eef2b93`. The exact default remains in-process. Opted-in sensors use a fixed
   same-binary worker, challenge-bound bounded IPC and parent-authoritative
   evidence. This is fault containment, not a resource, network, filesystem,
   syscall or malware sandbox.
9. [ ] **v0.2 release-readiness audit.** The documentation and claims audit was
   performed on 2026-11-16 (see `verification.md`). This item completes when the
   maintainer records the gate results for `7ae0356`, including hosted CI on
   `master`, and creates the tag; neither is done by the audit itself.

The finite acceptance contract is in [DELIVERY-PLAN.md](DELIVERY-PLAN.md), the
live queue is in [BACKLOG.md](BACKLOG.md), and current evidence is in
[verification.md](verification.md).

## Shipped in v0.2.0 beyond the original plan

All merged to `master`. Fleet, forwarding, SSO and tenancy are **experimental**;
the console and its embedded UI are new and verified in Chromium only.

- [x] **Operator console and embedded UI** (#74, #75, #78, #81). Disabled by
  default; fixed v1 API, token roles, bounded index, audited investigations,
  evidence origin and tenant/SSO screens. No sensor control. ADR-0017.
- [x] **Fleet inventory — experimental** (#76). Hub/agent roles, Ed25519
  identities, one-time enrollment, signed heartbeats, permanent revocation. The
  hub permanently has no command, configuration, file or code channel to nodes.
  ADR-0018.
- [x] **Evidence forwarding — experimental** (#79). Opt-in on both ends,
  best effort with counted loss, memory-only queue, local store authoritative.
- [x] **SSO via OIDC — experimental** and **logical tenant isolation —
  experimental** (#80). Exercised only against local test providers; one shared
  process, OS user, data directory and encryption recipient. ADR-0019/0020.
- [x] **Measured performance pass** (#82). `make bench` and
  `architecture/performance.md`; synthetic measurements, not capacity claims.
- [x] **Go 1.27.4 and `x/crypto` v0.59.0** (#72).

## Next after v0.2.0 — not commitments

Ordered by current intent, not by date. Each item needs its own design review;
none is implemented.

1. Review PR #71 (pinned GitHub Action bumps); keep dependency triage current.
2. Verify OIDC against real identity providers before any interoperability claim.
3. Durable encrypted forwarding spool with explicit offline guarantees.
4. Cross-node correlation on the hub, preserving the no-control-channel rule.
5. Hard tenant separation (per-tenant keys and/or processes) before any claim
   stronger than logical isolation.
6. Console performance follow-ups (shared SSE encoding, overview latency under an
   accepting hub, remaining measured items) in [BACKLOG.md](BACKLOG.md).
7. OTLP/SIEM delivery remains future explicit opt-in egress; local file encodings are
   implemented in the uncommitted round 3 slice below.
8. Real-cluster Kubernetes evidence for image, persistence, upgrades, rollback,
   NetworkPolicy and failure paths before any cluster-support claim.
9. Additional AI-agent deception sensors (multi-step synthetic MCP
   environments) and bounded protocol sensors where they add defensive value;
   Telnet and database emulation remain research rather than implied parity.
10. Continuous adversarial simulation that probes only operator-owned decoys in
    CI and never becomes an offensive execution framework.
11. Local-first clustering and TTP summaries over redacted evidence, with model
    output kept non-behavioral.
12. Publish the static landing page under `site/` (needs approval).

## Later product direction — not shipped commitments

- A managed AegisMesh SaaS/control plane around the Apache-2.0 core: hosted
  fleet management, hard tenant isolation, searchable retention, usage
  metering and managed upgrades. Nothing of this ships today.
- Distributed evidence aggregation with attestation, offline buffering and
  deterministic reconciliation. The inventory hub permanently has no
  command/configuration/file/code channel to nodes.

## Commercial and open-source boundary

AegisMesh is intended to be commercially usable and sellable without turning
its defensive core into a crippled teaser. The runtime, evidence format and
single-node defensive capabilities remain Apache-2.0 and self-hostable. A future
SaaS may charge for managed operation, collaboration, hosted retention and
control-plane services. That direction does **not** imply that hard
multi-tenancy, billing, public APIs or hosted operation ship today.

## Permanent non-goals

- Autonomous exploitation, credential theft, persistence, phishing, botnet
  behavior, destructive containment or execution of captured malware.
- Commands, filesystem choices, configuration mutation or enforcement derived
  from attacker input, configuration content, model output or extension output.
- Treating a decoy activation or recommendation as proof of an incident.
- Production-readiness, false-positive or compliance-certification claims
  without explicit independent evidence.


## AI observation pack — local implementation for review

- [x] Static synthetic AI-service profile with randomized scaffold persona and
  fake markers; no inference backend or model/key-management execution.
- [x] Bounded literal honeytokens, safe token-id evidence and generation CLI.
- [x] Append-only observe-only LLM/HT/AGT findings and COR-005..008 correlations.
- [x] Pinned editorial framework references in CLI and console API; structured
  synthetic corpus and loopback demo extension.

Verification and uncommitted status are recorded in `verification.md`.
Follow-up: broader independent synthetic/field evaluation before any detection
quality claim; no false-positive, attribution or coverage assertion follows
from this implementation. Credential distinctness remains intentionally
memory-only. Multi-step MCP environments are implemented locally in round 3; cross-node correlation and actual
provider interoperability are separate work; this pack does not implement them.


## Local backend continuation (uncommitted, ADR-0022)

- Implemented: bounded tenant-scoped source sessions, cadence/evidence/phase
  projections and catalog technique observations; conservative analyst indicator
  and Markdown report downloads; local verified `export indicators`.
- Verification: current exact commands/results are in `docs/verification.md`.
  No merge, release or deployment is implied.
- Deferred to frontend owner: sessions/coverage/export/report UI and dev mock
  integration. No mock change was required by existing contract tests.
- Future decisions: durable history/session identity beyond eviction, hard
  tenant boundaries and independently exercised SIEM interoperability. Current
  sampled observations are not completeness, attribution or incident verdicts.

## Round 3 backend — local implementation, uncommitted (ADR-0023)

Synthetic MCP environments, CEF/RFC5424/OTLP-JSON/ECS **local file formats**,
on-demand digest, value-free configured decoy/token catalogs and the console
contract additions are implemented in this branch. MCP read/replay uses the
existing observation/correlation boundary. Console/hub review fixes and
measured shared-SSE / accepting-hub overview work are documented in
`security-review-2026-11.md` and `architecture/performance.md`; final local gates
are in `verification.md`. This does not mark release/merge/deployment items done.

Remaining: scheduled digest delivery, real SIEM ingestion/interoperability,
same-sensor read/replay correlation, catalogs for remote effective configs,
external body-file planting inference, hard tenancy, cross-node correlation,
public saturation/p99 measurements and external IdP validation. No automatic
export/delivery or new runtime network destination exists.

## Round 4 backend — campaigns, actor profile, posture (ADR-0024)

- [x] Session `actor` (ten signals, hedged four-value assessment) and
  `campaign_id`; exact-prefix campaigns across >= 2 sources; posture checks
  POS-001..018; console routes and `campaigns`/`posture` CLI mirrors.
- Not done: similarity (non-exact) campaign matching, MCP rejected-call and
  SSH command signals (not in the index projection), body-file honeytoken
  planting, demo traffic from a second source (the demo is single-loopback, so
  it yields no campaign), and any evaluation of signal accuracy on field data.
  Assessments remain observations; no attribution or accuracy claim follows.
