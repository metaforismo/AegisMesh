# AegisMesh roadmap

Updated: 2026-11-15. Checked items are implemented **and verified** in this
repository. Intent, research and product direction remain unchecked until an
implementation and its acceptance gates are complete.

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
5. [x] **Optional evidence-at-rest encryption — in supplied master baseline.**
   Native age/X25519, explicit key rotation and persistent plaintext downgrade
   guard. Local uncommitted v3 work adds authenticated busy-flush checkpoints,
   live CLI prefix reads, interrupted-segment/doctor warnings and
   `--require-sealed`. Historical v2 stays seal-only. See ADR-0016 for the
   unavoidable rollback limit: a removed seal back to a checkpoint looks open
   unless strict completion is required. Local gates are in `docs/verification.md`;
   v3 hosted CI, merge and release are separate, not performed here.
6. [x] **Observe-only extension boundary.** Strict manifests and exact
   event-linked acknowledgements; extension output cannot affect evidence,
   policy, responses, paths, configuration or enforcement.
7. [x] **Self-contained demo.** Synthetic HTTP/TCP/MCP/SSH flow on OS-assigned
   loopback ports with verified evidence, one dry-run proposal and cleanup.
8. [x] **Optional per-sensor process isolation.** Merged in PR #54 as
   `eef2b93`. The exact default remains in-process. Opted-in sensors use a fixed
   same-binary worker, challenge-bound bounded IPC and parent-authoritative
   evidence. This is fault containment, not a resource, network, filesystem,
   syscall or malware sandbox.
9. [ ] **v0.2 release-readiness audit.** Complete only after item 5 is merged
   and the final `master` commit passes the full race, fuzz, Helm, license,
   secret, vulnerability and SBOM gates with documentation truth-synced.

The finite acceptance contract is in [DELIVERY-PLAN.md](DELIVERY-PLAN.md), the
live queue is in [BACKLOG.md](BACKLOG.md), and current evidence is in
[verification.md](verification.md).

## Later product direction — not shipped commitments

- A managed AegisMesh SaaS/control plane around the Apache-2.0 core: fleet
  inventory, authenticated enrollment, tenant isolation, searchable retention,
  SSO/RBAC, audit administration, usage metering and managed upgrades.
- Distributed evidence aggregation with per-node quotas, attestation, offline
  buffering and deterministic reconciliation. The inventory hub permanently has
  no command/configuration/file/code channel to nodes.
- First operator console: **implemented in open PRs #74 (API) and #75 (embedded
  UI), unmerged** for P3-2. Fixed v1 API, token roles, bounded index, audited
  investigations and an embedded zero-dependency UI (no build step). Hosted CI
  passes on both heads; human review and merge remain open. See the console contract and verification
  ledger; this is single-node/single-tenant with no sensor control.
- Continuous adversarial simulation that probes only operator-owned decoys in
  CI and never becomes an offensive execution framework.
- Local-first clustering and TTP summaries over redacted evidence, with model
  output kept non-behavioral.
- Additional bounded protocol sensors where they add real defensive value;
  Telnet and database emulation remain research rather than implied parity.
- Real-cluster Kubernetes evidence for image, persistence, upgrades, rollback,
  NetworkPolicy and failure paths before any cluster-support claim.

## Commercial and open-source boundary

AegisMesh is intended to be commercially usable and sellable without turning
its defensive core into a crippled teaser. The runtime, evidence format and
single-node defensive capabilities remain Apache-2.0 and self-hostable. A future
SaaS may charge for managed operation, collaboration, hosted retention and
control-plane services. That direction does **not** imply that multi-tenancy,
billing, public APIs or hosted operation ship today.

## Permanent non-goals

- Autonomous exploitation, credential theft, persistence, phishing, botnet
  behavior, destructive containment or execution of captured malware.
- Commands, filesystem choices, configuration mutation or enforcement derived
  from attacker input, configuration content, model output or extension output.
- Treating a decoy activation or recommendation as proof of an incident.
- Production-readiness, false-positive or compliance-certification claims
  without explicit independent evidence.


## Fleet foundation — `feat/fleet-enrollment`, PR #76, 2026-11-15

P3-1 now has experimental fleet inventory with authenticated enrollment and
heartbeats; ADR-0018 settles data/control-plane ownership for this bounded slice.
It is not multi-tenant, not a managed service, and forwards no evidence. The hub
cannot command nodes. Local and manual verification is in `verification.md`;
the PR is not yet open, hosted CI has not run, and review and merge remain open. P2-3 hosted tenancy/residency/billing design
remains incomplete. Evidence spool/batches, key rotation, attestation, SSO and
upgrades are proposed, not implemented, and require separate review. Any future
configuration workflow must preserve the permanent no hub-to-agent control
channel invariant. No arbitrary remote-runner stub is reserved.
