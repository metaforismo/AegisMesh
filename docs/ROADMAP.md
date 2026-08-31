# AegisMesh roadmap

Updated: 2026-08-31. Checked items are implemented **and verified** in this
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
5. [ ] **Optional evidence-at-rest encryption.** age/X25519 segment encryption,
   disabled by default, with no silent plaintext downgrade and explicit key
   rotation, recovery and mixed-history semantics.
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
- Distributed sensor fleets with explicit control-channel authorization,
  per-sensor identity and attestation, offline buffering and deterministic
  reconciliation.
- A read-only-by-default web console after the query and authorization contracts
  are stable.
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
