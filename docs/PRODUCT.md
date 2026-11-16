# AegisMesh product brief

Version: v0.2.0 (`master` at `7ae0356`, to be tagged by a maintainer). Status: active
early platform; no production-readiness claim. Updated 2026-11-16.

## One-liner

AegisMesh is a fully open-source, local-first, secure-by-default agentic
deception, detection and evidence platform: you deploy believable decoys and it
records every interaction as bounded, redacted, integrity-checked evidence. It
emits deterministic dry-run recommendations for operator review and does not
autonomously act on real assets.

## Problem

Modern attackers, including automated and LLM-assisted systems, probe service
and agent-tool surfaces. Deception can provide useful evidence because a decoy
should not be part of a legitimate production workflow. Existing options can
also impose trade-offs: heavyweight multi-container stacks, cloud-dependent AI
features, in-process plugin supply-chain risk, privileged default ports, and
marketing that conflates "someone touched a decoy" with "you are breached".

AegisMesh treats a decoy activation as an observation to investigate, never as
self-proving incident certainty.

## Product principles

1. **Safe by construction.** Decoys are non-production; listeners default to
   loopback on unprivileged ports; inbound content is data, never code; nothing
   executes attacker input.
2. **Local-first.** The core runtime runs offline. The deterministic local
   provider makes demos and tests reproducible without API keys. Remote model
   providers are opt-in adapters, not requirements.
3. **Evidence over alarmism.** Classification such as `interaction` or
   `canary_invocation` is mechanical. Incident determination requires human
   verification.
4. **Transparent behavior.** Every response maps to a configuration rule or an
   explicit provider call. Provider output remains untrusted response data.
5. **Bounded resources everywhere.** Queues, bodies, sessions, regular
   expressions, event sizes, retention, timeouts and goroutines have explicit
   limits.
6. **Progressive disclosure.** A self-contained one-command demo comes first;
   deeper sensors, extensions and exports appear only when the operator opts in.
7. **Minimal reviewed dependencies.** Dependencies are pinned, license-checked
   and added only when they replace riskier custom security code or provide a
   clear product boundary.
8. **Open core means usable core.** The Apache-2.0 runtime remains self-hostable
   and defensively useful. Commercial value may come from managed operation and
   collaboration, not from deliberately crippling the public runtime.

## Permanent non-goals

- **Not an IDS/IPS replacement.** Deception observes what touches decoys; it does
  not inspect all production traffic.
- **No autonomous enforcement against real assets.** Any response begins as a
  recommendation/dry-run. External action would require a separately designed,
  explicitly approved and audited boundary.
- **No offensive capability.** No exploitation, credential theft, persistence,
  botnet behavior, phishing delivery or destructive action in any tier.
- **No malware execution or detonation.** Captured binaries and commands remain
  inert evidence; AegisMesh is not a sandbox for running them.
- **No hard multi-tenancy claim.** Logical tenant isolation ships as an
  experiment in one shared process; a hard boundary (per-tenant keys or
  processes) needs tenant confusion, authorization, data residency and
  cross-tenant evidence risks designed and verified first.
- **Not a compliance certification.** AegisMesh can export evidence; auditors
  and operators decide what that evidence means.

## What "agentic deception" means here

Three product families:

1. **Infrastructure decoys** (HTTP/TCP/SSH shipped; Telnet/database research
   later): synthetic services that record bounded probes and authentication
   attempts. SSH is authentication-only, holds an ephemeral per-sensor Ed25519
   host key in memory, and rejects every channel and global request.
2. **Agent canaries** (MCP sensor shipped): decoy tools exposed on an MCP
   endpoint. Invocation can be consistent with prompt injection or direct tool
   exploration, but remains an observation rather than proof of compromise.
3. **Response intelligence** (v0 shipped): deterministic local rules turn
   verified evidence into static, evidence-linked dry-run recommendations for
   operator review. They never become enforcement.

## Current differentiators (evidence-linked, not guarantees)

| Dimension | AegisMesh position |
|---|---|
| Licensing | Apache-2.0 end to end; dependency license policy in CI and CycloneDX SBOM paths |
| Offline | Deterministic local provider plus static policy is functional without runtime network egress |
| Supply chain | Six direct third-party Go modules, each with a recorded justification: YAML, `golang.org/x/crypto` (SSH), `filippo.io/age` (encryption), and `go-oidc`, `oauth2`, `go-jose` (opt-in SSO); the resolved graph is license-checked in CI |
| Safe defaults | Loopback bind and unprivileged ports validated by `doctor`; strict config; dry-run behavior; optional fixed-worker fault containment with exact in-process default |
| Evidence hygiene | Versioned envelope, payload hashing, redaction, rotation/retention bounds and observation-not-incident semantics |
| Explainability | Stored policy/finding identifiers and inspection surfaces explain why a decoy responded or a recommendation was produced |
| Operator review | `recommend` emits deterministic proposed guidance linked to verified local evidence and cannot mutate assets or add egress |
| Extension authority | Explicit verified observer subprocesses receive bounded, successfully stored observations and may return only a canonical event-linked acknowledgement |
| First run | `aegismesh demo` exercises HTTP/TCP/MCP/SSH, evidence integrity and a dry-run proposal without configuration, cloud access or retained state |

These are repository positions backed by current code and tests, not promises of
zero false positives, complete attack coverage or production suitability.

## Open-source and commercial model

AegisMesh is intended to remain commercially usable under Apache-2.0 and to
support a future managed SaaS. The single-node runtime, evidence format,
self-hosted operation and core defensive capabilities remain public and usable.

A future hosted product may build on experimental inventory with tenant isolation, SSO and
RBAC, collaborative investigation, searchable managed retention, audit
administration, usage metering, managed upgrades, support and service-level
operations. Those capabilities introduce new identity, authorization, egress,
data residency and supply-chain boundaries. They are product direction only:
there is no shipped multi-tenant control plane, billing system or hosted evidence
service today. Self-hosted inventory administration is described below.

## Current core scope

Implemented on `master`: CLI (`init`, `doctor`, `validate`, `run`, `demo`, `inspect`, `recommend`,
`rules`, `migrate beelzebub`, `ext`, `healthcheck`, `console`, `version`, `completion`);
HTTP/TCP/MCP sensors plus authentication-only SSH; static policies;
deterministic local and opt-in remote providers; optional per-sensor fixed-worker
fault containment; JSONL evidence with correlation signals and optional native
age/X25519 at-rest encryption; ECS-compatible local export; deterministic dry-run
recommendations; loopback admin endpoints;
data-only observer extensions; opt-in webhook delivery; an opt-in operator console
with an embedded UI; Docker/Compose; Helm packaging; pinned CI/release definitions
and documentation. Opt-in **experimental** features: fleet inventory, evidence
forwarding, SSO via OIDC and logical tenant isolation.

Does not ship yet: Telnet/database sensors, OTLP or automatic SIEM connectors,
autonomous response connectors or enforcement,
durable offline evidence guarantees (the forwarding queue is memory-only),
cross-node correlation, hard tenant boundaries, a hosted SaaS/control plane,
verified real-cluster Kubernetes support, or a published image, signed binary or
provenance attestation. See `docs/ROADMAP.md`.

## Evidence encryption (ADR-0016)

Optional, off by default. New encrypted segments use container v3: CLI reads of a
running node work through the last authenticated checkpoint, and open segments
carry explicit incompleteness notices; older ones are interrupted-segment
warnings, also reported structurally by doctor. `--require-sealed` restores strict
completion checks. Checkpoints add 250 bytes per busy flush with pinned
age/X25519, and idle flushes write none. No private identity enters the runtime or
console. Historical v2 remains seal-only; no migration occurs. Encryption protects
new event contents on media; existing plaintext, exports and file metadata remain
exposed. Host/identity compromise, key loss, public-recipient forgery and
checkpoint-tail rollback remain limits. Even a removed seal looks open if
truncated to a checkpoint; strict reads are needed for full completion assurance.
See `evidence-encryption.md`.

## Operator console (P3-2, merged #74, #75, #78, #81)

The console provides a disabled-by-default, authenticated HTTP API and an
embedded operator UI inside the single binary. The UI has no build step and no
third-party code, and is served only when `console.enabled` is true. It uses named
token operators (viewer/analyst/admin), and reads bounded indexed evidence.
Operator-authored investigations and an append-only audit trail are the durable
writes. Optional fleet inventory administration is additive; the console cannot
control sensors. Encrypted storage exposes live envelopes only; audit/notes remain
plaintext. The UI has been verified in Chromium only. This is not a deployed or
production-readiness claim.

## Fleet inventory and evidence forwarding (experimental; #76, #79)

Experimental fleet inventory with authenticated enrollment and heartbeats. A hub
lists node identities and self-reported health through the authenticated console.
Agents dial that hub using local Ed25519 identities and a bounded independent
loop. One-time admin tokens establish identity; signed requests, expiry/replay
checks and permanent revocation protect the inventory boundary. Neither status
signatures nor online state attest host integrity. The hub cannot command nodes.

Experimental evidence forwarding sends copies of redacted live evidence from agent
to hub: best effort with counted loss, local store authoritative. Agent disclosure
and hub reception are separate opt-ins, both off by default. There is no on-disk
spool. Durable spooling, key rotation, attestation, upgrades and commercial
service boundaries remain proposed, not implemented. This is not a hosted service.
See ADR-0018 and `architecture/fleet-protocol.md`.

## Console identity and isolation (experimental; #80)

**SSO via OIDC (experimental)** and **logical tenant isolation (experimental)**,
specified in ADR-0019/0020 and `architecture/console-api.md`. OIDC is opt-in
Authorization Code/S256 with state/nonce/browser binding, library-owned
asymmetric token verification, explicit role and tenant mappings, bounded egress
and credential-capped sessions. Existing tokens remain break-glass by default;
`token_login: false` requires OIDC. Logout remains local. OIDC has only been
exercised against local test providers.

One declared active tenant covers index queries, sources/overview/by_node, SSE,
investigations, audit, fleet registries, enrollment tokens and forwarded evidence.
Local runtime views belong to `local_tenant`. Per-tenant quotas and recoverable
legacy migration isolate logical state pressure; there is no admin "all" view. At
most 32 tenants share a process, OS user, data directory, hub encryption recipient
and signing/egress settings. Host/process compromise and shared disk/CPU
exhaustion cross tenants. Per-tenant keys, billing, rate plans, self-service
creation and a hard hosted isolation boundary are out of scope.
