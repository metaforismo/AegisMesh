# AegisMesh product brief

Version: v0.2 development line. Status: active; no production-readiness claim.

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
- **No multi-tenancy claim** until tenant confusion, authorization, data
  residency and cross-tenant evidence risks are designed and verified.
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
| Supply chain | Two direct third-party Go modules in the current baseline: YAML and pinned `golang.org/x/crypto`; the resolved graph is license-checked |
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

A future hosted product may provide fleet enrollment, tenant isolation, SSO and
RBAC, collaborative investigation, searchable managed retention, audit
administration, usage metering, managed upgrades, support and service-level
operations. Those capabilities introduce new identity, authorization, egress,
data residency and supply-chain boundaries. They are product direction only:
there is no shipped multi-tenant control plane, billing system, hosted evidence
service or public administration API today.

## Current core scope

Ships: CLI (`init`, `doctor`, `validate`, `run`, `demo`, `inspect`, `recommend`,
`rules`, `migrate beelzebub`, `ext`, `healthcheck`, `version`, `completion`);
HTTP/TCP/MCP sensors plus authentication-only SSH; static policies;
deterministic local and opt-in remote providers; optional per-sensor fixed-worker
fault containment; JSONL evidence with correlation signals; ECS-compatible local
export; deterministic dry-run recommendations; loopback admin endpoints;
data-only observer extensions; opt-in webhook delivery; Docker/Compose; Helm
packaging; pinned CI/release definitions and documentation.

Does not ship yet: evidence-at-rest encryption, Telnet/database sensors, OTLP or
automatic SIEM connectors, autonomous response connectors or enforcement,
distributed deployment, multi-tenancy, hosted SaaS/control plane, web console,
or verified real-cluster Kubernetes support. See `docs/ROADMAP.md`.
