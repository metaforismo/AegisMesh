# AegisMesh product brief

Version: 0.1.0 (first batch). Status: active.

## One-liner

AegisMesh is a fully open-source, local-first, secure-by-default agentic deception, detection, and
response platform: you deploy believable decoys, it records every interaction as bounded, redacted,
integrity-checked evidence, and it recommends — never autonomously performs — containment actions.

## Problem

Modern attackers (human and automated, including LLM-driven agents) move laterally and probe agent tool
surfaces. Deception technology answers this cheaply: decoys that no legitimate workload should ever touch,
so any interaction is high-signal. But existing options force trade-offs: heavyweight multi-container
stacks, cloud-dependent AI features, in-process plugin supply-chain risk, privileged default ports, and
marketing that conflates "someone touched a decoy" with "you are breached".

## Product principles

1. **Safe by construction.** Decoys are non-production by definition; listeners default to loopback on
   unprivileged ports; inbound content is data, never code; nothing in AegisMesh executes attacker input.
2. **Local-first.** The core runtime runs offline. The deterministic local provider makes demos and tests
   reproducible without API keys. Cloud LLM providers are opt-in adapters, not requirements.
3. **Evidence over alarmism.** Events record *observations*. Classification ("interaction", "canary-hit")
   is mechanical; "incident" requires human verification. We never market interaction as proof of compromise.
4. **Transparent everything.** Every response a decoy gives is traceable to a config rule or provider call
   in the audit log. No hidden behavior, no black-box scoring.
5. **Bounded resources everywhere.** Queues, bodies, sessions, regex complexity, event sizes, retention:
   all have explicit caps that fail closed rather than degrade silently.
6. **Progressive disclosure.** Five-minute golden path with one command each; depth (custom sensors,
   extensions, SIEM export, response playbooks) appears only when the operator asks for it.
7. **Minimal dependencies.** Few third-party packages, pinned and reviewed; the smaller the supply chain,
   the smaller the attack surface.

## Non-goals (for the whole project, not just this batch)

- **Not an IDS/IPS replacement.** Deception detects what touches decoys; it does not inspect production traffic.
- **No autonomous enforcement against real assets.** Response begins as recommendation/dry-run; any external
  action requires explicit operator approval per-action, with audit trail.
- **No offensive capability.** No exploitation, credential theft, persistence, botnet behavior, phishing
  delivery, or malware execution — ever, in any tier.
- **Not a sandbox/detonation platform** for running attacker binaries (roadmap consideration only as an
  isolated, explicitly-enabled lab feature, never default).
- **No multi-tenancy claims** until tenant-confusion threats are formally addressed in the threat model.
- **Not a compliance certification.** We produce exportable evidence; auditors decide what it means.

## What "agentic deception" means here

Three sensor families, of which two ship in this first batch:

1. **Infrastructure decoys** (HTTP, TCP now; SSH/Telnet/DB personas roadmap): fake services that record
   probes and credential guessing attempts against synthetic credentials only.
2. **Agent canaries** (MCP sensor, this batch): decoy tools registered on an MCP endpoint that no honest
   agent should call. An invocation means either a prompt injection succeeded or someone is exploring your
   agent's tool surface directly — both are worth knowing immediately.
3. **Response intelligence** (roadmap): replaying collected interactions into detection engineering and
   recommended (dry-run) containment playbooks.

## Why AegisMesh is meaningfully better (evidence-linked)

| Dimension | AegisMesh position |
|---|---|
| Licensing | Apache-2.0 end to end; zero GPL dependencies; SBOM + license policy enforced in CI |
| Offline | Deterministic local provider + static policies = fully functional without network egress |
| Supply chain | Single third-party Go dependency at launch (YAML parser); extensions out-of-process behind manifests |
| Safe defaults | Loopback bind + unprivileged ports validated by `doctor`; strict config schema; dry-run modes |
| Evidence hygiene | Versioned envelope, payload hashing, redaction pipeline, retention bounds, observation≠incident |
| Explainability | Every response maps to a policy ID; `inspect` shows exactly why a decoy answered what it answered |

## First-batch MVP scope (honest boundary)

Ships: CLI (`init`, `doctor`, `validate`, `run`, `inspect`, `migrate beelzebub`, `version`, `completion`),
HTTP/TCP/MCP sensors, static policies + deterministic local LLM provider, JSONL evidence store with
retention/redaction, loopback admin endpoints (health/readiness/metrics), extension manifest+verifier+reference
host, Docker/compose demo, CI, docs.

Does not ship yet (see ROADMAP): SSH/Telnet sensors, real LLM providers beyond the adapter seam, OTLP
exporter, SIEM connectors, response playbook engine, distributed deployment, web console.
