# AegisMesh roadmap

Checked items are implemented **and verified** in this repository (see docs/verification.md for evidence).
Nothing is checked on intent alone.

## Batch 1 — Foundation (this batch)

- [x] Product brief, principles, non-goals, threat model, trust boundaries, data-flow diagrams
- [x] Competitive landscape research with claims/evidence separation
- [x] Governance: Apache-2.0 LICENSE/NOTICE, CONTRIBUTING, CoC, SECURITY, SUPPORT, RELEASE policy, AGENTS.md
- [x] CLI: `init`, `doctor`, `validate`, `run`, `inspect`, `migrate beelzebub`, `version`, `completion`
- [x] Schema-versioned strict config with env overrides and documented precedence
- [x] HTTP deception sensor (hardened net/http server)
- [x] TCP deception sensor (banner + line protocol, deadlines, caps)
- [x] MCP deception sensor (JSON-RPC 2.0 streamable HTTP; canary tool semantics)
- [x] Policy gate + deterministic local LLM provider (no API key required)
- [x] Event envelope v1 (integrity hash, sequence, redaction record) + JSONL store w/ rotation & retention
- [x] Loopback admin listener: `/healthz`, `/readyz`, `/metrics` (Prometheus text), `/version`
- [x] Extension manifest schema + digest/signature verifier + out-of-process reference host + contract tests
- [x] Clean-room `migrate beelzebub` importer (dry-run default, compatibility report, source preserved)
- [x] Dockerfile (non-root), docker-compose demo, reviewable install script
- [x] Tests: unit, integration, golden/CLI snapshot, fuzz seeds, race; CI workflows pinned by commit SHA
- [x] docs/verification.md + docs/HANDOFF.md

## Batch 2 — Depth on the same spine (proposed next)

1. R1: SSH deception sensor (crypto/ed25519 host key generation guidance, synthetic auth only) behind the
   same Sensor interface.
2. R2: Real remote provider adapter (OpenAI-compatible chat completions) with the untrusted-output pipeline,
   egress allowlist config, and cost/latency caps — off by default.
3. R3: SIEM-friendly export profiles (ECS-ish field mapping doc + `inspect export --profile ecs`).
4. R4: Response recommendation engine v0: rules over events producing *dry-run* playbooks only.
5. R5: Evidence at rest: optional age/x25519 encryption of JSONL segments.
6. R6: Wire verified extensions into live policy resolution (behind explicit operator enablement).
7. R7: `aegismesh demo` self-contained scripted scenario command.
8. R8: Optional per-sensor process isolation mode for fault containment.

## Later batches (direction, not commitments)

- Distributed mesh: multi-host sensor fleets with a control channel, per-sensor attestation.
- Continuous adversarial simulation harness that probes your own decoys in CI.
- Threat intelligence pipeline: clustering of captured interactions into TTP summaries (local models first).
- Web console (read-only by default) once the API surface stabilizes.
- Kubernetes: Helm chart only after single-node story is hardened; no production-readiness claims before then.

## Explicit non-goals reminder

See docs/PRODUCT.md. No autonomous enforcement, no offensive capability, no open-core split, ever.
