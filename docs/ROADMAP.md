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
- [x] Helm chart packaging with schema and contract tests; real-cluster support remains unverified
- [x] Tests: unit, integration, golden/CLI snapshot, fuzz seeds, race; CI workflows pinned by commit SHA
- [x] docs/verification.md + docs/HANDOFF.md

## Batch 1.5 — Secure intelligence layer (complete; merged through PR #12)

- [x] Deterministic prompt-injection / abuse rule engine (`internal/detect`: PI-001/PI-002, EXF-001,
      ESC-001, OBS-001, RES-001; static evidence-safe reasons; fail-open by design)
- [x] Provider credential references (`api_key_env` / `api_key_file`) with runtime resolution and
      strict loader containment checks; `ollama` provider profile (loopback http allowed for it only)
- [x] `init --profile local|ollama|remote` scaffolds
- [x] Detection enforcement in the MCP sensor (severity→action: observe/tag/isolate/refuse) with
      per-sensor throttling
- [x] LLM fallback analysis path behind sensor opt-in (`fallback.enabled`), untrusted-output pipeline
      (size caps, redaction-before-storage, structured findings)
- [x] `doctor` provider readiness without secret disclosure; shared egress classifier with validate
- [x] `validate --effective` resolved-policy preview (human + JSON); `inspect list --finding RULE_ID`
- [x] Importer credential safety gate (refuse inline material, report references, non-zero exit on refusal)

## Batch 2 — Depth on the same spine (proposed next)

1. R1: SSH deception sensor (crypto/ed25519 host key generation guidance, synthetic auth only) behind the
   same Sensor interface.
2. R2 (shipped): Real remote provider adapter — done. OpenAI-compatible chat completions via `openai` and
   `ollama` adapters (`internal/llm.Remote`) behind strict config: fail-closed construction before any
   listener binds, egress-classified dialing, loopback allowed only for `ollama`, response size + timeout
   caps enforced, off by default (PR deliver/llm-remote-provider). Provider output still passes the
   untrusted-output pipeline. Cost accounting beyond those size/timeout bounds stays future work.
3. R3 (shipped): ECS-compatible local evidence projection via `inspect export --profile ecs`, with a
   stable mapping, complete native-envelope preservation, deterministic golden tests, strict CLI validation,
   and fail-closed verified export. No connector or automatic upload is implied.
4. R4: Response recommendation engine v0: rules over events producing *dry-run* playbooks only.
5. R5: Evidence at rest: optional age/x25519 encryption of JSONL segments.
6. R6: Wire verified extensions into live policy resolution (behind explicit operator enablement).
   - [x] Data-only observer path shipped: supervised delivery queue, drop/revocation metrics, bounded
         shutdown, fail-closed manifest verification (`internal/extmanager`, PR feat/extension-observer-wiring).
         Response-influencing wiring stays unimplemented by design (ADR-0006).
7. R7: `aegismesh demo` self-contained scripted scenario command.
8. R8: Optional per-sensor process isolation mode for fault containment.

## Later batches (direction, not commitments)

- Distributed mesh: multi-host sensor fleets with a control channel, per-sensor attestation.
- Continuous adversarial simulation harness that probes your own decoys in CI.
- Threat intelligence pipeline: clustering of captured interactions into TTP summaries (local models first).
- Web console (read-only by default) once the API surface stabilizes.
- Kubernetes operation: the Helm chart is packaging, not real-cluster support. Add image, persistence,
  upgrade/rollback and cluster failure-path evidence before any production-readiness claim.

## Explicit non-goals reminder

See docs/PRODUCT.md. No autonomous enforcement, no offensive capability, no open-core split, ever.
