# HANDOFF — current verified state

Updated: 2026-11-15. Read `AGENTS.md`, then `docs/BACKLOG.md`, then
`docs/ROADMAP.md` before changing code.

## Authoritative baseline

- Repository: `metaforismo/AegisMesh`
- Default branch: `master`, last recorded head `01579d3`.
- Re-check this value before relying on it. Public repository state is mutable.

The work of 2026-11-14 and 2026-11-15 is committed and pushed as a stack of open,
unmerged pull requests against `master`. Merge order is the stack order; each
PR is based on the one above it.

| Order | PR | Branch | Adds | Hosted CI on PR head |
|---|---|---|---|---|
| 1 | #72 | `security/go-toolchain-vuln-fixes` | Go 1.27.4 and `x/crypto` v0.59.0 for the SSH vulnerability fixes | PASS, 6 of 6 jobs |
| 2 | #73 | `feat/evidence-at-rest-encryption` | Opt-in age/X25519 evidence encryption | PASS, 6 of 6 jobs |
| 3 | #74 | `feat/console-api` | Disabled-by-default operator console API | PASS, 6 of 6 jobs |
| 4 | #75 | `feat/console-ui-embed` | Embedded console UI, design system and landing page | PASS, 6 of 6 jobs (includes the Node UI tests step) |
| 5 | PR pending | `feat/fleet-enrollment` | Experimental fleet inventory: enrollment, signed heartbeats, operator routes and Fleet screen | NOT RUN |

None of these is merged. Human review and merge are pending for all five. No
release, tag, image, signature, deployment or repository-setting change has
happened. Dependabot PRs #68 and #70 are superseded by #72 but still open; #71
(pinned Action bumps) is untriaged.

Manual browser verification on 2026-11-15 is recorded in `docs/verification.md`
(console against the real server, and fleet with two real processes on
loopback). Fleet revocation was verified by a two-process run and automated
tests, not re-run in the browser.

## What ships

Already merged in `master`, AegisMesh is an early, defensive, local-first
deception and evidence platform. It ships:

- bounded HTTP, TCP, MCP and authentication-only SSH sensors;
- strict configuration, loopback and unprivileged defaults, redaction and
  bounded resource ownership;
- deterministic local responses plus opt-in OpenAI-compatible and Ollama
  providers whose output remains untrusted response data;
- native JSONL evidence with integrity checks, rotation and retention;
- a conservative ECS-compatible local projection that preserves the native
  envelope;
- deterministic evidence-linked dry-run recommendations for operator review;
- a one-command synthetic four-sensor demo;
- signed opt-in webhooks and verified observe-only subprocess extensions;
- optional same-binary process workers for every sensor kind;
- Docker/Compose and contract-tested Helm packaging;
- pinned CI/release definitions, vulnerability checks and CycloneDX SBOM paths.

After the stack above merges, `master` additionally contains:

- optional age/X25519 evidence-at-rest encryption (#73; ADR-0016,
  `docs/evidence-encryption.md`). Authenticated v2 segment footers detect
  record-boundary truncation and order changes. Sealing occurs only on size
  rotation, close or a flush at five minutes from the first event. Active
  segments stay unreadable until sealed, so full-directory inspection needs no
  unsealed successor (stop the runtime or inspect a sealed-only snapshot).
  Crash-incomplete segments fail closed and need deliberate operator recovery;
  there is no automatic repair, plaintext downgrade or key escrow.
- a disabled-by-default, single-node, single-tenant operator console API (#74;
  ADR-0017, `architecture/console-api.md`): token roles, Host/Origin/CSRF
  protections, SSE, investigations, hash-chained audit, `console token` and
  `console hash`, and opt-in `demo --console`;
- an embedded zero-dependency console UI, design system and landing page (#75),
  served only when `console.enabled` is true;
- experimental fleet inventory (this branch; ADR-0018,
  `architecture/fleet-protocol.md`): `identity` owns a private fixed seed,
  `protocol` owns exact signed envelopes, `hub` owns atomic registry, token and
  replay state plus a separate listener, and `agent` owns a fixed egress-checked
  transport and an independent jittered loop. Permanent key revocation and
  bounded replay state survive restart. Hub state and audit are plaintext.
  Status is self-reported, not attested.

No activation or recommendation proves an incident. Nothing shipped can execute
attacker/model/extension instructions or autonomously mutate real assets.

## Process-isolation truth

The process-isolation slice is **merged** (PR #54, `eef2b93`). Omitted or
`process_isolation: false` preserves the in-process path. `true` launches the
same audited binary with one fixed hidden argument, a minimal environment, a
private temporary working directory and bounded canonical stdio IPC. The parent
owns readiness, event identity, integrity, storage, metrics and shutdown.

This contains first-party sensor crashes; it is not a network, filesystem, CPU,
memory, syscall or malware sandbox. Workers retain the runtime UID and host or
container namespaces. v0.2 does not automatically restart them.

## Exact remaining v0.2 work

1. **Merge the PR stack in order** (#72, #73, #74, #75, then the fleet PR once
   it exists), each after human review and green hosted CI on its exact head.
2. **Final release-readiness audit.** Re-run every required gate on the
   resulting `master`, reconcile all product/security/deployment claims, and
   leave release publication, tags, signing and real-cluster operation
   explicitly unexecuted unless separately approved. Blocked on the stack
   merging.
3. **Dependency PR triage.** Triage #71; close #68 and #70 after #72 merges. Do
   not merge a Docker-only Go major-version bump as if it were a complete
   supported-toolchain upgrade.

`docs/BACKLOG.md` is the authoritative current queue. The previous cumulative
queue and verification ledger are preserved in timestamped history files.

## Product direction

The intended commercial model is an Apache-2.0, self-hostable defensive core
plus a future managed SaaS/control plane. Plausible hosted value includes fleet
management, authenticated enrollment, tenant isolation, SSO/RBAC, collaborative
investigation, searchable retention, audit administration, managed upgrades and
support. A local inventory foundation is implemented on the fleet branch (PR
pending); managed-service and multi-tenant capabilities remain proposed and
require separate authorization and threat models.

## Non-obvious invariants

- Authoritative storage append succeeds before webhook, extension or correlation
  offers. A failed append suppresses fan-out.
- The console evidence index is fed only after a successful storage append
  (`runtime.indexedSink`: storage first, then index). Bus and direct correlation
  persistence share it. The index is count- and byte-bounded and disposable.
- The console never changes sensors, policy or evidence. Its durable writes are
  operator investigations and the audit trail.
- The fleet hub cannot command nodes, now or through a reserved stub, and
  receives no evidence. It never dials agents.
- The UI has no build step and no third-party code, and renders evidence as text
  only.
- Derived correlation signals append directly to storage and never re-enter
  `Bus.Submit`; they do not currently reach webhooks or extensions. Adding that
  delivery is new egress and needs explicit approval.
- Provider and extension output are untrusted data. Neither can select commands,
  paths, configuration, evidence meaning or enforcement.
- Native evidence is the source contract. ECS export and recommendations are
  read-boundary projections.
- Evidence hashes prove observation-payload consistency only, not writer
  identity, metadata integrity, provenance or chain of custody.
- SSH authentication is synthetic. Usernames and credential contents are
  omitted, all channels/global requests are rejected, and host keys are
  ephemeral in memory.
- Process workers receive no config-selected executable, argv, path, credential,
  remote-provider destination or enforcement authority.
- Encrypted storage never loads a private identity in the runtime; console node
  history is `unavailable` for encrypted evidence. Console notes and audit, and
  fleet hub state, remain plaintext.
- Console and fleet registry/audit writes are separate durability transactions.
  Inspect state before retrying a 503 that says the investigation was already
  saved.
- Fleet operator config requires separate processes and state directories for
  hub and agent roles; package tests compose the roles.

## Known boundaries

- Evidence is plaintext by default. Encryption is opt-in and, until #73 merges,
  not in `master`.
- There is no Telnet/database sensor, decoy-listener TLS, multi-tenancy,
  autonomous response path or hosted control plane. The console API, UI and
  fleet inventory exist only in the unmerged stack above.
- The console is single-node and single-tenant, with no SSO.
- Fleet inventory forwards no evidence; evidence-spool, key rotation,
  mTLS/attestation, a local configuration workflow, upgrade, tenancy and SSO
  designs in ADR-0018 are proposals, not implementation claims. `fleet status`
  and `demo --fleet` were omitted; the console status API supplies live
  delivery state.
- Helm is verified packaging, not verified real-cluster support.
- No v0.2 tag, GitHub release, published image, binary signature or executed
  provenance statement exists.
- Direct SBOM generation is blocked inside linked worktrees; the ordinary-clone
  fallback is recorded in `docs/verification.md`.

## Commands that matter

```text
make lint test
make ui-test
make fuzz-seed
make helm-contract
make supply-chain-check
make sbom sbom-check
make vuln
make license-check secrets-scan
go mod verify
git diff --check
```

For encryption work, add focused storage/config/CLI tests, wrong-key and
corruption cases, restart/rotation/retention integration, affected-package race
runs, dependency/license review and exact CLI argument matrices.

## External-state rules

Merges, releases, tags, signing credentials, image publication, deployments,
repository settings, site publication, real-cluster deployment and any new
runtime destination or signal egress all remain unexecuted. Each needs explicit
approval from the repository owner; nothing here authorizes any of them. Pushing
branches and opening PRs does not imply approval to merge.

## Next priorities

1. Merge the stack in order (#72, #73, #74, #75, fleet PR) after review and
   green hosted CI.
2. Triage #71; close #68 and #70 once #72 has merged.
3. Evidence forwarding agent to hub (design in ADR-0018, not implemented).
4. Live `inspect` of the unsealed active encrypted segment.
5. SSO/OIDC and per-tenant isolation for the console.
6. OTLP/SIEM export.
7. Real-cluster Kubernetes evidence.
8. Additional AI-deception sensors (multi-step synthetic MCP environments).
9. Final v0.2 release-readiness audit and tag (needs approval).
