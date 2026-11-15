# HANDOFF — current verified state

Updated: 2026-11-15. Read `AGENTS.md`, then `docs/BACKLOG.md`, then
`docs/ROADMAP.md` before changing code.

## 2026-11-15 fleet inventory candidate

Worktree `feat/fleet-enrollment` stacks the operator console. Changes remain
uncommitted; no commit, push, branch switch, `gh`, merge, publish or deploy.
Read ADR-0018, `architecture/fleet-protocol.md`, the extended console contract
and current `verification.md` before integration. Required local gates and the
two-process binary walkthrough passed; hosted CI and review remain open.

`identity` owns a private fixed seed; `protocol` owns exact signed envelopes;
`hub` owns atomic registry/token/replay state plus a separate listener; `agent`
owns a fixed egress-checked transport and independent jittered loop. Runtime
preflights fleet state/credentials/CA before binding listeners, snapshots sensor
metadata without addresses and counts successful evidence appends. Console
routes administer inventory under existing role/CSRF/audit protections. Hub
state/audit are plaintext. Permanent key revocation and bounded replay state
survive restart. Registry and audit remain separate durability transactions.

This is experimental fleet inventory with authenticated enrollment and
heartbeats. It is not multi-tenant, not a managed service, and forwards no
evidence. The hub cannot command nodes, now or through a reserved stub. Status
is self-reported, not attested. `fleet status` and `demo --fleet` were omitted;
the existing console status API supplies live delivery state. Separate processes
and state dirs are required by operator config; package tests compose roles.

Review/hosted CI/merge and broader product acceptance remain separate. The
proposed evidence-spool, rotation, mTLS/attestation, local configuration workflow,
upgrade, tenancy and SSO designs in the ADR are not implementation claims.

## 2026-11-14 console API backend candidate

Worktree branch `feat/console-api` stacks the toolchain/encryption candidates.
All console changes remain uncommitted, including the supplied contract file.
No commit, push, branch switch, `gh`, merge, publication or deployment occurred.
Read `architecture/console-api.md` and ADR-0017 before changing the console.
`console.Options.UI fs.FS` is the sole UI injection; runtime passes
`consoleui.FS()`, the embedded zero-dependency UI (no build step), so `/` serves
the app when `console.enabled` is true. The API works independently of the UI;
`make ui-test` runs the UI's Node.js tests and `make ui-dev` a mock server.

The append tap is `runtime.indexedSink`: storage first, then index. Both the bus
sink and direct correlation persistence share it; derived signals acquire no new
webhook/extension/bus route. Runtime snapshots expose only node/sensor values.
Encrypted storage never loads a private identity; node history is `unavailable`.
The index is count- and byte-bounded; full envelope detail remains unmodified.

Config, token/hash CLI, opt-in `demo --console`, auth/CSRF/Host protections,
SSE, investigations, audit, metrics and API host are implemented. Local command
and curl receipts belong to `verification.md`; exact-head hosted CI, orchestrator
review remains separate; browser acceptance of the UI is recorded in `verification.md`. Added contract clarifications:
64 MiB accounted index budget, 65536-entry node metadata bound,
4096-envelope recommendation input, finite state/
audit quotas, timestamp-ordered pagination, zero expiry for bearer session views,
and separate investigation/audit transactions. Inspect state before retrying a
503 that explicitly says the investigation was already saved.

## 2026-11-14 encryption candidate

Implementation is uncommitted on `feat/evidence-at-rest-encryption`, based on
reviewed but unmerged toolchain branch head `c64b58f`. The recovered PR #58
patch is draft provenance only. The candidate uses age v1.3.2 and retains Go
1.27.4 / x/crypto v0.59.0 / x/sys v0.50.0. Local execution receipts are in
`docs/verification.md`; PR number is pending. Human review, exact-head CI and
merge remain open. No new publication or deployment occurred.

Authenticated v2 segment footers detect record-boundary truncation and order
changes. Flush writes buffers to the OS; sealing occurs only on size rotation,
close or a flush at five minutes from the first event. Empty segments do not
age out; only the next append after sealing opens a new file. Active segments
remain unreadable until sealed; full-directory inspection requires no unsealed
successor (stop the runtime or inspect a separate sealed-only snapshot).
Crash-incomplete segments fail closed and require deliberate operator recovery;
there is no automatic repair, plaintext downgrade or key escrow. Explicit read
identities remain file references only. See `docs/evidence-encryption.md` and
ADR-0016 for recovery and confidentiality limits.

The authoritative baseline below records merged history. BACKLOG P1-1 and
delivery-plan slice 6 distinguish this candidate from that merged state.

## Authoritative baseline

- Repository: `metaforismo/AegisMesh`
- Default branch: `master`
- Verified baseline before this truth-sync: `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4`
- That commit merged PR #54, optional fixed-worker process isolation.
- PR #54 head `6ded0223235fbb383f65accf762aa67fe481e316`
  passed every hosted CI job: full race/build/cross-build, eight fuzz targets,
  Helm contract, pinned vulnerability scan, dependency-license/secret checks,
  and deterministic CycloneDX generation/validation.

Re-check these values before relying on them. Public repository state is mutable.

## What ships

AegisMesh is an early, defensive, local-first deception and evidence platform.
It currently ships:

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

No activation or recommendation proves an incident. Nothing shipped can execute
attacker/model/extension instructions or autonomously mutate real assets.

## Process-isolation truth

The process-isolation slice is **merged**, not pending. Omitted or
`process_isolation: false` preserves the in-process path. `true` launches the
same audited binary with one fixed hidden argument, a minimal environment, a
private temporary working directory and bounded canonical stdio IPC. The parent
owns readiness, event identity, integrity, storage, metrics and shutdown.

This contains first-party sensor crashes; it is not a network, filesystem, CPU,
memory, syscall or malware sandbox. Workers retain the runtime UID and host or
container namespaces. v0.2 does not automatically restart them.

## Exact remaining v0.2 work

1. **Optional evidence-at-rest encryption review/merge gate.** Implementation
   and local focused/race/fuzz/license/vulnerability checks pass in this
   candidate. Direct SBOM generation remains blocked by linked-worktree support;
   identical-source ordinary-clone generation and validation pass. Human review,
   exact-head hosted CI and merge remain open; PR number is pending.
2. **Final release-readiness audit.** Re-run every required gate on the resulting
   `master`, reconcile all product/security/deployment claims, and leave release
   publication, tags, signing and real-cluster operation explicitly unexecuted
   unless separately approved.
3. **Dependency PR triage.** Review open Dependabot PRs against the repository's
   immutable-reference and whole-toolchain policies. Do not merge a Docker-only
   Go major-version bump as if it were a complete supported-toolchain upgrade.

`docs/BACKLOG.md` is the authoritative current queue. The previous cumulative
queue and verification ledger are preserved in timestamped history files.

## Product direction

The intended commercial model is an Apache-2.0, self-hostable defensive core
plus a future managed SaaS/control plane. Plausible hosted value includes fleet
management, authenticated enrollment, tenant isolation, SSO/RBAC, collaborative
investigation, searchable retention, audit administration, managed upgrades and
support. The local inventory foundation is implemented in this candidate;
managed-service and multi-tenant capabilities remain proposed and require
separate authorization and threat models.

## Non-obvious invariants

- Authoritative storage append succeeds before webhook, extension or correlation
  offers. A failed append suppresses fan-out.
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

## Known boundaries

- Evidence is plaintext by default. This candidate implements opt-in encryption;
  the merged baseline still awaits the slice review/CI/merge gate.
- There is no Telnet/database sensor, decoy-listener TLS, distributed mesh,
  public control API, multi-tenancy or autonomous response path. The optional
  console API candidate and its embedded UI are described above.
- Helm is verified packaging, not verified real-cluster support.
- No v0.2 tag, GitHub release, published image, binary signature or executed
  provenance statement exists.
- Local verification for this candidate ran in the requested macOS worktree.
  Hosted CI remains independent and pending. The linked-worktree SBOM limitation
  and exact ordinary-clone fallback are recorded in `docs/verification.md`.

## Commands that matter

```text
make lint test
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

PRs, merges and integrated-branch cleanup are authorized for this engineering
run. Release publication, tags, signing credentials, repository settings,
real-cluster deployment and any new runtime destination or signal egress remain
separate actions and must not be inferred from that authorization.
