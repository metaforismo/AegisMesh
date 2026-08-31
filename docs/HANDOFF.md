# HANDOFF — current verified state

Updated: 2026-08-31. Read `AGENTS.md`, then `docs/BACKLOG.md`, then
`docs/ROADMAP.md` before changing code.

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

1. **Optional evidence-at-rest encryption.** Design and implement age/X25519
   segment encryption behind an explicit opt-in. It must fail closed, never
   silently write plaintext, preserve the disabled path byte-for-byte, and cover
   restart, wrong-key, corruption, truncation, rotation, retention and recovery.
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
support. None of those control-plane or multi-tenant capabilities is shipped or
claimed today; they require separate authorization and threat models.

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

- Evidence is plaintext at rest until the remaining encryption slice lands.
- There is no Telnet/database sensor, decoy-listener TLS, distributed mesh,
  public control API, multi-tenancy, web console or autonomous response path.
- Helm is verified packaging, not verified real-cluster support.
- No v0.2 tag, GitHub release, published image, binary signature or executed
  provenance statement exists.
- The local macOS checkout named by the operator is not mounted in every agent
  environment. Record local commands as `BLOCKED` rather than inferring them;
  hosted CI can provide independent evidence but does not retroactively turn an
  unrun local command into `PASS`.

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
