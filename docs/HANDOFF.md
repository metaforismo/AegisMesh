# HANDOFF — current verified state

Updated: 2026-11-16. Read `AGENTS.md`, then `docs/BACKLOG.md`, then
`docs/ROADMAP.md` before changing code.

## Authoritative baseline

- Repository: `metaforismo/AegisMesh`, default branch `master`.
- Baseline: `master` at `7ae0356` (merge of PR #81), **to be tagged v0.2.0 by a
  maintainer**. No tag, GitHub release, container image, binary signature or
  provenance attestation exists for v0.2.0 yet.
- Every change listed under "What ships" is merged into `master`, each through a
  pull request whose head passed the six hosted CI jobs.
- Gate results on the exact baseline commit are recorded by the maintainer in the
  `2026-11-16 — v0.2.0 release-readiness audit` entry of `docs/verification.md`.
- Dependabot PRs #68 and #70 are closed as superseded by #72. PR #71 (pinned
  GitHub Action bumps) is open, rebased and CI-green, and has not been reviewed
  or merged.
- Older dated entries in `docs/verification.md` and the `*-history-*` archives
  describe the state when they were written (for example "uncommitted" or "open
  PR"); the merge status of every PR is in this file and the audit entry.

## What ships

AegisMesh is an early, defensive, local-first deception and evidence platform.

Single-node core:

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
- optional same-binary process workers for every sensor kind (PR #54);
- Docker/Compose and contract-tested Helm packaging;
- pinned CI/release definitions, vulnerability checks and CycloneDX SBOM paths;
- Go 1.27.4 and `golang.org/x/crypto` v0.59.0 (#72).

Added since the original v0.2 plan (all merged):

- **Evidence encryption (#73, #77).** Optional age/X25519 (ADR-0016,
  `docs/evidence-encryption.md`). New encrypted segments use container v3:
  authenticated checkpoints at the existing busy-flush cadence, prefix reads for
  `inspect`/`recommend` with explicit open/interrupted notices, `--require-sealed`
  for strict completeness, and keyless structural doctor warnings. Checkpoints and
  seals cost 250 bytes each and count toward the segment cap. Sealed v2 stays
  readable; unfinished v2 fails closed; there is no in-place migration. Full
  truncation assurance requires strict mode: removing a seal back to a checkpoint
  looks like an open file.
- **Operator console (#74, #75, #78, #81).** Disabled-by-default, authenticated
  API (ADR-0017, `architecture/console-api.md`): token roles, Host/Origin/CSRF
  protections, SSE, investigations, hash-chained audit, `console token`,
  `console hash` and `demo --console`. The embedded UI, design system and static
  landing page (`site/`, not published) are served only when `console.enabled` is
  true. Polish added elevation, icons, sparklines, an event drawer, a command
  palette, motion rules, evidence origin, SSO sign-in and tenant switching.
- **Fleet inventory, experimental (#76).** ADR-0018,
  `architecture/fleet-protocol.md`: `identity` owns a private fixed seed,
  `protocol` owns exact signed envelopes, `hub` owns atomic registry, token and
  replay state plus a separate listener, `agent` owns a fixed egress-checked
  transport and an independent jittered loop. Permanent key revocation and
  bounded replay state survive restart. Hub state and audit are plaintext. Status
  is self-reported, not attested.
- **Evidence forwarding, experimental (#79).** Agent to hub, best effort with
  counted loss, local store authoritative. Disclosure (agent) and reception (hub)
  are separate opt-ins, both off by default. Process-only oldest-drop queue (4,096
  events / 16 MiB) fed after successful local append, including direct correlation
  signals; independent signed batch delivery; hub hostile validation, bounded
  deduplication (4,096 IDs per node), per-node quotas and a 256 MiB per-tenant
  aggregate budget; native per-node copies inherit hub encryption. No private read
  identity, disk spool, historical forwarding, cross-node correlation or deletion
  propagation.
- **SSO via OIDC and logical tenant isolation, both experimental (#80).**
  ADR-0019/0020. OIDC is opt-in Authorization Code/S256 with state/nonce/browser
  binding, library-owned asymmetric token verification, explicit role and tenant
  mappings, bounded egress and credential-capped sessions. Operator tokens remain
  a break-glass login by default; `token_login: false` requires OIDC. Discovery
  outages retry without stopping sensors. Logout is local; there is no refresh
  persistence or provider logout. One declared active tenant covers index queries,
  sources/overview/by_node, SSE, investigations, audit, fleet registries,
  enrollment tokens and forwarded evidence; local runtime views belong to
  `local_tenant`. At most 32 tenants share a process, OS user, data directory, hub
  encryption recipient and signing/egress settings. State lives under
  `tenants/<slug>/`; legacy state migrates into `tenants/default` with a
  resumable, recoverable migration. Non-index static assets are gzip-compressed
  with strong ETags; per-sensor overview buckets are capped at 64 sensor IDs.
  New dependencies: go-oidc v3.21.0, oauth2 v0.38.0, go-jose v4.1.4.
- **Measured performance pass (#82).** Secondary indexes and overview snapshots in
  the console evidence index, `make bench`, and
  `docs/architecture/performance.md`. Synthetic local measurements only; no
  capacity claim.

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

## Product direction

The intended commercial model is an Apache-2.0, self-hostable defensive core
plus a possible future managed SaaS/control plane. Plausible hosted value includes
fleet management, hard tenant isolation, collaborative investigation, searchable
retention, audit administration, managed upgrades and support. Experimental fleet
inventory, forwarding, SSO and logical tenants exist locally; managed-service
and hard multi-tenant capabilities remain proposed and require separate
authorization and threat models.

## Non-obvious invariants

- Untrusted data never becomes behavior: network bytes, config files, model output
  and extension artifacts never reach `os/exec`, filesystem path selection,
  configuration mutation or enforcement (AGENTS.md rule 2).
- Authoritative storage append succeeds before webhook, extension, correlation or
  forwarding offers. A failed append suppresses fan-out.
- The console evidence index is fed only after a successful storage append
  (`runtime.indexedSink`: storage first, then index). Bus and direct correlation
  persistence share it. The index is count- and byte-bounded and disposable.
- The console never changes sensors, policy or evidence. Its durable writes are
  operator investigations and the audit trail (plus fleet registry administration
  when the hub role is enabled).
- The fleet hub cannot command nodes, now or through a reserved stub, and
  receives redacted evidence only with separate opt-in reception. It never dials
  agents.
- The local store is authoritative for forwarded evidence. Hub copies are
  consistency-checked, not provenance-attested, and are never fed back to a node.
- Tenants are logical isolation only: one process, OS user, data directory and
  encryption recipient. Do not describe them as a security boundary against a
  compromised host or process.
- The UI has no build step and no third-party code, and renders evidence as text
  only.
- Derived correlation signals append directly to storage and never re-enter
  `Bus.Submit`; they do not currently reach webhooks or extensions (they do reach
  the opt-in forwarding queue). Adding webhook/extension delivery is new egress
  and needs explicit approval.
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
  saved. One writer per state root.
- Fleet operator config requires separate processes and state directories for
  hub and agent roles; package tests compose the roles.

## Known boundaries

- Evidence is plaintext by default. Encryption is opt-in and protects the medium,
  not a compromised host; rollback to an earlier checkpoint is detectable only
  with `--require-sealed`.
- There is no Telnet/database sensor, decoy-listener TLS, hard tenant boundary,
  autonomous response path or hosted control plane.
- Forwarding has no durable spool, historical forwarding, cross-node correlation
  or deletion propagation; forwarded history on the hub is not re-indexed after a
  restart. Key rotation, mTLS/attestation, a local configuration workflow and
  upgrade designs in ADR-0018 remain proposals. `fleet status` and `demo --fleet`
  were omitted; the console status API supplies live delivery state.
- OIDC has been exercised only against local test providers, never a real
  external identity provider.
- The UI has been verified in Chromium only.
- Helm is verified packaging, not verified real-cluster support; no real-cluster
  Kubernetes run exists.
- No v0.2.0 tag, GitHub release, published image, binary signature or executed
  provenance statement exists. The landing page is not published.
- `golangci-lint` is not installed locally; the Makefile reports the skip and runs
  `gofmt` and `go vet`.
- Direct SBOM generation is blocked inside linked git worktrees (the pinned
  generator cannot resolve the main-module version); use an ordinary clone or
  hosted CI. See `docs/verification.md`.
- Some CLI doctor tests expect the default sensor ports to be free (backlog P1).

## Commands that matter

```text
make lint test            # gofmt + vet (+ golangci-lint if installed) and race tests
make ui-test              # console UI and site tests (Node.js >= 20, no npm install)
make bench                # opt-in synthetic backend benchmarks; not a CI gate
make fuzz-seed            # bounded real fuzz targets
make vuln                 # pinned govulncheck
make sbom sbom-check      # CycloneDX generation and validation
make license-check secrets-scan
make supply-chain-check
make helm-contract        # needs local helm v4
go mod verify
git diff --check
```

For encryption work, add focused storage/config/CLI tests, wrong-key and
corruption cases, restart/rotation/retention integration, affected-package race
runs, dependency/license review and exact CLI argument matrices.

## External-state rules

Merges, releases, tags, signing credentials, image publication, deployments,
repository settings, site publication, real-cluster deployment and any new
runtime destination or signal egress all remain unexecuted until the repository
owner approves each one at action time; nothing here authorizes any of them.
Pushing branches and opening PRs does not imply approval to merge.

## Next priorities after v0.2.0

1. Create the v0.2.0 tag after the maintainer fills the gate table in
   `docs/verification.md` (needs approval; no release, image or signature is
   implied by the tag).
2. Review PR #71 (pinned GitHub Action bumps) and refresh dependency issue state.
3. Verify OIDC against real identity providers.
4. Durable encrypted forwarding spool and offline guarantees.
5. Cross-node correlation on the hub.
6. Hard tenant separation (per-tenant keys and/or processes).
7. Performance follow-ups from `docs/BACKLOG.md`: SSE encode-once and overview
   latency under an accepting hub, then the other measured items.
8. OTLP/SIEM export.
9. Real-cluster Kubernetes evidence.
10. Additional AI-agent deception sensors (multi-step synthetic MCP environments).
11. Publish the landing page (needs approval).

`docs/BACKLOG.md` is the authoritative current queue. The previous cumulative
queue and verification ledger are preserved in timestamped history files.


## Backend round 3 continuation (local, uncommitted)

On `feat/decoy-environments-siem`: static exact-map MCP workspace, appended
MCP-001..003, local SIEM formats/analyst downloads, on-demand digest, catalog
and console API fields, perimeter regression fixes, shared SSE and measured
accepting-hub overview name resolution. ADR-0023 and `console-api.md` define
the final contracts. `security-review-2026-11.md` records checked controls and
limits; `verification.md` owns current local gate receipts. Nothing in this
slice is committed, pushed, published, tagged, merged or deployed. No dependency
or egress destination was added; UI/dev mock files remain untouched.
