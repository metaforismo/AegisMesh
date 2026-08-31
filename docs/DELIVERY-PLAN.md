# AegisMesh v0.2 delivery plan

Updated: 2026-08-31. This document is the finite completion contract for the
current milestone. `docs/BACKLOG.md` owns the detailed live queue.

## Goal

Ship a defensible single-node v0.2 core with four bounded deception sensor
families, trustworthy local evidence and exports, inspectable dry-run
recommendations, optional encrypted storage, a deterministic demo, hardened
release evidence, and contained extension/sensor lifecycle boundaries.

The runtime must remain local-first, observation-oriented, and incapable of
executing or enforcing attacker-, model-, config-, or extension-derived
instructions. A future managed SaaS is a later product layer and is not part of
this v0.2 completion claim.

## Pull-request train

| Slice | Deliverable | Depends on | Acceptance gate | Status |
|---|---|---|---|---|
| 1 | Evidence-reader fail-closed hotfix | PR #43 | Segment metadata/open/scan errors abort verified export without changing the target | MERGED — PR #44, `fa70969` |
| 2 | SSH authentication-deception sensor | 1 | Real loopback handshakes; synthetic auth only; bounded resources; no channel, shell, forwarding, filesystem, credential retention or exec | MERGED — PR #46, `150a305` |
| 3 | Supply-chain pinning | 2 | Immutable action/tool/image references; deterministic schema-valid SBOM; separated release authority; no publication credentials | MERGED — PR #47, `7d0e591` |
| 4 | Dry-run recommendation engine | 2 | Deterministic proposals linked to verified evidence; malformed input yields no report; no enforcement or external action seam | MERGED — PR #51, `86041b8` |
| 5 | Self-contained `aegismesh demo` | 2, 4 | Synthetic loopback HTTP/TCP/MCP/SSH flow, OS-assigned ports, integrity-verified evidence and deterministic cleanup | MERGED — PR #52, `1911678` |
| 6 | Optional evidence-at-rest encryption | 1 | Disabled by default; age/X25519 only; fail closed; no plaintext downgrade; restart/wrong-key/corruption/truncation/rotation/retention/recovery evidence; dependency/license proof | TODO |
| 7 | Extension live-policy boundary | 4 | Observe-only strict contract; no output-derived response, evidence, path, config or enforcement authority | MERGED — PR #53, `ee54a63` |
| 8 | Per-sensor process isolation | 2, 7 | Fixed same-binary identity, bounded versioned IPC, minimal environment, parent-authoritative evidence, crash/fuzz/race/cross-build proof | MERGED — PR #54, `eef2b93` |
| 9 | v0.2 release-readiness audit | 1–8 | Current docs and threat model; clean `master`; complete race/fuzz/Helm/license/secret/vulnerability/SBOM evidence; no unresolved P0/P1/P2 item | TODO — blocked on slice 6 |

Each implementation slice is one reviewable PR unless a red correctness or
security regression is safer as a smaller prerequisite. Splitting work may add
PRs but may not weaken or silently remove an acceptance gate.

## Required checks for every implementation PR

- focused tests covering the changed boundary and its failure paths;
- `go test -race` for affected concurrency paths;
- `make lint test`;
- applicable bounded fuzzing and Helm contract tests;
- dependency license, vulnerability, SBOM and secret checks when relevant;
- `git diff --check` and formatting checks;
- documentation, backlog, ADR, threat-model, verification and handoff truth-sync;
- a deslop review of the actual diff;
- all required hosted checks green on the exact head SHA before merge.

## Encryption slice constraints

The final functional slice may use the maintained BSD-licensed `filippo.io/age`
Go library only after exact version, transitive-license and vulnerability review.
The intended format is native age X25519, not a repository-designed cipher.

The implementation must:

- leave the disabled plaintext path byte-for-byte compatible;
- parse only explicit X25519 recipients and identities at the storage boundary;
- keep private identities out of checked-in configuration and logs;
- fail before a listener becomes ready when write encryption is misconfigured;
- make encrypted segment discovery explicit and reject missing/wrong identities;
- authenticate the entire encrypted stream and propagate truncation/corruption;
- define restart and rotation without appending to an unfinished prior stream;
- preserve retention and integrity semantics across plaintext and encrypted
  history without pretending existing plaintext has been migrated;
- add no network destination, key service or silent plaintext fallback.

## Completion predicate

v0.2 is complete only when all of the following are true:

1. Every slice above is `MERGED` with its PR and merge commit recorded.
2. No P0, P1 or P2 entry in `docs/BACKLOG.md` remains `TODO`, `IN PROGRESS`,
   `FAIL`, `NOT RUN` or ambiguously worded.
3. Required checks passed on each PR and on the final `master` commit.
4. `docs/verification.md` distinguishes current `PASS`, `FAIL`, `BLOCKED` and
   `NOT RUN` evidence without converting unavailable local commands into PASS.
5. README, PRODUCT, ROADMAP, HANDOFF, architecture, threat model, CLI/config,
   deployment, release and license documentation match the shipped runtime.
6. No new external egress, publication/signing action, real-cluster deployment or
   repository-setting change occurred without explicit action-time authorization.
7. The final handoff moves only genuinely later work to the next milestone.

A temporary tool or network failure does not complete a slice. It remains
`BLOCKED` until a safe documented fallback actually executes the acceptance
check or the milestone is explicitly changed.

## Explicit non-goals for v0.2

- autonomous exploitation, containment, credential rotation, process killing,
  phishing, persistence, malware execution or any action against real assets;
- distributed or multi-tenant control planes, billing, public administration
  APIs or hosted SaaS operation;
- accepting arbitrary extension/model output as policy or behavior;
- claiming full ECS compliance, production readiness, incident certainty,
  false-positive guarantees or a SLSA level;
- publishing a release, image, signature or repository credential.
