# AegisMesh v0.2 delivery plan

This document is the finite completion contract for the current engineering
run. `docs/BACKLOG.md` remains the detailed evidence queue; this file defines
the ordered pull-request train and the condition for stopping.

## Goal

Ship a defensible v0.2 core that is materially more useful than the v0.1
foundation: four bounded deception sensor families, trustworthy local evidence
and exports, inspectable dry-run recommendations, optional encrypted storage,
a deterministic demo, hardened releases, and contained extension/sensor
lifecycle boundaries. It must remain local-first, observation-oriented, and
incapable of executing or enforcing attacker-, model-, config-, or
extension-derived instructions.

PR #43 is the merged prerequisite: fail-closed ECS-compatible export,
shutdown-race fixes, and documentation truth-sync.

## Pull-request train

| Slice | Deliverable | Depends on | Acceptance gate | Status |
|---|---|---|---|---|
| 1 | Evidence-reader fail-closed hotfix | PR #43 | Metadata/open/scan errors abort verified export without changing its target; focused red regression and full race suite | MERGED — PR #44, `fa70969` |
| 2 | SSH authentication-deception sensor | 1 | Real loopback SSH handshakes; synthetic authentication only; no shell, PTY, channel acceptance, forwarding, filesystem, credential retention, or exec; bounded concurrency/deadlines; dependency/license proof | IN PROGRESS — PR #46; local gates PASS, CI pending |
| 3 | Supply-chain pinning | 2 | No mutable tool acquisition or container base tags; schema-valid SBOM path; release claims distinguish checksums, provenance, and signatures; no publication credentials | TODO |
| 4 | Dry-run recommendation engine | 2 | Deterministic typed recommendations linked to immutable evidence; conflict/false-positive tests; no enforcement or external action seam | TODO |
| 5 | Self-contained `aegismesh demo` | 2, 4 | Loopback-only synthetic HTTP/TCP/MCP/SSH flow, OS-assigned ports, bounded readiness/cleanup, deterministic human and JSON summaries, integrity-verified evidence | TODO |
| 6 | Optional evidence-at-rest encryption | 1 | Disabled by default; fail closed when enabled; no plaintext downgrade; restart/wrong-key/corruption/truncation/rotation/retention/recovery tests; dependency/license proof | TODO |
| 7 | Extension live-policy boundary | 4 | ADR resolves the boundary; shipped path remains typed, bounded, provenance-rich and non-enforcing; no execution/path/config mutation; no new signal egress without approval | TODO |
| 8 | Per-sensor process isolation | 2, 7 | Fixed executable identity, versioned bounded IPC, minimal inherited environment, lifecycle/resource/restart caps, crash/IPC fuzz/race tests; untrusted data cannot select commands or paths | TODO |
| 9 | v0.2 release-readiness audit | 1–8 | Documentation truth-sync, threat review, macOS/Linux CI, full test/race/fuzz/Helm/license/secret/vulnerability/SBOM/provenance evidence, clean `master`, and no unresolved P0/P1/P2 item | TODO |

Each slice is one reviewable PR unless a red regression or dependency review is
safer as a smaller prerequisite PR. Splitting a slice may add PRs but may not
weaken or silently remove its acceptance gate.

## Required checks for every implementation PR

- focused tests covering the changed boundary and its failure paths;
- `go test -race` for affected concurrency paths;
- `make lint test`;
- applicable fuzz smoke and Helm contract tests;
- dependency license, vulnerability, SBOM, and secret checks when relevant;
- `git diff --check`;
- documentation, backlog, decision-log, verification, and handoff truth-sync;
- a deslop review of only that PR's diff;
- all required GitHub checks green before merge.

## Completion predicate

The v0.2 goal is complete only when all of the following are true:

1. Every slice above is `MERGED` with its PR and merge commit recorded.
2. No P0, P1, or P2 entry in `docs/BACKLOG.md` remains `TODO`, `IN PROGRESS`,
   `FAIL`, `NOT RUN`, or ambiguously worded.
3. Slice 8 is implemented and verified; an architecture note alone does not
   count as completion.
4. Required checks passed on each PR and the final `master` commit.
5. `docs/verification.md` distinguishes current PASS, historical FAIL,
   environment BLOCKED, and deliberately out-of-scope NOT RUN evidence.
6. README, PRODUCT, ROADMAP, HANDOFF, architecture, threat model, CLI/config,
   deployment, release, and license documentation match the shipped runtime.
7. No new external egress, publication/signing action, or repository-setting
   change occurred without explicit action-time authorization.
8. The final handoff names remaining work only for a later milestone; it does
   not relabel unfinished v0.2 work as aspirational.

A temporary tool or network failure does not complete a slice. It is recorded
as `BLOCKED`, retried through the documented safe fallback, and remains open
until the acceptance gate is actually satisfied or the user explicitly removes
the slice from this milestone.

## Explicit non-goals for v0.2

- autonomous exploitation, containment, credential rotation, process killing,
  phishing, persistence, malware execution, or any action against real assets;
- a distributed multi-tenant control plane or public administrative API;
- accepting arbitrary extension output as policy or executable behavior;
- claiming full ECS compliance, production readiness, incident certainty, or
  false-positive guarantees;
- publishing a release or configuring signing/repository credentials. Release
  readiness is in scope; publication remains a separate approved action.
