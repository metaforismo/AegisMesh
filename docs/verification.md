# Verification ledger

Current evidence is kept first. The detailed cumulative ledger through
2026-08-24 is preserved in
[`verification-history-through-2026-08-24.md`](verification-history-through-2026-08-24.md).

Vocabulary: **PASS** means the named command or external check actually ran and
succeeded; **FAIL** means it ran and failed; **BLOCKED** means the required tool,
checkout, permission or environment was unavailable; **NOT RUN** means the
check or external action was deliberately not executed. Evidence from hosted CI
does not turn an unavailable local command into a local PASS.

Dated entries are records of the state when they were written. Words such as
"uncommitted", "candidate", "local" or "open, unmerged" in them describe that
moment and are not rewritten; headings carry "(merged as #NN)" where a PR has
since merged. Historical merge status is in the 2026-11-16 audit entry; the
new local uncommitted slice is recorded first.

## 2026-11-27 — round 8 backend: notifications, workspace, incremental sessions (local branch `feat/notifications-workspace`)

ADR-0027. Run locally on macOS (Apple M3, Go 1.27.4) in the backend
worktree, sequentially, on a host shared with other agents (1-minute load
7.8–12.5).

| Check | Result |
|---|---|
| `"$(go env GOROOT)/bin/gofmt" -l .` | PASS (empty) |
| `make lint` (gofmt + `go vet ./...`) | PASS; golangci-lint not installed: BLOCKED, vet+fmt fallback ran |
| `go vet -tags perf ./internal/console/ ./internal/evidenceview/` | PASS |
| `make test` (`go test -race ./...`, 56 packages) | PASS |
| `make secrets-scan` | PASS |
| `go test -fuzz FuzzDecode -fuzztime 15s ./internal/console/notifications/` | PASS (~1.07 M execs) |
| `go test -fuzz FuzzDecodeSnapshot -fuzztime 15s ./internal/console/investigations/` | PASS (~2.17 M execs) |
| `make perf PERF_PROFILE=large` ×3 and `go test -tags perf -run TestPerfIncrementalSessions ./internal/evidenceview` | PASS (correctness only); numbers in `docs/performance/2026-11-27/` |
| `make sbom` | NOT RUN (fails in worktrees, known) |
| UI / browser checks | NOT RUN (backend-only round; the console is built by a separate agent) |

New tests: notification store units (grouping window, observation- and
wall-clock budgets with overflow, ring cap and cursor paging, permission and
recipient filtering, preferences, read state across reopen, fail-closed
decoding, slow-subscriber closure, template injection with HTML, control,
bidi and instruction text); loopback integration tests for derivation from
appended observations, rate limiting, permission filtering and
account_security delivery (key create/revoke, role change, session revoked by
an administrator), preferences, read state and high-water mark across a
restart, tenant isolation, SSE delivery, filtering after permission loss and
closure on key revocation, campaign/session → investigation bounds, note
templates and audit, assignee validation, activity log and list filters, and
posture notifications. Also an investigations schema v2 migration test with
strict-decoding tables, the seeded-demo inbox (64 items: 29
honeytoken_replay, 27 critical_observation, 7 agent_canary, 1 new_campaign;
55 candidates folded into 4 overflow items), and randomized incremental-session
equivalence against full recompute (`evidenceview` and through the real
index and memo).

## 2026-11-23 — landing page redesign (local branch `feat/landing-taste`)

`site/index.html` rebuilt with the tasteskill design method (v2.5.1) and its
checker. Static, not hosted, not embedded. Checks run locally on macOS with
Chrome headless (a busy host: timing verdicts are relative).

| Check | Result |
|---|---|
| `make ui-test` (251 tests, including `webtest/site.test.mjs`: no script, no inline style, only local or project links) | PASS |
| `go build ./...` | PASS |
| tasteskill `gate.mjs site/index.html` (copy lint, checker at 1440 and 390, layout check, 320 walk) | PASS, with 2 waivers (below) |
| tasteskill `consistency.mjs`, widths 1440, 1024, 820, 768, 390; rhythm 1440, 820, 768, 390 | 1 FAIL per width, `scroll-linked`, waived (below); 35 WARN |
| tasteskill `assets/layout/check.mjs`, 1440x900, 1024x768, 820x1180, 768x1024, 390x844 | PASS, no findings |
| tasteskill `copy-lint.mjs --kind software` | PASS, 0 FAIL, 0 WARN |
| tasteskill `perf.mjs` | PASS rows; transfer 549 KiB at 1440, 231 KiB at 390; 0 KiB JS, 0 fonts, CLS 0 |
| No runtime request to another host (`grep` of `src`/`href` and CSS `url()`) | PASS: only plain links to `github.com/metaforismo/AegisMesh` |

Waivers (`.taste-skill/waivers.json`, local): `moment-none` and
`scroll-linked` on `section#promise`. The dealt moment, a statement that lights
up word by word, is built in CSS (`animation-timeline: view()`) because the
site test forbids scripts on site pages; the checker counts a moment only when
the kit's `moments.js` mounts it.

NOT RUN: browsers other than Chrome; a screen reader pass; real devices; the
page served from a host (it is not published).
: campaigns, actor profile, posture (local branch)

Branch `feat/campaigns-posture` cut from `7351bdd`, committed locally; no push,
PR, merge, release or deployment. `go.mod`/`go.sum`, `internal/consoleui/` and
`site/` unchanged. Apple M3, Darwin arm64, Go 1.27. Suites ran sequentially.

| Command | Result |
|---|---|
| `$(go env GOROOT)/bin/gofmt -l .` | PASS (empty) |
| `make lint` | PASS (gofmt + `go vet ./...`; golangci-lint not installed, skipped by the Makefile) |
| `make test` (`go test -race ./...`) | PASS, 51 packages ok |
| `make secrets-scan` | PASS (`secrets-scan: ok`) |
| `go test ./internal/evidenceview -fuzz FuzzShape -fuzztime 20s` | PASS (~0.88M execs, no failure) |
| `go test ./internal/evidenceview -bench SessionsFullSample -benchtime 20x` | about 25 ms/op after the scrub memo (about 111 ms before) |
| `make sbom` | NOT RUN (known to fail in worktrees) |
| `aegismesh demo` campaign | NOT RUN: the demo drives all traffic from one loopback source, so it cannot form a campaign; unchanged |

## 2026-11-22 — round 3 backend (local, uncommitted)

Branch `feat/decoy-environments-siem`, initial clean worktree at
`29c6f421bfe0c52e87ebc27438dbe37bcf76515b`. All changes remain uncommitted.
No push, tag, PR, merge, release, deployment or external provider/SIEM test was
performed. `go.mod`, `go.sum`, UI and dev mock are unchanged. Machine: Apple M3,
Darwin arm64, macOS 26.5.2 (25F84), Go 1.27.4. Disk remained about 12–13 GiB free,
above the 2 GiB cleanup threshold; no `go clean -cache` was needed. All Go suites
and benchmarks ran sequentially with `GOFLAGS=-p=1`.

Built and exercised: exact-map MCP file/env/query tools, strict config and
bounds, connection sequence/redaction, disabled/observe-only detection, pinned
catalog mappings/prose, multi-step demo, read-then-cross-sensor replay including
worker mode, deterministic SIEM formats/goldens/escaping, CLI staged output,
digest comparison/limits/Markdown, all new route roles and tenant isolation,
origin-qualified event/session/export behavior and retained-source histograms.
Full final JSON contracts are in `architecture/console-api.md`; ADR-0023 records
ownership and alternatives. The real perimeter source review and failing-first
findings are in `security-review-2026-11.md`.

| Check | Exact command / result |
| --- | --- |
| PASS | `GOFLAGS=-p=1 make lint` — gofmt and go vet; golangci-lint unavailable and explicitly skipped by the Makefile |
| PASS | `GOFLAGS=-p=1 make test` — full `go test -race ./...`; final run includes the long-marker sequence regression and bounded authentication-table expiry case |
| PASS | `GOFLAGS=-p=1 make secrets-scan` — existing tracked-file heuristic scanner |
| PASS | `GOFLAGS=-p=1 make ui-test` — 169 tests, zero failed/skipped, no UI/mock edits |
| PASS | `GOFLAGS=-p=1 go test ./internal/eventexport -run '^$' -fuzz '^FuzzEscapers$' -fuzztime=15s -fuzzminimizetime=0 -parallel=1` — 447,981 executions in this local run |
| PASS | `GOFLAGS=-p=1 go test ./internal/sensor/mcpsensor -run '^$' -fuzz '^FuzzEnvironmentLookup$' -fuzztime=15s -fuzzminimizetime=0 -parallel=1` — 246,654 executions in this local run |
| PASS | `GOFLAGS=-p=1 make bench BENCH_TIME=100ms BENCH_COUNT=1` — complete existing sequential backend benchmark target, including the accepting-hub fixture |
| PASS | `git diff --check`; no changes under `internal/consoleui`, `go.mod`, `go.sum` |
| PASS | Supplemental heuristic scan of tracked **and untracked** current files: 548 files at scan time, zero matches; no Git staging/index change used |
| NOT RUN | `make sbom` — deliberately skipped as requested because the existing generator is broken in linked worktrees |
| NOT RUN | Hosted CI, real SIEM/collector interoperability, external OIDC, public saturation/p99, releases/deployment/publication |

Full local command output is retained in [round3-verification.log](round3-verification.log).
The supplemental secret heuristic is a tripwire, not proof of secret absence.
The final first-party suites also run config/environment/escaper fuzz seeds;
the whole existing `make fuzz-seed` target was not run, only the two new targets
received timed fuzzing. The Makefile now includes both in future `fuzz-seed` runs.

Failing-first receipts for Bearer throttling, full-table expiry, early hub
rejection headers, raw event audit and long-marker redaction are retained under
`performance/2026-11-22/*-red.txt`; the final full race suite passes. The first
complete race run failed a newly added test that required a handled-tool result
for duplicated arguments, even though strict parsing had correctly rejected the
whole object. That test was corrected to require rejection/no secret content;
the failing run is retained in the log, not counted as PASS. Earlier focused
contract/golden count drift was corrected with explicit backend fixtures; no UI
or mock contract was edited.

Performance uses three matching before/after samples, with raw logs/ranges in
[performance/2026-11-22](performance/2026-11-22/README.md). Accepting-hub overview:
median 7,427,986 → 2,923,616 ns/op, 2,850,836 → 1,159,193 B/op,
38,916 → 5,770 allocs/op; eight real enrolled synthetic identities, 14,167
retained of 50,000 offered envelopes. This is read-side work with acceptance
enabled/live name resolution, not concurrent ingestion load. SSE sixteen-client
allocation per 100 events: 1,741,952 → 643,920 B/op, 13,432 → 5,967 allocs/op;
paced wall time remains about 101 ms. Single-client bytes increase
554,048 → 608,032. An exploratory SSE after sample failed its healthy-client
assertion under variable load; retained and excluded, then all comparison cases
passed on retry. No capacity, statistical-significance or blanket speedup claim.

Limits retained deliberately: digest is on demand with no delivery/scheduler;
OTLP is format only with no exporter; history/source novelty is sample-relative;
CLI missing investigation state is null; local catalogs do not infer remote
config or external body-file planting; COR-008 remains cross-sensor contact
plus marker presentation, not same-sensor read proof; public/real-provider
behavior and hard tenancy remain unverified. No new runtime egress or execution
capability was introduced.

## 2026-11-16 — v0.2.0 release-readiness audit

**Documentation and claims audit of `master` at `7ae0356`, with the gates run on
that commit in an ordinary clone.** This entry records what the repository
claims against what is recorded as verified. Besides documentation, the change
raises the handshake bound of one load-sensitive test and ignores local browser
tool output; it changes no runtime code. `make lint test` was re-run on the
release-preparation head after that test change: PASS. The tag is created from
the merge of this change, whose hosted CI run is the final evidence for the
tagged commit. No image, signature, deployment or repository-setting change was
performed.

### Merged pull requests

Everything below is merged into `master`. Each pull request head passed the six
hosted CI jobs before merge.

| PR | Merge commit | Content |
|---|---|---|
| #72 | `5bdfd41` | Go 1.27.4 and `golang.org/x/crypto` v0.59.0 (security) |
| #73 | `6d46429` | Opt-in evidence-at-rest encryption (age/X25519) |
| #74 | `0f578e3` | Operator console API (auth, roles, sessions/CSRF, hash-chained audit, investigations, SSE) |
| #75 | `2a9363f` | Embedded console UI, design system, static landing page under `site/` (not deployed) |
| #76 | `484bd65` | Experimental fleet inventory: Ed25519 node identity, one-time enrollment, signed heartbeats |
| #77 | `7b96af1` | Encrypted container v3 with authenticated checkpoints; `--require-sealed` |
| #79 | `777dcc9` | Experimental opt-in evidence forwarding, agent to hub |
| #80 | `6f89837` | Experimental SSO via OIDC and logical tenant isolation; gzip/ETag static assets; per-sensor overview buckets; go-oidc v3.21.0, oauth2 v0.38.0, go-jose v4.1.4 |
| #82 | `8f1a0b2` | Measured performance pass (secondary indexes, overview snapshots), `make bench`, `architecture/performance.md` |
| #78 | `c5328ac` | Console UI polish (elevation, icons, sparklines, event drawer, command palette, motion rules) |
| #81 | `7ae0356` | UI for evidence origin, SSO sign-in and tenant switching |

Dependabot PRs #68 and #70 are closed as superseded. PR #71 (pinned GitHub Action
bumps) is open, rebased and CI-green, and has not been reviewed or merged.

### Acceptance criteria (BACKLOG P1-2)

| Criterion | State |
|---|---|
| Every delivery-plan slice (1-8) merged, PR and merge commit recorded | MET — `DELIVERY-PLAN.md` |
| Clean `master` | MET at audit start: the audit change was cut from `7ae0356` with a clean tree |
| Full race/fuzz/Helm/license/secret/vulnerability/SBOM gates on the exact commit | MET — see "Gates on `7ae0356`" below |
| No unresolved P0/P1/P2 milestone item | DEFERRED — P1-3 (#71, pinned Action updates awaiting review), P2-1, P2-2 and P2-3 are moved to the milestone after v0.2.0 at tagging time (2026-11-16); P2-4 was already a later milestone. None of them changes shipped runtime behavior |
| Documentation and threat model match runtime | AUDITED — in-flight wording replaced with merged state, versions/quotas/ports/dependency counts cross-checked, relative links checked; `THREAT-MODEL.md` and the API/protocol contracts were checked for status wording and numbers, not re-derived from source; no independent human review |
| Release, tag, signing, image and cluster actions explicitly `NOT RUN` unless authorized | MET — none performed |
| Verification vocabulary separates `PASS`, `FAIL`, `BLOCKED`, `NOT RUN` | MET |
| Final handoff moves only genuinely later work | MET — `HANDOFF.md` "Next priorities after v0.2.0" |

### Manual browser verification (2026-11-15)

Run against the real server with separate hub and agent processes and two
tenants, in Chromium:

- token sign-in;
- overview including forwarded counts;
- events with the origin column;
- fleet screen with forwarding state;
- tenant switch showing none of the other tenant's data;
- gzip and ETag on static assets.

Earlier manual checks (console against `aegismesh demo --console`; fleet with two
real processes, including `stale` after three missed heartbeats) are in the
2026-11-15 entries below. Fleet token revocation was verified by a two-process
backend run and automated tests, not in the browser.

### NOT RUN / NOT VERIFIED

- **NOT RUN:** tag, GitHub release, container image, binary signature and
  provenance attestation for v0.2.0 — none exists. A maintainer creates the tag
  after the gates below are filled.
- **NOT VERIFIED:** OIDC against any real external identity provider; it has been
  exercised only against local test providers.
- **NOT VERIFIED:** the UI in any browser other than Chromium.
- **NOT RUN:** a real-cluster Kubernetes run; the Helm chart is contract-tested
  only.
- **NOT RUN:** publication of the landing page; it is not hosted anywhere.
- **NOT RUN:** `golangci-lint` — not installed locally; the Makefile runs `gofmt`
  and `go vet` and reports the skip.
- **NOT RUN:** physical power-loss testing, external-IdP interoperability, durable
  offline forwarding (not implemented) and review of PR #71.
- **BLOCKED:** `make sbom sbom-check` inside a linked git worktree (the pinned
  generator cannot resolve the main-module version there); run it in an ordinary
  clone.
- **Known test fragility:** CLI doctor tests expect the default ports
  8081/6399/8090/9110 to be free; a busy machine can fail `make test` for that
  reason alone (BACKLOG follow-up).

### Gates on `7ae0356`

To be filled by the maintainer on the exact commit before this change merges. Do
not replace a cell with anything but the real outcome (`PASS`, `FAIL`, `BLOCKED`
or `NOT RUN`, plus the exact blocker or output summary).

| Gate | Result | Notes |
|---|---|---|
| `make lint` | PASS | gofmt and `go vet`; `golangci-lint` NOT RUN (not installed) |
| `make test` | FAIL then PASS | first run on `7ae0356` failed only `TestHostHandshakeFailures/echoes_wrong_frame_type` (fixed 2 s handshake bound on a loaded machine; 3/3 PASS in isolation). The bound was raised in this change and `make lint test` re-run on the release-prep head: see below |
| `make ui-test` | PASS | Node.js >= 20 |
| `make vuln` | PASS | pinned govulncheck |
| `make fuzz-seed` | PASS | bounded real fuzz targets |
| `make license-check` | PASS | |
| `make secrets-scan` | PASS | |
| `make supply-chain-check` | PASS | |
| `make helm-contract` | PASS | local Helm v4 |
| `make sbom` | PASS | run in the ordinary clone |
| `make sbom-check` | PASS | needs the SBOM from the previous row |
| `go mod verify` | PASS | |
| Hosted CI on `master` | PASS | all six jobs on the `7ae0356` run |

### Checks the audit author ran

| Command/check | Result | Output summary |
|---|---|---|
| `git diff --check` | PASS | exit 0, no output, run on the final documentation change |
| `make secrets-scan` | PASS | `secrets-scan: ok` (heuristic tracked-file scan) |
| `make ui-test` | PASS | 169 tests, 169 passed, 0 failed, 0 skipped (Node.js v25.8.2); run because `site/index.html` changed, and it includes the site link and CSS-copy tests |
| In-flight wording sweep (`grep -rn -i 'uncommitted\|candidate\|PR pending\|open PR\|unmerged\|awaits\|awaiting\|orchestrator\|backend engineer\|frontend engineer\|in flight\|stacked on\|hosted CI: NOT RUN\|this branch'` over `README.md`, `CHANGELOG.md`, `docs/*.md`, `docs/architecture/*.md`) | PASS | no stale in-flight statement remains outside dated entries of this file and the `*-history-*` archives; remaining hits are unrelated uses of "candidates" or historical descriptions of fixed defects |
| Relative links and heading anchors in every changed Markdown file (ad hoc script, not a repository command) | PASS | 0 broken links across the changed files; one pre-existing dead link to an uncommitted benchmark file was replaced by a note |
| `make lint`, `make test`, `make vuln`, `make fuzz-seed`, `make license-check`, `make supply-chain-check`, `make helm-contract`, `make sbom`, `make sbom-check`, `go mod verify` | NOT RUN | deliberately skipped by the audit author (documentation-only change, tight disk); the maintainer records them in the gate table above |

## 2026-11-16 — measured backend performance and architecture pass (merged as #82)

**PASS — local implementation, final benchmark set and required gates.** Worktree
`perf/console-hot-paths`, initially clean at `338eea7b0ed4bb69fb1ddb6402704d1b27efc842`,
which is also the local `feat/console-sso` head (PR #80 per task context).
Measurements started November 15; final verification and SSE pacing refresh
completed November 16 CET. Changes remain uncommitted; no commit, push, branch
switch or `gh` command ran. `internal/consoleui/**`, `site/**`, existing test
files, config surface, API/cursor contracts, dependencies and on-disk formats
were not changed. Hosted CI, review, merge, deployment and external-provider
validation are **NOT RUN**.

The first `make lint test` **FAIL** is retained: CLI doctor tests encountered
occupied default ports 8081/6399/8090/9110. No live listeners or tests were changed.
A later doctor control on the archived original source passed, and the complete
`make lint test` retry passed after the conflict cleared. The initial failure is
not erased or presented as a pass. The inherited fixed-port test fragility has
a concrete follow-up in `BACKLOG.md`.

### Measurement setup and bounds

Darwin arm64, Apple M3, eight logical CPUs, macOS 26.5.2 (25F84), Go 1.27.4;
benchmark suffix `-8`. Total RAM, thermal/power state and other processes' load
were not available (`sysctl`/process inventory restricted). Disk started at
7.7 GiB and was 7.1 GiB after the commands. No cache/user-data cleanup ran.
Suites and benchmarks ran sequentially. Verification used `GOFLAGS=-p=1` to
serialize package execution; fuzzing additionally used `GOMAXPROCS=2`.
Benchmarks used the normal eight-P setting for both sources.

The final set contains **63 leaves**, each with three short samples. Full runs
used `make bench BENCH_COUNT=3` (100 ms per leaf); append and SSE refinements have
explicit before/after subset receipts. A 2.6 MiB archived source snapshot in
`/tmp/aegis-perf-baseline-hupcrne6` preserves the original implementation with
the same benchmark sources and two delegating source-aggregation adapters.
No checkout or branch was switched. Raw samples, adapter/workload details,
excluded exploratory runs and table generator are in
[`performance/2026-11-15/README.md`](performance/2026-11-15/README.md).

Each tenant receives 50,000 synthetic envelopes. The configured count limit is
50,000, but the unchanged 64 MiB byte accounting (including 4 KiB per projection)
evicts first: the fresh read fixture retains **14,167 events per tenant**.
**NOT RUN — 50,000 simultaneously retained realistic events:** impossible under
that existing invariant without changing behavior. The append benchmark exercises
actual eviction with the real bound; eight-tenant reads rotate through eight
independent populated partitions. No cross-tenant post-filter substitutes for
partitioning.

SSE operations contain 100 events paced against absolute 1 ms deadlines;
scheduler delays are caught up instead of dropping ticker slots. Achieved
rate includes healthy-reader drain: roughly 987/s in the 100-event samples,
998.6/s in the one-second profiles. B/op and allocs/op are per **100-event batch**,
not per event. Fleet evidence ingestion is per **1,000-event batch**; heartbeat
has 1,000 registered nodes. Console measurements run the actual handler stack
into a recorder, without sockets/TLS. Storage uses real buffered files, including
append plus per-event encrypted `Flush` for the checkpoint case; no fsync claim.
Runtime tap measurements use a successful no-op primary control to isolate real
index/forwarding-queue overhead from disk.

### Before/after results

Three-sample medians; ranges are min/max, not confidence intervals. Shared-machine
noise is material. Eight-tenant cookie overview latency did not improve despite
lower allocation; untuned session/storage/heartbeat controls also varied or
regressed. No blanket speedup, significance, throughput or capacity claim is made.
The additional metadata costs and unchanged worst cases are described in
[`architecture/performance.md`](architecture/performance.md).

| Benchmark | ns/op before -> after | B/op before -> after | allocs/op before -> after | ns/op range before; after |
| --- | ---: | ---: | ---: | --- |
| `Index/tenants=1/AppendEvict` | 16,087 → 9,367 | 4,868 → 4,637 | 84 → 55 | 14,305–17,254; 9,243–12,632 |
| `Index/tenants=1/Query/None` | 7,787,269 → 12,787 | 489,431 → 13,617 | 8,403 → 74 | 6,619,000–9,765,288; 11,725–17,282 |
| `Index/tenants=1/Query/Node` | 5,341,047 → 93,609 | 99,997 → 13,970 | 1,506 → 84 | 4,633,518–6,776,702; 92,585–130,666 |
| `Index/tenants=1/Query/Classification` | 6,998,309 → 98,724 | 72,271 → 13,617 | 823 → 73 | 5,211,058–9,094,626; 75,476–124,109 |
| `Index/tenants=1/Query/Sensor` | 2,185,781 → 145,866 | 116,663 → 13,634 | 1,850 → 74 | 2,018,171–2,921,936; 145,010–150,776 |
| `Index/tenants=1/Query/Kind` | 4,961,009 → 353,445 | 201,998 → 13,636 | 3,621 → 74 | 4,330,151–6,528,170; 262,720–376,781 |
| `Index/tenants=1/Query/Source` | 2,229,097 → 14,163 | 34,132 → 13,633 | 136 → 74 | 1,619,817–2,471,544; 13,450–15,382 |
| `Index/tenants=1/Query/Rule` | 4,620,558 → 334,430 | 219,101 → 14,197 | 3,621 → 108 | 4,331,179–5,583,415; 294,593–385,505 |
| `Index/tenants=1/Query/Severity` | 3,339,749 → 1,534,449 | 219,086 → 14,216 | 3,621 → 108 | 3,235,427–4,072,089; 699,312–1,634,089 |
| `Index/tenants=1/Query/Q` | 11,310,903 → 2,841,003 | 1,012,168 → 13,654 | 20,233 → 74 | 8,655,920–14,211,759; 874,515–3,493,561 |
| `Index/tenants=1/Query/Since` | 5,362,914 → 18,911 | 36,304 → 13,617 | 168 → 74 | 3,420,113–8,589,315; 17,171–20,246 |
| `Index/tenants=1/Query/Until` | 3,968,776 → 1,482,756 | 373,018 → 13,618 | 6,288 → 73 | 3,924,964–4,563,021; 1,152,638–2,103,274 |
| `Index/tenants=1/Query/Combined` | 1,378,036 → 1,443 | 3,760 → 1,232 | 18 → 10 | 1,350,964–1,940,657; 1,396–1,730 |
| `Index/tenants=1/Query/DeepCursor` | 7,162,763 → 16,028 | 490,960 → 14,950 | 8,415 → 86 | 4,251,338–9,195,802; 14,311–21,123 |
| `Index/tenants=1/Overview/1h` | 7,778,199 → 187,337 | 3,388,928 → 121,976 | 16,724 → 578 | 7,453,253–8,085,035; 171,661–192,242 |
| `Index/tenants=1/Overview/24h` | 10,592,438 → 1,751,812 | 3,468,961 → 413,304 | 17,039 → 915 | 9,967,635–12,478,400; 1,138,417–4,212,208 |
| `Index/tenants=1/Overview/7d` | 21,862,132 → 8,499,257 | 3,444,610 → 285,520 | 17,034 → 902 | 20,177,125–25,558,938; 6,917,740–11,723,683 |
| `Index/tenants=1/Sources` | 7,952,536 → 557,325 | 3,387,264 → 216,512 | 16,936 → 792 | 7,582,942–9,379,993; 396,557–563,006 |
| `Index/tenants=1/SourceTimeline` | 16,279,622 → 13,609 | 3,421,712 → 14,257 | 17,073 → 78 | 10,532,088–18,490,412; 13,349–15,540 |
| `Index/tenants=1/Related` | 2,173,845 → 402.5 | 384 → 416 | 3 → 5 | 1,252,054–2,219,845; 389.4–413.4 |
| `Index/tenants=8/AppendEvict` | 13,035 → 12,508 | 4,864 → 4,635 | 83 → 55 | 12,229–13,455; 10,243–13,166 |
| `Index/tenants=8/Query/None` | 12,493,858 → 8,198 | 489,480 → 13,616 | 8,403 → 74 | 12,455,833–20,625,432; 8,174–8,550 |
| `Index/tenants=8/Query/Node` | 10,714,296 → 105,106 | 100,069 → 13,969 | 1,506 → 84 | 8,242,885–17,324,206; 100,477–200,723 |
| `Index/tenants=8/Query/Classification` | 7,483,950 → 64,287 | 72,272 → 13,617 | 823 → 73 | 7,157,602–7,614,659; 63,539–69,410 |
| `Index/tenants=8/Query/Sensor` | 5,773,788 → 130,204 | 116,737 → 13,634 | 1,850 → 74 | 5,748,339–6,591,631; 128,295–163,099 |
| `Index/tenants=8/Query/Kind` | 5,744,158 → 558,845 | 202,033 → 13,641 | 3,621 → 74 | 5,681,440–7,053,390; 552,084–568,429 |
| `Index/tenants=8/Query/Source` | 4,926,783 → 11,286 | 34,173 → 13,632 | 136 → 74 | 4,613,536–6,533,258; 10,493–17,901 |
| `Index/tenants=8/Query/Rule` | 10,404,597 → 1,123,903 | 219,218 → 14,212 | 3,621 → 108 | 8,455,858–11,783,950; 1,063,340–1,219,943 |
| `Index/tenants=8/Query/Severity` | 9,328,372 → 2,869,635 | 219,186 → 14,241 | 3,621 → 108 | 9,162,799–12,616,938; 2,825,993–2,887,701 |
| `Index/tenants=8/Query/Q` | 25,139,979 → 3,600,964 | 1,012,195 → 13,692 | 20,234 → 74 | 17,824,681–25,912,396; 3,562,296–3,710,328 |
| `Index/tenants=8/Query/Since` | 14,009,300 → 17,585 | 36,434 → 13,616 | 168 → 74 | 13,777,125–17,299,783; 13,155–21,880 |
| `Index/tenants=8/Query/Until` | 16,172,250 → 2,806,595 | 373,221 → 13,649 | 6,289 → 73 | 12,795,792–22,835,981; 2,762,071–2,860,795 |
| `Index/tenants=8/Query/Combined` | 9,382,905 → 1,116 | 3,760 → 1,232 | 18 → 10 | 5,467,414–14,255,810; 1,115–1,121 |
| `Index/tenants=8/Query/DeepCursor` | 16,356,976 → 18,598 | 490,592 → 14,945 | 8,415 → 86 | 14,695,575–16,653,851; 16,153–25,848 |
| `Index/tenants=8/Overview/1h` | 23,158,882 → 130,062 | 3,388,920 → 121,976 | 16,724 → 578 | 14,591,968–24,718,750; 109,119–135,108 |
| `Index/tenants=8/Overview/24h` | 22,466,618 → 3,953,401 | 3,468,952 → 413,304 | 17,039 → 915 | 19,767,722–22,915,076; 3,908,781–5,646,656 |
| `Index/tenants=8/Overview/7d` | 26,226,427 → 10,067,546 | 3,444,592 → 285,520 | 17,034 → 902 | 24,628,525–26,897,354; 9,208,521–12,531,521 |
| `Index/tenants=8/Sources` | 12,235,146 → 1,447,581 | 3,387,264 → 216,512 | 16,936 → 792 | 10,418,925–12,958,653; 1,424,253–1,757,995 |
| `Index/tenants=8/SourceTimeline` | 20,736,924 → 12,218 | 3,421,749 → 14,256 | 17,074 → 78 | 20,087,512–21,055,125; 12,196–12,692 |
| `Index/tenants=8/Related` | 7,290,479 → 399.3 | 384 → 416 | 3 → 5 | 6,253,363–7,889,044; 368.6–420.0 |
| `ConsoleRequest/tenants=1/events/Cookie` | 4,651,458 → 79,314 | 513,850 → 34,336 | 8,432 → 102 | 4,447,170–5,598,569; 78,246–84,459 |
| `ConsoleRequest/tenants=1/events/Bearer` | 6,837,183 → 74,588 | 521,154 → 34,181 | 8,432 → 100 | 6,375,167–7,113,272; 74,094–75,378 |
| `ConsoleRequest/tenants=1/overview/Cookie` | 11,237,075 → 1,532,432 | 3,552,919 → 415,551 | 17,074 → 947 | 11,206,733–13,839,449; 1,334,869–1,603,650 |
| `ConsoleRequest/tenants=1/overview/Bearer` | 12,265,657 → 1,347,560 | 3,550,308 → 411,902 | 17,072 → 944 | 10,666,112–15,949,662; 1,208,282–1,403,401 |
| `ConsoleRequest/tenants=1/session/Cookie` | 2,818 → 4,161 | 2,152 → 2,152 | 23 → 23 | 2,665–2,910; 3,829–5,442 |
| `ConsoleRequest/tenants=1/session/Bearer` | 3,973 → 2,949 | 1,888 → 1,888 | 21 → 21 | 3,710–3,993; 2,936–4,220 |
| `ConsoleRequest/tenants=8/events/Cookie` | 7,001,703 → 122,956 | 515,680 → 34,356 | 8,432 → 102 | 6,941,608–7,146,647; 117,786–260,533 |
| `ConsoleRequest/tenants=8/events/Bearer` | 7,112,542 → 139,190 | 515,480 → 34,144 | 8,430 → 100 | 7,052,458–7,138,967; 133,544–314,903 |
| `ConsoleRequest/tenants=8/overview/Cookie` | 11,151,958 → 12,574,607 | 3,550,276 → 421,938 | 17,074 → 948 | 11,019,142–12,659,921; 12,186,814–15,502,533 |
| `ConsoleRequest/tenants=8/overview/Bearer` | 13,077,644 → 7,471,986 | 3,552,460 → 416,373 | 17,072 → 945 | 13,048,551–13,634,940; 5,646,798–13,933,818 |
| `ConsoleRequest/tenants=8/session/Cookie` | 3,214 → 7,500 | 2,152 → 2,152 | 23 → 23 | 3,108–4,420; 5,339–13,830 |
| `ConsoleRequest/tenants=8/session/Bearer` | 3,598 → 5,236 | 1,888 → 1,888 | 21 → 21 | 3,005–4,041; 4,625–6,795 |
| `SSEFanout/One` | 101,268,750 → 101,281,416 | 571,904 → 536,576 | 8,738 → 5,813 | 101,261,959–101,287,125; 101,278,834–101,299,959 |
| `SSEFanout/Sixteen` | 101,297,500 → 101,229,167 | 1,845,792 → 1,738,568 | 17,882 → 13,449 | 101,277,667–101,302,333; 101,225,583–101,253,125 |
| `SSEFanout/Slow` | 101,268,917 → 101,287,750 | 1,771,528 → 1,666,432 | 17,314 → 12,977 | 101,267,584–101,285,208; 101,279,083–101,302,541 |
| `StorageAppend/Plain` | 8,005 → 11,725 | 1,089 → 1,089 | 3 → 3 | 7,420–10,036; 9,693–13,092 |
| `StorageAppend/Encrypted` | 275,333 → 370,472 | 12,534 → 12,554 | 120 → 120 | 272,467–351,117; 336,299–724,429 |
| `StorageAppend/EncryptedCheckpoint` | 537,376 → 688,632 | 22,198 → 22,196 | 239 → 239 | 441,622–619,492; 533,979–1,384,535 |
| `RuntimeTap/Primary` | 17.82 → 14.51 | 0 → 0 | 0 → 0 | 14.04–22.50; 9.23–16.57 |
| `RuntimeTap/Index` | 15,499 → 8,339 | 4,738 → 4,521 | 80 → 52 | 11,362–18,537; 7,638–9,363 |
| `RuntimeTap/IndexForwarder` | 10,936 → 11,314 | 5,826 → 5,609 | 83 → 55 | 10,129–13,073; 10,694–15,022 |
| `Heartbeat1000` | 88,610 → 126,321 | 15,487 → 15,690 | 166 → 168 | 86,808–94,088; 109,138–127,794 |
| `EvidenceBatch1000` | 26,586,000 → 25,452,625 | 16,154,572 → 15,638,752 | 185,464 → 150,483 | 23,886,625–27,315,281; 23,621,967–34,013,792 |

Paced SSE producer time and observed rate (the wall-time rows above include waiting):

| SSE case (100 events/op) | producer ns/event before → after | achieved events/s before → after |
| --- | ---: | ---: |
| One | 29,011.0 → 26,393.0 | 987.0 → 987.1 |
| Sixteen | 36,442.0 → 19,258.0 | 986.6 → 987.4 |
| Slow | 32,728.0 → 23,840.0 | 986.8 → 986.8 |

### Changes and profile interpretation

- Queries select the smallest bounded chronological secondary list; append and
  eviction maintain/remove its links and empty keys. Unfiltered totals use
  occupancy, retained authenticated cursor anchors seek directly, timestamp
  bounds stop old scans, and a 200-reference buffer allocates exactly the returned
  page. Search text is derived once from immutable display fields.
- Overview uses native timestamps and one aggregation pass over window-limited
  immutable references; aggregation/sorting run outside the index lock. Source
  handlers use indexed source/window aggregation. There is no time-based overview
  cache. The original overview/source JSON golden passes unchanged, including
  half-open windows, comparison totals, ordering, names and sensor buckets.
- Projection avoids ID hex-decoder allocation, rebuilding already bounded clean
  strings and decoding absent optional fields. Rule lookup uses immutable
  compile-time metadata; `All` retains its fresh-copy contract. Tests cover owner
  equivalence, caller mutation, misses/bounds, secondary eviction, expired cursor
  anchors and concurrent snapshot ownership.
- Mechanical refactors: identical console/protocol JSON validation is now in
  `internal/strictjson`; protocol-specific caps/errors remain at the call sites.
  Runtime append taps are in `evidence.go`, lifecycle in `lifecycle.go`, and
  shutdown joins its maintenance worker. Five real listener lifecycle cycles have
  a settling goroutine-count assertion.

CPU and allocation profiles were captured/read for fleet evidence ingestion,
eight-tenant 7d overview and eight-tenant free-text query (the three slowest
non-paced baseline leaves), plus console overview/cookie and **all three SSE
cases**. Whole-process profiles include setup/calibration; focused reports isolate
actual request stacks. Index overview allocation was about 95% summary copying;
console overview about 92%. Query matching accounted for about 97% of focused
allocation, with repeated lowercasing and timestamp parsing prominent in CPU.
Fleet request CPU had about 56% syscall samples and `DecodeEvidence` about 61%
of focused allocation. Sixteen/slow SSE profiles attribute about 61–64% of
focused allocation to per-subscriber JSON marshaling; CPU sampling is sparse at
this paced rate. Profile files and read `pprof` reports are retained under the
measurement directory; percentages are sample diagnostics with overlapping
cumulative callers, not independent shares to add together.

Concrete backlog entries cover encoded-envelope ownership, late-arrival/lock
contention and high-cardinality workloads, unscoped/tenant fleet lookups,
accepting-hub overview/name resolution, runtime sensor-monitor ownership and
shutdown/error causes, neutral state-IO package ownership, shared SSE frames,
paired noisy controls and fixed-port CLI fixtures. Constant-time auth scans
(maximum 32), distinct limiter/state/cursor policies, existing OIDC refresh and
configuration validation were reviewed and retained. Shared SSE encoding and
broader lifecycle/API changes were deliberately left for scoped work.

### Command receipts

`PASS` for `make bench` means the benchmark command completed successfully, not
that every timing improved. It is opt-in and **not a CI gate**; `make help`
documents it, with `BENCH_COUNT` and `BENCH_TIME` overrides. All new benchmark
inputs are synthetic; the existing fleet benchmark file is unchanged.

Receipt file names in the table below refer to local run output that is not
committed; `docs/performance/2026-11-15/table.md` holds the resulting medians.

| Command/check | Result | Captured output |
| --- | --- | --- |
| `make bench BENCH_COUNT=3`, original and changed source | PASS | 63 leaves × 3 samples each; `before.txt`, `after.txt`; corrected append subset in `before-append.txt` |
| `go test -run '^$' -bench '^BenchmarkSSEFanout$' -benchmem -benchtime=100ms -count=3 ./internal/console`, both sources | PASS | 3 cases × 3 samples, `before-sse.txt`, `after-sse.txt`; supersedes earlier ticker rows |
| `make lint test`, first attempt | FAIL | `lint-test.txt`: fmt/vet passed; doctor bind conflicts on 8081/6399/8090/9110; all other packages passed |
| Archived baseline `go test -race -count=1 -run '^TestDoctor' ./internal/cli` | PASS | `baseline-cli-control.txt`; conflict had cleared at this later check |
| `make lint test`, retry | PASS | `lint-test-retry.txt`: fmt clean, vet exit 0, all tests with race passed; unchanged packages reused Go test cache; optional golangci-lint unavailable/skipped |
| `go test -race -count=1 ./internal/console/...` | PASS | `race-console.txt`: console, auth, audit, investigations, OIDC, stateio, tenant |
| `go test -race -count=1 ./internal/fleet/...` | PASS | `race-fleet.txt`: agent, hub, identity, protocol |
| `go test -race -count=1 ./internal/evidenceindex` | PASS | `race-evidenceindex.txt`, including original tests and new ownership/golden checks |
| `go test -race -count=1 ./internal/storage` | PASS | `race-storage.txt` |
| `go test -race -count=1 ./internal/runtime` | PASS | `race-runtime.txt`, including real repeated lifecycle/goroutine-count check |
| `make fuzz-seed` | PASS | `fuzz-seed.txt`: all 14 bounded real fuzz targets completed with two workers |
| `make vuln` | PASS | `vuln.txt`: pinned govulncheck v1.7.0, "No vulnerabilities found" |
| `make license-check secrets-scan` | PASS | `license-secrets.txt`: 18 modules within policy; tracked-file heuristic secret scan OK; no dependency changes |
| `git diff --check` | PASS | `diff-check.txt`; final documentation check recorded separately after this entry |

Exit codes were recorded in `command-results.tsv` in the local run directory
(not committed; see [`performance/2026-11-15/README.md`](performance/2026-11-15/README.md)).
Unmeasured scenarios and reproducibility limits are explicit in the architecture
note. These local checks are not hosted-CI, review, deployment or production proof.

## 2026-11-15 — console SSO, logical tenant isolation and delivery polish (merged as #80)

**PASS — local implementation and verification.** Worktree `feat/console-sso`,
initially clean at `245ccd0`, stacked on `feat/evidence-forwarding` (PR #79).
All changes remain uncommitted. No commit, push, branch switch or `gh` command
was run. Hosted CI, human review, merge, deployment and external-IdP
interoperability are **NOT RUN**. This ledger records local proof only.

SSO via OIDC (experimental) and logical tenant isolation (experimental) are
implemented with ADR-0019/0020 and the exact console-api.md additions. Delivery
polish includes gzip/strong representation ETags/304 and aligned per-sensor
buckets. Tests, fuzzing, scans and the binary demonstration ran sequentially on
Darwin arm64 with Go 1.27.4. Disk availability was 8.0 GiB initially and about
7.3 GiB after build/test caches; no cache or user-data cleanup was performed.

| Command/check | Result | Captured output summary |
| --- | --- | --- |
| `make lint test` | PASS | gofmt clean; `go vet ./...` exit 0; `go test -race ./...` all packages OK |
| `go test -race -count=1 ./internal/console/...` | PASS | console plus auth, audit, investigations, OIDC, stateio and tenant packages OK |
| `go test -race -count=1 ./internal/fleet/...` | PASS | agent, hub, identity and protocol packages OK |
| `go test -race -count=1 ./internal/evidenceindex` | PASS | index projection, cursors, origins and sensor-bucket tests OK |
| `go test -race -count=1 ./internal/runtime` | PASS | runtime/listener/lifecycle/forwarding integration checks OK |
| `go test -race -count=1 ./internal/config` | PASS | strict config, defaults, identity mappings, secret references, overrides and state-root checks OK |
| `go test -race -count=1 ./internal/cli` | PASS | CLI checks and reference-only identity reporting OK |
| `go test -race -count=1 ./internal/console/oidc` | PASS | supplemental configured string-claim, tenant-mapping and name-fallback tests OK |
| `make fuzz-seed` | PASS | 14 bounded real fuzz targets, 15 seconds each, including new FuzzTenantSlug; 14 PASS results |
| `make vuln` | PASS | pinned govulncheck v1.7.0: `No vulnerabilities found.` |
| `make license-check secrets-scan` | PASS | `18 module(s) within policy`; `secrets-scan: ok` (heuristic tracked-file scan) |
| `make supply-chain-check` | PASS | `supply-chain-check: ok` |
| `go mod verify` | PASS | `all modules verified` |
| `git diff --check` | PASS | no whitespace errors |
| `git ls-files --modified --others --exclude-standard` Go files piped to `awk 'length($0) > 140'` and counted | PASS, observed count 8 | all 8 are unchanged legacy lines (7 config error strings and CSP); no added/edited Go line exceeds 140 |
| `make ui-test` | PASS | 81 tests, 81 passed, 0 failed, 0 skipped |
| `go build -o /tmp/aegismesh-sso-manual ./cmd/aegismesh` | PASS | built standalone binary used below |
| application `go list -deps` | PASS | Google metadata package is absent from the application graph; its module is graph-only |
| optional golangci-lint | NOT RUN | not installed; Makefile reported the skip explicitly; fmt/vet ran |

Regression runs were repeated after session-eviction and migration/credential
hardening; the final full race suite and all six focused uncached groups passed.
The mapping-only supplemental test also passed. Fuzz inputs exercise bounded
parsers, not physical power loss or production IdP behavior.

**Authentication proof.** The in-process provider performs real HTTP discovery,
S256 code exchange and signed tokens; tests cover RS256, ES256, EdDSA, public and
Basic confidential clients, browser-bound state, wrong/replayed state, absent/
foreign cookies, nonce/audience/issuer/expiry/iat/nbf/azp/sub failures, none/HMAC
rejection, unknown-kid refresh pacing and real key rotation, missing roles/
tenants, oversized claims, name sanitization, configured claims/mappings,
pending-state exhaustion/expiry, listener redirect mismatch, token disabling,
startup outage/recovery, session rotation and ID-token expiry caps. Provider
response byte caps, redirect refusal and destination/proxy guards are checked.
Audit retains issuer/subject; oversized denied names cannot poison the chain.

**Tenant proof.** The registered-route matrix covers every protected route for
B viewer/analyst/admin operators using bearer tokens and real OIDC cookies.
A has a real investigation, outstanding enrollment credential, enrolled signed
machine identity and accepted forwarded evidence. B sees no A data in lists,
direct IDs, mutations, sources, overview/by_node, local views or audit. Foreign
IDs use the normal absent response; this is a timing-class design, not a
constant-time wall-clock measurement. Separate SSE producer indexes prove the
stream emits only its own tenant's observation. Switching rotates session ID
and CSRF; nonmembers cannot switch. A quota fixtures leave B investigation,
credential, node, session and forwarding budgets usable. Native listeners and
signatures exercise enrollment/forwarding; full byte-quota accounting is
constructed without writing 256 MiB of fixture data.

Legacy migration preserves exact bytes and resumes injected interruptions after
legacy rename, ancestor recreation and completed default move. Unexpected
non-state entries are refused before any rename. Ancestor links are fsynced
before retiring the durable backup. These are deterministic crash-point tests;
physical power-loss testing is **NOT RUN**. Console/hub state and audit remain
separate transactions and require one writer per state root.

**PASS — built binary, separate process provider and curl.** A throwaway stdlib
Ed25519 IdP process and all proof scripts/config/cookies lived outside the repo
in private temporary paths. The actual AegisMesh binary ran two declared tenants,
with one configured token operator each, and a local HTTP sensor. Curl completed
OIDC discovery/authorization/callback and read an OIDC session with CSRF, tenant
and membership. A saw stored observations; B's event/source lists and overview
counts were empty. B received identical 404 bodies for A's event and an absent
ID, and could not read A's investigation. Audit actor checks stayed scoped.
A compressible embedded CSS asset returned gzip, a SHA-256 strong ETag,
no-cache/Vary, then a bodyless 304 with unchanged CSP. Static effective/doctor
identity summaries were checked; doctor correctly reported occupied ports while
the demonstration ran, so this is not an overall doctor-health assertion.

The temporary curl driver initially treated curl's omitted empty 304 output file
as an error; its handling was corrected and the entire demonstration reran with
exit 0. No product change was needed. Runtime stopped cleanly; console, sensor
and provider sockets were verified closed. Binary SHA-256:
`c56c0d79fdf985c339fee30c6874534270f0700ce087cb448c807e0d685575b0`.
No transcripts, manual credentials or throwaway provider/scripts were added to
the repository; the reusable signed test provider is test infrastructure only.

**Explicit limits/deviations.** Issuer discovery/auth/token/JWKS must share a
scheme/authority; all redirects are refused. Confidential clients use HTTP Basic.
Expiry is strict; future iat/nbf allow 30 seconds. Tenant switching requires a
cookie session; bearer callers use their first configured membership. Unresolved
authentication denials use a separate operator-inspected authentication chain
when multiple tenants are configured, with no cross-tenant console audit view.
Existing bare-ID investigation links remain local-only. UI rendering was not
changed; the frontend can consume meta/session additions. Logout remains local;
no RP-initiated logout, refresh persistence, per-tenant keys, billing, rate plans,
self-service creation or hard hosted isolation boundary ships. Host/process
compromise and shared disk/CPU/request/stream admission cross tenants.

## 2026-11-15 — experimental evidence forwarding, local uncommitted slice (merged as #79)

**PASS — local verification.** Worktree `feat/evidence-forwarding`, initially clean at
`25645c03188b9dcc0a6e81c7bbd7177b46ecbb58` (encrypted live-read / stacked PR #77,
above local inventory merge #76). Changes remain uncommitted. No commit, push, branch
switch or GitHub CLI operation was performed; hosted CI, review, merge and deployment
of this amendment are **NOT RUN**.

Experimental; **best-effort forwarding with counted loss; local store authoritative**.
Both evidence consent switches default off. Native redacted envelopes enter a memory-only
oldest-drop ring after successful local append, including correlation signals. Independent
signed batch delivery and transport preserve heartbeat scheduling. Hub validation, per-node
locks/quotas, bounded deduplication and atomic aggregate reservations precede native storage
and origin-tagged live indexing. No private read identity, disk spool or new dependency.

All suites were run sequentially on macOS arm64 / Apple M3, Go 1.27.4; disk availability
remained approximately 8.1 GiB. Fuzz workers alone used `GOMAXPROCS=4` to bound pressure.

| Command | Result and captured output summary |
| --- | --- |
| `make lint test` | **PASS**, exit 0 on final rerun: `go vet ./...`, `go test -race ./...`, all packages successful. Optional `golangci-lint` unavailable; Makefile reports `golangci-lint not installed; skipped (vet+fmt ran)`. |
| `go test -race -count=1 ./internal/fleet/... ./internal/console/... ./internal/evidenceindex ./internal/runtime ./internal/config ./internal/cli` | **PASS**, exit 0; all named packages/subpackages `ok`, no race report. |
| `make fuzz-seed` | **PASS**, exit 0; all 13 targets pass, sequentially. New `FuzzEvidenceBatch`: 1,553,537 executions in approximately 15 s; Makefile and CI both include it. |
| `make vuln` | **PASS**, exit 0: `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0: `14 module(s) within policy`; `secrets-scan: ok`. No dependency added. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `git diff --check` | **PASS**, exit 0, no output (rechecked after ledger edit). |
| `awk 'length($0) > 140'` over all new/changed Go files | **PASS**, 36 files, **0 lines** over 140 characters. |
| `make ui-test` | **PASS**, exit 0: **81 tests, 81 pass, 0 fail**, no UI changes. |
| `make build` | **PASS**, exit 0, built the binary used in the final manual run. |

Earlier development failures were corrected: the scalar-only fleet env fixture needed nested
consent coverage; the integration test needed to wait for enqueue rather than an earlier append
counter; the hostile-acknowledgement test needed a private child state directory instead of the
parent test temp directory. The final full suite and focused race run both pass after those fixes.

**Benchmarks — PASS.** Three repetitions each, `-run '^$' -bench ... -benchmem -count=3`:

| Benchmark | Three timings | Allocation evidence |
| --- | --- | --- |
| `BenchmarkAgentEnqueue/disabled-8` | 5.208 / 5.216 / 5.223 ns/op | 0 B/op; 0 allocs/op |
| `BenchmarkAgentEnqueue/enabled-8` | 785.2 / 786.0 / 788.8 ns/op | 864 B/op; 3 allocs/op |
| `BenchmarkEvidenceBatch1000-8` | 17.268 / 17.006 / 16.818 ms/batch | 16,372,315 / 16,384,530 / 16,372,445 B/batch; 187,153 / 187,177 / 187,154 allocs/batch |

Commands were `go test ./internal/fleet/agent -run '^$' -bench BenchmarkAgentEnqueue -benchmem -count=3`
and the corresponding hub command with `BenchmarkEvidenceBatch1000`. The hub workload includes
synthetic envelope/batch encoding, signing, HTTP handler parsing/authentication, strict validation,
real native-store appends/flush/retention and live indexing; it is not a network throughput or
production sizing claim. Protocol quotas intentionally cap an individual node below that throughput.

**Behavioral coverage — PASS.** Real-loopback hub/agent tests cover accepted copies and origin,
unavailable hub and ordered recovery, oldest overflow and heartbeat drop/gap counters, fresh-signed
duplicate idempotence, hash mismatch, oversize, malformed framing, wrong signature, replay,
revocation, node byte-quota exhaustion while another succeeds, both disabled-consent cases,
independent heartbeats, hub encrypted copies/live index and encrypted local agent forwarding.
Runtime console tests exercise node list/detail/overview filters and SSE. Authorization matrix
rows cover changed query routes. Origin-collision tests prevent cross-node related links,
recommendation input contamination and inherited local investigations. Hostile acknowledgement
integer overflow is rejected without removing queued evidence. Atomic aggregate reservation and
small configured segment-cap/rotation tests check bounded storage admission. Native readers verify
payload hashes, including encrypted checkpoint prefixes with explicit test-only read identities.

**Manual built-binary run — PASS**, repeated on the final build. One hub (console plus reception)
and two agents ran in separate temporary data dirs on real loopback listeners. Each agent generated
one initial HTTP observation: `GET /api/v1/events?node=<id>` returned one correctly attributed
summary and `/overview.by_node` contained one event per node. The hub was stopped; both agents
continued sensor traffic and local writes, generating three observations each. After restart,
each filtered live index returned `/offline-0`, `/offline-1`, `/offline-2` (newest first in API),
and by_node reported three per node. Both heartbeat snapshots reached `forwarded_total:4`,
`dropped_total:0`, `gaps_total:0`. The difference between four forwarded and three currently
indexed is intentional: forwarded index history is not backfilled after restart.

`bin/aegismesh inspect list --data-dir <hub-state>/evidence/<id> --verify --json` exited **0**
for each node, returning **four envelopes each**, every `integrity_ok:true`, `corrupt_lines:0`.
All three processes were stopped by the harness. Only synthetic data was used; no transcript or
helper file was added to the repository.

**Chosen bounds and deviations.** Agent queue: 4,096 events /16 MiB, plus one bounded 4 MiB
in-flight reference set. Batches: 1,000 events /4 MiB. Hub: five-second per-node spacing,
1,000 events per fixed second, 16 MiB request bytes/minute/node, 16 MiB retained segment
bytes/node, 256 MiB aggregate. Segments cap at 4 MiB while respecting smaller configured caps;
small caps use conservative raw-size +1 KiB fit admission. This bounds disk pressure and
rotation slack and prevents one identity consuming the aggregate budget. Conservative reservations
can refuse a batch before physical capacity; many colluding nodes can exhaust the shared budget.
Deduplication is the last 4,096 accepted IDs per node, in memory. Duplicate-only/invalid-only
batches perform no append-space retention eviction. Per-node copies inherit hub encryption and
count/age retention; dormant copies are revisited on that node's next batch.

The wire adds `stream_id` because process-local sequence resets otherwise masquerade as replay
or hide gaps. This is not a durable node-lifetime sequence or exact crash-loss count. Queue
evictions can still arrive if already in flight; dropped counters count evictions and invalid
acknowledgements, not proven permanent absence. Crashes/stops with a queue, outages longer than
its coverage and a trailing missing range leave evidence only on the node. A bounded dedup
window or hub restart can permit another append; flush is OS publication, not fsync. Native
instance/listen metadata is disclosed with the envelope. A compromised hub learns redacted
evidence; a compromised node can forge its own evidence or include secrets. Redaction is the
control, not a proof the hub can validate. Hash consistency on the hub is not provenance.

Cross-node correlation, historical forwarding, deletion propagation, disk spool, node-scoped
investigation annotations, forwarded-index history backfill, hub-to-node traffic and tenancy
are not implemented; the last two retain the permanent no-control/single-tenant boundary.
Exact additive API fields and integrity wording are in architecture/console-api.md.

## 2026-11-15 — stack status (all merged; see the 2026-11-16 audit)

**Status record, not a new test run.** The work of 2026-11-14/15 is committed and
pushed as a stack of open, unmerged pull requests against `master` (`01579d3`).
Each PR is stacked on the previous one. Older entries below that say "uncommitted"
or name a candidate describe the state when they were written.

| PR | Branch | Content | Hosted CI on PR head | Merged? |
|---|---|---|---|---|
| #72 | `security/go-toolchain-vuln-fixes` | Go 1.27.4, x/crypto v0.59.0 | **PASS**, all 6 jobs | no |
| #73 | `feat/evidence-at-rest-encryption` (on #72) | opt-in age/X25519 evidence encryption | **PASS**, all 6 jobs | no |
| #74 | `feat/console-api` (on #73) | operator console API | **PASS**, all 6 jobs | no |
| #75 | `feat/console-ui-embed` (on #74) | embedded console UI, design system, landing page | **PASS**, all 6 jobs, including the Node UI tests step | no |
| pending | `feat/fleet-enrollment` (on #75) | experimental fleet inventory | **NOT RUN** | no |

**Update 2026-11-16:** the table above records the state on 2026-11-15. The
fleet PR is #76; #72-#76 are all merged into `master` (merge commits are listed
in the 2026-11-16 audit entry), and later PRs #77-#82 are merged as well.

No release, tag, image, signature, deployment or repository-setting change
happened. Dependabot PRs #68 and #70 are superseded by #72 but still open; #71
(pinned Action bumps) is untriaged.

**Manual browser verification, 2026-11-15.**

- Console against the real server started by `aegismesh demo --console`: login,
  overview, events, recommendations, node, audit and investigation creation.
- Fleet with two real processes on loopback: a token minted through the operator
  API; an agent enrolled and appeared `online`; interaction counters propagated;
  after the agent stopped it became `stale` once three 10 s heartbeats were
  missed; a token created from the Fleet screen was recorded in the audit trail.
- Fleet token revocation was **not** re-run in the browser. It was verified by
  the backend two-process run and automated tests.

## 2026-11-15 — fleet review: abuse resistance and heartbeat write coalescing (merged as #76)

**PASS — local fixes and requested gates.** Base is the local draft `ad53dc7`
(`wip(fleet): draft before review`), branch `feat/fleet-enrollment`. These changes
were uncommitted when the entry was written; they are now committed on
`feat/fleet-enrollment` (PR #76). No commit, push, branch switch or `gh`
command was run during the recorded checks.
`docs/architecture/console-api.md` and the operator-facing response shapes are
unchanged. No module files, dependencies or configuration knobs were added.
This entry supersedes the earlier candidate's rejection-audit, replay-budget and
per-heartbeat durability claims; the earlier verification record is historical.

All suites ran sequentially on macOS arm64 / Apple M3, Go 1.27.4, with
`GOTOOLCHAIN=go1.27.4 GOFLAGS=-p=1 GOMAXPROCS=2`. The `vuln` target itself
sets `GOFLAGS=-mod=readonly`, as printed in the captured command output.
[Raw command output](fleet-review-verification.log) includes the initial expected
regression failures, all benchmark samples, and the final complete gate outputs.
[Decision trail](fleet-review-decisions.tsv) records the main tradeoffs.

| Check | Exact command | Result |
| --- | --- | --- |
| Formatting, vet and complete race suite | `make lint test` | **PASS**, exit 0; all packages passed. Optional `golangci-lint` was not installed and was skipped explicitly; gofmt/vet ran. |
| Fresh affected-package race suite | `go test -race -count=1 ./internal/fleet/... ./internal/console/... ./internal/runtime` | **PASS**, exit 0; all 10 packages passed. |
| Bounded real fuzzing | `make fuzz-seed` | **PASS**, exit 0; all 12 targets passed at 15 seconds each. Fleet protocol: 680703 executions, 44 new interesting inputs, no failure. |
| Pinned vulnerability check | `make vuln` | **PASS**, exit 0; `No vulnerabilities found.` |
| Heartbeat benchmark | `go test ./internal/fleet/hub -run '^$' -bench '^BenchmarkHeartbeat1000$' -benchmem -benchtime=200x -count=3` | **PASS**, exit 0; before/after samples below. |
| Patch whitespace | `git diff --check` | **PASS**, exit 0; no output, repeated after this ledger update. |
| Fleet Go line lengths | `awk 'length($0) > 140 {n++} END {print n+0}' $(rg --files internal/fleet -g '*.go')` | **PASS**, exit 0; **0**, including all new Go files. |
| Protected API document | `git diff --exit-code -- docs/architecture/console-api.md` | **PASS**, exit 0; no output. |

The new regression tests drove the three reported defects before implementation:
100 invalid requests wrote 100 audit records; an immediate second heartbeat
returned 200 instead of 429; accepted heartbeats changed the snapshot immediately.
Those expected pre-fix failures are retained in the raw log, separately from the
passing final gates. Final review also extended the reuse fixture's token TTL
past the ten-second retry spacing, so the cross-key refusal proves single-use
consumption rather than expiration. The complete and focused race suites were
rerun afterward; production code did not change after fuzz/vuln/benchmark checks.

**Implemented evidence:**

- A 100-request malformed burst increments 100 rejection metrics and produces
  exactly five audit samples plus one summary with count 95 after the injected
  minute boundary. The real concurrent HTTP test also keeps a legitimate signed
  heartbeat successful during four workers' 400-request invalid burst.
- Stateless rejection tests hold the hub mutex and still complete method, path,
  content-type, header, body-cap, skew and enrollment-signature failures. Stored
  heartbeat public-key lookup is the necessary short state dependency; crypto,
  body parsing and response writes hold no hub mutex.
- Source-IP throttling returns 429/Retry-After, aggregates changing ports and
  ignores forwarded headers. More than 4096 distinct remotes leave exactly 4096
  buckets; expiry/pruning restores admission. Fixed 8192 requests/minute supports
  the maximum ten-second fleet behind one NAT, with documented collateral risk.
- A rogue key's 155 attempts over 31 injected seconds admit exactly four
  heartbeats at its ten-second interval while the second node's four heartbeats
  succeed. A filled 64-nonce window affects only its node; expiry reclaims it.
  Revoked and rate-limited requests leave the snapshot, dirty flag and nonce count
  unchanged. Signed re-enrollment retries cannot bypass the write throttle.
- Snapshot-byte tests verify no synchronous heartbeat rewrite, no flush before
  five seconds, one snapshot containing both nodes at the deadline, no clean
  rewrite, synchronous revocation, and orderly shutdown flushing. A real worker
  test verifies an injected-clock advance triggers the background flush.
- Abrupt-restart tests reopen the real last on-disk snapshot without Close's
  soft-state flush: last flushed inventory and replay protection survive; an
  unflushed nonce can be accepted again inside the skew window, then expires.
  A real stale temporary file proves background write failure latches unavailable
  and Close reports the failure. Legacy oversized live nonce windows fail closed;
  startup succeeds after expiry without discarding live replay protection.

**Benchmark comparison.** The identical final benchmark harness seeds a valid
1000-node enrolled registry, then times signing, request construction, ServeHTTP,
verification, replay handling and acknowledgement. Empty sensor lists are used;
setup and shutdown are excluded. Each node reports at 30-second intervals when
cycled; per-node synthetic source IPs keep remote throttling out of this workload.
The controlled 200-operation samples finish before the worker's first wake, so
these are request-path measurements, **not amortized background flush cost or
production throughput**. Coalescing correctness is tested separately above.

The draft was measured with the same final `benchmark_test.go` using
`go test -overlay=/tmp/fleet-baseline/overlay.json` plus the benchmark flags above.
The overlay substitutes `hub.go`, `requests.go`, `nodes.go`, `tokens.go`,
`state.go`, and `server.go` from `git show ad53dc7:internal/fleet/hub/<file>`;
new `limits.go` and `abuse_test.go` are replaced with `package hub` stubs.
No working source replacement or branch switch was needed.

| Version | Median ns/op | Median B/op | Median allocs/op | Time range, 3 samples |
| --- | ---: | ---: | ---: | --- |
| Draft `ad53dc7` | 9276050 | 2458381 | 1294 | 9205144..10794933 ns/op |
| Fixed worktree | 63871 | 15441 | 165 | 61161..80244 ns/op |

Medians are computed per metric. The measured request path is about 145 times
faster, with about 87% fewer allocations, for this bounded synthetic workload.

**Residual risks and durability:** durable enrollment/key/interval/revocation and
token changes remain synchronous. Normally a crash loses at most the latest
five-second soft-state interval; scheduler/IO stalls can extend elapsed loss.
Restart displays the last flushed inventory until the next heartbeat. Unflushed
nonces can reopen within signed timestamp ±120 seconds (up to 240 seconds after
initial receipt for a future-dated request). No process-start timestamp floor is
imposed. Pending rejection samples/counts can also be lost on crash. Flushed
nonces, consumed tokens and revocation remain durable. Shared NAT throttling,
remote-table saturation, bounded audit quota exhaustion and distributed CPU/disk
pressure remain possible; no DDoS/host isolation or prospective performance
claim is made. The full registry is still rewritten under the mutex at the
coalesced cadence, plus synchronous durable changes.

## 2026-11-15 — experimental fleet inventory candidate (merged as #76)

**PASS — local implementation and required verification.** Branch
`feat/fleet-enrollment`, base HEAD `20a2dbb`, stacking the operator console.
All changes were uncommitted when this entry was written; they are now committed
on `feat/fleet-enrollment` (PR #76, unmerged). No commit, push, branch
switch, `gh`, merge, publication or deployment occurred during the recorded checks. macOS arm64, `go version go1.27.4 darwin/arm64`.
No module files or dependencies changed. All suites ran sequentially with
`GOTOOLCHAIN=go1.27.4 GOFLAGS=-p=1 GOMAXPROCS=2`; Makefile pins that toolchain.

The candidate is experimental fleet inventory with authenticated enrollment and
heartbeats. It is not multi-tenant, not a managed service, and forwards no
evidence. The hub cannot command nodes. ADR-0018 and `architecture/fleet-protocol.md`
define the implemented boundaries and proposed work.

| Check | Exact command | Final local result / captured output |
| --- | --- | --- |
| Formatting, vet, complete race suite | `make lint test` | PASS, exit 0; `go vet ./...`, `go test -race ./...`; all packages passed. Optional `golangci-lint` was not installed and was explicitly skipped. (49.80 s) |
| Fresh affected-package race suite | `go test -race -count=1 ./internal/fleet/... ./internal/console/... ./internal/runtime ./internal/config ./internal/cli` | PASS, exit 0; fleet agent/hub/identity/protocol, console and its subpackages, runtime, config and CLI all passed with `-count=1`. (49.26 s) |
| Bounded real fuzzing | `make fuzz-seed` | PASS, exit 0; all 12 targets passed at 15 seconds/target. New `FuzzFleetProtocol`: 692619 executions, 65 new interesting inputs; no failure. Target added to Makefile and CI lists. (198.29 s) |
| Pinned vulnerability check | `make vuln` | PASS, exit 0; `No vulnerabilities found.` (3.57 s) |
| Dependency licenses and tracked-file secret scan | `make license-check secrets-scan` | PASS, exit 0; `license-check: ok — 14 module(s) within policy`; `secrets-scan: ok`. (2.00 s) |
| Immutable supply-chain references | `make supply-chain-check` | PASS, exit 0; `supply-chain-check: ok`. (0.09 s) |
| Module checksum verification | `go mod verify` | PASS, exit 0; `all modules verified`. (0.56 s) |
| Patch whitespace | `git diff --check` | PASS, exit 0; empty output. Repeated after the final documentation update. (0.02 s) |
| Built binary for manual verification | `make build` | PASS, exit 0; built `bin/aegismesh` with the Makefile version/commit flags. (2.28 s) |
| New Go line-length count | `git ls-files --others --exclude-standard '*.go'` piped to `awk 'length($0) > 140 {count++} END {print count+0}'` | PASS, exit 0; **0** overlong lines across 25 new Go files. |
| Supplemental secret scan | Existing scanner with its file inventory extended to `git ls-files --cached --others --exclude-standard`, temporary helper outside the repo | PASS, exit 0; `secrets-scan: ok`; includes the untracked new files. |

Captured focused-suite output includes:

```text
ok  github.com/metaforismo/aegismesh/internal/fleet/agent
ok  github.com/metaforismo/aegismesh/internal/fleet/hub
ok  github.com/metaforismo/aegismesh/internal/fleet/identity
ok  github.com/metaforismo/aegismesh/internal/fleet/protocol
ok  github.com/metaforismo/aegismesh/internal/console
ok  github.com/metaforismo/aegismesh/internal/console/audit
ok  github.com/metaforismo/aegismesh/internal/console/auth
ok  github.com/metaforismo/aegismesh/internal/console/investigations
ok  github.com/metaforismo/aegismesh/internal/console/stateio
ok  github.com/metaforismo/aegismesh/internal/runtime
ok  github.com/metaforismo/aegismesh/internal/config
ok  github.com/metaforismo/aegismesh/internal/cli
```

Integration evidence uses real loopback listeners and the real hub/agent:
enrollment → heartbeat → online, injected-clock stale/offline, token reuse and
concurrent single-use consumption, expiry/wrong token, proof failure, tampered
body/path/timestamp/nonce, replay across hub restart, out-of-window skew,
revocation and refused re-enrollment, oversized body, registry/identity restart,
TLS with a generated CA and unknown-CA refusal, redirect/proxy refusal and safe
response bounds. Runtime tests send a real sensor request and verify stored
evidence while the hub is down. Config tests cover every new field and override,
unknown/inline fields, unsafe egress/TLS and credential references. A hub can run
without sensors; ordinary nodes/agents still require sensors. Dry-run startup
binds listeners without agent egress/token consumption; an explicit live send
from the same preflighted agent then succeeds.

The route-driven authorization matrix now covers all 30 registered routes with
210 exact-status cases (none, malformed, wrong, expired, viewer, analyst, admin).
An additional enabled-fleet matrix exercises 28 role cases across all seven new
routes, plus cookie CSRF/Origin, strict bodies/queries, token secrecy and audit.
Initial development runs exposed missing matrix fixtures, an invalid HTTP test
fixture, a wrong session-field reference and formatting-helper comma errors;
all were corrected. The final receipts above supersede those intermediate
failures. The dry-run egress issue and hub-only sensor requirement found during
review were fixed and the complete/focused/fuzz gates rerun afterward.
The timestamp-tamper fixture was then strengthened to change the header by one
second, inside the allowed skew window, so signature verification must reject
it. `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/fleet/hub -run
TestAuthenticatedRequestFailuresAndReplayAcrossRestart` passed (exit 0,
`ok .../internal/fleet/hub 2.165s`), followed by another passing `make lint test`.
This final edit changed test coverage only; the manually exercised production
binary was unchanged.

Manual built-binary receipt (**PASS**, separate processes and private temp data
roots, loopback HTTP development transport, ten-second reporting interval):

1. Started a sensor-free hub with console. Authenticated `GET /api/v1/fleet`
   returned 200 with hub enabled.
2. Admin `POST /api/v1/fleet/enrollment-tokens` returned 201. Token **REDACTED**;
   supplied through a 0600 file, never a command argument or inline config.
3. Started a second process as agent. One node appeared `online`; the token
   disappeared from outstanding metadata and agent status reported enrolled.
4. Agent sensor returned HTTP 200. The next heartbeat carried interaction=1;
   the hub's evidence endpoint still returned an empty event list.
5. Stopped the agent with SIGTERM (exit 0). Inventory became `stale` **30.0 s**
   after stop. Restart reused the same node ID and returned to `online` with
   exactly one inventory record.
6. Admin revoked the node (200, status `revoked`). Its next live heartbeat was
   refused: agent reported the fixed HTTP-403 category
   `fleet: node revoked; operator review required`. Last-seen did not advance.
   Audit contained token.create, node.enroll, node.revoke and node.rejected.
7. Both processes stopped cleanly, exit 0. Disposable state/token/key directories
   were removed. Only redacted summaries are retained here; no raw transcript or
   helper script was added to the repository.

Offline-after-ten-intervals was verified with the injected clock in integration
tests, not by waiting 100 seconds in this manual run. Public-network deployment,
scale/load validation, UI acceptance, hosted CI, merge and production operation
are **NOT RUN**. The inventory is authenticated self-report, not host attestation.
Optional `fleet status` and `demo --fleet` were omitted. Evidence forwarding,
rotation, mTLS/attestation, remote configuration, upgrades, tenancy and SSO remain
proposed, not implemented; no hub-to-agent control channel is reserved.

## 2026-11-15 — embedded operator console UI (merged as #75)

Worktree branch `feat/console-ui-embed` on top of `feat/console-api`, macOS arm64,
Go **1.27.4**, Node.js v25.8.2. Local commits only: no push, `gh`, hosted CI,
merge or deployment. The runtime now passes `consoleui.FS()` to the console, so the
UI is embedded, has no build step and no third-party code, and is served only
when `console.enabled` is true. Makefile targets `ui-test`/`ui-dev` and a Node.js
CI step were added; the CI step has not run on hosted CI.

| Command / check | Result |
|---|---|
| `make ui-test` | **PASS**: 63 tests, 0 failures (DOM safety, routing, API client, stream, charts, components, mock server, site checks). |
| `go test -race -count=1 ./internal/consoleui ./internal/console/... ./internal/runtime ./internal/cli` | **PASS**: all eight packages, including the new `TestConsoleServesEmbeddedUI` (real runtime on loopback: `/` is 200 `text/html` with the exact CSP and `no-store`, the entry script is served as JavaScript, unauthenticated `/api/v1/overview` is 401). |
| `make lint` | **PASS**: gofmt clean, `go vet ./...`; `golangci-lint` not installed, skipped by the Makefile. |
| `make supply-chain-check` and `./scripts/check-supply-chain_test.sh` | **PASS**: no new action was added; the CI step uses the runner's Node.js. |
| `make license-check secrets-scan` | **PASS**: 14 modules within policy; no secrets found. |
| `git diff --check` | **PASS** after stripping trailing whitespace from the staged UI scripts. |
| Full `make test`, fuzzing, `make vuln` | **NOT RUN** in this change; covered by hosted CI on PR #75. |
| Hosted CI for the new Node.js step | **NOT RUN** when this entry was written; later **PASS** on PR #75 (see the stack status entry). |

**Manual browser evidence (recorded separately from the implementer's checks).** Run in
a browser against the real server started by `aegismesh demo --console`: login,
overview, events, recommendations, node, audit trail, and creating an
investigation (cookie session plus CSRF) all worked, with no CSP violations. The
mock-based walk-through of all 13 screens in both themes and at 375px is recorded
in `docs/design-system.md`.

## 2026-11-15 — console backend review fixes (merged as #74)

Worktree `feat/console-api`, continuing local draft `4976522` without committing,
pushing, switching branches, or running `gh`. macOS arm64 / Go 1.27.4. Verification
suites ran sequentially with `GOFLAGS=-p=1 GOMAXPROCS=2` to constrain build and
fuzz concurrency. No dependencies or module files changed.

Resource handlers and HTTP tests are separated by responsibility; console state,
authentication, and listener lifetime retain one owner. Construction helpers use
one deferred error cleanup. The new packages document their trust boundaries and
exported API. Multi-field literals, local names, and logical steps are expanded
for review. The sole Go line over 140 characters is the fixed CSP string constant.

Summaries now project stored HTTP, MCP, SSH, TCP, and correlation fields with a
160-character cap and control-character sanitization. Fuzzing exercises each
sensor kind. Cross-endpoint cursors are rejected even with matching filters.
Literal/encoded traversal returns 404 before ServeMux can normalize a path.
Investigation startup rejects JSON null and reports the state filename plus
inspection/recovery guidance for corrupt snapshots.

The HTTP authorization matrix derives from all 23 route registrations and has
161 exact-status cases: no credentials, malformed Authorization, wrong token,
expired session, viewer, analyst, admin. Missing success fixtures fail the test
when a route is added. Expected roles are declared independently in the fixtures,
so a changed authorization policy also fails the matrix. Loopback tests cover
CSRF/Origin, bearer mutations,
Host/port/localhost/IPv6 authority, exact 64 KiB and 64 KiB+1 bodies, strict JSON,
bodyless routes, cursor tampering/truncation/scope, static files and headers,
login throttling/Retry-After, session rotation/logout/TTL/eviction, SSE capacity
and shutdown, investigation field limits and quota status mapping, and TLS login
and logout Secure cookies. TTL tests use an injected atomic clock, without sleeps.

Auth tests fill the 4096-remote throttle registry directly and prove reclamation
at its clock boundary. Store tests cover every investigation field/count limit,
32 MiB encoded-state refusal without mutation, successful restart, failed atomic
replacement preserving the prior snapshot, and corrupt/stale state failing closed.
Audit tests modify, remove an interior record, and reorder records, each reporting
`first_invalid_seq: 2`; rotation/restart keeps the verified chain continuous.
These file/state tests exercise the owning packages directly; HTTP policy and
quota mapping tests use real loopback listeners and the actual runtime snapshot
provider. Runtime tests retain sensor → storage → index → API/SSE, backfill,
encrypted live-only indexing, correlation provenance, and shutdown wiring.

The user reported the integrated embedded UI browser flow accepted during review;
that browser run was not repeated here. The one-off smoke script and transcript
were deleted; the historical manual receipt remains a short entry below. CLI help
now describes available UI assets without assuming whether this build embeds them.

| Command / check | Result and captured output |
|---|---|
| `make lint test` | **PASS**, exit 0: gofmt clean; `go vet ./...`; `go test -race ./...` passed across all 36 tested packages. Optional `golangci-lint` is absent; Make printed `golangci-lint not installed; skipped (vet+fmt ran)`. |
| `go test -race -count=1 ./internal/console/... ./internal/evidenceindex ./internal/runtime ./internal/cli ./internal/config` | **PASS**, exit 0, all nine packages: console 7.708 s; audit 1.551 s; auth 1.474 s; investigations 6.491 s; stateio 1.383 s; evidenceindex 6.045 s; runtime 14.408 s; CLI 3.637 s; config 1.651 s. |
| `make fuzz-seed` | **PASS**, exit 0: all eleven bounded real fuzz targets emitted `PASS`; `FuzzObservationProjection` executed 555260 cases in 15 s, and `FuzzCursorFilter` passed. Two fuzz workers, sequential targets. |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0 printed `No vulnerabilities found.` |
| `git diff --check` | **PASS**, exit 0, no output; supplemental untracked-file whitespace scan found 0 issues. |
| `awk 'length($0) > 140'` over all 48 new Go files, including draft files and untracked additions | **PASS**, 1 line: `internal/console/server.go:24`, the 189-character fixed CSP string. All other lines are at most 140 characters. |
| Exported Go documentation audit | **PASS**, 0 missing declaration, field, or interface-method comments in the new production Go files. |

## 2026-11-14 — first operator console backend candidate (merged as #74)

Worktree `feat/console-api`, base `e82df977c4119629b3bd87b8496428615ff1b865`,
macOS arm64 / Go **1.27.4**. All changes were uncommitted when this entry was written, including the supplied
console contract; they are now committed in PR #74 (open, unmerged). No commit,
push, branch switch, `gh`, hosted CI, merge, publication or deployment occurred
during the recorded checks. UI embedding and browser QA were **NOT RUN** in this
entry (later done in PR #75); at this point the runtime passed a nil UI and `/`
served a notice.

**Architecture.** `runtime.indexedSink` serializes successful storage append →
`evidenceindex.Index` for both bus observations and direct correlation signals.
The existing observer/webhook fan-out receives no new signal path. The index
owns envelope copies, bounded defensive summaries, signed pagination, aggregates,
provenance lookup and non-blocking bounded SSE subscriptions. `console.Server`
receives runtime node/sensor snapshots through a read-only interface; auth,
audit, investigations and private rooted state I/O are separate packages.
`storage.SnapshotMetadata` bounds node directory reads without reading payloads.
All new implementation dependencies are standard library; module files unchanged.

**Contract safety clarifications.** The contract now records the additional
64 MiB accounted-envelope budget, latest-4096 recommendation input, 65536-entry
node metadata bound (503 beyond), 1000 investigations / 100 notes per case /
32 MiB encoded state, 4 MiB audit rotation / 128-file quota, bearer session empty
CSRF/zero expiry, strict bodyless routes, and separate investigation/audit
transactions. Encrypted evidence is live-only with `history: "unavailable"`;
no evidence read identity enters the runtime. Audit and notes remain plaintext.
The audit chain proves internal consistency, not writer identity or external
anchoring. A successful investigation snapshot can precede a failed final audit
append; the API explicitly reports that state may already be saved.

**Behavioral evidence.** Real loopback HTTP tests cover 21 authenticated routes ×
six states (anonymous, invalid token, a genuinely expired 60-second cookie, viewer,
analyst, admin), public meta/session behavior, cookie/CSRF/Origin/Host checks,
strict/oversized bodies and queries, cursor tampering, a real sensor event through
storage/index/API/SSE, actual correlation-engine signals with three provenance
links, plaintext backfill, encrypted live-only indexing, failed-store exclusion,
TLS Secure cookies, session rotation/revocation, login rate/audit records,
investigation persistence and limits, and chain verification. Sixteen real SSE
streams are accepted, the seventeenth is 503, and shutdown closes the sixteen.
Static tests inject an FS through a real server and verify CSP, types, caching,
index-only-root behavior and traversal/listing refusal. Bounded metadata is
compared with real segment files and rejects excessive entry counts.

**Fixed regression.** `go test ./internal/console/audit -run
'^TestIncompleteJSONLRecordRejected$' -count=1` first reproduced **FAIL**, exit 1:
"unterminated JSONL record accepted; a later append would concatenate two records".
The scanner now rejects a missing final newline before accepting or extending a
chain. The regression and full audit race suite subsequently passed. No repair,
truncation or deletion of existing audit data is performed.

| Command | Final result and captured output |
|---|---|
| `make lint test` | **PASS**, exit 0: gofmt clean, `go vet ./...`, complete `go test -race ./...`; runtime `ok` (78.382 s), audit `ok` (1.969 s). |
| `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/console/... ./internal/evidenceindex ./internal/storage` | **PASS**, exit 0, all seven packages; console 7.920 s, audit 1.929 s, auth 1.672 s, investigations 3.061 s, stateio 3.395 s, evidenceindex 11.765 s, storage 5.377 s. |
| `make fuzz-seed` | **PASS**, exit 0, eleven bounded real fuzz targets; each emitted `PASS`, including `FuzzObservationProjection` and `FuzzCursorFilter`. Makefile and CI lists both include them. |
| `make vuln` | **PASS**, exit 0, pinned govulncheck v1.7.0: `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0: `14 module(s) within policy`; `secrets-scan: ok`. The script scans tracked files; supplemental scan below covers untracked additions. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `make build` | **PASS**, exit 0; built `bin/aegismesh` with the project toolchain and metadata. |
| `GOTOOLCHAIN=go1.27.4 go test -race ./internal/console/audit -count=1` | **PASS**, exit 0 (1.607 s), including the reproduced/fixed incomplete-JSONL regression. |
| `git diff --check` | **PASS**, exit 0, no output. |
| Optional `golangci-lint` | **BLOCKED**, not installed; the Make target explicitly reported its skip. Gofmt/vet and the race suite did run and pass. |

Complete successful command output and the built binary checksum are preserved in
[console-verification.log](console-verification.log). Supplemental fixed-pattern secret scan: 33 untracked files, 0 findings. Untracked whitespace scan: 0 findings.


Historical manual run (2026-11-14): the built binary was exercised with curl
through login, reads, operator mutations, audit, and live SSE; both processes
exited on SIGINT. The one-off script and transcript were removed during review;
the Go integration tests are the maintained reproduction path.

## 2026-11-14 — steady-traffic encryption segment review (merged as #73)

Candidate was uncommitted when written (now committed in PR #73), on `feat/evidence-at-rest-encryption`, based on
`c64b58f29373ac475ec6a44ce692722062c5dfba`, macOS arm64 / Go **1.27.4**.
This entry supersedes the unconditional flush/seal policy in the earlier recovery
receipt below. No commit, push, branch switch, `gh`, staging, hosted CI, merge,
publication or deployment was performed.

**Changed behavior.** Ordinary flushes publish buffered ciphertext to the OS and
keep the segment open. The fixed `maxEncryptedSegmentAge = 5 * time.Minute`
starts at the first successful event append; only size rotation, close or a flush
at that age seals. Empty segments never age out, repeated aged flushes leave the
sealed bytes unchanged, and a successor opens only on the next accepted append.
Five minutes balances near-live read delay with at most 288 age-driven seals/day
under steady traffic instead of 17,280. Size rotation and restarts add files.
This preserves the existing non-`fsync` flush contract; power-loss durability is
not claimed. No runtime timer or configuration field changed.

**Regression evidence.** Injected-clock tests cover 60 interleaved appends/flushes
inside the age window with exactly one segment, observable ciphertext bytes after
each flush, active-reader/count "not sealed" errors, an exact-boundary seal that
verifies every event and footer, repeated seals producing no additional bytes or
files, successor age reset, empty idle flushes across 100 minutes, first append
after idle, and byte-for-byte plaintext output across age bounds. Existing
size-rotation, active-retention, restart, corruption/truncation and concurrent
append/flush/retention tests remain in the race suite. Runtime wiring now proves
that flush leaves evidence unsealed and close makes it readable.

**Related resource review.** An unfit encrypted frame could previously rotate a
populated/sealed segment before rejection. Such frames now fail the fresh-segment
header/frame/footer fit check before any seal/rotation; a regression checks ten
rejections both before and after an age seal without creating a successor or
changing the original event count. Append/flush do no directory listing or
retention scan. The writer holds one segment descriptor and closes it before
opening the successor. Encryption is in memory; identity loading is bounded to
eight files and closes each read. Read/count/alias checks open segments one at a
time. CLI export creates one staged file per explicit export, removes it on error,
and syncs once per export, not once per event. There is no per-event `fsync`.

Retention still lists/sorts all segments and scans their frames every ten minutes;
it holds the store mutex, so a large pass can delay writes/flushes. Size rotation
is proportional to accepted bytes, retention can overshoot between passes, and a
damaged closed segment blocks count retention. These are documented limits, not
a hard disk quota or an absolute daily file cap. Under the earlier v2-only implementation (superseded by the 2026-11-15
v3 amendment below), active evidence was unreadable until sealed, normally within five minutes of the first event plus the next
five-second flush (longer if maintenance stalls). Full-directory inspection can
still fail on a new active successor: stop the runtime or inspect a separate
sealed-only snapshot. Documentation, configuration reference, ADR-0016, threat
model, CLI/data-flow guidance, roadmap and handoff now describe these boundaries.

| Command | Result and captured output |
|---|---|
| `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/storage ./internal/runtime` | **PASS**, exit 0 after all code/test edits: storage `ok` (4.431 s), runtime `ok` (15.679 s). |
| `make lint test` | **PASS**, exit 0 after all code/test edits: gofmt check, `go vet ./...`, `go test -race ./...`; all packages passed. Storage `ok` (4.692 s), runtime `ok` (15.999 s). Make reported `golangci-lint not installed; skipped (vet+fmt ran)`; no separate lint execution is claimed. |
| `make fuzz-seed` | **PASS**, exit 0: all nine 15-second targets passed. `FuzzEncryptedFrameStructure`: 479969 executions, 20 new interesting inputs, no failure (`ok`, 16.372 s). |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0, `No vulnerabilities found.` |
| `git diff --check` | **PASS**, exit 0 after the final documentation/ledger update; no whitespace errors. |

## 2026-11-14 — evidence-at-rest encryption recovery and review (merged as #73)

Candidate: `feat/evidence-at-rest-encryption` (uncommitted when written; now PR #73) on
`c64b58f29373ac475ec6a44ce692722062c5dfba` (reviewed but unmerged toolchain
upgrade). Host: macOS arm64, Go **1.27.4**. No commit, push, reset, branch
checkout, `gh`, hosted workflow, publication or deployment was performed.
The index is unchanged. PR number at the time: pending; now #73 (open, unmerged). PR #58 is closed/unmerged and
its patch is draft provenance, not review or exact-head CI evidence.

### Recovery and defects corrected

Fifteen `git show origin/codex/evidence-at-rest-age-v2:.codex/encryption-v2.partNN`
reads were concatenated outside the repository in `$TMPDIR`. Verified SHA-256:
`4fc51a53fe6e7aa89c3e9d7925d0afdff6fd84f47786861d5474093c753c26c7`.
Split sizes/digests also matched the source workflow:

| Patch | Bytes | SHA-256 |
|---|---:|---|
| `01-runtime.patch` | 56285 | `658a31a84f272994045376572b085f8e4de72e015572d758a3294f3093d5e992` |
| `02-tests.patch` | 49399 | `9455112109ecf3c3b9dd183e629ff91067edde2a8e8e3be79031f15b1d33f7be` |
| `03-docs.patch` | 42380 | `f6cfbc5933271b5e71707678c6f17da44d833b774b8486b8ef9b5d00f802de94` |

The runtime and tests applied without three-way conflicts. Module files were
resolved by retaining the current toolchain/x/* versions and acquiring age
v1.3.2. The docs patch conflicted in license-policy/verification; those files
were reconciled manually without importing historical PASS claims. Neither
`.codex` chunks nor the reconstruction workflow was added.

- **FAIL reproduced, then fixed:**
  `go test ./internal/storage -run TestEncryptedFrameBoundaryTruncationFailsClosed -count=1`
  exited 1 on the recovered implementation: it accepted truncation at byte 23
  (header only) and byte 605 (complete event boundary). Independent event
  ciphertexts did not establish segment completion. The v2 format adds an
  age-authenticated footer binding count and ordered framed-ciphertext digest.
  Initially flush/rotation/close sealed the segment; the steady-traffic review
  above supersedes the unconditional flush policy.
- Exact-match `inspect show` stopped early, bypassing later encrypted failures;
  it now consumes all input before emitting output. Authenticated but empty or
  malformed event JSON was silently skipped; encrypted records now fail closed.
- Identity diagnostics could echo an inline private value used as a filename
  or rejected flag value. Diagnostics now suppress identity values, and the
  loader rejects inline identities. The byte limit is enforced on actual file
  reads as well as metadata, covering concurrent growth and comment suffixes.
- Dedicated encryption configuration matrices were absent. Added YAML/JSON
  field/default/invalid/unknown/inline-identity cases and identity-flag matrices
  across all four read commands (including repetition and positional input), plus mixed ordering,
  counting, age/count retention, active-segment protection, concurrency,
  interrupted restart and real buffered-file failure regressions.
- The draft did not complete resolved-graph license review. All fourteen
  modules were reviewed; the scanner now uses Go-resolved module directories
  (including uppercase escaping), with a checksum-pinned README grant for the
  upstream CCTV test-only module's selected 0BSD option. No CC0/Unlicense grant
  is selected. See `license-policy.md` for versions, justification and hashes.
- Diff-scoped deslop review removed a redundant plaintext byte copy, obsolete
  early-stop handling and an unbounded guard-creation retry. It preserved
  trust-boundary validation and the existing plaintext representation.

### Commands executed on this candidate

| Command | Result and captured output |
|---|---|
| `go test ./internal/event ./internal/storage ./internal/config ./internal/cli ./internal/runtime ./internal/agekey -count=1` | **PASS**, exit 0; all six packages `ok`. Additional matrix/mixed-retention tests added later are included in the final race runs below. |
| `go test -race ./internal/storage ./internal/config ./internal/cli ./internal/runtime ./internal/agekey -count=1` | **PASS**, exit 0 on final runtime/test code; all five packages `ok` (output below). Includes concurrent encrypted append/flush/retention. |
| `make lint test` | **PASS**, exit 0, repeated after final code/test changes: formatting, `go vet ./...`, `go test -race ./...`; 30 test packages `ok`. `golangci-lint` is not installed; Make explicitly reported `skipped (vet+fmt ran)`. No unavailable tool was relabeled as run. |
| `make fuzz-seed` | **PASS**, exit 0, nine targets at 15 s each (158.97 s total). New `FuzzEncryptedFrameStructure` exercises framing/counting and age decryption with a valid sealed seed; 736929 executions, 220 new interesting inputs, no failure. Target is listed in both CI and Makefile. |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0, `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0: `license-check: ok — 14 module(s) within policy`; `secrets-scan: ok`. New untracked files were also checked separately for secret-shaped values; all identities in tests are generated, not literals. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `make sbom sbom-check` in the linked worktree | **BLOCKED by tool/layout**, make exit 2: pinned generator returned `failed to determine version of main module: git: reference not found`. The second target is not reached by this failed invocation. This reproduces the base branch's known limitation, not a successful local generation. |
| `make sbom sbom-check` in an identical-source ordinary temporary clone | **PASS**, exit 0: `sbom.sh: wrote dist/sbom-aegismesh.cdx.json (darwin/arm64, cgo=1)`; `SBOM valid`. An initial shared-object clone attempt exited 2 (`git: object not found`); materializing its objects with `git -C "$SNAPSHOT" repack -a` resolved that temporary-clone limitation. Original worktree Git metadata was untouched. |
| Repeat ordinary-clone `make sbom sbom-check` plus SHA-256 comparison | **PASS**, exit 0, identical JSON SHA-256 `20be56525e9fcc61fea0ddbf860f4e7d96cc63c0eb95df62604dfee593b907da`. Generator warned `no licenses detected module=std@go1.27.4`; heuristic license evidence remains distinct from the explicit dependency review. |
| `make sbom-check` in the worktree against the copied snapshot artifact | **PASS**, exit 0: `SBOM valid`. The artifact stays ignored under `dist/`; this does not relabel direct worktree generation as PASS. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `git diff --check` | **PASS**, exit 0, no output (repeated after documentation). |
| `make build` | **PASS**, exit 0; native binary built with existing Makefile version flags. |
| `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$TMPDIR/.../aegismesh-linux-arm64" ./cmd/aegismesh` | **PASS**, exit 0. |
| `CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "$TMPDIR/.../aegismesh-darwin-arm64" ./cmd/aegismesh` | **PASS**, exit 0. |
| `sh -n scripts/license-check.sh`; `./scripts/check-supply-chain_test.sh` | **PASS**, exits 0; `check-supply-chain_test: ok`. |
| Human review, exact-head hosted CI and merge | **NOT RUN** when written; hosted CI later **PASS** on the PR #73 head, human review and merge pending. |
| Explicit `make helm-contract` | **NOT RUN** in this encryption slice; chart behavior did not change. The normal guarded package tests ran under `make test`; they are not a live Helm receipt. |

Final focused race stdout:

```text
ok  	github.com/metaforismo/aegismesh/internal/storage	2.868s
ok  	github.com/metaforismo/aegismesh/internal/config	2.742s
ok  	github.com/metaforismo/aegismesh/internal/cli	5.396s
ok  	github.com/metaforismo/aegismesh/internal/runtime	15.332s
ok  	github.com/metaforismo/aegismesh/internal/agekey	2.123s
```

The SBOM fallback was created by a local shared/no-hardlink clone, then a
SHA-256-verified overlay of 232 tracked/untracked working-source files, then
materialization of Git objects in that temporary clone. Runtime, module and
check source matches the final worktree code; documentation receipts were
updated afterwards. No commit or fabricated version/tag was created. It uses
the unchanged pinned generator and validator. The application SBOM contains
age v1.3.2, hpke v0.4.0, x/crypto v0.59.0, yaml v3.0.1 and std go1.27.4.
Graph-only upstream test dependencies are separately covered by license review.

### Acceptance evidence map

| Contract | Behavioral evidence |
|---|---|
| Disabled filenames and bytes unchanged | `TestEncryptionDisabledPreservesPlaintextRecord` compares encoded bytes/newline and suffix; existing storage/CLI tests pass. |
| Recipient validation before readiness | `TestStorageEncryptionConfigMatrix` (YAML and JSON), `TestParseRecipient`, `TestBuildRejectsInvalidEncryptionBeforeCreatingDataDir`. |
| Read-only bounded identities, no inline secrets or diagnostic disclosure | `TestLoadIdentityFile`, FIFO rejection, config unknown-identity fields, duplicate/alias CLI tests, `TestIdentityArgumentsNeverEchoInlinePrivateKey`. File-only references are deliberately supported; no identity env-value or inline config surface exists. |
| Missing/wrong identities, corruption/truncation fail closed | Recovered storage/CLI matrices, new frame-boundary/footer/order tests and `TestEncryptedShowValidatesPastExactMatch`; failed exports leave targets untouched. |
| Restart, rotation and partial failures never downgrade | `TestEncryptedRestartCreatesIndependentSegments`, key-rotation tests, `TestEncryptedFlushSealsAndNextAppendRotates`, `TestEncryptedRestartAfterInterruptedWriteAndWriteFailure`, persistent guard/history checks. |
| Mixed history, retention, ordering and protected active segment | `TestMixedHistoryOrderingCountingAndRetention` checks unchanged plaintext, exact 2/2/1 counts, sorted output, count deletion, age deletion and old encrypted active preservation; concurrent append/flush/retention regression. |
| Bounded records/frames and concurrency | Exact stored-envelope boundary tests, length-prefix rejection, fuzz target and final affected/full race runs. |
| No added external destination, key service, captured-data path or exec | Source/diff review of agekey/config/runtime/storage/CLI wiring: only explicit operator data/identity/output paths and native X25519 library constructors. Manual traffic is loopback only. |

### Manual built-binary transcript summary

**PASS**, repeated after the final runtime edits. A private temporary workspace
was created; a small Go helper using age v1.3.2 generated two X25519 identities
into owner-only files without printing private values. Only the public recipient
entered `mesh.json`. A native built binary ran one HTTP sensor on an unprivileged
loopback port; two synthetic requests returned HTTP 200. SIGINT exited 0.

```text
aegismesh run --config TEMP/mesh.json
GET http://127.0.0.1:PORT/encryption-manual-marker-1 -> 200
GET http://127.0.0.1:PORT/encryption-manual-marker-2 -> 200
SIGINT -> exit 0; one .jsonl.age segment; zero .jsonl segments
inspect list --identity TEMP/identity.txt --verify --json -> exit 0, 2 events, both integrity_ok=true
inspect list [no identity] -> exit 1, empty stdout, requires at least one identity file
inspect list --identity TEMP/wrong.txt -> exit 1, empty stdout, did not match any supplied identity
inspect show --id EVENT --identity TEMP/identity.txt -> exit 0, verified=true
recommend --identity TEMP/identity.txt -> exit 0, dry-run report (0 recommendations)
inspect export [missing/wrong identity] -> exit 1, empty stdout, existing output unchanged
inspect export --identity TEMP/identity.txt -> exit 0, 2 events exported
run --config TEMP/mesh.json --dry-run [encryption enabled] -> exit 0; new encrypted segment
inspect list --identity TEMP/identity.txt --json -> exit 0, still 2 events
run --config TEMP/mesh.json --dry-run [encryption removed] -> exit 1, refusing plaintext writes
```

Every segment was checked for absent marker and envelope-schema plaintext bytes;
no plaintext `.jsonl` segment existed before or after restart/downgrade attempts.
Logs/transcript were checked against both generated private values. Temporary
private identity files were removed after the run. Exported synthetic NDJSON is
explicit plaintext outside the data directory.

### Remaining limits

Encryption protects contents on storage media, not a compromised runtime host or
stolen identity. Names, sizes, timing, logs and exports remain visible. Existing
plaintext is not migrated; lost keys cannot be recovered. The directory is for
one runtime writer; there is no cross-process lock. Readers require a completed
footer; live unfinished writes and crash-unsealed segments fail closed. There
is no automatic salvage or whole-file deletion/replacement detection, and anyone
holding the public recipient can create new ciphertext: this is confidentiality
and consistency, not writer provenance. Count retention validates framing without
private keys; it cannot authenticate ciphertext. The low-level reader may invoke
callbacks before a later failure; CLI outputs remain buffered/staged until the
complete read succeeds. Direct linked-worktree SBOM generation, human review and
exact-head CI/merge remain open as stated above.

## 2026-11-14 — whole-repository Go security refresh (merged as #72)

Baseline: clean `security/go-toolchain-vuln-fixes` at `01579d3`. Local host:
macOS arm64. Selected Go **1.27.4**, `golang.org/x/crypto` **v0.59.0** and
`golang.org/x/sys` **v0.50.0**. The public Go proxy returned these latest
module releases; x/crypto selects x/net v0.62.0, x/term v0.48.0 and x/text
v0.44.0. Both upgraded modules retain BSD-3-Clause licenses. No runtime
module was added. The SSH advisories
[GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) were fixed in v0.56.0.
[Go release history](https://go.dev/doc/devel/release#go1.27.4) identifies
the selected security patch. No fallback to Go 1.26 was made.

Make and the standalone SBOM script derive their exact toolchain from the
module's `go` directive. Formatting uses that toolchain's gofmt. Every CI and
release `setup-go` step already uses `go-version-file: go.mod`; those workflows
need no duplicate version edit. Extension fixture modules use the same version.
Govulncheck v1.7.0 and CycloneDX GoMod v1.10.0 remain pinned.

| Command / check | Result and captured output |
|---|---|
| Baseline `make vuln` before edits | **FAIL**, make exit 2 (scanner exit 3): `Your code is affected by 14 vulnerabilities from 1 module and the Go standard library.` Also reported 1 imported-package and 3 module-only findings. |
| Docker Hub registry index resolution | **PASS**: authenticated GET of `https://registry-1.docker.io/v2/library/golang/manifests/1.27.4-alpine` returned an OCI multi-platform index; `Docker-Content-Digest` matched SHA-256 of the response bytes: `sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf`. Index includes Linux amd64 and arm64. |
| `GOTOOLCHAIN=go1.27.4 go version` | **PASS**, exit 0: `go version go1.27.4 darwin/arm64`. |
| `GOTOOLCHAIN=go1.27.4 go get golang.org/x/crypto@v0.59.0 golang.org/x/sys@v0.50.0` | **PASS**, exit 0: upgraded x/crypto v0.55.0 to v0.59.0 and x/sys v0.47.0 to v0.50.0. |
| `go mod tidy` | **PASS**, exit 0; module graph and checksums refreshed under Go 1.27.4. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `make lint test` | **PASS**, exit 0: gofmt, `go vet ./...` and `go test -race ./...` across all packages; `golangci-lint` is not installed locally (documented fallback). One earlier run under heavy concurrent host load failed `TestHostHandshakeFailures/echoes_wrong_frame_type` on its fixed 2 s handshake timeout; the test passed 6/6 in isolation (`-race -count=6`) and in the clean full rerun. Recorded as a pre-existing load-sensitive test, not changed here. |
| `make vuln` | **PASS**, exit 0: `No vulnerabilities found.` (govulncheck v1.7.0 under Go 1.27.4). |
| `make fuzz-seed` | **PASS**, exit 0: all eight bounded targets. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `./scripts/check-supply-chain_test.sh` | **PASS**, exit 0. Checker and fixtures needed no version-specific change. |
| `make license-check secrets-scan` | **PASS**, exit 0: `license-check: ok — 7 module(s) within policy` / `secrets-scan: ok`. |
| `make helm-contract` | **PASS**, exit 0 with Helm `v4.2.2`. |
| `make sbom sbom-check` | **BLOCKED** locally: the pinned CycloneDX generator fails with `failed to determine version of main module: git: reference not found` inside a linked `git worktree`, which is where this change was prepared. Hosted CI on the pull-request head is the acceptance evidence for this gate. |
| `sh -n scripts/sbom.sh` / `git diff --check` | **PASS**, exit 0. |

An earlier attempt in the same session was interrupted by a full disk; every
gate above was rerun afterwards. No tests or gates were weakened. Historical
ledgers were left intact. No tag, release publication, container
build/publication or deployment was performed.

## 2026-08-31 — storage `max_event_bytes` enforcement

| Check | Command / evidence | Status |
|---|---|---|
| Isolated source and toolchain | exact `master` source snapshot with temporary branch-only workflow removed; `/mnt/data/aegismesh-workspace/toolchain/x64/bin/go version` | PASS — source matches public `52b6ead` outside the removed temporary workflow; Go `1.25.14 linux/amd64` |
| Red implementation audit | compare config default/validation, `runtime.Build` and `storage.Options` | FAIL before fix — `storage.max_event_bytes` was never passed to or enforced by the store |
| Focused storage regressions | `go test ./internal/storage -run 'Test(MaxEventBytes|OversizeEventRejected|AppendAndReadBack)' -count=1 -v` | PASS |
| Runtime wiring regression | `go test ./internal/runtime -run TestBuildWiresStorageMaxEventBytes -count=1 -v` | PASS |
| Affected race suite | `go test -race -count=1 ./internal/storage ./internal/runtime` | PASS |
| Repository-wide local gate | two `make lint test` attempts, the second with a warm cache | BLOCKED — `go vet ./...` passed and the race run completed through 23 packages before this execution wrapper terminated the still-running aggregate command; affected packages and additional sensor packages passed separately, and exact-head PR CI remains the authoritative aggregate gate |
| Dependency and egress change | `git diff -- go.mod go.sum`; runtime destination review | PASS — no dependency, secret, provider, webhook, extension or destination changed |
| Module, supply-chain, license and secret checks | `go mod verify`; `make supply-chain-check`; offline cached `make license-check`; `make secrets-scan` | PASS — seven resolved modules remained within policy; no module graph changed |
| Helm contract locally | `make helm-contract` | BLOCKED — no Helm binary is installed in this environment; the unchanged chart remains covered by required PR CI |
| Release and repository administration | publication, tag, signing, settings and cluster actions | NOT RUN |

## 2026-08-31 — repository ground truth and PR #54 truth-sync

| Check | Command / evidence | Status |
|---|---|---|
| Requested local checkout | `test -d /Users/francescogiannicola/Documents/ChatGPT/AegisMesh`; search mounted work areas | BLOCKED — the macOS path is not mounted in this Linux execution environment and no alternate AegisMesh checkout was present |
| Local toolchain | `go version` | BLOCKED for repository gates — available Go is `go1.23.2 linux/amd64`, below the module requirement `go 1.25.14`; no source checkout is available to test |
| Public repository identity | GitHub repository metadata and branch/commit queries | PASS — `metaforismo/AegisMesh`, default branch `master`, baseline `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4` |
| Process-isolation merge | PR #54 metadata | PASS — PR #54 is merged; head `6ded0223235fbb383f65accf762aa67fe481e316`, merge commit `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4` |
| PR #54 hosted CI | workflow run `32717789361` | PASS — `fmt, vet, build, test (-race)` including Linux/Darwin cross-build; eight bounded fuzz targets; Helm contract; pinned `govulncheck`; dependency-license and secret checks; deterministic CycloneDX generation and validation all concluded `success` |
| Exa connector probe | one `web_search_exa` call and one `web_fetch_exa` call | PASS — both connector functions returned results; historical blocked entries remain archived as historical environment facts |
| Public maintenance queue | GitHub open PR and issue queries | PASS — no open issues; open Dependabot PRs #48 and #49 require policy-aware review |
| Local `make lint test` | unavailable checkout and insufficient local Go version | BLOCKED — not run in this environment; PR #54 hosted CI remains independent evidence for its exact head only |
| Documentation-only dependency/egress review | compare proposed truth-sync paths with runtime/module files | PASS — no `go.mod`, `go.sum`, runtime destination, provider, webhook or extension behavior changes in this block |
| Release, tag, signing, image and cluster actions | external-state review | NOT RUN — no release publication, tag, signature, attestation execution, image publication, repository-setting change or Kubernetes deployment was performed |

## Required evidence for the next implementation slice

Slice 6 (evidence encryption) merged as #73 and #77; this list is kept as the
record of the criteria that were applied.

Optional evidence-at-rest encryption is not complete until the exact PR head has:

- focused config, storage, reader and CLI tests;
- wrong-key, corruption, truncation, restart, rotation, retention and recovery
  integration cases;
- affected-package `go test -race`;
- `make lint test` and applicable bounded fuzzing;
- `go mod verify`, dependency-license, secret, vulnerability and deterministic
  CycloneDX checks;
- documentation, ADR, threat-model, backlog and handoff truth-sync;
- all required hosted jobs green before merge.

Release publication and real-cluster operation remain separate `NOT RUN` actions
unless explicitly authorized at action time.

## 2026-11-15 — v3 encrypted checkpoint/live-read amendment (local, uncommitted) (merged as #77)

**Scope and baseline.** `feat/encrypted-live-read` started clean at local master
`484bd65`; local ancestry includes merges #72-#76. New encrypted writes are v3;
plaintext and sealed v2 remain readable, while unfinished v2 fails closed with
v3 guidance. No commit, push, branch switch, `gh`, hosted-CI query, merge,
release or deployment was performed. `go.mod`/`go.sum` and dependencies are
unchanged. The Makefile selected Go 1.27.4 from `go.mod`; direct Go commands
used `GOTOOLCHAIN=go$(awk '/^go / {print $2; exit}' go.mod)`. Suites ran one after
another, with `-p 1` for the focused race command. Available disk remained about
8.4–8.5 GiB during verification. No transcript or helper script was added to the repo;
only this summary and the intentional CLI golden fixture are retained here.

| Command / proof | Result and captured output summary |
| --- | --- |
| `make lint test` (final code) | **PASS**, exit 0. `go vet ./...`, fmt check and `go test -race ./...`; 41 package results `ok`. `golangci-lint not installed; skipped (vet+fmt ran)`; optional golangci analysis **NOT RUN**. |
| `go test -race -count=1 -p 1 ./internal/storage ./internal/cli ./internal/runtime ./internal/recommend` | **PASS**, exit 0. Final uncached output: storage `8.768s`, cli `3.509s`, runtime `14.001s`, recommend `1.282s`; no race reports. |
| `make fuzz-seed` | **PASS**, exit 0. All 12 bounded 15-second targets passed. V2/v3 `FuzzEncryptedFrameStructure`: 2,224,879 executions, 15 new interesting inputs, no failures. The target remains in Makefile and CI lists. |
| `make vuln` | **PASS**, exit 0. Pinned govulncheck v1.7.0: `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0. `license-check: ok — 14 module(s) within policy`; `secrets-scan: ok` (the existing scanner covers tracked files). New source/golden files contain synthetic fixtures and generated identities only, no retained private values. |
| `make build` | **PASS**, exit 0. Built `bin/aegismesh`, version `484bd65-dirty`, commit `484bd65`, build timestamp `2026-11-15T21:12:12Z`. |
| Built-binary live/graceful/crash/restart proof below | **PASS**, exit 0 from the temporary driver. Real runtime, native generated identity and HTTP listener on an ephemeral unprivileged loopback port; no provider/network egress. Temporary evidence/keys removed after the run, processes reaped. |
| `git diff --check` | **PASS**, exit 0, no output. |
| Hosted CI, publication, deployment | **NOT RUN**, outside the authorized task. Local gates are not hosted or production proof. |

**Behavioral evidence.** `TestCheckpointRecordSequences` covers sealed/open
records, complete/torn trailing frames and controls, multiple checkpoints,
count/digest/kind mismatch, corrupt frames/control records, reordering, records
after seals, duplicate seals, unsupported versions, invalid lengths, sealed v2
and unsealed v2. A literal wire vector in `TestCheckpointPlaintextWireContract`
checks the exact 42-byte format independently of writer/reader agreement.
`TestCheckpointCrashEveryByte` truncates a small segment at every
byte offset: no panic, no callback beyond the last verified checkpoint, every
incomplete accepted prefix carries typed status; complete corruption is terminal.
`TestCheckpointSnapshotChangesFailClosed` rejects a file shortened between
validation and replay and proves the captured-size boundary excludes later data.

Writer tests use the injected clock for idle/busy flushes, exact five-minute
sealing, repeated flushes after sealing and successor age reset. Space/rotation
and close tests check all files stay within `max_file_bytes`; restart tests
preserve the old bytes and read the interrupted prefix. Mixed-directory tests
cover plaintext, v2, v3, structural count retention and active-file protection.
CLI tests cover list/show/export/recommend prefixes, strict stdout/destination
protection, complete reads after close, stderr/JSON notices, interrupted doctor
warnings (retained even when the newest successor has no checkpoint), and
`checkpoint-list.golden.txt`. An intermediate added assertion failed because it
expected exit 1 from doctor's existing JSON mode. That mode actually returns
exit 0 with `overall: "fail"`; the corrected regression checks that report and
separately proves human doctor exits 1 for a blocking scan failure. This existing
contract is preserved and documented in `docs/cli.md`. Existing runtime and console tests
remain green; the console still reports encrypted history unavailable and loads
no private identity.

**Manual transcript summary.** Commands used the built binary with a temporary
config/data directory and owner-only native identity. `inspect list` used
`--json --limit 1000`; the count assertions inspected its actual event/status
objects. HTTP requests continued while the live reads ran.

1. Live `inspect list --data-dir DIR --identity KEY --json --limit 1000`:
   exit **0**, **56 events**, one open-segment notice and one `open_segments`
   entry naming `events-20261115T211242.273686000Z.jsonl.age`; verified count 56.
   Its line ended `0 trailing bytes ignored; later events may exist`.
2. While still running, the same command plus `--require-sealed`: exit **1**,
   empty stdout and the named not-sealed error.
3. Stop with SIGTERM, then strict list: exit **0**, **58 events**, no
   incompleteness field/notice. Count matched every successful synthetic request.
4. Start a second run, receive traffic through a checkpoint, then `kill -9`:
   newest segment `events-20261115T211247.478872000Z.jsonl.age` remained readable.
   List exited **0** with **114 total events** (58 sealed + **56 checkpointed**),
   reporting **8192 ignored tail bytes**. Its newest-only status was open, since
   an unsealed newest file cannot alone distinguish a live writer from a crash.
5. Restart and receive traffic through the successor's first flush: list exited
   **0**, **171 events**, and printed `WARNING: interrupted segment` for the
   unchanged second-run file, still exactly **56 verified events / 8192 ignored
   bytes**, plus a separate notice for the open newest successor.
6. Stop the successor gracefully. Strict list still exited **1** with empty
   stdout because of the interrupted predecessor. `doctor --config FILE --json`
   exited **0** with a `storage-segments` **warn** naming that interrupted file:
   `structural checkpoint only; authenticity not checked`.

**Measured overhead and deviations.** `TestCheckpointOverhead` checks **250
bytes** for both checkpoint and seal: 42 plaintext + 200 age envelope + 8 framing.
A busy five-second cadence costs about **4.12 MiB/day** in checkpoints. Idle
flushes add none. A flush seals rather than consuming reserved seal space when
a checkpoint would not fit; this preserves the configured size cap without
adding a cadence knob. The legacy storage `ForEach` API stays strict;
`ForEachVerified` returns typed notices, and CLI callers opt into that API.
Flush still means buffered publication to the OS, without `fsync` or a power-loss
promise. The read path uses bounded-memory two-pass authentication/replay rather
than buffering a segment in memory or staging additional plaintext on disk.

**Decision flaw and residual risks.** A checkpoint cannot prove later bytes
existed. Open tails can be rolled back to an earlier checkpoint. In addition,
a formerly sealed v3 file truncated to a prior checkpoint is indistinguishable
from an open file: the requested unconditional sealed-truncation guarantee is
impossible in permissive mode. `--require-sealed` detects missing completion;
trusted external monotonic completion state is not implemented. A present/required
seal still binds the full sequence, and trailing records fail closed. Whole-file
deletion/replacement and whole-segment forgery by anyone with the public recipient
remain outside the guarantee. Reads are per-file size snapshots, not an atomic
directory snapshot; callbacks are provisional until the final result. See the
ADR-0016 amendment, threat model and encryption guide for the same boundaries.


## 2026-11-22 — AI attack observation pack (uncommitted)

Branch `feat/ai-threat-detection`, base `f05f6a8`. All changes remain
**UNCOMMITTED** for owner review. No push, tag, PR, release or deployment.
Only synthetic, operator-owned loopback traffic was used. No dependency changes
(`git diff -- go.mod go.sum` is empty). Design: ADR-0021 and
[ai-threat-design.md](ai-threat-design.md); behaviour and limitations:
[ai-threat-detection.md](ai-threat-detection.md).

Implemented: randomized static AI HTTP scaffold/example; bounded fake credential
and agent markers across four sensors and process workers; six appended
observe-only findings; four appended correlations; editorial framework mappings
in text/JSON CLI and rules API; synthetic interaction and sequence corpora; and
the extended loopback demo. No deliverable was descoped.

### Final checks

The environment prefixes keep package compilation/tests sequential and limit
host CPU contention. The first full-tree race run failed in a fleet/hub transport integration test;
its result is retained below. A final gate is run only after that failure and
the newly found credential-preview edge cases have been resolved.

| Command | Result |
|---|---|
| `GOFLAGS=-p=1 GOMAXPROCS=4 make lint` | **PASS**, exit 0 on the final Go source. `go vet ./...` and gofmt passed; golangci-lint is unavailable and the Makefile's documented fallback ran. |
| `GOFLAGS=-p=1 GOMAXPROCS=2 make test` | **FAIL**, first complete attempt: fleet/hub `TestAgentQueueRecoveryOverflowAndGaps`, transport unavailable during queue recovery. All other packages passed. |
| `GOFLAGS=-p=1 GOMAXPROCS=4 make test` | **PASS**, exit 0 on final Go source; all test-bearing packages passed with the race detector (including the runtime, sensors and fleet/hub). Output below. |
| `GOMAXPROCS=4 go test -p 1 -v ./internal/ruletest -run TestSynthetic` | **PASS**, exit 0; 24 benign interactions, eight attack-shaped interactions; four benign sequences and four attack-shaped sequences. Output counts below. |
| `GOMAXPROCS=4 go build -p 1 -o /tmp/aegismesh-ai ./cmd/aegismesh` | **PASS**, exit 0 on the final source. |
| `/tmp/aegismesh-ai validate --config examples/ai-decoy.yaml` | **PASS**, exit 0, 2 HTTP sensors / 20 static rules. |
| `/tmp/aegismesh-ai rules list` and `rules list --json`, each compared with `cmp` to its checked-in golden | **PASS**, exit 0; text and JSON match their goldens. |
| `/tmp/aegismesh-ai demo --json` | **PASS**, exit 0; output below, including integrity, listener release and cleanup. |
| `/tmp/aegismesh-ai honeytoken new --kind credential --format openai --id review-key` | **PASS**, exit 0; synthetic YAML snippet printed to a private temporary file. Both kinds/all formats also have CLI tests in the full gate. |
| `make secrets-scan` | **PASS**, exit 0, `secrets-scan: ok` for tracked files. |
| `sh /tmp/aegis-ai-secrets-scan-all.sh` | **PASS**, exit 0, `secrets-scan: ok`; exact repository scanner copied to `/tmp` with only its inventory changed from `git ls-files` to `git ls-files --cached --others --exclude-standard`, so all new unstaged files were scanned too. No files were staged. |
| `git diff --check` | **PASS**, exit 0, no output. |
| `make sbom` | **NOT RUN**, explicitly skipped per task: generator cannot resolve the main module inside a linked worktree. |

Lint output:

```text
go vet ./...
golangci-lint not installed; skipped (vet+fmt ran)
```

### Synthetic corpus measurement

These are hits **on this 24-sample synthetic benign interaction corpus** and
**on this four-sequence synthetic benign correlation corpus**. They are not a
false-positive rate, prospective measurement, client attribution or framework
coverage claim. Ordinary model/version/health clients and a placeholder key
account for low findings; the cross-family ordinary client sequence accounts
for COR-006. Every medium-or-higher detection rule has zero hits on these
particular benign samples; the test fails otherwise. All six new detection
rules and all four new correlations have attack-shaped positive fixtures.

```text
PI-001: 0 hits on this 24-sample synthetic benign corpus
PI-002: 0 hits on this 24-sample synthetic benign corpus
EXF-001: 0 hits on this 24-sample synthetic benign corpus
ESC-001: 0 hits on this 24-sample synthetic benign corpus
OBS-001: 0 hits on this 24-sample synthetic benign corpus
RES-001: 0 hits on this 24-sample synthetic benign corpus
LLM-001: 7 hits on this 24-sample synthetic benign corpus
LLM-002: 0 hits on this 24-sample synthetic benign corpus
LLM-003: 0 hits on this 24-sample synthetic benign corpus
LLM-004: 1 hits on this 24-sample synthetic benign corpus
HT-001: 0 hits on this 24-sample synthetic benign corpus
AGT-001: 0 hits on this 24-sample synthetic benign corpus
COR-001: 0 hits on this 4-sequence synthetic benign corpus
COR-002: 0 hits on this 4-sequence synthetic benign corpus
COR-003: 0 hits on this 4-sequence synthetic benign corpus
COR-004: 0 hits on this 4-sequence synthetic benign corpus
COR-005: 0 hits on this 4-sequence synthetic benign corpus
COR-006: 1 hits on this 4-sequence synthetic benign corpus
COR-007: 0 hits on this 4-sequence synthetic benign corpus
COR-008: 0 hits on this 4-sequence synthetic benign corpus
```

### Development failures and corrections

Earlier focused runs were **FAIL**, then corrected: old tests expected six
active detection rules/four correlations or every rule to match plain text;
the new context-dependent registries have 12/8 entries. A test-only config
called validation before setting required legacy action defaults; one fixture
used a generic marker while expecting a provider-key class; an index test used
the wrong constructor parameter type; and the first build caught an incorrect
`RemoteAddr()` call. The first final lint found one unkeyed imported Match
literal in a new test; the keyed form passed the retry. No such failure is
silently treated as a pass.

A focused full runtime pass also failed `TestSystemEndToEndLifecycle` with
`only 0/4 events recorded`. Its existing five-second polling deadline equalled
the runtime's five-second flush interval. The test helper now permits two flush
intervals; production timing is unchanged. The subsequent focused lifecycle /
AI sensor regression command passed (runtime package `ok`, 6.621s):

```text
GOMAXPROCS=2 go test -p 1 ./internal/runtime ./internal/detect ./internal/honeytoken ./internal/redact ./internal/policy ./internal/ruletest -run 'TestAI|TestAIRules|TestRepeatedMarkers|TestSystemEndToEndLifecycle|TestStructuredInteraction|TestSynthetic' -count=1
```

Earlier targeted checks also exercised all 20 generated static profile replies
through real loopback listeners, exact rule mappings over the authenticated
rules API, maximum 64-marker findings through the recommendation reader,
redaction/index exclusion and both in-process and same-binary isolated sensor
paths. The full final race gate below covers their final source versions.

### Focused verification after the first full race failure

```text
GOMAXPROCS=4 go test -race -p 1 ./internal/redact ./internal/detect ./internal/fleet/hub -run 'TestPresentedKeyContextsRemoveWholeValues|TestProviderShapesAndMemoryOnlyAuthDigests|TestAIRules|TestAgentQueueRecoveryOverflowAndGaps' -count=2
ok  	github.com/metaforismo/aegismesh/internal/redact	1.517s
ok  	github.com/metaforismo/aegismesh/internal/detect	1.439s
ok  	github.com/metaforismo/aegismesh/internal/fleet/hub	6.991s
```

**PASS**, exit 0, including the failed fleet test twice in isolation. No fleet
transport or hub implementation/test was changed. This does not conclusively
attribute the earlier transport failure; the full retry is required evidence.
The preview review found TCP AUTH/standalone placeholders and JSON `key`
values that needed complete scrubbing. The final redactor covers these and
512-byte provider-shaped values; format recognition accepts only key ASCII
characters. Regression cases passed twice under the race detector.

### Demo output from the final binary

```json
{
  "detection_rules": [
    "LLM-001",
    "LLM-002",
    "LLM-004",
    "HT-001",
    "AGT-001"
  ],
  "schema": "aegismesh.demo/v1",
  "mode": "synthetic",
  "network": "loopback-only",
  "egress": "none",
  "sensors": [
    "http",
    "tcp",
    "mcp",
    "ssh"
  ],
  "events": 8,
  "interactions": 7,
  "canary_invocations": 1,
  "integrity_verified": true,
  "recommendations": 5,
  "dry_run": true,
  "enforcement": false,
  "signal_not_incident": true,
  "listeners_released": true,
  "cleanup_complete": true
}
```

### Review boundaries

- COR-007 compares in-memory auth digests and persists only contributing event
  IDs in signals. Stored evidence cannot reconstruct auth distinctness.
- Source IP is a grouping key, not an identity; NAT and rotation can merge or
  split observations. Cadence also matches ordinary scanners/scheduled clients.
- Shared `/v1/*` request paths default to `openai_compatible`; they do not prove
  which backend exists. No actual AI model or provider integration was used.
- Framework mappings are editorial "relates to" references. AGT-001 maps the
  defender-mirrored technique, not proven attacker use.
- Hosted CI, deployment, external-provider tests and field detection-quality
  measurement were **NOT RUN** and are not implied by local synthetic checks.

### Final full race output

```text
go test -race ./...
?   	github.com/metaforismo/aegismesh/cmd/aegismesh	[no test files]
ok  	github.com/metaforismo/aegismesh/deploy/helm/aegismesh	(cached)
?   	github.com/metaforismo/aegismesh/examples/extensions/echo-responder	[no test files]
?   	github.com/metaforismo/aegismesh/internal/admin	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/agekey	(cached)
ok  	github.com/metaforismo/aegismesh/internal/cli	5.529s
ok  	github.com/metaforismo/aegismesh/internal/config	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console	11.315s
ok  	github.com/metaforismo/aegismesh/internal/console/audit	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/auth	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/investigations	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/oidc	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/stateio	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/tenant	(cached)
ok  	github.com/metaforismo/aegismesh/internal/consoleui	(cached)
ok  	github.com/metaforismo/aegismesh/internal/correlate	(cached)
ok  	github.com/metaforismo/aegismesh/internal/demo	2.083s
ok  	github.com/metaforismo/aegismesh/internal/detect	(cached)
ok  	github.com/metaforismo/aegismesh/internal/ecsexport	(cached)
ok  	github.com/metaforismo/aegismesh/internal/egress	(cached)
ok  	github.com/metaforismo/aegismesh/internal/event	(cached)
ok  	github.com/metaforismo/aegismesh/internal/evidenceindex	(cached)
ok  	github.com/metaforismo/aegismesh/internal/ext	(cached)
ok  	github.com/metaforismo/aegismesh/internal/extmanager	(cached)
ok  	github.com/metaforismo/aegismesh/internal/fleet/agent	(cached)
ok  	github.com/metaforismo/aegismesh/internal/fleet/hub	28.192s
ok  	github.com/metaforismo/aegismesh/internal/fleet/identity	(cached)
ok  	github.com/metaforismo/aegismesh/internal/fleet/protocol	(cached)
ok  	github.com/metaforismo/aegismesh/internal/honeytoken	(cached)
ok  	github.com/metaforismo/aegismesh/internal/llm	(cached)
ok  	github.com/metaforismo/aegismesh/internal/migrate/beelzebub	(cached)
ok  	github.com/metaforismo/aegismesh/internal/observe	(cached)
ok  	github.com/metaforismo/aegismesh/internal/policy	3.390s
ok  	github.com/metaforismo/aegismesh/internal/recommend	(cached)
ok  	github.com/metaforismo/aegismesh/internal/redact	1.363s
ok  	github.com/metaforismo/aegismesh/internal/rulecatalog	(cached)
ok  	github.com/metaforismo/aegismesh/internal/rulesinput	(cached)
ok  	github.com/metaforismo/aegismesh/internal/ruletest	1.929s
ok  	github.com/metaforismo/aegismesh/internal/runtime	35.209s
?   	github.com/metaforismo/aegismesh/internal/sensor	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/sensor/httpsensor	2.073s
ok  	github.com/metaforismo/aegismesh/internal/sensor/mcpsensor	1.806s
ok  	github.com/metaforismo/aegismesh/internal/sensor/sshsensor	3.948s
ok  	github.com/metaforismo/aegismesh/internal/sensor/tcpsensor	1.501s
?   	github.com/metaforismo/aegismesh/internal/sensorfactory	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/sensorproc	8.516s
ok  	github.com/metaforismo/aegismesh/internal/storage	(cached)
ok  	github.com/metaforismo/aegismesh/internal/strictjson	(cached)
?   	github.com/metaforismo/aegismesh/internal/testutil/benchfixture	[no test files]
?   	github.com/metaforismo/aegismesh/internal/testutil/oidctest	[no test files]
?   	github.com/metaforismo/aegismesh/internal/version	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/webhook	(cached)
ok  	github.com/metaforismo/aegismesh/tools/sbomcheck	(cached)
```

### AI pack file inventory

92 changed/new files; all left unstaged and uncommitted.

```text
CHANGELOG.md
README.md
cmd/aegismesh/main.go
docs/ROADMAP.md
docs/THREAT-MODEL.md
docs/ai-threat-design.md
docs/ai-threat-detection.md
docs/architecture/adr.md
docs/architecture/console-api.md
docs/canary-model.md
docs/cli.md
docs/configuration.md
docs/verification.md
examples/ai-decoy.yaml
internal/cli/cli_test.go
internal/cli/completion.go
internal/cli/demo.go
internal/cli/demo_cli_test.go
internal/cli/effective_finding_test.go
internal/cli/healthcheck_test.go
internal/cli/honeytoken.go
internal/cli/honeytoken_test.go
internal/cli/init.go
internal/cli/rules.go
internal/cli/rules_cli_test.go
internal/cli/testdata/demo.golden.json
internal/cli/testdata/demo.golden.txt
internal/cli/testdata/rules.golden.json
internal/cli/testdata/rules.golden.txt
internal/config/ai_decoy.go
internal/config/ai_test.go
internal/config/config.go
internal/config/fuzz_test.go
internal/config/load.go
internal/config/scaffold.go
internal/config/validate.go
internal/console/types.go
internal/correlate/ai_test.go
internal/correlate/catalog.go
internal/correlate/correlate.go
internal/correlate/correlate_test.go
internal/correlate/rules.go
internal/demo/demo.go
internal/demo/demo_test.go
internal/detect/ai.go
internal/detect/ai_test.go
internal/detect/catalog_test.go
internal/detect/detect.go
internal/event/envelope.go
internal/evidenceindex/index.go
internal/evidenceindex/index_test.go
internal/evidenceindex/projection.go
internal/honeytoken/honeytoken.go
internal/honeytoken/honeytoken_test.go
internal/policy/actions.go
internal/policy/ai_test.go
internal/policy/policy.go
internal/recommend/recommend.go
internal/recommend/recommend_test.go
internal/redact/auth.go
internal/redact/redact.go
internal/redact/redact_test.go
internal/rulecatalog/frameworks.go
internal/rulecatalog/frameworks_test.go
internal/rulecatalog/performance_regression_test.go
internal/rulecatalog/rulecatalog.go
internal/rulecatalog/rulecatalog_test.go
internal/rulecatalog/testdata/frameworks.tsv
internal/ruletest/corpus_test.go
internal/ruletest/correlation_corpus_test.go
internal/ruletest/interaction.go
internal/ruletest/ruletest.go
internal/ruletest/ruletest_test.go
internal/ruletest/testdata/ai-corpus.json
internal/ruletest/testdata/ai-correlation-corpus.json
internal/runtime/ai_detection_test.go
internal/runtime/console.go
internal/runtime/correlate.go
internal/runtime/evidence.go
internal/runtime/isolation.go
internal/runtime/runtime.go
internal/runtime/runtime_test.go
internal/sensor/httpsensor/sensor.go
internal/sensor/mcpsensor/sensor.go
internal/sensor/sensor.go
internal/sensor/sshsensor/sensor.go
internal/sensor/tcpsensor/sensor.go
internal/sensorfactory/factory.go
internal/sensorproc/builtin.go
internal/sensorproc/protocol.go
internal/sensorproc/proxy.go
internal/sensorproc/worker.go
```


## 2026-11-22 — backend review corrections and bounded observation downloads

Scope: uncommitted changes on `b9b4edd` in the backend worktree. HEAD was
unchanged at completion; no staging, commit, push, tag, PR or deployment.
No dependencies, configuration fields or dev-mock changes. UI integration remains
with the frontend owner. This ledger records local synthetic and loopback proof,
not external-provider, SIEM interoperability or production-capacity evidence.

| Command | Result |
|---|---|
| `go test ./internal/honeytoken ./internal/detect ./internal/correlate ./internal/evidenceview ./internal/indicatorexport ./internal/evidencereport ./internal/console ./internal/ruletest` (initial integration run) | **FAIL**, exit 1: six new routes required explicit authorization fixtures and valid session IDs in tenant fixtures. Part 1 packages passed. Fixtures were corrected; subsequent focused and full race runs passed. |
| `go test ./internal/console ./internal/cli ./internal/evidenceindex ./internal/config ./internal/ruletest ./internal/correlate ./internal/evidenceview ./internal/indicatorexport ./internal/evidencereport` | **PASS**, exit 0; final focused run before the final gates. |
| `AEGISMESH_UPDATE_INDICATOR_GOLDENS=1 go test ./internal/cli -run TestIndicatorExportCLIGolden -count=1` | **PASS**, exit 0; generated non-secret deterministic CSV/TXT/STIX goldens, subsequently checked by normal tests and the race suite. |
| `go test ./internal/evidencereport -run '^$' -fuzz=FuzzMarkdownNeutralizer -fuzztime=5s -fuzzminimizetime=0 -parallel=2` | **PASS**, exit 0; 60,136 executions, 156 new interesting inputs, no failure. Final race suite also ran seed cases after adding explicit Unicode-format-control neutralization. |
| `make ui-test` | **PASS**, exit 0; 169 tests, 169 passed, zero failed/skipped. Existing mock contracts require no mock edit. |
| `make secrets-scan` | **PASS**, exit 0; tracked working-tree heuristic. Supplemental fixed-pattern scan of all 19 new/untracked source/golden files also passed. No full provider-shaped marker literals were committed or added as fixtures. |
| `make lint` | **PASS**, exit 0; gofmt check and `go vet ./...`. `golangci-lint` unavailable; Makefile explicitly skipped it. |
| `make test` (after `make lint`) | **PASS**, exit 0; `go test -race ./...`, full package results captured below. |
| `git diff --check` | **PASS**, exit 0. |
| `df -h /System/Volumes/Data` | **PASS**, about 15 GiB initially and 14 GiB after the race gate. Never approached the 1.5 GiB cache-clean threshold; no cache deletion performed. |
| `make sbom` | **NOT RUN**, deliberately skipped as requested: known linked-worktree generator limitation. |
| External SIEM import / provider credential validation / UI for new endpoints | **NOT RUN**. No external validation request or runtime egress was added. Frontend implementation was outside this backend task. |

Evidence includes exact 30-minute idle/tie/tenant ID cases, cadence and regularity
formulas, phase/timeline caps, 8192-entry scan truncation, local-vs-forwarded ID
collisions, cursor filter/snapshot binding, strict query/role/tenant checks,
real-listener attachments, audit failure before download, required STIX object
properties/patterns/UUIDv5/resolved references, skipped-source accounting,
CLI since/usage/corruption/size/golden checks, and Markdown HTML/fence/control
neutralization. The expanded benign corpus has 26 samples (generic version/SSE
added, metrics retained); it produces six LLM-001 hits, one LLM-004 hit and zero
medium-or-higher hits. These are fixture properties, not field error rates.

Important limit: locally generated provider-shaped random decoys are never
registered or verified with providers. It is impossible to prove offline that
random strings can never collide with provider-issued values. The docs and
implementation make no absolute provider-invalidity claim. Committed example
placeholders are rejected with an actionable `honeytoken new` instruction.

Captured final lint output:

```text
go vet ./...
golangci-lint not installed; skipped (vet+fmt ran)
```

Captured final full race gate output:

```text
go test -race ./...
?   	github.com/metaforismo/aegismesh/cmd/aegismesh	[no test files]
ok  	github.com/metaforismo/aegismesh/deploy/helm/aegismesh	(cached)
?   	github.com/metaforismo/aegismesh/examples/extensions/echo-responder	[no test files]
?   	github.com/metaforismo/aegismesh/internal/admin	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/agekey	(cached)
ok  	github.com/metaforismo/aegismesh/internal/cli	15.287s
ok  	github.com/metaforismo/aegismesh/internal/config	5.817s
ok  	github.com/metaforismo/aegismesh/internal/console	19.192s
ok  	github.com/metaforismo/aegismesh/internal/console/audit	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/auth	3.062s
ok  	github.com/metaforismo/aegismesh/internal/console/investigations	16.954s
ok  	github.com/metaforismo/aegismesh/internal/console/oidc	2.494s
ok  	github.com/metaforismo/aegismesh/internal/console/stateio	(cached)
ok  	github.com/metaforismo/aegismesh/internal/console/tenant	(cached)
ok  	github.com/metaforismo/aegismesh/internal/consoleui	(cached)
ok  	github.com/metaforismo/aegismesh/internal/correlate	4.386s
ok  	github.com/metaforismo/aegismesh/internal/demo	4.219s
ok  	github.com/metaforismo/aegismesh/internal/detect	3.793s
ok  	github.com/metaforismo/aegismesh/internal/ecsexport	(cached)
ok  	github.com/metaforismo/aegismesh/internal/egress	(cached)
ok  	github.com/metaforismo/aegismesh/internal/event	(cached)
ok  	github.com/metaforismo/aegismesh/internal/evidenceindex	35.417s
ok  	github.com/metaforismo/aegismesh/internal/evidencereport	2.395s
ok  	github.com/metaforismo/aegismesh/internal/evidenceview	2.701s
ok  	github.com/metaforismo/aegismesh/internal/ext	16.645s
ok  	github.com/metaforismo/aegismesh/internal/extmanager	34.419s
ok  	github.com/metaforismo/aegismesh/internal/fleet/agent	(cached)
ok  	github.com/metaforismo/aegismesh/internal/fleet/hub	42.717s
ok  	github.com/metaforismo/aegismesh/internal/fleet/identity	(cached)
ok  	github.com/metaforismo/aegismesh/internal/fleet/protocol	(cached)
ok  	github.com/metaforismo/aegismesh/internal/honeytoken	2.404s
ok  	github.com/metaforismo/aegismesh/internal/indicatorexport	4.839s
ok  	github.com/metaforismo/aegismesh/internal/llm	(cached)
ok  	github.com/metaforismo/aegismesh/internal/migrate/beelzebub	1.701s
ok  	github.com/metaforismo/aegismesh/internal/observe	(cached)
ok  	github.com/metaforismo/aegismesh/internal/policy	11.685s
ok  	github.com/metaforismo/aegismesh/internal/recommend	3.482s
ok  	github.com/metaforismo/aegismesh/internal/redact	(cached)
ok  	github.com/metaforismo/aegismesh/internal/rulecatalog	3.743s
ok  	github.com/metaforismo/aegismesh/internal/rulesinput	(cached)
ok  	github.com/metaforismo/aegismesh/internal/ruletest	3.948s
ok  	github.com/metaforismo/aegismesh/internal/runtime	46.563s
?   	github.com/metaforismo/aegismesh/internal/sensor	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/sensor/httpsensor	7.183s
ok  	github.com/metaforismo/aegismesh/internal/sensor/mcpsensor	7.691s
ok  	github.com/metaforismo/aegismesh/internal/sensor/sshsensor	8.584s
ok  	github.com/metaforismo/aegismesh/internal/sensor/tcpsensor	2.484s
?   	github.com/metaforismo/aegismesh/internal/sensorfactory	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/sensorproc	14.127s
ok  	github.com/metaforismo/aegismesh/internal/storage	20.317s
ok  	github.com/metaforismo/aegismesh/internal/strictjson	(cached)
?   	github.com/metaforismo/aegismesh/internal/testutil/benchfixture	[no test files]
?   	github.com/metaforismo/aegismesh/internal/testutil/oidctest	[no test files]
?   	github.com/metaforismo/aegismesh/internal/version	[no test files]
ok  	github.com/metaforismo/aegismesh/internal/webhook	(cached)
ok  	github.com/metaforismo/aegismesh/tools/sbomcheck	(cached)
```

## 2026-11-23 — accounts, API keys, sessions, settings and audit export (ADR-0025)

Scope: branch `feat/accounts-access` in the backend worktree; local commits
only, no push, PR or deployment. No new dependency. New config field
`console.session_idle_seconds`. Loopback synthetic proof only: no real IdP,
no multi-process deployment, no frontend integration in this run.

| Command | Result |
|---|---|
| `gofmt -l .` (toolchain gofmt) | **PASS**, empty. The Homebrew `gofmt` disagrees with the go1.27.4 toolchain on one existing test file; the toolchain layout was kept. |
| `make lint` | **PASS**, exit 0; gofmt check and `go vet ./...`. `golangci-lint` unavailable; Makefile skipped it. |
| `make test` | **PASS**, exit 0; `go test -race ./...`, 52 packages ok, none failed. |
| `make secrets-scan` | **PASS**, exit 0 (`secrets-scan: ok`). |
| `go test -run '^$' -fuzz=FuzzDecode -fuzztime=10s ./internal/console/accounts` | **PASS**, about 90,000 executions, no failure. Target added to `make fuzz-seed`. |
| `AEGISMESH_UPDATE_CAMPAIGN_GOLDENS=1 go test ./internal/cli -run 'TestAccountsCLI\|Posture'` | **PASS**; regenerated `accounts-list` goldens and the posture goldens for POS-019, then checked by normal runs. |
| `git diff --check` | **PASS** after removing two trailing blank lines. |
| `make sbom` | **NOT RUN**: known linked-worktree generator limitation. |
| `make ui-test`, real IdP, multi-replica sessions | **NOT RUN**: frontend owned elsewhere; OIDC exercised only with the local test provider; sessions are per process by design. |

Loopback integration tests cover: create account → mint key → authenticate
(bearer and session) → self-service key mint/revoke → disable (key and session
fail at once) → re-enable → revoke; the last-admin guard across a restart with
no config admin; `not_managed` for config and OIDC identities; role and
local-tenant denials; CSRF and Origin on cookie mutations; preference
validation; session handles not accepted as cookies; idle expiry; admin
session revocation; key-auth throttling (429); settings provenance and secret
absence; system components; CSV formula neutralisation; audit exports free of
tokens, digests and cookie values; OIDC directory ids stable and free of
issuer/subject; and SSE streams opened with a managed key closing within one
heartbeat after key revocation or account disable.

## 2026-11-24 — permissions, custom roles, settings overlay and accepted risk (ADR-0026)

Scope: branch `feat/roles-settings` in the backend worktree; local commits
only, no push, PR or deployment. No new dependency. New config fields
`console.settings_editing`, `key_max_days`, `key_default_days`,
`sign_in_banner`, `organization_name`, `default_window`. Loopback synthetic
proof only; no frontend integration in this run.

| Command | Result |
|---|---|
| `gofmt -l .` (toolchain gofmt) | **PASS**, empty. |
| `make lint` | **PASS**, exit 0; gofmt check and `go vet ./...`. `golangci-lint` unavailable; Makefile skipped it. |
| `make test` | **PASS**, exit 0; `go test -race ./...`, 54 packages ok, none failed. A first run failed one new test because a file was edited while the suite compiled; the committed tree was re-run in full and passed. |
| `make secrets-scan` | **PASS**, exit 0 (`secrets-scan: ok`). |
| `go test -run '^$' -fuzz=FuzzDecode -fuzztime=15s ./internal/console/settings` | **PASS**, about 147,000 executions, no failure. Target added to `make fuzz-seed`. |
| `go test -run '^$' -fuzz=FuzzDecode -fuzztime=15s ./internal/console/accounts` | **PASS**, about 91,000 executions with new v2 role seeds, no failure. |
| `AEGISMESH_UPDATE_CAMPAIGN_GOLDENS=1 go test ./internal/cli -run TestPostureCLIGolden` | **PASS**; regenerated posture goldens for POS-020..022, the `accepted` count and the `accepted risks:` line, then checked by normal runs. |
| `make sbom` | **NOT RUN**: known linked-worktree generator limitation. |
| `make ui-test` | **NOT RUN**: frontend owned by another worktree. |

`TestBuiltinRoleRouteMatrix` was committed before the refactor, recording for
every registered route the least built-in role that passes the gate on master;
it stayed green through the permission refactor and pins the new routes.
Loopback integration tests cover: a custom role passing exactly its
permissions on every registered route; a role edit applying at the next
request for a bearer key and an existing cookie session, and closing an open
event stream; built-in immutability (`builtin`), `in_use`, invalid
combinations, name conflicts; `last_admin` across custom roles on a console
whose only administrator holds a custom role; every escalation path (create an
admin, promote, disable an admin, mint or revoke an admin's key, create or
widen a role, end an admin's session) refused with `exceeds_own_permissions`
and audited; settings PUT/DELETE/history with CSRF, permission denial,
`not_editable`, `editing_disabled`, range and reason validation; live session
TTL, idle timeout, key limits and `/meta` text; the overlay surviving a
restart; overrides ignored when editing is off; an out-of-range override
ignored at startup with a logged warning, POS-022 and a degraded `settings`
component; a corrupt overlay neither applied nor overwritten; posture
acceptance validation, expiry and audit; POS-021 for a service account with a
high-risk custom role; and the offline `posture` command reading acceptances
read-only or saying it could not. Store tests cover the v1 fixture migration
with backup, refusal of a newer schema, role validation and quotas.

## 2026-11-26 — console round 7: scale, folding caveats, dark review (UI only)

| Check | Result |
|---|---|
| `make ui-test` (362 tests) | **PASS** |
| `go build ./...`, `go test ./internal/consoleui/...` (non-race) | **PASS** |
| Go race suite | **NOT RUN**: UI-only change; the brief excluded it on this machine |
| In-app Chromium against the mock (normal, `--scale large`, editing off, older posture server): screens, themes and widths, performance method and numbers | Recorded in `docs/design-system.md`, "Round 7" |
| The real server with the round-7 backend (`acceptable`, `organization_name` on the digest, `synthetic`) | **NOT RUN**: built against the backend agent's stated contract and the mock's twin of it |
