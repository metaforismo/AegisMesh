# Seeded console measurements, 2026-11-26

Local synthetic measurements of the console API on a seeded demo history.
They are not capacity, throughput, concurrency or deployment results.

## Machine and method

- Apple M3, 8 logical CPUs, 16 GiB RAM, macOS 26.5.2 (25F84), darwin/arm64,
  Go 1.27.4 (`GOMAXPROCS=8`). Shared desktop machine; power and thermal state
  were not controlled. The 1-minute load average was 2.8–5.5 during the
  comparison below. An earlier exploratory pair ran at load ~21. Its latencies
  were 2–4× higher and are not used.
- Harness: `make perf` (`go test -tags perf -run '^TestPerfSeededConsole$'
  ./internal/console`, file `internal/console/perf_seed_test.go`). It is not
  part of `make test` and asserts only correctness, never timing.
- Baseline: commit `4dda260` (harness present, no optimisation), checked out
  in a temporary detached worktree. After: commit `f97737a` (memoisation plus
  posture acceptability). Before/after runs alternated three times (B A B A B A),
  sequentially. Tables give the median of three runs; ranges are below.
- Each endpoint runs 3 warm-up requests, then up to 300 timed requests within
  a 4 s budget (at least 30). Every request goes through the real
  bearer-auth, tenant, handler and JSON stack into an `httptest` recorder (no
  socket or TLS). p50/p95 are nearest-rank over those samples. B/op and
  allocs/op are `runtime.MemStats` deltas divided by requests and include the
  recorder. For the "append before each" rows, one fresh observation is added
  untimed before every request, so no per-generation reuse is possible. Their
  allocation figures exclude the append itself.
- SSE: 1, 4 and 16 real stream handlers with in-memory writers. 200 events are
  appended 2 ms apart. Delivery latency runs from just before `Index.Add` to the
  writer receiving that event's frame.

## Data profile

`demoseed` profile `large` (see `docs/cli.md`): exactly 50,000 synthetic sensor
observations plus 7,464 correlation signals from the real correlation engine,
1,075 documentation-range sources, all four sensor kinds, spread over the 7
days before the run. Generated and appended to a real evidence store, then read
back with the runtime's backfill loop (read, validate, verify the payload hash,
`Index.Add`), with the demo console's `index_max_events: 50000`.

The unchanged 64 MiB index accounting bound retains **13,362** of the 57,464
envelopes (the newest, roughly two days). History reports `truncated`. The
8,192-event analysis sample holds 456 sessions and 28 campaigns.

| Measurement (3 runs, same for before and after) | Result |
| --- | --- |
| Generate + append 57,464 envelopes | 2.76–2.94 s |
| Backfill of 57,464 envelopes into the index | 685–700 ms |
| Live heap of the retained index after GC | 26.6 MiB (≈2,085 B per retained entry, including index structures) |

## Before → after (medians of three runs)

| Endpoint | p50 ms | p95 ms | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| overview 1h | 0.125 → 0.126 | 0.134 → 0.147 | 121,970 → 121,263 | 390 → 390 |
| overview 24h | 2.056 → 2.154 | 2.944 → 2.868 | 922,415 → 922,901 | 7,028 → 7,028 |
| overview 7d | 3.107 → 3.083 | 4.341 → 3.847 | 1,371,507 → 1,370,044 | 11,247 → 11,247 |
| events limit=50 | 0.033 → 0.034 | 0.036 → 0.037 | 40,715 → 40,715 | 84 → 84 |
| events page 2 (cursor) | 0.036 → 0.036 | 0.040 → 0.041 | 45,105 → 44,804 | 106 → 106 |
| events classification filter | 0.056 → 0.055 | 0.061 → 0.059 | 44,123 → 44,123 | 112 → 112 |
| events sensor filter | 0.105 → 0.107 | 0.112 → 0.110 | 42,555 → 42,555 | 64 → 64 |
| events q=env | 0.728 → 0.745 | 0.824 → 0.825 | 41,334 → 41,545 | 78 → 78 |
| event detail | 20.979 → 4.015 | 21.982 → 5.838 | 31,163,492 → 15,403 | 86,708 → 97 |
| sessions 24h | 23.122 → 0.331 | 24.518 → 0.738 | 47,458,251 → 833,655 | 70,583 → 310 |
| sessions 7d | 23.044 → 0.304 | 24.908 → 0.669 | 47,395,254 → 831,384 | 70,582 → 310 |
| session detail | 15.880 → 0.020 | 17.348 → 0.024 | 30,424,860 → 31,471 | 70,314 → 73 |
| campaigns | 17.189 → 0.055 | 18.222 → 0.060 | 31,474,207 → 85,279 | 73,645 → 211 |
| campaign detail | 17.494 → 0.405 | 20.074 → 0.708 | 32,690,470 → 554,976 | 74,008 → 562 |
| coverage 7d | 10.368 → 2.034 | 11.534 → 3.209 | 15,492,323 → 2,201,556 | 105,705 → 29,735 |
| posture | 1.895 → 0.224 | 3.936 → 0.234 | 10,291,569 → 58,072 | 4,201 → 157 |
| digest 24h | 56.489 → 2.909 | 59.378 → 5.640 | 79,223,787 → 11,730,971 | 585,655 → 17,047 |
| digest 7d | 56.493 → 2.915 | 57.977 → 5.766 | 79,160,252 → 11,665,232 | 585,684 → 17,076 |
| sources 24h | 0.542 → 0.541 | 0.642 → 0.618 | 443,737 → 443,303 | 2,425 → 2,425 |
| decoys 24h | 4.394 → 0.506 | 5.935 → 0.521 | 20,418,141 → 11,650 | 4,183 → 55 |
| honeytokens 24h | 4.198 → 0.446 | 5.803 → 0.462 | 20,430,390 → 20,217 | 4,200 → 70 |
| recommendations | 35.863 → 0.028 | 37.765 → 0.031 | 40,287,324 → 35,347 | 498,411 → 39 |
| admin/settings | 0.032 → 0.033 | 0.036 → 0.036 | 40,080 → 40,080 | 315 → 315 |
| system | 0.004 → 0.004 | 0.005 → 0.005 | 9,372 → 9,372 | 48 → 48 |
| me | 0.004 → 0.004 | 0.004 → 0.004 | 9,039 → 9,047 | 41 → 41 |
| sessions 24h, append before each | 22.974 → 21.252 | 24.400 → 23.215 | 47,257,121 → 39,172,989 | 70,253 → 70,221 |
| campaigns, append before each | 17.220 → 15.893 | 17.727 → 16.927 | 31,332,716 → 23,257,000 | 72,743 → 72,661 |
| overview 24h, append before each | 2.193 → 2.234 | 2.941 → 2.976 | 922,950 → 922,037 | 7,030 → 7,031 |
| posture, append before each | 1.882 → 0.718 | 4.027 → 2.071 | 10,282,271 → 2,225,564 | 3,755 → 3,773 |

The "after" posture figure includes the new per-check acceptability. The
harness caller is an admin with editing on, so it also evaluates the local
view's unaccepted posture.

| SSE subscribers | delivery p50 ms | delivery p95 ms | append p50 ms |
| ---: | ---: | ---: | ---: |
| 1 | 0.066 → 0.066 | 0.133 → 0.134 | 0.049 → 0.049 |
| 4 | 0.091 → 0.095 | 0.189 → 0.216 | 0.060 → 0.063 |
| 16 | 0.105 → 0.118 | 0.253 → 0.285 | 0.062 → 0.068 |

SSE was not changed. The small after-side increases are within run-to-run
variation of this harness and are not read as a regression or an improvement.

p50 ranges (minimum..maximum of the three runs), before; after:

| Endpoint | before | after |
| --- | --- | --- |
| event detail | 20.955..20.993 | 3.953..4.138 |
| sessions 24h | 22.586..23.148 | 0.317..0.339 |
| session detail | 15.650..15.983 | 0.020..0.020 |
| campaigns | 17.179..17.321 | 0.054..0.055 |
| campaign detail | 17.246..17.563 | 0.405..0.408 |
| coverage 7d | 9.595..10.788 | 2.031..2.038 |
| posture | 1.853..1.914 | 0.222..0.227 |
| digest 24h | 56.407..56.750 | 2.890..2.925 |
| decoys 24h | 4.217..4.404 | 0.505..0.506 |
| recommendations | 35.772..35.942 | 0.028..0.028 |
| sessions 24h, append before each | 22.896..23.054 | 21.108..21.334 |
| campaigns, append before each | 17.072..17.361 | 15.770..15.907 |

The other rows' ranges are in the raw files (`before-*.txt`, `after-*.txt`).

## What changed, and why these rows

Profiles of the baseline (digest, sessions, coverage, decoys) showed the same
derivation repeated per request. Each request built a fresh 8,192-summary copy
(~10 MB), ran `Sessions`/`Campaigns`, and re-marshalled the whole sample to
hash the session cursor digest. Digest and recommendations re-validated up to
4,096 envelopes strictly (~70% of digest CPU). `time.Parse` ran inside sort
comparators. Optimisations, each with an equivalence test:

1. **Shared analysis sample per index generation** (`Index.SharedAnalysis`).
   The index advances a generation on append, eviction, history or name
   resolver change. `Analysis` still returns an independent copy (existing
   aliasing test unchanged). Test: `TestSharedAnalysisIsolatesCallerAppends`,
   and the snapshot comparison in `TestMemoisedAnalysisMatchesReference`.
2. **Per-tenant-view memo** (`internal/console/analysis_memo.go`) of sessions,
   campaigns, the event→session map, the SHA-256 state after the cursor
   digest's shared prefix, the recommendation report and the digest's
   recommendation count. Test: `TestMemoisedAnalysisMatchesReference`, which on
   seeded data for two tenants compares sessions, every session detail,
   campaigns, every campaign detail, cursor digests (including HTML,
   U+2028 and quote characters), session lookup for every event,
   recommendations at two limits, and digest counts with a missing ID against
   the former per-request computation. `TestAnalysisMemoReuseAndInvalidation`
   covers reuse, replacement on append, never replacing a newer entry, and no
   memoisation with a live node-name resolver.
3. **Canonical timestamp decoding** in `evidenceview.Time`. Test:
   `TestTimeMatchesTimeParse` (table of edge and invalid inputs plus 20,000
   random timestamps, compared with `time.Parse` by `==` on `time.Time`) and
   `FuzzTimeMatchesTimeParse` (15 s, ~3.1 M executions, no failure).
4. **Coverage** derives each event's time and mappings once. Test:
   `TestCoverageMatchesReferenceOnSeededHistory` against the former
   implementation (four windows, an unsorted duplicate and an unparsable time).
5. **Decoy/honeytoken window** returns the contiguous run of the shared sample
   instead of copying. A non-contiguous layout falls back to the copy. Test:
   `TestCatalogWindowMatchesReference`.

The cold rows ("append before each") show the honest worst case. After any
append, sessions still cost ~21 ms and ~39 MB, and campaigns ~16 ms. Only the
copy and timestamp parsing got cheaper. Event detail's remaining ~4 ms was not
profiled; that handler also appends a synced audit record. Overview, events,
sources and SSE were measured but not changed.

## Memory cost of the memo

One extra run each (`heap-before.txt`, `heap-after.txt`; harness line added
to both trees, test-only) measured live heap after GC once every endpoint had
been served warm, relative to before the index was built. Before: index
26.6 MiB plus 0.3 MiB of server state. After: index 26.6 MiB plus 9.4 MiB.
The memo for this one tenant view and this sample therefore holds **about
9.1 MiB**: the shared 8,192-summary sample, its 456 sessions (with their event
slices), campaigns, the event→session map, one recommendation report and the
digest state. It is bounded to one generation per tenant view and replaced,
never accumulated, when the index changes. With N tenant views it can reach N
times this size (not measured beyond one tenant). Single runs; the figure was
not repeated.

## Not claimed

No capacity, concurrency, multi-tenant (one tenant measured), fleet/hub,
TLS/socket, encrypted-store, p99 or long-running results. No claim that the
memo helps under constant ingest: with an append between every pair of
requests, sessions and campaigns cost about as much as before. Results come
from one machine and seeded synthetic data whose shape is described in
`docs/cli.md`. The 50,000-event profile is not 50,000 retained events.
