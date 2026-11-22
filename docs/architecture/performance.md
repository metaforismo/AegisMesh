# Performance characteristics

Measurements began on 2026-11-15; verification and the SSE refresh completed on
2026-11-16 CET for the performance pass merged as #82, measured from the tree at
`338eea7` (the SSO change, #80). Machine: Apple M3, eight logical CPUs, Darwin arm64, macOS 26.5.2
(25F84), Go 1.27.4. RAM, thermal/power state and other processes' load were not
available. Disk went from 7.7 to 7.1 GiB free. Suites and benchmarks ran
sequentially. These are synthetic local measurements, not deployment capacity.

`make bench` runs the backend set sequentially with 100 ms per leaf and allocation
metrics. It is opt-in, not a CI gate; `BENCH_COUNT` and `BENCH_TIME` override the
defaults. The comparison uses three samples per leaf. All **63 before/after rows
and min/max ranges** are in the [verification ledger](../verification.md) and
[measurement table](../performance/2026-11-15/table.md). The
[workload notes](../performance/2026-11-15/README.md) retain raw output, baseline
adapters, profile commands, corrected subsets and excluded exploratory runs.

Each tenant receives 50,000 synthetic envelopes across eight sensors, four
protocols, 256 sources and three classifications, including rules and same-origin
related events. The configured count limit is 50,000, but the **unchanged 64 MiB
accounting bound evicts first**: the fresh read fixture retains **14,167 events
per tenant**, spanning just under four days after nearly fourteen days were
offered. This is not 50,000 simultaneously retained events. Eight-tenant runs
hold eight independent partitions and rotate reads between them. Deep cursors
start after 10,000 results.

Selected three-sample medians, eight tenants except the runtime tap:

| Workload | ns/op before → after | B/op before → after | allocs/op before → after |
| --- | ---: | ---: | ---: |
| Index events, no filter | 12,493,858 → 8,198 | 489,480 → 13,616 | 8,403 → 74 |
| Index overview/1h | 23,158,882 → 130,062 | 3,388,920 → 121,976 | 16,724 → 578 |
| Index overview/24h | 22,466,618 → 3,953,401 | 3,468,952 → 413,304 | 17,039 → 915 |
| Index overview/7d | 26,226,427 → 10,067,546 | 3,444,592 → 285,520 | 17,034 → 902 |
| Console events/cookie | 7,001,703 → 122,956 | 515,680 → 34,356 | 8,432 → 102 |
| Console overview/cookie | 11,151,958 → 12,574,607 | 3,550,276 → 421,938 | 17,074 → 948 |
| Runtime index + forwarder/event | 10,936 → 11,314 | 5,826 → 5,609 | 83 → 55 |

The cookie overview did **not** show a latency improvement despite lower
allocation. Untuned session/storage/heartbeat controls also varied or regressed.
Shared-machine noise is material; the short samples do not establish statistical
significance, blanket speedups or a causal explanation for small regressions.

Queries choose the smallest chronological secondary list for node,
classification, sensor, kind, source or rule. Append/eviction maintain/remove all
links, empty keys and cursor anchors together. Unfiltered totals use occupancy;
retained authenticated anchors seek directly. Timestamp bounds stop old scans,
and a bounded 200-reference buffer permits exactly sized result allocation.
Lowercased search text is derived once from immutable projected fields.
Overview/source aggregation takes window-limited immutable references under the
read lock, then aggregates/sorts unlocked using native timestamps. Only returned
summaries are copied and resolve current names. There is no time-based overview
cache or stale-window approximation.

Projection avoids hex-decoder allocation, rebuilding already clean bounded
strings, and decoding absent fields. Catalog lookup scans immutable metadata
derived once from compile-time registries; `All` still returns an independent
slice. Tests check owner equivalence, caller mutation, miss bounds, count/byte
retention, stale secondary keys, cursor eviction, late immediate eviction,
concurrent snapshot ownership and unchanged pre-optimization overview/source JSON.
All existing tests remain unchanged and passed on the final full-suite retry.

Storage benchmarks use real buffered files: plain, encrypted, and encrypted
append plus per-event checkpoint-inclusive `Flush`. This cadence exceeds the
runtime's five-second flush; `Flush` does not fsync, and close/seal is untimed.
Runtime tap benchmarks isolate real index/forwarding queues with a successful
no-op primary. Console cases use the real auth/tenant/handler/JSON stack into an
HTTP recorder. SSE uses real stream handlers with controlled writers: 100 events
per operation at absolute 1 ms deadlines, with catch-up after scheduler jitter.
Observed delivery including drain was about 987/s in short samples and 998.6/s
in one-second profiles. Wall ns/op includes waiting; producer ns/event is reported
separately. B/op and allocs/op are per 100 events. Sixteen is the stream cap; the
blocked subscriber fills its 32 slots and disconnects while healthy readers drain.
Existing fleet benchmarks remain unchanged: heartbeat with 1,000 identities and
signed ingestion of 1,000 events per operation, including batch construction.

The byte accounting has a conservative projection allowance; it is **not an
exact resident-heap cap**. Secondary metadata lives only with retained entries.
Severity/free-text queries can still scan all candidates for exact totals;
late insertion can scan chronological lists under the writer lock. Sources still
sort by window activity and stable ties. Unscoped remote-ID ambiguity lookup
retains its fallback scan. Related lookup adds a small candidate-ordering
allocation while removing the full-index relation scan. Config/API/cursor
contracts, stream/queue bounds, native envelopes and on-disk formats are unchanged.

**Not measured:** concurrent read/write contention or saturation, p95/p99,
resident-heap comparison, skew/high cardinality, maximum 32 tenants/operators,
external OIDC/refresh, accepting-hub overview/live node-name resolution,
partitioned fleet dispatch, network/TLS/socket-deadline fidelity, fsync durability,
long-running retention, crashes/power loss and encrypted close/seal. Console
fixtures end at 12:00 UTC on November 15 while overview keeps its real wall clock.
No capacity extrapolation follows from these results.

CPU/allocation profiles were captured/read for the three slowest non-paced
baseline leaves (fleet ingestion, eight-tenant 7d overview and free-text query),
plus console overview and all three SSE cases. Focused reports separate request
work from setup: summary copying dominated overview allocation; repeated search
construction/time parsing dominated query work; hostile parsing/IO remain fleet
costs; per-subscriber JSON encoding remains an SSE cost. Details are in the ledger.

The exact bounded JSON validator now lives in `internal/strictjson`; consumers
retain byte caps and typed errors. Runtime taps are grouped in `evidence.go`,
lifecycle in `lifecycle.go`; shutdown joins maintenance before closing storage.
Repeated real listener cycles have a goroutine-count assertion. Broader codec,
lifecycle/error, state-IO ownership, tenant fleet dispatch and shared-SSE changes,
plus unmeasured/noisy cases, have concrete entries in [BACKLOG](../BACKLOG.md).

## Round 3 measured follow-up — 2026-11-22 (local, uncommitted)

Shared SSE encoding and accepting-hub overview name resolution now have matching
three-sample before/after harnesses, raw logs, ranges and limits in
[performance/2026-11-22](../performance/2026-11-22/README.md). The hub fixture
uses a real accepting registry, eight signed/enrolled synthetic nodes and
14,167 retained of 50,000 offered events, all in the selected window. Median
handler overview: **7.428 ms → 2.924 ms**, **2,850,836 → 1,159,193 B/op**,
**38,916 → 5,770 allocs/op**. Names resolve once per origin after counting,
not once per observation. There is no overview cache or stale-window shortcut.

SSE shares one immutable lazy JSON frame inside each tenant index, across its
node-filter classes; each subscriber still validates session/filter/deadlines.
Sixteen streams, 32-slot queues, slow-client drop/close and cancellation
ownership are unchanged. Per 100-event batch with sixteen subscribers,
median allocation was **1,741,952 → 643,920 B/op** and **13,432 → 5,967 allocs/op**.
Wall time stays around 101 ms because the harness deliberately paces at 1000/s;
no throughput gain follows. Single-stream bytes rise **554,048 → 608,032**.
One exploratory after run failed its healthy-reader assertion under variable
load; its raw output is retained and excluded, and the full retry passed.
These are local synthetic measurements, not statistical significance, p99,
capacity or deployment proof. Concurrent ingestion/reads, IO controls, public
socket/TLS behavior and stronger load isolation remain unmeasured.
