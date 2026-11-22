# Round 3 synthetic local performance measurements

Apple M3 / darwin arm64, eight Go benchmark CPUs, Go 1.27.4. Same worktree,
sequential `GOFLAGS=-p=1` invocations, three samples per leaf, 100 ms benchtime,
`-benchmem`, following `make bench` conventions. Power/thermal state and other
processes' load are uncontrolled. Disk remained above 2 GiB; no build-cache
purge was required. These are synthetic local measurements, not capacity,
statistical significance, p95/p99 or production/TLS/socket results.

Commands (before/after use the same command/harness):

```sh
GOFLAGS=-p=1 go test ./internal/console -run '^$' -bench '^BenchmarkSSEFanout$' -benchmem -benchtime=100ms -count=3
GOFLAGS=-p=1 go test ./internal/console -run '^$' -bench '^BenchmarkAcceptingHubOverview$' -benchmem -benchtime=100ms -count=3
```

The SSE baseline was captured before changing stream publication/encoding.
The hub baseline includes the round 3 contract additions and the same new
harness, before changing `ByNode` name-resolution ownership. The accepting
fixture uses second-truncated timestamps so encoded event lengths and retained
occupancy stay identical. Its initial exploratory timestamp-length variant
was replaced before the measured comparison; it was not used as evidence.
Raw files: `sse-before.txt`, `sse-after.txt`, `hub-overview-before.txt`,
`hub-overview-after.txt`. The first exploratory SSE after run failed its
healthy-consumer delivery assertion under scheduler/load variation; retained
as `sse-after-exploratory-failed.txt`, excluded from the medians. A subsequent
complete same-harness run passed all three cases/samples. This limitation is
not a throughput or healthy-client delivery guarantee under saturation.

Three-sample medians (SSE is **per 100-event operation**, not per event):

| Workload | ns/op before → after | B/op before → after | allocs/op before → after |
| --- | ---: | ---: | ---: |
| SSE / one | 101,270,583 → 101,284,958 | 554,048 → 608,032 | 5,847 → 5,792 |
| SSE / sixteen | 101,278,417 → 101,295,459 | 1,741,952 → 643,920 | 13,432 → 5,967 |
| SSE / one slow of sixteen | 101,269,500 → 101,298,916 | 1,674,696 → 650,912 | 12,975 → 5,952 |
| Accepting-hub overview / eight enrolled nodes | 7,427,986 → 2,923,616 | 2,850,836 → 1,159,193 | 38,916 → 5,770 |

Ranges (minimum..maximum across the same three samples):

| Workload | ns/op before; after | B/op before; after | allocs/op before; after |
| --- | --- | --- | --- |
| SSE / one | 101,264,500..104,262,167; 101,254,375..101,298,292 | 554,048..595,304; 605,632..649,272 | 5,847..5,946; 5,781..5,892 |
| SSE / sixteen | 101,262,208..101,298,000; 101,292,583..101,303,166 | 1,736,720..1,751,368; 642,272..655,840 | 13,420..13,479; 5,914..5,992 |
| SSE / slow | 101,236,125..104,496,500; 101,261,959..101,308,083 | 1,661,008..1,678,544; 644,480..652,000 | 12,927..12,996; 5,926..5,953 |
| Hub overview | 6,926,966..7,997,146; 2,825,668..3,080,822 | 2,846,324..2,850,904; 1,158,271..1,170,123 | 38,915..38,916; 5,770..5,771 |

SSE paces 100 events at absolute one-millisecond deadlines, through real stream
handlers with controlled writers. Sixteen remains the process-wide limit;
queues stay at 32; the deliberately blocked writer is dropped and healthy
writers are checked for complete delivery before the measured batch ends.
Most ns/op is deliberate pacing. The result supports lower multi-subscriber
allocation, **not a latency/throughput gain**. Single-stream bytes increased by
about 9.7%; shared immutable state has overhead at that scale. Producer median
append-ns/event was one 31,144 → 27,731, sixteen 35,225 → 34,292, slow
38,203 → 31,517, but baseline ranges are noisy (one 19,129..115,683), so these
are not presented as speedup evidence.

Accepting-hub setup creates a real `hub.Hub` with evidence reception enabled,
enrolls eight synthetic Ed25519 identities through signed requests, installs
its live `Node` resolver, and offers 50,000 synthetic forwarded envelopes.
The unchanged 64 MiB accounting cap retains **14,167**, all in the 24-hour
window; no claim of 50,000 simultaneous retention. The real console
handler/auth/tenant/JSON path runs into an HTTP recorder and includes `ByNode`.
Name resolution moved from once per observation to once per origin after
aggregation. The measured median latency decreases about 60.6% in this fixture,
with allocation reductions; it is not evidence for ingestion/read contention,
max tenants, registry saturation or socket behavior. Enrollment/setup is untimed;
no ingest traffic runs concurrently with the measured reads.

Correctness checks cover shared frame identity/concurrent encoding, tenant and
node filters, slow queue drop, expiry/shutdown, unchanged overview golden
semantics, and one resolver call per origin. Broader IO controls and accepting
hub read/write contention remain backlog items. Failing-first security logs in
this directory are regression receipts, not benchmark data.
