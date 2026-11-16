# Local benchmark evidence, 2026-11-15–16

> The raw sample files, pprof profiles and exit-code table named in this document
> (`*.txt`, `*.pprof`, `command-results.tsv`) were produced during the run but are not committed: they are
> machine-specific and reproducible with `make bench`. `table.md` holds the
> medians and ranges taken from them.

Baseline source: `338eea7b0ed4bb69fb1ddb6402704d1b27efc842`, read with
`git archive HEAD go.mod go.sum internal` into `/tmp/aegis-perf-baseline-hupcrne6`.
The snapshot contains the same benchmark files and fixture package as the working
tree, plus two baseline-only source aggregation adapters that delegate to the
original `Sources(index.Summaries(), ...)` implementation. There was no branch
switch, commit, push or GitHub access. The snapshot is 2.6 MiB; no caches or active
work were deleted. It excludes the ongoing frontend work.

`before.txt` and `after.txt` contain three samples per benchmark:
`make bench BENCH_COUNT=3` (100 ms per leaf, packages run sequentially).
`before-append.txt` refreshes only the append leaf after increasing the *untimed*
ID pool for eight partitions; it supersedes its rows in `before.txt`. IDs and
timestamps advance across benchmark calibration and repetitions. The pool is
larger than the retained horizon across all participating partitions.

`before-sse.txt` and `after-sse.txt` supersede the SSE rows in the full runs.
They use the final absolute-deadline pacing harness: it catches up after
scheduler delays instead of losing ticker slots. `events/s` reports achieved
delivery including the final healthy-reader drain (about 987/s in these short
100-event samples; the one-second profiles are nearer 1000/s). The remaining
60 benchmark leaves are unchanged by this benchmark-only refinement.

`initial-harness-failure.txt` and `second-harness-failure.txt` record temporary
fixture-directory permission failures, fixed by using new private subdirectories.
`exploratory-before.txt` predates the unique-append/related-link fixture correction;
it is not the comparison baseline. `after-first-pass.txt` predates the exactly
sized page/full-window allocation refinement and is likewise excluded. These
files are retained to distinguish exploration and harness errors from the final evidence.

Each tenant receives 50,000 synthetic redacted envelopes spread over nearly 14
days (24 seconds apart), eight sensors, four protocols, 256 sources, three
classifications, one known detection rule and correlation links 40 events apart
(the same authenticated origin). The configured count limit is 50,000. The
unchanged byte budget evicts earlier; the fresh read fixture retains **14,167**
events (oldest
2026-11-11 13:33:12 UTC; `fixture-metadata.txt`). The append output also records
occupancy after replacing part of that fixture with the timed payload. Read benchmarks rotate through independent 1/8 tenant partitions, one
query per operation, with no simultaneous writes. The deep cursor starts after
10,000 results, using the same filter and an authenticated cursor.

Storage benchmarks perform real buffered file appends, segment rotation, and,
for `EncryptedCheckpoint`, a real `Flush` after each append. This is the
checkpoint-inclusive worst cadence, not the runtime's five-second cadence.
`Flush` does not fsync. Age setup, directory creation and close/seal are untimed.
Runtime tap benchmarks use a no-op successful primary to isolate index/queue
cost from storage, include a primary-only control, use real index and forwarding
queue implementations, and send no network traffic.

Console request benchmarks call the actual `ServeHTTP` stack, including host
checks, auth, role, tenant-view selection, admission and JSON encoding into an
`httptest.ResponseRecorder`; request construction and login are untimed. These
are handler-stack measurements, not socket/TLS/client latency. Overview uses
its existing wall clock; the fixed fixture ends at 12:00 UTC on November 15,
while the console measurements occurred later that day. No clock/config/API
behavior was changed for measurement.

SSE uses the real authenticated stream handler and index subscriptions, with a
writer that implements flush/deadline controls. Each operation is **100 events**
paced at absolute 1 ms deadlines (nominal 1,000/s); wall time therefore includes intentional
waiting. `append-ns/event` records active producer time. B/op and allocs/op include
all healthy subscriber encodes/writes for the batch. Sixteen is the stream cap;
the slow case has fifteen healthy writers and one blocked writer whose bounded
subscription overflows and closes. Cleanup cancels, releases and joins every
handler. Socket backpressure/deadline fidelity is not measured by this writer.

Existing fleet hub benchmarks are unchanged: heartbeat signing/HTTP verification
with 1,000 registered identities, and signed ingestion/indexing of a **1,000-event
batch**. Batch construction is included in the latter; compare per-batch units.

CPU/alloc profiles are in `before-*.{cpu,alloc}.pprof`. Text `profile-*-{cpu,alloc}`
files contain the top 20 nodes. Whole-process profiles include untimed fixture
construction and benchmark calibration, so `profile-*-focus` views distinguish
actual request work from setup. They are diagnostic evidence, not ns/op data.
The three slowest non-paced paths in the final baseline by median were fleet
evidence batch, index overview/7d with eight tenants, and index free-text query
with eight tenants. Console overview/cookie and all three SSE cases were additionally
profiled to inspect the full handler stack and the paced wall-time case.
`report.py` renders the complete median/range table from raw samples.

Profile acquisition pattern (one path at a time):

```sh
go test -run '^$' -bench '<exact leaf pattern>' -benchtime=1s -count=1 -benchmem \
  -cpuprofile before-NAME.cpu.pprof -memprofile before-NAME.alloc.pprof \
  -memprofilerate=65536 -o /tmp/aegis-before-NAME.test ./internal/PACKAGE
go tool pprof -top -nodecount=20 before-NAME.cpu.pprof
go tool pprof -top -sample_index=alloc_space -nodecount=20 before-NAME.alloc.pprof
```

The machine reports Darwin arm64, macOS 26.5.2 (25F84), Apple M3, Go 1.27.4,
benchmark suffix `-8`.
The sandbox denied `sysctl` hardware inventory and process listing; total RAM,
performance/power state and other processes' load were not verified. Repeated
latency varies considerably; medians and min/max ranges are reported without
statistical significance or capacity extrapolation.

All requested gates completed on 2026-11-16 CET. `command-results.tsv` records
exit codes; command-named text files capture output. The initial full gate
failed because the doctor tests could not bind default ports 8081/6399/8090/9110.
No listeners or existing tests were changed. A later archived-baseline doctor
control and the complete `make lint test` retry both passed after the conflict
cleared. An empty `lsof` result was inconclusive in this sandbox; only the actual
bind/test results establish this sequence. Full-suite success is the retry,
not the failed first attempt. `golangci-lint` was unavailable; fmt and vet ran.
