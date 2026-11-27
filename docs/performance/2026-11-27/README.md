# Incremental sessions after appends, 2026-11-27

Addendum to [2026-11-26](../2026-11-26/README.md): same machine, harness,
profile and method (`make perf`, profile `large`: 13,362 retained envelopes,
an 8,192-summary analysis sample, 456 sessions, 28 campaigns). Local synthetic
measurements, not capacity.

## What changed

Before, any append, eviction or history change started a new index
generation, and the next sessions or campaigns request regrouped all 8,192
sampled summaries. Sessions of one source key depend only on that source's
events. `evidenceview.UpdateSessions` aligns the new sample with the previous
generation's sample. An append can insert anywhere; eviction and the sample
bound drop only at the oldest end. It then regroups and summarises only the
affected source keys, keeps every other session, and assigns campaigns over
the full list as before. When the samples do not align that way (a reorder,
a removal in the middle, more than 1,024 changes, or no earlier generation
with computed sessions) it recomputes from scratch.

The memo (`internal/console/analysis_memo.go`) derives a generation's sessions
from the newest earlier generation whose sessions were computed. It keeps at
most one such base alive and releases it once the new sessions exist.

**Equivalence.** `TestUpdateSessionsMatchesFullRecompute` (6 seeds × 120
random batches with scripted multi-source sequences so campaigns form,
out-of-order native times, idle gaps, eviction beyond capacity, sample
truncation, forwarded-id collisions and unknown sources) compares, after
every batch, the incremental sessions with `Sessions` by `reflect.DeepEqual`
(unexported step data included) and by JSON. It also compares `Campaigns`
over both. It asserts that the incremental path ran in at least 100 of 120
steps and that campaigns existed in at least 40. `TestSampleDiffFallsBack`
tables the alignment and fallback cases.
`TestIncrementalSessionsAfterAppendsMatchFullRecompute` replays seeded
envelopes through the real index and memo in 40 random batches. It compares
sessions, campaigns and every campaign detail (JSON) with a full recompute
and asserts the incremental path was taken for every generation.

## Results

The 1-minute load average was **8.4–12.5** during these runs (other agents
were building and testing on the same machine), against 2.8–5.5 for the
2026-11-26 baseline. Latencies are therefore conservative. The allocation
figures do not depend on load.

`make perf`, "append before each" rows (one fresh observation added untimed
before every request), medians of three runs (`after-1..3.txt`). Before =
the 2026-11-26 "after" medians:

| Endpoint, append before each | p50 ms | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| sessions 24h | 21.252 → 11.678 | 39,172,989 → 20,576,886 | 70,221 → 8,783 |
| campaigns | 15.893 → 4.629 | 23,257,000 → 5,530,541 | 72,661 → 13,003 |

p50 ranges over the three runs: sessions 10.998..14.982 ms, campaigns
4.041..6.972 ms. Run 2 hit its 4 s budget after 222 sessions samples, and its
posture row (5.7 ms) shows the host contention. Warm rows (no append) are
unchanged within noise: sessions 24h 0.314..0.343 ms, campaigns
0.056..0.060 ms.

Derivation alone (`go test -tags perf -run TestPerfIncrementalSessions
./internal/evidenceview`, 60 appends on the same seed, `incremental.txt`):

| After one append | p50 ms | p95 ms | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| full `Sessions` + `Campaigns` | 14.744 | 16.161 | 20,966,080 | 69,045 |
| `UpdateSessions` + `Campaigns` | 1.919 | 2.599 | 2,179,908 | 7,112 |
| `UpdateSessions` only | 1.315 | 1.556 | 1,309,702 | 3,937 |
| `Campaigns` only | 0.712 | 0.829 | 872,462 | 3,183 |

## Where the remaining cost is

After an append, the sessions list still costs ~11 ms and ~20 MB. Derivation
accounts for about 2 ms and 2 MB of that. Most of the rest is the
per-generation work that must still happen: the new 8,192-summary
`SharedAnalysis` copy, and the session cursor digest, which marshals the whole
sample to JSON to seed its SHA-256 prefix. Neither was made incremental. The
digest's prefix changes whenever a new event is added at the front, and
changing the digest's definition would change cursor semantics; ROADMAP lists
both as not done. Campaigns are regrouped in full twice per generation (once
inside session assignment, once for the list, whose members carry
`campaign_id`). That costs about 0.7 ms each.

The harness does not start the notification deriver (`Server.Start` is not
called), so these rows exclude it. Per append the deriver reads the newly
appended summaries by ordinal and matches rules (no sample copy). At most every
15 s while evidence arrives it reads campaigns through this same memo.

## Not claimed

No capacity, concurrency, multi-tenant or long-running results, and no claim
for constant ingest beyond what the "append before each" rows show. Single
machine, contended host, synthetic data.
