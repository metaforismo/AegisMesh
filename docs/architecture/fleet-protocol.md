# Experimental fleet protocol v1

This is experimental fleet inventory with authenticated enrollment and heartbeats.
It is not multi-tenant or a managed service. Explicit opt-in evidence forwarding is described below.
Agents initiate every connection. The hub cannot command nodes, including a node
whose administrator has enabled the agent. There is no command, configuration,
file, code, upgrade or enforcement response field or endpoint.

## Transport and versioning

A hub can run with zero sensors. The machine API has its own listener, default `127.0.0.1:9130`. It never shares a
mux with console, admin or sensors. All machine submissions are POST with exactly
`Content-Type: application/json`. TLS 1.2 or newer is mandatory beyond loopback;
HTTP on loopback is for local development only. Agents verify hostname and the
system trust roots, optionally augmented by `hub_ca_file`. Proxies and redirects
are refused. An HTTP localhost name must still resolve to loopback at dial time.
The shared egress classifier checks each resolved destination and the final
socket address. Metadata and link-local are always denied; RFC1918/ULA require
`fleet.agent.allow_private_egress`, independent of the LLM/webhook opt-in.

`/fleet/v1` and signing domain `AEGISMESH-FLEET/1` version the whole contract.
Incompatible changes need a new version; there is no negotiated downgrade.
Unknown routes/methods return 404; the hub never redirects paths.

## Signing envelope and exact canonical encoding

Each request carries exactly one of each header:

| Header | Value |
| --- | --- |
| `X-AegisMesh-Node` | first 16 bytes of SHA-256(raw 32-byte Ed25519 public key), lowercase hex (32 characters) |
| `X-AegisMesh-Time` | positive Unix seconds in canonical decimal, no sign/leading zeros, at most 12 digits |
| `X-AegisMesh-Nonce` | fresh 16 random bytes, lowercase hex (32 characters) |
| `X-AegisMesh-Signature` | raw 64-byte Ed25519 signature, lowercase hex (128 characters) |

Sign the following ASCII bytes joined by single LF bytes, **without a final LF**:

```text
AEGISMESH-FLEET/1
<node id>
POST
<exact path: /fleet/v1/enroll, /fleet/v1/heartbeat or /fleet/v1/evidence>
<lowercase hex SHA-256 of the exact transmitted body bytes>
<timestamp header>
<nonce header>
```

There is no JSON reserialization in signature verification. Query strings,
encoded/alternate paths, duplicate headers, uppercase hex and noncanonical
numbers are rejected. Node ID is included in addition to the requested tuple to
bind the signing envelope explicitly to its identity. Timestamp skew is at most
120 seconds in either direction. Each node has its own 64-entry nonce window
(shared by enrollment, heartbeats and evidence batches), retained until the signed timestamp plus
120 seconds. Only that node's expired entries are pruned on acceptance; live
entries are never evicted. Saturation returns `capacity` only for that node and
cannot consume another identity's budget. The total is at most 64000 entries.
Replay windows are soft state, flushed as described under durability below.

## `POST /fleet/v1/enroll`

Body:

```json
{"token":"<one-time token>","public_key":"<64 lowercase hex characters>","name":"edge-node","interval_seconds":30}
```

The entire request, including token, public key, proposed name and interval,
is the request-bound challenge. The hub derives the node ID from the supplied
key and verifies the envelope signature with that key before consuming a token.
This proves possession without adding a server challenge round trip. Protect
the token in transit: a stolen unused token can enroll a different key.

Tokens contain 32 random bytes encoded as 64 lowercase hex characters. The hub
stores SHA-256 only. Token creation defaults to one hour, accepts 1..86400 seconds,
and shows the raw value once through the admin console API. Expiry is exclusive:
`now >= expires_at` refuses it. One snapshot transaction inserts the node and
consumes the token, so concurrent requests cannot use it for different keys.
A fresh signed request for an already enrolled key is idempotent even if its
token is consumed or empty. It preserves name and enrollment time, refreshes the
reporting interval, and still enforces signature, skew, replay and revocation.
Accepted enrollment retries are spaced by the currently registered interval,
separately from heartbeats; an earlier retry returns `rate_limited` (429).
Unchanged retries dirty only the replay window; interval changes save immediately.
The process-local enrollment retry timer resets on restart. A revoked key cannot
enroll again. Renaming an existing identity is unsupported; keep `node_name` stable across restarts.

Names are 3..64 characters matching `[a-z0-9][a-z0-9._-]{2,63}`. Intervals are
10..300 seconds. Enrollment alone does not establish liveness: a node with no
heartbeat reads as offline. Success is 200 `{"node_id":"<id>"}`. There is no
shared bearer secret after enrollment and no private key upload.

## `POST /fleet/v1/heartbeat`

The same signing envelope is verified against the stored public key. Body fields:

| Field | Meaning and bounds |
| --- | --- |
| `name` | immutable enrolled node name |
| `version` | `{version,commit,go}`, printable ASCII, each at most 128 bytes |
| `uptime_seconds` | nonnegative process uptime |
| `sensors` | at most 64 `{id,kind,state}` records with unique slug IDs; kind http/tcp/mcp/ssh; state running/stopped/failed |
| `sensors_wanted`, `sensors_started` | wanted equals list length; started within 0..wanted |
| `counters` | uint64 `{interaction,canary_invocation,correlation_signal}`, successful local evidence appends since process start |
| `bus_dropped_events` | uint64 process drop count |
| `storage_healthy` | false after observed append/flush failure, latched for this process |
| `console_enabled`, `hub_enabled` | local role flags |

No addresses, evidence, credentials, notes or free-form error strings are sent.
The hub records the bounded snapshot and its own receive time. These values are
self-reported inventory, not attestation or authenticated incident evidence.
The first heartbeat may immediately follow enrollment. Subsequent accepted
heartbeats must be at least the registered interval apart, using hub receive
time. Earlier fresh requests return `rate_limited` (429); a repeated live nonce
returns `replay` (401). Revoked and rate-limited requests perform constant work,
without nonce insertion, registry serialization or disk writes. Rejected requests
can only enqueue bounded audit samples, never trigger an audit fsync themselves.
Success is 200 `{"node_id":"<id>"}`; the agent rejects unknown acknowledgement
fields or a mismatched ID. Hub response bytes never become behavior.

Liveness is derived at read time using the hub clock and enrolled interval:
online below three intervals, stale at three, offline at ten. Revocation takes
precedence. Agent success records its local acknowledgement time. Delivery runs
independently of sensors/storage, retries with exponential equal jitter from
1..2 seconds initially up to 150..300 seconds, and resets to the configured
interval on success. Failure does not enqueue historical heartbeats; evidence has its own bounded queue below.
A restart reuses the local identity and performs signed idempotent enrollment.
An unknown identity without a token remains unenrolled and reports a safe error.

## Limits, durability, errors and audit

Inventory requests and all responses are at most 32 KiB; evidence requests are at most 4 MiB. Strict JSON rejects null, unknown and
duplicate fields, invalid UTF-8, extra documents, depth above 32 and arrays or
objects above 256 entries. The listener bounds ordinary work to eight handlers,
headers to 8 KiB, header time to five seconds, read/write to ten seconds and idle
time to 30 seconds. Before parsing bodies, the hub permits 8192 requests per
remote IP per fixed one-minute window. This accommodates 1000 nodes sharing a
NAT at ten-second intervals. Source ports and forwarding headers cannot create
new buckets. The table holds at most 4096 addresses; new remotes fail closed
when full until expired entries are pruned by maintenance (once per second).
Remote throttling returns 429 and `Retry-After: 60`; node spacing returns 429
with the remaining interval rounded up to seconds. Shared NATs and a saturated
remote table can still cause collateral throttling. These are fixed constants,
not configuration knobs. Agent attempts have a ten-second total timeout, five-second
dial/TLS/header limits, an 8 KiB response-header cap, one connection per host,
no compression, no redirects and no environment proxy.

Registry capacity is 1000 nodes including permanent revoked tombstones and 100
outstanding tokens. The single snapshot is capped at 32 MiB and uses private
fixed-name write/fsync/rename/directory-fsync. New node/key records, token
creation/consumption/deletion, interval changes and revocation save synchronously.
Heartbeat last-seen, sensors, version/health/counters and replay windows stay in
memory and mark one dirty snapshot. A joined background worker checks the injected
clock once per second and flushes on a five-second cadence, at most once per
interval; durable changes may include pending soft state sooner. Orderly shutdown
after listener drain flushes pending soft state and rejection audit counts.

A crash can lose soft updates since the last successful flush: normally at most
the last five-second interval of liveness and replay state (scheduler/IO stalls
can extend that elapsed time; this is not a real-time deadline). After restart,
nodes show their last flushed inventory until the next accepted heartbeat;
liveness status is still derived from that timestamp and the current clock.
Flushed nonces still reject replays, and timestamp skew always limits validity
to signed time ±120 seconds. **Residual replay gap:** a nonce accepted only since
the last flush can be accepted again after an abrupt restart if still in that
skew window, subject to the restored node spacing. A request originally dated
120 seconds into the future can thus remain valid for up to 240 seconds after
its original receipt. No process-start timestamp floor is imposed. Durable token
consumption and revocation do not share this gap. Snapshots exceeding 64 live nonces
for one node fail startup validation, including older draft snapshots. Wait for
those entries to expire, then reopen; startup safely discards expired entries.
Inspect private state rather than discard live replay protection.

Identity is a 0600 Ed25519 seed in a 0700 agent state directory. Hub state, replay entries and audit remain plaintext
regardless of evidence encryption. State is single-writer; same-UID tampering,
rollback and disk loss are outside the authenticity claim. Noncanonical or
corrupt registry state fails startup. A snapshot write error latches the hub
unavailable until restart/inspection because rename may already have succeeded.
A stale `.tmp` file requires inspection; it is not silently overwritten.

Errors have `{"error":{"code":"..."}}`, without echoed request data:

| HTTP | Codes |
| --- | --- |
| 400 | `invalid_argument` |
| 401 | `unauthenticated`, `invalid_token`, `clock_skew`, `replay` |
| 403 | `revoked` |
| 409 | `evidence_disabled` |
| 404 | `not_found` |
| 413 | `body_too_large` |
| 429 | `rate_limited` (with `Retry-After`) |
| 503 | `capacity`, `unavailable` |

A path tamper that causes an invalid enrollment schema can return 400 before
signature verification; it still cannot mutate state. Agents log fixed safe
local categories only, never server error text, signatures or tokens.

`fleet.node.enroll` enters the private hub audit chain synchronously and, when
enabled, the console audit chain. Every rejection increments a fixed-code metric.
Rejections queue at most five anonymous `fleet.node.rejected` samples per global
one-minute audit window. A background worker writes the samples outside the hub
mutex. At each elapsed audit window with suppression, one
`fleet.node.rejected.summary` record carries the decimal suppressed count in
`target` and `outcome: suppressed`, mirrored to the console audit chain as well.
Only five pending samples plus a saturating uint64 suppression count are retained;
no rejected request data or identity is stored. Shutdown emits the pending samples
and summary. Abrupt crashes can lose pending rejection samples/counts. Request
arrival never triggers audit IO, and no burst can fsync at packet rate. This paces
history growth; existing finite audit segment quotas still apply and can
ultimately fail closed. Operator token creation/deletion and
node revocation use the existing console auth/CSRF/audit rules. Audit exhaustion
fails closed. Registry and audit are separate transactions; a failed post-save
audit response may mean state is already saved. Inspect before retrying.
Metrics have fixed outcome labels only, never node IDs:
`aegismesh_fleet_agent_attempts_total` and `aegismesh_fleet_hub_requests_total`.

## Experimental evidence forwarding (2026-11-15 amendment)

This slice implements **best-effort forwarding with counted loss; local store authoritative**.
Both `fleet.agent.forward_evidence.enabled` and `fleet.hub.accept_evidence.enabled`
default false. Enabling forwarding explicitly discloses redacted evidence to the hub,
including correlation signals. The runtime offers only envelopes whose local authoritative
append succeeded. It never reads historical evidence or holds a private decryption identity.
Local encryption therefore does not prevent live forwarding; plaintext is sent within TLS
outside loopback. Redaction is the confidentiality control at that boundary.

### `POST /fleet/v1/evidence`

The existing canonical signing domain, headers, exact method/path/body hash, skew,
per-node nonce window and revocation checks apply. Evidence has a separate **4 MiB**
body cap; inventory remains 32 KiB. Example framing (envelopes abbreviated):

```json
{"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","first":4,"last":5,"events":[{},{}]}
```

`stream_id` is a fresh random 128-bit lowercase hex value per agent process.
`first`/`last` are inclusive uint64 forwarding positions, starting at one;
`last-first == len(events)-1`. At most **1,000 events** per batch. Every envelope
retains its native bytes and payload hash, without origin fields inserted.
Unknown/duplicate outer fields, null framing, invalid UTF-8, inconsistent ranges,
extra documents or malformed JSON reject the whole batch with `invalid_argument`.
Individual malformed/oversized/invalid-hash envelopes are skipped and counted.
Envelope validation checks required fields, schema, strict nested metadata, JSON
container bounds (depth 32, 256 entries), UTF-8, lowercase IDs/hashes, nonzero
sequence, recognized kind/classification, bounded metadata/rules and timestamp
from 2020-01-01 through hub time +120 seconds. Native envelopes are at most 1 MiB;
instance ≤128 bytes, sensor ID ≤64, listen ≤256, redaction rules ≤64 ×128 bytes.
Observation content is display data only and cannot change behavior.

Success: `200 {"node_id":"…","accepted":2,"invalid":0,"duplicates":0}`.
Counts sum to the submitted range length. Invalid envelopes are final acknowledged
loss on the agent; request errors retain the pending range. A fresh signed retry
is idempotent within each node's last **4,096 accepted event IDs**, in memory.
Repeating the exact signed request is a replay (401); it is not a delivery retry.
Duplicate IDs across nodes never collide in storage or index metadata. Deduplication
is bounded and process-local: an older ID or a retry after hub restart may append again.
No exactly-once, crash-durable acknowledgement or provenance claim is made.
Append/flush/retention errors return `unavailable`; flush reaches the OS, not fsync.
Partial appends can exist after an error and are covered by the bounded retry window.

Reception disabled returns **409 `evidence_disabled`** after authentication and
revocation checks. The agent reports that fixed category and retries every
**5–6 minutes**, independently of heartbeats. Other failures use equal-jitter
exponential backoff (initial 1–2 s, capped 150–300 s). Successful/idle cycles
wait five seconds. A dedicated transport isolates evidence from heartbeat
connection capacity. Hub response data is only strictly bounded acknowledgement
and fixed local status selection; it cannot command a node.

### Queue, quotas and retention

The in-memory agent ring holds at most **4,096 events / 16 MiB encoded bytes**.
Overflow evicts oldest queued envelopes and counts each eviction. Enqueue performs
bounded serialization and a short memory-only critical section; it waits on no
network, disk or queue capacity. Disabled enqueue is O(1), without allocation.
One in-flight batch may retain up to another 4 MiB while overflow evicts its queued
references. An evicted in-flight event can still arrive; `dropped_total` counts
queue evictions and invalid acknowledgements, not a proof of permanent loss.
Forwarding sequence gaps are recorded by the hub per process stream; the first
received range also exposes an already-dropped prefix. A trailing dropped suffix,
process crash or a forged stream reset cannot be inferred as a gap without a later
range. Counters and stream changes are node self-reports, not loss attestation.

There is **no on-disk spool**. A plaintext spool would defeat local encryption,
and the runtime holds no read identity. Events observed while the hub is unreachable
for longer than the queue covers, or queued at a crash, are not forwarded and remain
only on the node. Orderly stop cancels delivery; remaining pending events also remain
only on the node. No historical replay or deletion propagation is implemented.

Per cryptographic node: **five-second request spacing**, **1,000 events per fixed
second**, **16 MiB encoded request bytes per fixed minute**, and **16 MiB retained
segment bytes**. Requests exceeding a quota receive 429 `rate_limited` with
`Retry-After`; the agent uses its local jittered schedule. Concurrent evidence work
for the same identity fails quickly instead of occupying all handler slots.
The registry lock is released before validation/appending/indexing. Separate nodes
have separate ingestion locks and replay/rate/dedup budgets.

The aggregate forwarded-segment cap is **256 MiB**, enforced with atomic reservations
including a conservative encryption/rotation allowance (2× valid new envelope bytes +4 KiB per new event
+4 KiB, reconciled to actual flushed segment sizes). Reservations can temporarily
refuse a batch before the physical cap is reached. One identity can consume at most
16 MiB of it; many colluding identities can exhaust the shared cap. Closed oldest
segments are evicted within that node to make space; the active segment is retained.
Count/age retention also runs after batches using the hub storage policy. Global
capacity refusal does not evict other nodes' evidence. Dormant copies remain until
that node next submits or the operator manages local retention; no deletion API exists.
These finite fixed limits are intentional experimental defaults, not tuning fields.

Copies live in `<fleet.hub state dir>/evidence/<validated cryptographic node id>/`.
Only canonical authenticated IDs select a child beneath that trusted parent; node
names and envelope fields never select paths. Hub `storage.encryption` applies,
with the same persistent encryption guard, native rotation/checkpoints and inspect
reader. Forwarded segment size is capped at 4 MiB, respecting smaller configured caps, to bound rotation slack; the
stored-envelope limit is 1 MiB. Other storage count/age settings are inherited.
The disposable console index is fed after append and keeps origin separately.
Forwarded history is not backfilled on restart, including plaintext copies.

Heartbeat adds optional `forwarding` with `enabled`, `forwarded_total`,
`dropped_total`, `last_forwarded_at`, `gaps_total` and optional `queued_events`,
`queued_bytes`, `last_error`. Old inventory-only agents remain readable without it.
The node view preserves hub-authored last receive time and gap count instead of
trusting those reported fields. Registry gap/stream updates have the existing
coalesced crash window. Metrics add fixed outcomes only:
`aegismesh_fleet_forwarding_total{label}` (agent accepted/failed/dropped),
`aegismesh_fleet_evidence_events_total{label}` (hub accepted/invalid/duplicate).
No node ID, event ID, source or attacker string becomes a metric label.

Smaller configured segment caps also enforce a conservative raw-size +1 KiB
fit allowance per envelope; envelopes that cannot meet it are counted invalid,
so an operator-selected small segment cannot cause endless retries of an event.
