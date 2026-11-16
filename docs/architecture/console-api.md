# Console API v1 — contract

Status: **implemented contract for the single-tenant operator console**. This is
the only interface between the Go console server (`internal/console`) and the
embedded web UI (`internal/consoleui`). Change this document in the same commit
as any behavior change.

The console is a *read-mostly* view over evidence already owned by the runtime.
It never changes sensor behavior, policy, configuration or evidence, and it adds
no outbound connection. Mutable state includes operator-authored investigations,
audit and optional fleet inventory/token administration (ADR-0018).

## Transport and exposure

- Disabled by default (`console.enabled: false`). Default listen
  `127.0.0.1:9120`. Plain HTTP is accepted on loopback only; a non-loopback
  bind requires `security.allow_public_bind: true` **and** a configured TLS
  certificate and key, otherwise startup fails.
- Every response carries `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and
  `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
  The UI therefore uses no inline script, inline style attribute, `eval`, or
  third-party origin.
- `/api/` responses are `Cache-Control: no-store`.
- The `Host` header must match the configured listen authority (or `localhost`
  / loopback literal with the same port) — DNS-rebinding defense. Mismatch → 421.
- Request bodies are JSON, capped at 64 KiB, decoded strictly (unknown fields
  rejected).

## Authentication, sessions, roles

Operators are configured as named tokens. The config holds only the SHA-256 of
each token (`token_sha256`), never the token. `aegismesh console token` prints a
fresh random token once together with the config snippet.

Two ways to authenticate:

1. `Authorization: Bearer <token>` — for scripts. No cookie, no CSRF header.
2. Browser session: `POST /api/v1/session` exchanges a token for an opaque
   in-memory session delivered as cookie `aegismesh_session`
   (`HttpOnly; SameSite=Strict; Path=/`, plus `Secure` under TLS). Mutating
   requests authenticated by cookie must send `X-AegisMesh-CSRF: <csrf_token>`
   and, when an `Origin` header is present, it must match the request host.

Token comparison is constant-time over digests. Failed logins are rate-limited
per remote address (429 with `Retry-After`). Sessions expire after
`console.session_ttl_seconds` (default 3600, max 86400) and on restart.

| Role | Grants |
|---|---|
| `viewer` | all `GET` endpoints except audit |
| `analyst` | viewer + investigation writes |
| `admin` | analyst + audit trail |

## Conventions

- Timestamps are RFC 3339 UTC strings. IDs are opaque strings.
- Lists are newest-first and paginated with an opaque `cursor`; the response
  has `next_cursor` (empty string when exhausted). `limit` defaults to 50,
  max 200.
- Errors: `{"error":{"code":"<code>","message":"<human text>"}}` with codes
  `invalid_argument` (400), `unauthenticated` (401), `forbidden` (403),
  `not_found` (404), `conflict` (409), `rate_limited` (429),
  `unavailable` (503), `internal` (500).
- All evidence text (paths, previews, user agents, tool names, summaries) is
  attacker-controlled data. The API returns it as JSON strings; the UI must
  render it as text only.

## Types

```jsonc
// Principal
{ "name": "alice", "role": "admin" }

// Session
{ "principal": Principal, "csrf_token": "…", "expires_at": "2026-11-14T12:00:00Z" }

// Finding — static, rule-authored; never quotes matched input
{ "rule_id": "PI-001", "severity": "high", "confidence": "medium", "reason": "…" }

// EventSummary — derived projection of one stored envelope
{
  "id": "32 hex", "time": "…", "seq": 12,
  "sensor": { "id": "web", "kind": "http", "listen": "127.0.0.1:8080" },
  "classification": "interaction",      // interaction | canary_invocation | correlation_signal
  "source": "203.0.113.7",              // remote host or correlation source key; "" when unknown
  "summary": "GET /admin → 200",        // stored structured fields only, ≤160 chars
  "severity": "high",                   // highest finding severity, or "" when no finding
  "rule_ids": ["PI-001"],               // detection or correlation rule ids
  "action": "observe"                   // detection action when present, else ""
}

// EventDetail
{
  "summary": EventSummary,
  "envelope": { /* the complete native aegismesh.event/v1 envelope, unmodified */ },
  "integrity": { "verified": true, "algorithm": "sha256", "error": "" },
  "findings": [Finding],
  "related": [EventSummary],            // for a correlation signal: its source events;
                                        // for an interaction: signals that cite it
  "investigations": [ { "id": "…", "title": "…", "status": "open" } ]
}

// Bucket
{ "start": "…", "interaction": 4, "canary_invocation": 1, "correlation_signal": 0 }

// Overview
{
  "window": "24h", "generated_at": "…",
  "totals": { "events": 120, "interaction": 100, "canary_invocation": 15,
              "correlation_signal": 5, "sources": 9, "sensors_active": 3 },
  "previous_totals": { /* same shape, for the preceding window of equal length */ },
  "buckets": [Bucket],                  // 60 buckets for 1h, 48 for 24h, 56 for 7d
  "by_sensor": [ { "sensor_id": "web", "kind": "http", "events": 80 } ],
  "by_severity": { "critical": 0, "high": 3, "medium": 8, "low": 2, "info": 0,
                   "none": 107 },         // "none" = events without any finding
  "top_rules": [ { "rule_id": "PI-001", "events": 6, "severity": "high" } ],
  "top_sources": [SourceSummary],       // up to 10
  "recent_signals": [EventSummary],     // up to 10 correlation signals
  "open_investigations": 2
}

// SourceSummary
{ "source": "203.0.113.7", "events": 42, "first_seen": "…", "last_seen": "…",
  "sensors": ["web","mcp"], "kinds": ["http","mcp"],
  "canary_invocations": 2, "signals": 1, "max_severity": "high" }

// Sensor
{ "id": "web", "kind": "http", "listen": "127.0.0.1:8080",
  "state": "running",                   // running | failed | stopped
  "process_isolation": false,
  "events_total": 80, "last_event_at": "…",   // last_event_at "" when none indexed
  "by_classification": { "interaction": 70, "canary_invocation": 10 } }

// Node
{
  "instance": "…", "version": { "version": "…", "commit": "…", "go": "…" },
  "started_at": "…", "uptime_seconds": 3600, "healthy": true,
  "sensors": { "wanted": 4, "started": 4 },
  "bus": { "dropped_events": 0 },
  "storage": { "segments": 3, "bytes": 123456, "encrypted": false,
               "retention": { "max_events": 100000, "max_age_days": 30 } },
  "index": { "events": 1200, "capacity": 50000, "oldest": "…",
             "history": "complete" },   // complete | truncated | unavailable
  "console": { "listen": "127.0.0.1:9120", "tls": false, "session_ttl_seconds": 3600 }
}

// Rule
{ "id": "PI-001", "family": "detection",   // detection | correlation
  "title": "…", "description": "…",          // description may be ""
  "severity": "high", "enabled": true }      // severity is "" for correlation rules

// Investigation
{
  "id": "…", "title": "…",                           // title 1..200 chars
  "status": "open",                                  // open | monitoring | closed
  "priority": "medium",                              // low | medium | high
  "created_at": "…", "updated_at": "…", "created_by": "alice",
  "event_ids": ["…"],                                // max 200
  "notes": [ { "id": "…", "time": "…", "author": "alice", "text": "…" } ], // text ≤4000 chars
  "events": [EventSummary]   // detail responses only: attached events still present in the
                             // index, newest first; ids missing here are no longer indexed
}

// AuditRecord — append-only, hash-chained
{
  "seq": 17, "time": "…", "actor": "alice", "role": "admin",
  "action": "investigation.create",    // see Audit actions
  "target": "inv_…", "outcome": "ok",  // ok | denied | error
  "remote": "127.0.0.1", "detail": "…",
  "prev_hash": "64 hex", "hash": "64 hex"
}
```

## Endpoints

Unauthenticated:

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/meta` | `{ "product": "AegisMesh", "api_version": "v1", "version": "…" }` |
| POST | `/api/v1/session` | body `{ "token": "…" }` → `Session` + cookie |

Authenticated (`viewer` and above unless noted):

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/session` | `Session` |
| DELETE | `/api/v1/session` | 204, clears cookie (a mutation: cookie callers send the CSRF header) |
| GET | `/api/v1/overview?window=1h\|24h\|7d` | `Overview` (default `24h`) |
| GET | `/api/v1/events` | `{ "events": [EventSummary], "next_cursor": "", "total_matched": 120 }` |
| GET | `/api/v1/events/{id}` | `EventDetail` |
| GET | `/api/v1/events/stream` | `text/event-stream`, see below |
| GET | `/api/v1/sources?window=&limit=` | `{ "sources": [SourceSummary] }` — `window` is `1h\|24h\|7d` (default `24h`), ranked by events, `limit` default 50, max 200 |
| GET | `/api/v1/sources/{source}` | `{ "source": SourceSummary, "events": [EventSummary], "next_cursor": "" }` (accepts `cursor`, `limit`). `{source}` is one percent-encoded path segment (IPv6 literals and keys containing `/` included), ≤255 bytes decoded |
| GET | `/api/v1/sensors` | `{ "sensors": [Sensor] }` |
| GET | `/api/v1/rules` | `{ "rules": [Rule] }` |
| GET | `/api/v1/recommendations?limit=` | the existing `recommend.Report` JSON, unchanged; `limit` default 20, max 1000 |
| GET | `/api/v1/node` | `Node` |
| GET | `/api/v1/investigations?status=` | `{ "investigations": [Investigation] }` (notes omitted in list) |
| POST | `/api/v1/investigations` | *analyst* — body `{title, priority?, event_ids?}` → 201 `Investigation` |
| GET | `/api/v1/investigations/{id}` | `Investigation` including `notes` and `events` |
| PATCH | `/api/v1/investigations/{id}` | *analyst* — body any of `{title, status, priority}` → `Investigation`. No version check: the last write wins |
| POST | `/api/v1/investigations/{id}/notes` | *analyst* — body `{text}` → 201 `Investigation` |
| PUT | `/api/v1/investigations/{id}/events/{event_id}` | *analyst* — attach evidence → `Investigation` |
| DELETE | `/api/v1/investigations/{id}/events/{event_id}` | *analyst* — detach → `Investigation` |
| GET | `/api/v1/audit?cursor=&limit=&action=&actor=` | *admin* — `{ "records": [AuditRecord], "next_cursor": "" }` |
| GET | `/api/v1/audit/verify` | *admin* — `{ "verified": true, "records": 17, "first_invalid_seq": 0, "error": "" }` (`first_invalid_seq` is 0 when verified) |

### `GET /api/v1/events` filters

All optional and AND-combined: `node` (cryptographic id or `local`), `classification`, `sensor` (id), `kind`,
`source` (exact), `rule` (rule id), `severity` (minimum:
`info|low|medium|high|critical`), `since`, `until` (RFC 3339), `q`
(case-insensitive substring over `summary`, `source` and rule ids, ≤128 chars),
`cursor`, `limit`. Unknown parameters or malformed values → `invalid_argument`.

### `GET /api/v1/events/stream`

Server-Sent Events. `event: observation` with `data: <EventSummary JSON>` for
each newly stored envelope; `event: heartbeat` with `data: {"time":"…"}` every
15 s. The stream accepts optional `node=<id>|local`; other filters remain client-side. A browser
`EventSource` cannot read the status of a failed stream, so on close the UI
calls `GET /api/v1/session` to tell an expired session from an outage. A slow client is disconnected rather than buffered without bound. At most
16 concurrent streams (503 beyond).

## Audit actions

`session.login`, `session.login_failed`, `session.logout`,
`investigation.create`, `investigation.update`, `investigation.note`,
`investigation.attach`, `investigation.detach`, `audit.read`, `audit.verify`,
`authz.denied`. Token values, session identifiers and note bodies are never
written to the audit trail.

## Implementation safety bounds and clarified semantics

- The index also has a 64 MiB accounted-envelope budget (encoded envelope plus
  bounded projection allowance). It can evict before `index_max_events`; this is
  a deliberate safety extension and reports `truncated`. It is not a process RSS
  quota. Newest-first evidence lists follow native envelope time, with successful
  append ordinal breaking timestamp ties. Cursors bind this order and filters
  to one process; they are not portable across restart.
- `/node` reads at most 65536 storage-directory entries for physical segment
  metadata. A larger/unreadable directory returns 503 `unavailable`; no evidence
  payload is read in this request.
- Recommendations use at most the latest 4096 indexed envelopes (the existing
  engine's `MaxEvidence`); the returned report JSON is unchanged.
- Investigations: 1000 maximum, 100 notes each, 32 MiB total encoded state.
  Empty notes, duplicate event IDs and invalid enum values are rejected.
  Detail responses include empty `notes`/`events` arrays. List responses omit
  notes/events. Empty PATCH objects are rejected.
- Audit hashes the JSON-encoded record in declared field order with `hash` set
  to the empty string, excluding the terminating newline. Persisted records
  must be canonical JSON in that same field order, with a terminating newline;
  an unterminated final record fails startup/verification rather than being
  concatenated with a future append. The initial `prev_hash` is
  64 zeroes; each next record references the preceding hash.
- Audit rotates at 4 MiB, retaining at most 128 files, with no automatic deletion.
  Exhaustion fails closed. Audit and investigation state are plaintext, even
  with encrypted evidence. Investigation snapshot and audit append are separate
  transactions: 503 may report that state was saved but audit failed; inspect
  before retrying. A failed write poisons further audit appends until restart.
- Bearer-authenticated `GET /session` returns the principal, an empty CSRF token
  and the zero RFC3339 expiry (`0001-01-01T00:00:00Z`): bearer tokens have no
  session expiry. Cookie authentication returns the actual session fields.
- Endpoints without a body schema reject bodies, including chunked bodies.
  JSON endpoints use the strict 64 KiB decoder.
- HTTP requests have an 8192-byte URI cap, strict duplicate query/key rejection,
  eight concurrent ordinary handlers, and independent sixteen-stream capacity.
  Login attempts (including successful attempts) are capped at ten/address/minute
  across at most 4096 addresses; sessions are capped at 1024. Expired cookie SSE
  closes at expiry; logout is noticed at the next heartbeat/event.
- Public/wildcard listeners accept the exact configured hostname/IP and
  loopback aliases at the actual bound port; forwarded Host/Origin headers are
  ignored. TLS paths and nonempty relative state paths resolve against config.
- Plaintext backfill skips malformed/invalid-integrity entries and reports
  `unavailable` when any were skipped; terminal reader failures abort startup.
- The embedded UI (`consoleui.FS()`, wired by the runtime) is snapshotted in memory at construction (1024 files,
  16 MiB/file, 32 MiB total). Requests select no filesystem paths; no directory
  listing, `/index.html` alias or SPA fallback is provided. Only `/` serves the
  index. A server constructed without a UI FS serves a plain-text notice at `/`.

## Stated limits (honest boundaries)

- The index is an in-memory, bounded projection (`console.index_max_events`,
  default 50 000). Older evidence stays on disk and is reachable with
  `aegismesh inspect`; `Node.index.history` says whether the index is complete.
- With evidence-at-rest encryption the runtime holds no read identity, so the
  index contains only envelopes observed since process start
  (`history: "unavailable"`).
- The audit chain proves internal consistency of the audit file, not writer
  identity; an attacker with filesystem write access can rewrite it wholesale.
- Single tenant. Fleet inventory and opt-in evidence reception are experimental; SSO and tenant isolation are not shipped.

### Summary and cursor projection

Event summaries use only stored structured observation fields, replace control
characters, repair malformed UTF-8, and cap the joined result at 160 characters.
HTTP uses method/path and valid response status when available. MCP uses method
and optional tool name. SSH uses outcome, auth method (or last attempted method),
and attempt count. TCP uses lines/bytes and an optional matched response rule id.
Correlation signals use their stored rule id and summary. Missing or malformed
required fields fall back to `<kind> observation`; no preview or credential field
is used. Findings continue to use catalog-authored explanations.

Event and source-detail pagination have distinct trusted cursor scopes, even
when their selection filters match. Invalid, truncated, tampered, wrong-scope,
or changed-filter cursors return 400. Audit cursors use a separate process key.
Static traversal paths are rejected with 404 before path normalization.

## Experimental fleet inventory additions (ADR-0018)

These routes use the existing console listener, authentication, role hierarchy,
Host checks, cookie CSRF/Origin checks, request bounds, errors and audit. They do
not share the machine-facing hub mux. No route controls a sensor. This is
experimental fleet inventory with authenticated enrollment and heartbeats; it
is not multi-tenant or a managed service. Evidence reception is an additional off-by-default consent boundary.

| Method and path | Minimum role | Response |
| --- | --- | --- |
| `GET /api/v1/fleet` | viewer | `{hub:{enabled,listen,tls,accept_evidence},agent:{enabled,hub_url,node_id,enrolled,last_heartbeat_at,last_error,forwarding}}` |
| `GET /api/v1/fleet/nodes?status=` | viewer | `{nodes:[FleetNode]}` sorted by ID; optional status online/stale/offline/revoked |
| `GET /api/v1/fleet/nodes/{id}` | viewer | `FleetNode`, 404 if absent |
| `POST /api/v1/fleet/enrollment-tokens` | admin | 201 `{id,token,expires_at}`; raw token returned only here |
| `GET /api/v1/fleet/enrollment-tokens` | admin | `{tokens:[{id,expires_at,note}]}`; outstanding only, sorted ID; `expires_at` is RFC 3339 UTC like every other timestamp |
| `DELETE /api/v1/fleet/enrollment-tokens/{id}` | admin | 204; 404 if absent/expired |
| `POST /api/v1/fleet/nodes/{id}/revoke` | admin | `FleetNode`; idempotent permanent revoked state, 404 if absent |

Mint body is `{ttl_seconds?,note?}`: default TTL 3600, 1..86400 accepted; note
printable ASCII up to 256 bytes. Zero selects the default. Mint expiry is a UTC
RFC3339Nano string. Token listing exposes neither raw token nor digest. All
other mutations accept no body. Unknown/duplicate query keys are rejected;
only the node-list route accepts `status`.

`FleetNode` retains `{id,name,status,enrolled_at,last_seen_at,version,
uptime_seconds,sensors,counters,bus_dropped_events,storage_healthy,
public_key_fingerprint}` and optional `forwarding` described below. `version` is `{version,commit,go}`, `sensors` is
`[{id,kind,state}]`, and counters are uint64
`{interaction,canary_invocation,correlation_signal}`. Sensor addresses and
evidence are absent. Timestamps are UTC RFC3339Nano, empty before the first
heartbeat. Enrollment time is hub-owned; version/health/counters are signed
self-reports, not attestation. The fingerprint is full SHA-256(public key) hex.
Liveness is derived at read time (stale at three missed reporting intervals,
offline at ten); no heartbeat reads offline. Revoked takes precedence.

With hub disabled every node/token route returns 503 `unavailable` and a clear
hub-disabled message after auth/CSRF validation. `GET /fleet` always works.
Agent status reflects this process; last error is a fixed safe local category,
last heartbeat is the last acknowledged send, and empty strings mean no result.
With both roles off all enabled flags are false. Enabled hub listen reports the
actual authority, including an assigned test port. No secret references appear
in this endpoint.

Audit adds `fleet.token.create`, `fleet.token.delete`, `fleet.node.enroll`,
`fleet.node.revoke`, `fleet.node.rejected`. Machine enrollment/rejection are also
written to private hub audit state when the console is off. Mutation/audit are
separate durability transactions: an audit failure may follow a saved mutation;
503 tells operators to inspect before retrying. Audit's existing quota and
failure gates apply to admin routes as well as analyst mutations. Ordinary
inventory reads remain unaudited.

The [machine protocol](fleet-protocol.md) defines signing, skew/replay protection,
limits and errors. There is no hub-to-agent command or configuration API.


## Experimental forwarded evidence additions (2026-11-15)

Best-effort forwarding with counted loss; local store authoritative. Existing field names,
local envelope shapes, authentication and role grants remain compatible. The UI is unchanged.

| Endpoint/type | Additive contract |
| --- | --- |
| `EventSummary` | Optional `node: {id:string,name:string}`, absent for local observations. ID is authenticated origin; name comes from the current registry. |
| `GET /api/v1/events` | `node=<32 lowercase hex id>` selects that origin; `node=local` selects local observations; omitted combines all. Node is included in the cursor scope. |
| `GET /api/v1/events/{id}` | Optional `node=<id>|local` disambiguates IDs. Without it, local is preferred; a unique remote ID resolves, multiple remote matches return 404. Detail adds optional top-level `node`, also present on `summary`. Native `envelope` is unchanged. |
| Forwarded detail `integrity` | Existing `{verified,algorithm,error}` plus `scope:"hub_payload_hash_consistency"` and `description:"Verified on the hub against the envelope payload hash; consistency, not provenance."` |
| `GET /api/v1/events/stream` | Optional `node=<id>|local` filter; `observation` emits the optional summary `node`. Heartbeat shape unchanged. |
| `GET /api/v1/overview` | Accepting hubs add `by_node:[{id,name,events}]`, sorted by ID, within the selected overview window and retained index. `id:"local"`, `name:""` denotes local observations. Empty accepting index yields `[]`; disabled reception omits the field. |
| `FleetNode` | Optional `forwarding:{enabled,forwarded_total,dropped_total,last_forwarded_at,gaps_total}`. Optional queue/error fields may also be present as below. Absent for old agents before any forwarding report/submission. |
| `GET /api/v1/fleet` | `hub.accept_evidence:boolean`; `agent.forwarding` always present with the shape below, even when disabled. |

Forwarding counters are JSON uint64 numbers. Required fields when `forwarding` exists:
`enabled:boolean`, `forwarded_total:uint64`, `dropped_total:uint64`,
`last_forwarded_at:string` (UTC RFC3339Nano or empty), `gaps_total:uint64`.
Optional fields omitted at zero/empty: `queued_events:int`, `queued_bytes:int`,
`last_error:string` (fixed local categories, including `evidence_disabled`).
FleetNode counters/queue/error are heartbeat self-reports; its last receive time and gaps
are hub-authored. Agent status last-forward time is the local successful acknowledgement time.
Dropped counts include queue evictions (an in-flight eviction may still arrive) and invalid
acknowledgements. A trailing loss or crash cannot be inferred without a subsequent sequence.

All changed GET routes require viewer (also analyst/admin). Unauthenticated requests are
401; existing invalid credential, Host, session and body checks still apply. No new operator
write route exists. A node filter cannot grant access; every console operator shares this
single-tenant fleet view. Recommendations continue to use local evidence only; no cross-node
correlation is implemented. Related events resolve within an origin. Legacy investigation
annotations use bare event IDs and resolve local observations only; node-scoped annotations
are not implemented. A forwarded event cannot inherit a local investigation by colliding with its ID.

Forwarded index history is live-only after restart, including plaintext copies. Retention
and bounded-index eviction are independent; index entries can outlive hub retention until
index eviction. `index.history` reports `unavailable` on accepting hubs. Inspect the native
per-node copies locally for retained history, with explicit read identities when encrypted.
