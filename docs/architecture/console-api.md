# Console API v1 — contract

Status: **implemented and merged (v0.2.0); SSO via OIDC (experimental), logical tenant isolation (experimental)**. This is
the only interface between the Go console server (`internal/console`) and the
embedded web UI (`internal/consoleui`). Change this document in the same commit
as any behavior change.

The console is a *read-mostly* view over evidence already owned by the runtime.
It never changes sensor behavior, policy, configuration or evidence, and adds issuer discovery, JWKS and token egress only when OIDC is enabled. Mutable state includes operator-authored investigations,
audit, optional fleet inventory/token administration (ADR-0018), managed accounts, API keys and
preferences (ADR-0025, [below](#accounts-access-and-settings-adr-0025)), custom roles and, only when
`console.settings_editing` is `console`, a fixed allowlist of console settings and accepted posture
risks (ADR-0026, [below](#permissions-roles-and-editable-settings-adr-0026)).

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
`console.session_ttl_seconds` (default 3600, max 86400), after
`console.session_idle_seconds` without an authenticated request (default 1800,
`0` disables), and on restart. Console-managed `amk_` API keys authenticate the
same two ways (ADR-0025).

| Role | Grants |
|---|---|
| `viewer` | read endpoints except analyst downloads and admin audit |
| `analyst` | viewer + investigation writes |
| `admin` | analyst + audit trail; members of `local_tenant` also administer accounts, sessions, settings and system status |

Since ADR-0026 each route declares a permission and these roles are fixed
permission sets granting exactly the access above; managed accounts may also
hold custom roles ([permissions](#permissions-roles-and-editable-settings-adr-0026)).

## Conventions

- Timestamps are RFC 3339 UTC strings. IDs are opaque strings.
- Lists are newest-first and paginated with an opaque `cursor`; the response
  has `next_cursor` (empty string when exhausted). `limit` defaults to 50,
  max 200.
- Errors: `{"error":{"code":"<code>","message":"<human text>"}}` with codes
  `invalid_argument` (400), `unauthenticated` (401), `forbidden` (403),
  `not_found` (404), `conflict` (409), `last_admin` (409), `not_managed` (409), `builtin` (409),
  `in_use` (409), `editing_disabled` (409), `not_editable` (409), `exceeds_own_permissions` (403),
  `rate_limited` (429),
  `unavailable` (503), `internal` (500).
- All evidence text (paths, previews, user agents, tool names, summaries) is
  attacker-controlled data. The API returns it as JSON strings; the UI must
  render it as text only.

## Types

```jsonc
// Principal
{ "name": "alice", "role": "admin", "auth_method": "token", "tenant": "default",
  "tenants": ["default"] }

// Session
{ "principal": Principal, "tenant": "default", "tenants": ["default"],
  "csrf_token": "…", "expires_at": "2026-11-14T12:00:00Z" }

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
  "by_sensor": [ { "sensor_id": "web", "kind": "http", "events": 80, "buckets": [Bucket] } ],
  "by_severity": { "critical": 0, "high": 3, "medium": 8, "low": 2, "info": 0,
                   "none": 107 },         // "none" = events without any finding
  "top_rules": [ { "rule_id": "PI-001", "title": "instruction-override phrasing directed at an automated agent", "events": 6, "severity": "high" } ],
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
  "storage": { "segments": 3, "bytes": 123456, "encrypted": false, "healthy": true,
               "retention": { "max_events": 100000, "max_age_days": 30 } },
  "index": { "events": 1200, "capacity": 50000, "oldest": "…",
             "history": "complete" },   // complete | truncated | unavailable
  "console": { "listen": "127.0.0.1:9120", "tls": false, "session_ttl_seconds": 3600 }
}

// Rule
{ "id": "PI-001", "family": "detection",   // detection | correlation
  "title": "…", "description": "…", "guidance": "…", "observe_only": false,
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
| GET | `/api/v1/meta` | `{ "product": "AegisMesh", "api_version": "v1", "version": "…", "auth": {"token": true, "oidc": {"enabled": false, "display_name": "Single sign-on"}}, "organization_name": "", "sign_in_banner": "" }` (both plain text, `""` when unset) |
| GET | `/api/v1/auth/oidc/login` | 302 to the configured IdP, with short-lived pre-login cookie |
| GET | `/api/v1/auth/oidc/callback` | code exchange; 302 to `/` on success, fixed-code login error otherwise |
| POST | `/api/v1/session` | body `{ "token": "…" }` → `Session` + cookie |

Authenticated (`viewer` and above unless noted):

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/session` | `Session` |
| POST | `/api/v1/session/tenant` | body `{"tenant":"bravo"}` → `Session` + rotated session cookie/CSRF; cookie authentication required |
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
16 concurrent streams (503 beyond). Observation JSON is encoded once per tenant/event
and shared across its node-filter classes; heartbeat frames remain per stream.

## Audit actions

`session.login`, `session.login_failed`, `session.logout`,
`session.oidc_login`, `session.oidc_denied`, `session.tenant_switch`,
`investigation.create`, `investigation.update`, `investigation.note`,
`investigation.attach`, `investigation.detach`, `audit.read`, `audit.verify`,
`authz.denied`, `event.read`, `export.events`, `account.create`, `account.update`, `key.create`,
`key.revoke`, `session.revoke`, `preferences.update`, `audit.export`, `role.create`, `role.update`,
`role.delete`, `settings.update`, `settings.revert`, `posture.accept`, `posture.unaccept`. Records may carry `actor_id`
(stable principal id). Token values, key digests, session identifiers and note bodies are never
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
  across at most 4096 addresses; sessions are capped at 1024 per tenant (32768 globally). Expired cookie SSE
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
- SSO via OIDC (experimental) and logical tenant isolation (experimental) are
  opt-in local capabilities. They do not isolate a compromised process or host.

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
uses logical tenant isolation (experimental); it is not a hosted service. Evidence reception is an additional off-by-default consent boundary.

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
active-tenant fleet view. Recommendations continue to use local evidence only; no cross-node
correlation is implemented. Related events resolve within an origin. Legacy investigation
annotations use bare event IDs and resolve local observations only; node-scoped annotations
are not implemented. A forwarded event cannot inherit a local investigation by colliding with its ID.

Forwarded index history is live-only after restart, including plaintext copies. Retention
and bounded-index eviction are independent; index entries can outlive hub retention until
index eviction. `index.history` reports `unavailable` on accepting hubs. Inspect the native
per-node copies locally for retained history, with explicit read identities when encrypted.


## OIDC and tenant contract (ADR-0019, ADR-0020)

`meta.auth.token` controls both bearer and token-session authentication.
`oidc.enabled` means configured, not a live provider readiness assertion. The
UI links to `/api/v1/auth/oidc/login` and renders `display_name` as plain text.

OIDC is Authorization Code + S256 PKCE, state and nonce, for public clients or
confidential clients using HTTP Basic client authentication. The callback accepts
only single-valued `state`, `code`, `error`, `error_description`, `iss` and
`session_state`; provider text is discarded. Error redirects are exactly
`/#/login?error=<code>` where code is `unavailable`, `rate_limited`,
`invalid_request`, `invalid_state`, `invalid_identity` or `access_denied`.
The host-only `aegismesh_oidc` cookie has Path `/api/v1/auth/oidc`, HttpOnly,
SameSite=Lax and Max-Age=120 (Secure with console TLS). Pending state is
server-side, single-use, 120 seconds, at most 128 entries globally. Missing or
foreign browser cookies fail closed. The registered redirect authority must
match the bound console listener; the login request must use that exact authority.

Successful callbacks rotate an existing session and create the same session
format as token login. The cookie is HttpOnly, SameSite=Strict, Path `/`, Secure
with TLS; `Expires` is capped by the ID token's actual expiry and configured
session TTL. It has no longer-lived Max-Age override. `auth_method` is `token`
or `oidc`. Session responses repeat `tenant`/`tenants` at the top level and in
`principal`; membership is fixed at login. Token bearer requests select the
first configured operator tenant and have no mutable active-session state.
`POST /session/tenant` with bearer auth returns 400; cookie callers must supply
CSRF and same Origin as for every mutation. Undeclared or nonmember tenant →
404 `{"error":{"code":"not_found","message":"tenant not found"}}`.
Switching rotates both session ID and CSRF, preserves the original expiry and
invalidates the old session and its streams. OIDC initial tenant is the first
lexicographically sorted mapped membership; token initial tenant is the first
configured membership. Logout stays local: no RP-initiated logout, token refresh,
UserInfo fetch or provider session revocation is implemented.

All authenticated routes select a startup-created tenant view before accessing
data. Lists, overview, sources, related events, by_node, recommendations,
investigations, audit and SSE use only that tenant's index/stores. Local sensors,
rules, agent status and node metadata belong to `console.local_tenant`; other
tenants receive empty sensor/rule lists, no local agent telemetry and 404 for
`/node`. Their `/fleet` still reports their hub availability. Foreign IDs follow
the same 404 code/body and store lookup as absent IDs; no global existence probe
runs. In configurations with multiple tenants, new investigation evidence
references must resolve to that tenant's local index (404 otherwise); already
attached, evicted references can still be detached. Existing bare-ID annotations
remain local-only; forwarded-event annotation support is not implemented.

Each tenant has independent 1000-investigation/32 MiB snapshots, up to 100 notes
per investigation, 200 event references, 100 outstanding enrollment tokens,
1000 fleet nodes including tombstones, 256 MiB forwarded retention and a 64 MiB
accounted evidence index. Existing per-node forwarding budgets remain unchanged.
At most 32 declared tenants bounds global totals to 32000 investigations/nodes,
3200 outstanding tokens, 8 GiB forwarded retention and 2 GiB accounted index
bytes; sessions are capped at 1024 per tenant/32768 globally; request concurrency and stream caps remain shared.
Audit chains retain the existing 128-segment/4 MiB limits independently per tenant.
These bounded quotas do not reserve disk or isolate process CPU/RSS.

`FleetNode`, outstanding token metadata and mint responses gain `tenant`.
Raw enrollment secrets remain opaque one-use values whose hash is stored only
in the minting registry. Enrollment binds a public key immutably to that registry;
a later token from another tenant cannot move it. Machine signatures and wire
schemas do not accept a tenant field from agents. Accepted forwarded evidence
uses the owning registry's index, never an agent-selected partition.

Audit records for OIDC gain optional `issuer` and `subject` fields, the stable
`iss` + `sub` pair; display name remains `actor`. Existing records omit the new
fields and their canonical hashes stay valid. Successful actions and role/CSRF
denials go to the active tenant's chain. Switching is recorded in the departing
chain without naming the target tenant. Authentication attempts with no resolved
tenant go to the fixed `authentication/` chain in multi-tenant configurations
(no console API for this operator-inspected chain); single-tenant behavior keeps
them in its existing chain. Provider diagnostics, codes, tokens and cookies are
never audited.

Non-index assets negotiate gzip above 256 bytes for text/JS/JSON/SVG when smaller.
The startup manifest's 32 MiB cap includes compressed variants; individual raw
files remain capped at 16 MiB and file count at 1024. Non-index responses use
`Cache-Control: no-cache`, representation-specific strong SHA-256 `ETag` and
`Vary: Accept-Encoding`. Matching `If-None-Match` (including lists, weak validators
and `*`) returns 304; headers/CSP remain unchanged. Ranges are ignored: 200 full
representation, no Content-Range/Accept-Ranges. Excluding every available encoding
returns 406. `/` (index.html) stays `no-store` with no ETag or compression.
`by_sensor` has at most 64 entries; each `buckets` array has exactly the same
starts, length and classification fields as `overview.buckets`, including zeros.
When more sensor IDs occur across a fleet, only the first 64 represented in
newest-first evidence are detailed; the main totals still include all events.


### AI pack rule metadata addition (uncommitted)

`GET /api/v1/rules` adds `frameworks: [{framework, id, name}]` to each Rule,
using the same catalog as `rules list`/`explain`. References are editorial
"relates to" mappings, not coverage or completeness claims. AGT-001 reflects
the defender-mirrored technique; it does not prove attacker use. HT-001 has
severity `critical`; all six appended AI/token rules are observe-only.
Native event observations may contain safe `ai_family`, `credential_class`,
and `token_id` finding metadata. Auth-attempt digests are memory-only and are
excluded from the index, API envelope JSON and all durable/exported evidence.
See [../ai-threat-detection.md](../ai-threat-detection.md).

## Attacker sessions, framework relations and downloads (ADR-0022)

These are deterministic read projections of already redacted evidence. There is
no model call, connector, new console egress, enforcement or evidence mutation.
An observed source key is not an actor identity; NAT and proxies can combine
clients. The existing listener, tenant selection, viewer/analyst hierarchy,
Host/Origin/authentication checks, body rejection, eight-handler capacity and
error envelope apply. Unknown/duplicate query keys are rejected. No new config
field or dependency is introduced. UI and dev mock support are separate work.

| GET route | Role | Selection and response |
|---|---|---|
| `/api/v1/sessions` | viewer | `window=1h\|24h\|7d` (default 24h), exact `source` (<=255 bytes), `limit` (default 50, 1..200), `cursor`; `{sessions:[Session],total_matched,next_cursor,as_of,window,bounds}` |
| `/api/v1/sessions/{id}` | viewer | No query; `Session` fields plus `{timeline:[TimelineEvent],phases:[Phase],timeline_truncated,bounds}` |
| `/api/v1/coverage` | viewer | `window` as above; `{frameworks:[{framework,techniques:[{id,name,rule_ids,observed_event_count,last_seen}]}],since,until,interpretation,bounds}` |
| `/api/v1/export/indicators` | analyst | Exactly one of `session=<id>`, `source=<key>`, `investigation=<id>`, `window=<window>`; required `format=stix\|csv\|txt`; attachment |
| `/api/v1/sessions/{id}/report` | analyst | No query; deterministic `text/markdown` attachment; when `console.organization_name` is set, the Scope section adds an `Organization: …` line after the tenant, quoted and fenced like all report text |
| `/api/v1/investigations/{id}/report` | analyst | No query; deterministic `text/markdown` attachment, including attached notes; same optional `Organization: …` line |

`bounds` is `{index:{events,capacity,oldest,history},scanned_events,scan_limit:8192,
scan_truncated}`. One locked snapshot samples the newest 8192 entries before
selection; a sparse source/investigation/window can therefore have no sampled
events even when older entries remain indexed. History is `complete`,
`truncated` or `unavailable` under the existing index contract. Neither complete
history nor an untruncated scan establishes completeness outside this process's
retained index. Response bodies are at most 2 MiB; an oversized response returns
503 `unavailable` with no partial download. STIX also caps object construction
at approximately 2048 objects (a final bounded group can cross this guard before
failure). Reduce list limit or export scope after a size error.

### Session contract

A session joins consecutive events with the same nonempty source key in the
sample, including signals and all authenticated node origins, until an idle gap
is **greater than 30 minutes**. Exactly 30 minutes stays in the session. Empty
source keys are excluded rather than combined. Time order is native timestamp,
then `local|node_id:event_id` lexical order for ties. The 32-hex ID is the first
128 bits of SHA-256(JSON array `[tenant,source,first_origin_event_key]`). This
is stable while that first retained event stays first; eviction, restart,
late equal-time arrivals or sample movement can change it. No session state is
persisted. Foreign, evicted and absent IDs return the same 404. Malformed IDs
return 400.

Grouping precedes list window selection: return sessions overlapping the
inclusive interval `[as_of-window,as_of]`. Counts and detail include the whole
sampled session, including context outside that interval. Source selection is
exact. Sort sessions by last seen descending, then session ID ascending.
Cursors are HMAC authenticated, tenant/process scoped, and bind source, window,
snapshot digest and the first page's `as_of`. Limits may change between pages.
Changed evidence, changed filters, restart, tampering, cross-endpoint or
cross-tenant reuse returns 400; restart pagination without the cursor.

`Session` fields (arrays and maps are present even when empty):

```json
{
  "id":"32 hex", "source":"observed peer key",
  "first_seen":"RFC3339Nano UTC", "last_seen":"RFC3339Nano UTC",
  "duration_ms":1000, "event_count":8,
  "sensors":["sensor-id"], "sensor_kinds":["http"],
  "sensors_truncated":false,
  "classification_counts":{"interaction":7,"correlation_signal":1},
  "rule_ids":["LLM-001","COR-005"], "max_severity":"low",
  "frameworks":[{"framework":"mitre-attack","id":"T1595","name":"Active Scanning"}],
  "cadence":{"min_gap_ms":0,"median_gap_ms":100,"p90_gap_ms":200,
    "events_per_minute":60,"regularity":0.75},
  "automation":{"assessment":"inconclusive",
    "evidence":[{"code":"insufficient_events","detail":"fixed explanatory prose"}]}
}
```

Durations/gaps are numeric milliseconds and can be fractional. `max_severity`
is empty if no detection severity is mapped (correlation signals have no catalog
severity). Sensors and kinds are unique/sorted and independently capped at 64,
with `sensors_truncated`; rule IDs and framework references are unique/sorted
catalog values. Classifications count retained envelopes, including signals.

Cadence uses all retained session events: nonnegative adjacent gaps, upper
median (`sorted[len/2]`), nearest-rank p90 (`ceil(.9*gap_count)-1`), and rate
`(event_count-1)/elapsed_minutes`. Rate is zero for zero elapsed time. Regularity
is the fraction of gaps whose absolute distance from the upper median is
<=25% of that median; for a zero median, only zero gaps count. No gaps yields
all zeros. Zero timestamps/gaps can reflect clock precision or scheduling.

Automation **separately excludes correlation-signal events from timing and
minimum-count checks** to avoid artificial sub-second gaps. At least eight
non-signal events are required for any assessment other than `inconclusive`.
With eight or more, any listed predicate yields
`consistent_with_automation`; otherwise `mixed` means none of these selected
predicates established consistency, not evidence of a human/automated mixture.
Evidence codes, in deterministic order:

- `sub_second_cadence`: interaction upper median gap <1000 ms, including zero;
  this is cadence, not a measured request/response reaction.
- `regular_cadence`: median in [1000,30000] ms and at most one interaction gap
  outside median +/-25%.
- `agent_canary`, `correlation_cadence`, `multi_surface_enumeration`,
  `honeytoken_replay`, `cross_sensor_replay`: AGT-001, COR-005, COR-006,
  HT-001 and COR-008 respectively were present in sampled session rules.
- `insufficient_events`: fewer than eight non-signal observations, even when
  one of the rule predicates is present. Evidence remains listed.

This is an observation with supporting evidence, never an automation verdict,
LLM attribution or a claim that an observed technique succeeded.

Detail timeline contains the **first 200** chronological session events:
`{event_id,node_id,time,gap_ms,sensor,kind,classification,rule_ids,summary}`.
`node_id` is `local` for local events. `gap_ms` is null on the first event.
Phases segment that same capped timeline into contiguous runs:
`{stage,first_seen,last_seen,event_ids}`. Static precedence is:

1. `decoy_credential_replay`: HT-001 or COR-008.
2. `ai_service_abuse`: LLM-002, LLM-003, AGT-001, PI-001, PI-002 or ESC-001.
3. `credential_access`: EXF-001, LLM-004, COR-007 or SSH kind.
4. `discovery`: all other observations.

Stages can recur or appear in any order; segmentation describes evidence,
not a forced attack lifecycle or inferred intent. `timeline_truncated` also
means the phases cover only that prefix. Node-qualified timeline entries
resolve colliding fleet IDs; phase event IDs are bare references into it.

### Framework relations

Always returns the catalog's `mitre-attack`, `mitre-atlas`, `owasp-llm-2025`
mappings, including unobserved techniques (`0` and empty `last_seen`). Counts
use unique retained entries per technique, even when several rules map there,
in the inclusive selected window. Rules and techniques are sorted by ID;
frameworks have the order above. Disabled rules remain catalog relations.
This answers "which techniques our rules relate to, and what we observed";
it is not coverage/completeness, compliance, technique execution or attribution.
AGT-001 references the defender-mirrored technique as documented in the AI pack.

### Indicator downloads

Only literal IPv4/IPv6 source keys are eligible. IPv4-mapped IPv6 normalizes to
IPv4; zone identifiers, hostnames, host:port values, empty keys and other strings
are skipped and counted. No DNS lookup or provider validation occurs. Deduplicate
canonical IPs and origin-qualified event references. Confidence is **15/100**,
deliberately low: decoy contact is an observation. Session scope includes its
sampled context; source scope includes all sampled events for that key;
investigation scope resolves only attached local bare event IDs, preserving
legacy annotation semantics; window scope selects individual events.

Downloads use fixed filenames (`aegismesh-indicators.json|csv|txt`),
`Content-Disposition: attachment`, and the existing no-store/security headers.
No input selects a filesystem path. All downloads add:
`X-AegisMesh-Index-History`, `X-AegisMesh-Index-Events`,
`X-AegisMesh-Scanned-Events`, `X-AegisMesh-Scan-Limit`,
`X-AegisMesh-Scan-Truncated`. Indicators add
`X-AegisMesh-Skipped-Non-IP-Sources` and `X-AegisMesh-Skipped-Non-IP-Events`.
CSV with no indicators contains only its header; skip counts remain in headers
(and CLI stderr). TXT includes skip counts even when empty.

STIX follows [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html):
a bundle of synthetic instance identity, low-confidence IP indicators, evidence
notes, ATT&CK/ATLAS attack-pattern references and `related-to` relationships.
Notes link exact `local|node_id:event_id` references without copying observations.
OWASP mappings remain in sessions/reports; they are not emitted as ATT&CK/ATLAS
attack patterns. Indicator patterns are `[ipv4-addr:value = 'IP']` or
`[ipv6-addr:value = 'IP']`, `pattern_type:stix`, `pattern_version:2.1`, with
`valid_from`, created/modified timestamps and descriptions preserving uncertainty.
The export summary note includes skipped counts. Every contained SDO/SRO has
`spec_version:"2.1"`; the bundle itself has no spec_version, per the specification.
IDs are deterministic RFC 4122 UUIDv5 (DNS namespace, JSON array name including
type). Identity namespace derives from trusted console state directory plus
tenant; paths are hashed, never exported. CLI uses the sorted native instance
labels instead. These namespaces need not produce equal console/CLI identity IDs.
Static identity/catalog metadata has fixed 2026-01-01 timestamps; observed bounds
use UTC RFC3339 with nine fractional digits. Changing indicator content yields a
new immutable ID. No TAXII delivery or validation against an external SIEM is
claimed; tests check required properties, patterns, UUIDs and resolved references.

CSV columns: `indicator,type,first_seen,last_seen,event_count,confidence,
interpretation,skipped_non_ip_sources,skipped_non_ip_events`. Only IPs populate
the indicator column. TXT has one canonical IP per line after a **PROPOSED
blocklist for operator review; never applied by AegisMesh** comment header.

### Observation reports and audit

Markdown reports contain scope, bounded timeline, sources (up to 64), rules with
editorial mappings, automation observations (up to 200 session groups), notes,
proposed dry-run recommendations and explicit limits. Omitted counts are shown.
Investigations disclose unresolved attached references; forwarded collisions
never resolve a local attachment. Recommendations use the existing engine on
up to 4096 verified local envelopes, at most 20 proposals. Forwarded inputs and
inputs over the cap are counted as excluded; events evicted after the summary
snapshot are counted as unavailable. Invalid recommendation inputs fail closed
with 503. There is no cross-node recommendation engine. Report filename is
`aegismesh-observation-report.md`; no generated-at clock makes downloads drift.

All variable strings (including titles, notes, sources, summaries and catalog
prose) are capped at 4000 characters, controls and Unicode formatting controls replaced, JSON quoted onto one
line and fenced as text. A leading quote prevents attacker fences from starting
a line; JSON escapes HTML and Unicode line separators. Only static text creates
Markdown structure. Newline formatting within notes is flattened deliberately.
No raw credential values, prompts or request bodies are copied. The report is
not a declaration that an incident occurred or a forensic chain of custody.

Audit adds successful `export.indicators`, `session.report` and
`investigation.report` reads; audit must append before response bytes. Targets
are session/investigation IDs where selected, never raw source keys or note
text. Audit exhaustion/failure returns 503 and no attachment. Existing
`authz.denied` applies to insufficient roles. Sensors, policy and stored evidence
remain immutable through all these routes.

## Round 3 additions (local, uncommitted)

These additions use the existing authentication, tenant selection, Host/Origin,
CSRF, URI/body bounds, eight-handler admission and no-store response policy.
None adds an egress destination or sensor/configuration mutation.

| Method and path | Minimum role | Result |
| --- | --- | --- |
| `GET /api/v1/export/events?format=...&window=24h` | analyst | Bounded audited attachment, formats `cef`, `syslog-rfc5424`, `otlp-json`, `ecs` |
| `GET /api/v1/digest?window=24h` | viewer | Digest JSON, windows `24h`, `7d`, default `24h`; `organization_name` first when `console.organization_name` is set (omitted otherwise) |
| `GET /api/v1/decoys?window=24h` | viewer | `{decoys:[Decoy],bounds:Bounds}`; windows `1h`, `24h`, `7d`, default `24h` |
| `GET /api/v1/honeytokens?window=24h` | viewer | `{honeytokens:[Honeytoken],bounds:Bounds}`; same windows/default |

Export events accepts **exactly one** of `session`, `source`, `investigation`,
`window`, matching indicator download scopes and validation. Session context
can extend beyond the selected window; investigations resolve attached local
IDs only. Selection is newest-8192 sampled; native lookups are origin-qualified,
with a conservative 2 MiB input budget, and missing references fail closed.
Output is capped at 2 MiB and audited as `export.events` before bytes. Fixed
attachment names are `aegismesh-events-cef.log`,
`aegismesh-events-syslog-rfc5424.log`, `aegismesh-events-otlp-json.json`,
`aegismesh-events-ecs.ndjson`. Content types are text/plain, application/json
(OTLP), application/x-ndjson (ECS). Bounds headers match indicator downloads.
There is no disk path parameter. **OTLP is format only; AegisMesh does not ship
an OTLP exporter.** [Format/escaping/severity contract](../siem-export.md).

The digest captures one `as_of` and compares `[as_of-window,as_of)` with the
immediately preceding equal window. Both totals count classifications, sources
and active sensors. Source novelty and technique novelty are relative to the
preceding sample, not first-ever observations. Automation session counts reuse
retained source sessions and their eight-non-signal minimum; a session counts
once if any event overlaps the current window and its full sampled context is
consistent with automation. No client identity is inferred. Honeytoken/agent
hits count events with HT-001/AGT-001, once per rule per event. Top rules are the
ten largest event counts with stable ID ties and static catalog title/severity.
New techniques are unique `{framework,id,name}` references absent from the
preceding window, sorted by framework then ID. Open investigations count every
current annotation whose status is not closed, independent of evidence window.
Recommendations use at most 4096 current-window local verified envelopes, at
most 20 proposed dry-run recommendations; forwarded, over-cap and evicted
references are counted explicitly. This is on demand, without scheduling.

```jsonc
// Digest — arrays are present even when empty
{
  "window":"24h", "as_of":"RFC3339Nano UTC",
  "totals":{"events":9,"interaction":8,"canary_invocation":1,"correlation_signal":0,"sources":2,"sensors_active":2},
  "previous_totals":{"events":2,"interaction":2,"canary_invocation":0,"correlation_signal":0,"sources":1,"sensors_active":1},
  "new_sources":1, "returning_sources":1,
  "sessions_consistent_with_automation":1,
  "top_rules":[{"rule_id":"MCP-001","title":"declared synthetic credential content was requested","severity":"medium","events":1}],
  "new_techniques":[{"framework":"mitre-atlas","id":"AML.T0055","name":"Unsecured Credentials"}],
  "honeytoken_hits":1, "agent_canary_hits":0,
  "open_investigations":2, "dry_run_recommendations":1,
  "bounds":{"index":{"events":11,"capacity":50000,"oldest":"…","history":"complete"},"scanned_events":11,"scan_limit":8192,"scan_truncated":false},
  "limits":{"interpretation":"Retained observations, not incidents, client attribution or technique execution; no scheduler or delivery.","history":"complete","scan_truncated":false,"source_comparison":"New means absent from the preceding sampled window, not first-ever seen.","investigations_available":true,"recommendation_excluded":0,"recommendation_missing":0,"recommendation_cap":20}
}

// Decoy — only configured local surfaces of the active local_tenant
{"id":"ai-workspace","kind":"mcp","listen":"127.0.0.1:8002",
 "surface_families":["mcp_environment"],"rules":0,"tools":5,"fake_files":2,
 "honeytoken_ids":["decoy-key"],"events":4,"last_activity":"RFC3339Nano UTC"}

// Honeytoken — ID and kind are safe catalog metadata, never the marker value
{"id":"decoy-key","kind":"credential","sensor_ids":["ai-api","ai-workspace"],
 "hit_count":1,"last_hit":"RFC3339Nano UTC","sources":["192.0.2.4"]}
```

Catalog arrays are sorted by ID; families, planted IDs, sensor IDs and sources
are sorted/unique. Metadata derives once from the effective config, with no
bodies, schemas, prompts, env content or token values retained in the console
catalog. HTTP families derive from configured static paths (vLLM profile rule
names disambiguate its shared paths); unclassified HTTP surfaces use `http`.
Tool counts include five environment tools; rule counts combine HTTP/TCP static
rules; fake file counts exclude synthetic env/query entries. Planting is found
only in inline configured response material; external body files are not read
for this catalog, so their planting is not inferred. A token with no detected
planting has `sensor_ids:[]`. Other tenants get empty local catalogs, even
administrators. Forwarded observations do not count as hits or activity for
local-config catalogs, avoiding node/sensor-ID collisions. Activity/hits use the
selected half-open window within the newest 8192-event snapshot; empty last
activity/hit is `""`. Honeytoken counts use exact configured IDs from detection
metadata; several tokens can each count on the same event. Bodies/values are
never returned. These are observations, not proof of successful secret use.

Existing types gain:

```jsonc
// Rule, all catalog records have nonempty static prose
{"id":"MCP-001","family":"detection","title":"declared synthetic credential content was requested",
 "description":"Declared synthetic credential content was requested from the workspace.",
 "guidance":"Check the connection tool sequence and later HT-001 or COR-008 observations.",
 "severity":"medium","enabled":true,"observe_only":true,"frameworks":[]}
// Overview (additions)
{"index":{"events":0,"capacity":50000,"oldest":"","history":"complete"},
 "top_rules":[{"rule_id":"PI-001","title":"instruction-override phrasing directed at an automated agent","severity":"high","events":1}]}
// EventDetail (addition)
{"session_id":"32 hex, or empty if outside retained analysis sessions"}
// Source detail (addition beside source/events/next_cursor)
{"inter_arrival":[{"lt_ms":100,"count":0},{"lt_ms":1000,"count":0},{"lt_ms":10000,"count":7},{"lt_ms":60000,"count":0},{"lt_ms":300000,"count":0},{"lt_ms":1800000,"count":0},{"lt_ms":null,"count":0}]}
```

`observe_only` is true for all correlation signals and detection rules that
cannot select a response action. It does not suppress older findings on the
same interaction. Top-rule severity now comes from the rule's own catalog
entry, including empty severity for correlations, rather than another finding
on the same event. `index.events==0` explicitly means the index is empty;
nonzero occupancy with zero window totals is a quiet window. History still
qualifies completeness. Event-session links use the newest 8192 retained
summaries and authenticated origin, so colliding fleet IDs cannot link the
wrong event; evicted anchors can change session IDs. Raw detail reads are now
sensitive reads: `event.read` is audited with `local|node_id:event_id` before
response bytes, even for viewers. Audit unavailable/exhausted means 503 with
no envelope. This also applies to HEAD's GET handler semantics.

Inter-arrival uses **all** retained events for the exact source, independent of
page limit, cursor or the 8192 analysis sample. It sorts by index timestamp /
append order and counts each nonnegative adjacent gap, including equal-time
arrivals and correlation signals. Buckets have exclusive upper bounds
100 ms, 1 s, 10 s, 1 min, 5 min, 30 min, then infinity (`lt_ms:null`). Thus exact
1 s enters the `<10 s` bucket. Sum of counts is retained source count minus
one. This includes generated signals and clock/scheduling artifacts; it is not
an automation assessment. No events yields zero counts. No new query parameter
is accepted on source detail.

Malformed/duplicate/unknown query parameters or bodies on the new GET routes
return 400. Export scopes use the existing 512-byte generic query cap and
255-byte source cap. Invalid Bearer authorization attempts are separately
budgeted from browser login attempts: ten/address/minute across the existing
4096-key throttle table, then 429 with Retry-After 60. Successful Bearer reads
do not consume this budget; once exhausted that remote must wait before retrying
a valid Bearer token. Cookie sessions remain independent. Bounds are process
local and are not a distributed rate-limit or hard tenant boundary.

### Digest availability and null fields (clarification)

`GET /api/v1/digest` returns **503 `unavailable`** when (1) the recommendation
input lookup is refused (`digest recommendation inputs exceed limits`; the
handler caps lookups at 4096 IDs, so this is defensive), (2) recommendation
generation rejects a retained local envelope, for example a duplicate identity
or an envelope failing recommendation validation (`digest cannot produce
verified recommendations`), (3) the encoded report would exceed 2 MiB, or (4)
the shared admission/shutdown/audit-state conditions every route has. No
partial digest is returned. Bad `window` or unknown/duplicate query keys are 400.

`open_investigations` is typed `number | null` because the digest schema is
shared with `aegismesh digest`. The console always computes it from the
tenant's open investigation store, so the console API returns a number (and
`limits.investigations_available: true`). The CLI returns `null` with
`investigations_available: false` when `--investigations-dir` does not exist,
because an absent store is unknown, not zero. Clients must still accept null.
`organization_name` is likewise console-only: `aegismesh digest` reads no
console settings, so its JSON omits the field and its Markdown has no
`Organization:` line. When present, Markdown renders it quoted and fenced like
every other digest value.

## Round 4: campaigns, actor profile and posture (ADR-0024)

All three are viewer GET routes with the existing authentication, tenant
selection, Host/Origin checks, body rejection, eight-handler admission,
no-store responses and 400 for any query parameter (none are accepted).
Responses are capped at 2 MiB (503 otherwise). They read the same
newest-8192 analysis snapshot as sessions; nothing is persisted, no egress,
model or enforcement is added. Rules and limits:
[ai-threat-detection.md](../ai-threat-detection.md#campaigns).

| GET route | Result |
|---|---|
| `/api/v1/campaigns` | `{items:[Campaign],scanned_sessions,truncated,session_limit:4096,campaign_limit:100,total_campaigns,generated_at,bounds}` |
| `/api/v1/campaigns/{id}` | Campaign plus `{steps,steps_truncated,sessions,sessions_truncated,caveats,generated_at,bounds}`; malformed ID (not `cmp_` + 12 lowercase hex) 400; unknown, foreign-tenant or no longer sampled 404 |
| `/api/v1/posture` | `{generated_at,scope,summary:{attention,ok,info},checks:[Check],disclaimer}`; every console check also carries `acceptable` and `acceptable_reason` (below) |

`truncated` is true when more than 4096 sessions existed or more than 100
campaigns matched (`total_campaigns` gives the full count). Campaigns sort by
`last_seen` descending, then ID. Arrays are never null; `automation_counts`
always has the four actor assessment keys.

Each `/api/v1/posture` check has `"acceptable": true|false` and
`"acceptable_reason"`, always present. The reason is `""` when acceptable;
otherwise the first that applies of `permission_denied` (caller lacks
`settings.manage`), `editing_disabled` (`console.settings_editing` is off; a
POST returns 409), `overlay_unavailable` (settings overlay problem; POST 503),
`already_accepted` (the check is currently accepted; `DELETE` removes it, and a
POST would replace the acceptance) and `not_attention` (the local view's
unaccepted status is not `attention`; POST 409). Acceptance is instance-wide,
so the status test uses the local tenant's configuration and evidence, as the
POST does. `true` means the request would be admitted now; a valid reason and
expiry are still required. The CLI's `aegismesh posture` output is unchanged.

```jsonc
// Campaign (list item). Fields beyond the round-4 contract: fingerprint_steps,
// session_ids_truncated, client_families.
{"id":"cmp_ea5e7da9f36e","label":"GET /api/tags → GET /v1/models → POST /v1/chat/completions",
 "basis":["same_step_sequence","same_client_family"],"fingerprint_steps":3,
 "source_count":2,"sources":["192.0.2.10","198.51.100.20"],"sources_truncated":false,
 "session_count":2,"session_ids":["32 hex","32 hex"],"session_ids_truncated":false,
 "event_count":14,"first_seen":"RFC3339Nano UTC","last_seen":"RFC3339Nano UTC",
 "sensor_kinds":["http"],"rule_ids":["LLM-001","LLM-002"],"max_severity":"medium",
 "stages":["discovery","ai_service_abuse"],"client_families":["openai_sdk"],
 "automation_counts":{"inconclusive":1,"likely_automated":1,"likely_human":0,"possibly_ai_agent":0}}
// Campaign detail additions
{"steps":[{"index":0,"sensor_kind":"http","shape":"GET /api/tags","stage":"discovery","sessions":2}],
 "steps_truncated":false,
 "sessions":[{/* Session */ "step_marks":[{"index":0,"offset_ms":0},{"index":2,"offset_ms":4000}]}],
 "sessions_truncated":false,
 "caveats":["Shared behaviour does not prove a shared operator; …"]}
// Session additions (list, detail, campaign detail)
{"campaign_id":"cmp_… or null",
 "actor":{"assessment":"possibly_ai_agent","summary":"Behaviour is consistent with … not attribution.",
   "signals":[{"code":"tool_call_chaining","label":"MCP tools were discovered and then called in a chain",
     "strength":"strong","present":true,"detail":"3 tool call(s) across 2 tool(s); tools/list before first call: true"}]}}
// Posture check
{"id":"POS-014","area":"detection","status":"attention","title":"Correlation engine and rules",
 "detail":"Correlation is disabled, …","recommendation":"Set correlation.enabled: true.",
 "doc":"docs/ai-threat-detection.md#correlation-rules"}
```

Step `stage` uses the session phase vocabulary (`discovery`, `ai_service_abuse`,
`credential_access`, `decoy_credential_replay`); `stages` is the distinct set in
that order. `steps` holds, per position, the most common kind/shape among
members long enough to have it (ties lexical), so `sessions` can be below
`session_count` after the fingerprint prefix. `step_marks` lists positions
where that member's own step equals the representative step, with the offset
from the member's first interaction. `shape`, `label` and `sources` are
attacker-influenced text: render as text. `posture.scope` is
`configuration_and_evidence` for the configured `local_tenant` and
`evidence_only` (POS-017 only) for other tenants, which never see local
configuration. Posture details never contain token values, digests, URLs or
secret references.

## Accounts, access and settings (ADR-0025)

Implements the round-5 contract. All routes use the existing authentication,
Host/Origin checks, strict 64 KiB JSON bodies, cookie CSRF for mutations and
the eight-handler admission. Arrays are never null; times are RFC 3339 UTC.

**Principals.** Every principal has a stable `id`: `cfg:<name>` (config-file
operator, read-only here, the break-glass path), `acc_<16 hex>` (managed
account, API keys only, no passwords) or `oidc:<12 hex>` (HMAC of issuer and
subject; neither is exposed). `Principal` in `/session` gains `id`, `source`
(`config|managed|oidc`) and `kind` (`person|service`). OIDC identities are
listed after their first sign-in (bounded directory of 1000, least recently
seen evicted; no tokens are kept).

| Method | Path | Role | Result |
|---|---|---|---|
| GET | `/api/v1/me` | viewer | `Me` |
| GET/PUT | `/api/v1/me/preferences` | viewer | `Preferences`; PUT merges the given keys, unknown keys or values → 400 |
| GET | `/api/v1/me/sessions` | viewer | `{"items":[Session]}` of the caller's principal |
| DELETE | `/api/v1/me/sessions/{handle}` | viewer | 204; another principal's or unknown handle → 404; the current one also clears the cookie |
| GET/POST | `/api/v1/me/keys` | viewer | managed accounts only (else 403): `{"items":[Key]}` / 201 `{"key":Key,"token":"amk_…"}` |
| DELETE | `/api/v1/me/keys/{key_id}` | viewer | 204 (idempotent for an already revoked key) |
| GET/POST | `/api/v1/admin/accounts` | admin† | `{"items":[Account],"limits":{…}}` / 201 `Account` |
| GET/PATCH | `/api/v1/admin/accounts/{id}` | admin† | `Account` + `keys`, `sessions` / `Account`; config or OIDC → 409 `not_managed` |
| POST | `/api/v1/admin/accounts/{id}/keys` | admin† | 201 `{"key":Key,"token":"amk_…"}`; disabled account → 409 `conflict` |
| DELETE | `/api/v1/admin/accounts/{id}/keys/{key_id}` | admin† | 204 |
| GET | `/api/v1/admin/sessions` | admin† | `{"items":[Session]}` for every principal and tenant |
| DELETE | `/api/v1/admin/sessions/{handle}` | admin† | 204 |
| GET | `/api/v1/admin/settings` | admin† | `Settings` |
| GET | `/api/v1/admin/audit/export?format=jsonl\|csv&since=RFC3339` | admin† | attachment |
| GET | `/api/v1/system` | admin† | `System` |

† admin role **and** membership of `console.local_tenant` (otherwise 403,
audited as `authz.denied`). Administration changes are appended to the local
tenant's audit chain. `/admin/sessions` and `/admin/accounts` show principals of
every tenant: metadata only, never evidence (ADR-0025 exception to ADR-0020).

```jsonc
// Me
{"id":"acc_fc92e7e510f57147","name":"Dana Analyst","kind":"person","source":"managed","role":"analyst",
 "tenants":["default"],"tenant":"default","auth_method":"token","created_at":"…","last_seen_at":"…",
 "capabilities":{"manage_own_keys":true,"administer":false}}
// created_at: account creation (managed) or first sign-in (OIDC); null for config operators.
// last_seen_at: last key use (managed, minute resolution), last sign-in (OIDC), or in-memory
// activity since process start (config); null when unknown.
// manage_own_keys: source managed and token authentication enabled.
// administer: role admin and member of local_tenant.

// Preferences (defaults shown)
{"timezone":"utc","default_window":"24h","density":"comfortable","theme":"system","reduce_motion":"system"}

// Session
{"handle":"ses_<16hex>","current":true,"auth_method":"token","tenant":"default","created_at":"…",
 "last_seen_at":"…","expires_at":"…","idle_expires_at":"… | null","remote":"203.0.113.7",
 "client":"Chrome on macOS","account_id":"cfg:alice","account_name":"alice"}
// handle = HMAC of the session id under a per-process key; it is never a credential.
// client is one of: "<Chrome|Edge|Firefox|Safari|Opera> on <Windows|macOS|Linux|iOS|Android|ChromeOS>",
// a browser name alone, "curl", "Wget", "Go HTTP client", "Python client", "Node.js client",
// "PowerShell", "Other client", "Unknown client". Bearer requests have no session.

// Key (never contains the digest; token only in the 201 response)
{"id":"key_941d642de1f4","label":"laptop","prefix":"amk_VdYe","created_at":"…","created_by":"acc_…",
 "expires_at":"…","last_used_at":"… | null","revoked_at":"… | null","status":"active|expired|revoked"}

// Account (additions to the contract: updated_at, editable)
{"id":"acc_…","name":"Dana Analyst","kind":"person","source":"managed","role":"analyst",
 "tenants":["default"],"status":"active","created_at":"…","created_by":"cfg:admin","updated_at":"…",
 "last_seen_at":"…","active_keys":2,"active_sessions":0,"editable":true}
// config operators: created_at/updated_at null, created_by "config", status "disabled" when
// token_login is false; OIDC identities: created_by "oidc", status always "active".
// limits: {"max_accounts":200,"max_keys_per_account":10,"max_key_days":365,"default_key_days":90}
```

**Rules.** Create body `{"name","kind","role","tenants"}`: name 1..80 printable
runes without surrounding spaces, unique case-insensitively among managed
accounts and config operator names (409 `conflict`); kind `person|service`;
role `viewer|analyst|admin` or a custom role id (ADR-0026); 1..32 declared tenants. PATCH takes any of
`name, role, tenants, status` (empty → 400). Role, tenant or status changes
revoke the account's sessions; disabling also makes its keys fail at once.
Key body `{"label","expires_in_days"}`: label 1..64 printable runes; days
1..365, 0/omitted = 90. An account holds at most 10 keys; at the limit the
longest-inactive revoked or expired key is pruned, and 10 active keys → 409.
Sessions opened with a key expire no later than the key and end when it is
revoked. Event streams re-check their credential before every event and on
every 15 s heartbeat: a stream opened with a managed bearer key closes once the
key is revoked or expired, the account is disabled, or the account no longer
belongs to the stream's tenant, and closes at the key's `expires_at` at the latest. A change leaving no administrator who can sign in → 409
`last_admin`: config admins in `local_tenant` count while token login is on,
managed admins count when active, in `local_tenant` and holding a usable key;
OIDC admins do not count.

```jsonc
// Settings (round 5 shape; ADR-0026 adds editing, effective, file_value, overridden, constraints, applies)
{"generated_at":"…","editable":false,"note":"Settings are read-only in the console; …",
 "sections":[{"id":"access","title":"Access and sessions","items":[
   {"key":"console.session_ttl_seconds","label":"Session lifetime","value":"1h","kind":"duration",
    "source":"config","editable":false,"note":"Change in the config file and restart."}]}]}
// Section ids in order: access, console, sso, tenants, listener, evidence, detection, fleet, exports.
// kind: boolean | duration | count | text | list | bytes | timestamp. Durations are compact ("8h", "30m", "off").
// source: config | env | default, plus "runtime" for observed facts (usage, occupancy, discovery
// state, certificate expiry) that are not settings. Built-in limits use "default".
// Never included: token digests, OIDC client secret (only "file reference"/"environment variable"/"none"),
// issuer path (host only), filesystem paths.

// System
{"version":"…","commit":"…","build_date":"…","go_version":"go1.27.4","started_at":"…",
 "uptime_seconds":3600,"config_schema":"aegismesh.io/v1alpha1",
 "components":[{"id":"console","status":"ok","detail":"serving; 2 live session(s)"},
   {"id":"storage","status":"ok","detail":"1.2 MiB in 3 segment(s); encryption off"},
   {"id":"index","status":"ok","detail":"1200 of 50000 events; history complete"},
   {"id":"sensors","status":"ok","detail":"4 of 4 running"},
   {"id":"fleet","status":"off","detail":"hub and agent disabled"},
   {"id":"oidc","status":"off","detail":"OIDC sign-in is not configured"}],
 "licenses_url":""}
// status: ok | degraded | off, derived from live state. licenses_url is "/licenses" only when the
// embedded UI ships that asset, otherwise "". No host details beyond /api/v1/node.
```

**Audit export.** `format` defaults to `jsonl`; `since` is an inclusive RFC 3339
time. The `audit.export` record is appended to the exported (active tenant's)
chain before any byte is sent. At most 10000 records (oldest first) per
download; `X-AegisMesh-Export-Records` and `X-AegisMesh-Export-Truncated`
report the count and whether more matched (continue with a later `since`).
JSONL lines are the canonical stored records, so the hash chain can be
re-verified offline. CSV columns: `seq,time,actor,actor_id,role,action,target,
outcome,remote,detail,issuer,subject,prev_hash,hash`; cells starting with
`= + - @`, TAB or CR are prefixed with `'`.

**Limits.** Sessions are in memory: a restart signs everyone out and nothing
is shared between processes. Only the ADR-0026 allowlist of settings can be
edited here, and only when enabled. `last_used_at` has one-minute resolution and
is persisted at most once a minute. No SCIM or password login. Account state is
plaintext like investigations.

## Permissions, roles and editable settings (ADR-0026)

Implements the round-6 contract. Same conventions as above: strict 64 KiB JSON
bodies, cookie CSRF and Origin on mutations, arrays never null, RFC 3339 UTC.
Administration changes are appended to the local tenant's audit chain.

**Permission catalogue** (`GET /api/v1/permissions`, any authenticated
principal → `{"version":1,"items":[{"id","group","label","risk"}]}`):

| Permission | Risk | Routes | Built-in |
|---|---|---|---|
| `evidence.read` | low | overview, events, event detail, stream, sources, sensors, rules, node, decoys, honeytokens, attacker sessions, campaigns | viewer |
| `analysis.read` | low | digest, posture, coverage, recommendations | viewer |
| `investigations.read` | low | `GET /investigations[/{id}]` | viewer |
| `fleet.read` | low | `GET /fleet`, `/fleet/nodes[/{id}]` | viewer |
| `keys.self` | low | `/me/keys` (managed accounts only) | viewer |
| `evidence.export` | elevated | `/export/events`, `/export/indicators` | analyst |
| `reports.download` | elevated | session and investigation reports | analyst |
| `investigations.write` | elevated | investigation create, patch, notes, attach/detach | analyst |
| `audit.read` | elevated | `/audit`, `/audit/verify` | admin |
| `audit.export` | elevated | `/admin/audit/export`† | admin |
| `fleet.manage` | high | node revoke, enrollment tokens (list, mint, delete) | admin |
| `accounts.read` | elevated | `GET /admin/accounts[/{id}]`, `GET /admin/sessions`, `GET /admin/roles[/{id}]`† | admin |
| `accounts.manage` | high | account create/patch, account key mint/revoke† | admin |
| `sessions.manage` | high | `DELETE /admin/sessions/{handle}`† | admin |
| `roles.manage` | high | `POST /admin/roles`, `PATCH`/`DELETE /admin/roles/{id}`† | admin |
| `settings.read` | elevated | `GET /admin/settings`, `GET /admin/settings/history`† | admin |
| `settings.manage` | high | `PUT`/`DELETE /admin/settings/{key}`, `POST`/`DELETE /posture/{check_id}/accept`† | admin |
| `system.read` | elevated | `/system`† | admin |

No permission (any authenticated principal): `/session` (GET, DELETE),
`/session/tenant`, `/me`, `/me/preferences`, `/me/sessions`, `/permissions`.
† also requires membership of `local_tenant`. viewer holds the viewer rows,
analyst adds the analyst rows, admin holds every permission; a test pins every
route against each built-in role. Permissions resolve from the role on every
request: a role edit applies at the next request of every key and session
holding it, and event streams close at the next event or heartbeat once
`evidence.read` is gone. A denied permission answers 403 `forbidden` and is
audited as `authz.denied`.

**Roles.**

| Method | Path | Permission | Result |
|---|---|---|---|
| GET | `/api/v1/admin/roles` | accounts.read† | `{"items":[Role],"limits":{"max_roles":32,"max_name_runes":40,"max_description_runes":200}}` (built-ins first) |
| POST | `/api/v1/admin/roles` | roles.manage† | body `{"name","description","permissions":[…]}` → 201 `Role` |
| GET | `/api/v1/admin/roles/{id}` | accounts.read† | `Role` |
| PATCH | `/api/v1/admin/roles/{id}` | roles.manage† | any of `name, description, permissions` → `Role` |
| DELETE | `/api/v1/admin/roles/{id}` | roles.manage† | 204 |

```jsonc
// Role (from a test run)
{"id":"role_b2f285701ad4","name":"Responder","description":"Triage without administration","builtin":false,
 "permissions":["analysis.read","evidence.read","investigations.read","investigations.write"],
 "assigned":{"managed":1,"config":0,"oidc":0},"created_at":"…","created_by":"cfg:admin","updated_at":"…"}
// Built-ins: id = name = viewer|analyst|admin, builtin true, created_by "builtin", created_at/updated_at null.
```

Rules: names 1..40 printable runes, unique case-insensitively, never a
built-in name (409 `conflict`); permissions are catalogue ids, stored sorted
and deduplicated; `roles.manage` and `settings.manage` need `accounts.manage`,
`accounts.manage` and `sessions.manage` need `accounts.read`, and
`settings.manage` needs `settings.read` (400 `invalid_argument`); at most 32
custom roles (409 `conflict`); built-ins cannot be changed or deleted (409
`builtin`); an assigned role cannot be deleted (409 `in_use`); no change may
leave zero active principals able to manage both accounts and roles (409
`last_admin`, counted as in ADR-0025). Managed accounts take `role` = any role
id; account views gain `role_name`. Config operators and OIDC `role_mapping`
keep built-in names. `/me` gains `"role_name"` and `"permissions"` (sorted);
`capabilities.administer` is true when the role grants any of `accounts.read`,
`settings.read`, `system.read` or `audit.export` and the principal belongs to
`local_tenant`; `manage_own_keys` also needs `keys.self`.

**No escalation.** 403 `exceeds_own_permissions` (audited with that detail)
refuses any change that would grant or touch permissions the caller's role
does not hold: creating an account with, or moving one to, a wider role;
changing, disabling, or minting or revoking keys for an account whose role
holds more; creating or widening a role beyond the caller's set; editing or
deleting a role holding more; ending a session of a more privileged principal.

**Editable settings.** `GET /api/v1/admin/settings` (settings.read†) gains a
top-level `"editing":"off|console"`, `editable` (true when editing is on and
the overlay loaded), and per item `effective` and `file_value` (canonical raw
values for allowlisted keys, the display text otherwise), `overridden`,
`constraints` (`{}` when none) and `applies` (`live`, `restart`, or `none` for
built-in limits and observed facts). Overridden items report source `console`.
A new section `console` holds `console.settings_editing`,
`console.organization_name`, `console.sign_in_banner`,
`console.default_window` and `posture.accepted`; `access` holds the session and
key lifetime keys (the round-5 `accounts.key_lifetime` item is replaced by
`console.key_max_days` and `console.key_default_days`).

```jsonc
// Editable item (from a test run)
{"key":"console.session_ttl_seconds","label":"Session lifetime","value":"2h","kind":"duration","source":"console",
 "editable":true,"note":"Editable here with settings.manage; reverting restores the config file value.",
 "effective":"7200","file_value":"60","overridden":true,
 "constraints":{"max":86400,"min":900,"reason_max_len":200,"unit":"s"},"applies":"live"}
// Non-editable item
{"key":"console.listen","label":"Console address","value":"127.0.0.1:51219","kind":"text","source":"config",
 "editable":false,"note":"Change in the config file or the AEGISMESH_CONSOLE_LISTEN environment variable, then restart.",
 "effective":"127.0.0.1:51219","file_value":"127.0.0.1:51219","overridden":false,"constraints":{},"applies":"restart"}
```

| Method | Path | Permission | Result |
|---|---|---|---|
| PUT | `/api/v1/admin/settings/{key}` | settings.manage† | body `{"value":…,"reason":"…"}` → item |
| DELETE | `/api/v1/admin/settings/{key}` | settings.manage† | item reverted to the file value (no body) |
| GET | `/api/v1/admin/settings/history` | settings.read† | `{"items":[Change],"limits":{"max_items":500}}`, newest first |

`value` is a JSON integer for `console.session_ttl_seconds` (900..86400),
`console.session_idle_seconds` (0 or 300..86400), `console.key_max_days`
(1..365, not below the effective default) and `console.key_default_days`
(1..effective maximum), and a JSON string for `console.sign_in_banner` (≤500
printable runes, newlines allowed), `console.organization_name` (≤80, one
line) and `console.default_window` (`1h|24h|7d`). `reason` is required, 1..200
printable characters. Out-of-range values → 400 `invalid_argument`; editing off
→ 409 `editing_disabled`; any other key (including `posture.accepted`, which
uses the posture endpoints) → 409 `not_editable`; an unloadable overlay → 503.
Changes apply live: session lifetime for sessions created afterwards, idle
timeout at once, key limits for keys minted afterwards, banner and
organization name in `/meta`, default window for principals without saved
preferences. With editing off, stored overrides are kept but not applied.

```jsonc
// Change (history; from a test run)
{"seq":1,"key":"console.session_ttl_seconds","from":"60","to":"7200","actor_id":"cfg:admin","actor_name":"admin",
 "reason":"Longer shifts","at":"…"}
// posture.accepted entries: "from":"POS-007: not accepted","to":"POS-007: accepted until 2026-12-24T18:05:19Z"
```

Audit: `settings.update` / `settings.revert` with target = key and detail
`from="…" to="…" seq=N reason="…"` (Go-quoted, truncated to the 256-byte detail
limit; the history entry holds the full values). Values are not secret by
construction.

**Posture acceptance.**

| Method | Path | Permission | Result |
|---|---|---|---|
| POST | `/api/v1/posture/{check_id}/accept` | settings.manage† | body `{"reason":"…","until":"RFC3339"}` → the posture `Check` |
| DELETE | `/api/v1/posture/{check_id}/accept` | settings.manage† | 204; none recorded → 404 |

Only a check whose current status is `attention` can be accepted (409
`conflict` otherwise; unknown id → 404). `until` must be in the future and at
most 180 days ahead. Every posture check gains `"accepted":{"by","by_name",
"reason","until"}|null`; an accepted attention check reports status
`accepted`, `summary` gains `accepted`, and reports gain
`"acceptances":"applied|unavailable"`. Expired acceptances are ignored and
pruned on the next write. Audit: `posture.accept` (detail `until=… reason="…"`)
and `posture.unaccept`, target = check id. New checks POS-020..022 are listed in
`docs/ai-threat-detection.md`. `/api/v1/system` gains component `settings`
(`off|ok|degraded`).
