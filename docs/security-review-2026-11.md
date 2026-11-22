# Console and fleet hub perimeter review — 2026-11-22

Scope: source review of `internal/console/**` and `internal/fleet/hub/**` on
`feat/decoy-environments-siem`, including new round 3 handlers. This is a local
engineering review with regression tests, not an independent audit, penetration
test, deployment assessment or statement that the perimeter is secure. Changes
remain uncommitted. No real IdP, public listener, production tenant or external
SIEM was contacted. Existing opt-in provider/webhook/fleet/OIDC transports are
outside the no-new-egress change.

## Reproduced findings and fixes

| Finding | Before | Change and evidence |
| --- | --- | --- |
| SR-01 — Bearer failure path bypassed login throttling (medium) | Repeated explicit invalid Authorization headers returned 401 indefinitely; only browser login/OIDC admission had a per-remote budget. | Failed Bearer attempts now use a separate `bearer:` namespace in the existing bounded attempt table. Ten invalid attempts/minute, then 429 + Retry-After 60 before further digest checks. Success does not consume this budget; a full table refuses new remote keys and expires old keys before reuse. Missing credentials/cookie failures are not charged to it. `TestBearerFailuresAreRateLimited` failed 401 vs 429 before the fix and passes after it. A failing-first capacity regression additionally covers full-table admission and expiry recovery. |
| SR-02 — hub listener saturation response missed security/cache headers (low) | The eight-slot listener rejects before `Hub.ServeHTTP` installs headers; its 503 had no Content-Type, no-store or nosniff. | Fixed headers now belong to the shared error-response writer, including early capacity rejection. `TestCapacityRejectionAlwaysHasSecurityHeaders` reproduces the exact writer path used by the listener; failed before and passes after. It does not reproduce real socket saturation. |
| SR-03 — raw event reads could disclose redacted envelope without audit (medium, coverage gap) | A viewer could retrieve native observation/related evidence with an unavailable audit writer. Unlike attachments, raw detail reads were not recorded. | `event.read` records the authenticated tenant and origin-qualified ID before any response bytes. Audit failure yields 503 and no envelope. `TestRawEventReadRequiresAuditBeforeDisclosure` failed 200 vs 503 before the fix; successful-read audit assertions and tenant/role tests cover the new behavior. |

Failing-first transcripts: [security-red.txt](performance/2026-11-22/security-red.txt),
[event-read-red.txt](performance/2026-11-22/event-read-red.txt),
[auth-capacity-red.txt](performance/2026-11-22/auth-capacity-red.txt).
The full passing final commands are recorded in [verification.md](verification.md).
SR-01 intentionally holds a remote's Bearer access until the one-minute window
expires after exhaustion, including valid retries. Browser cookies are separate;
remote keys still share a 4096-entry process-wide capacity with login keys.
This can be an availability tradeoff behind NAT and is not distributed abuse
protection. Failed Bearer attempts remain a bounded counter/rate-limit signal,
not per-attempt durable audit writes that an unauthenticated peer can amplify.

## Checked, no additional issue established in this pass

| Area | Source and exercised controls | Boundary / limit |
| --- | --- | --- |
| Route authentication and roles | `routes.go`, `fleet_handlers.go`, `security.go`; actual registered route table feeds `TestEveryRouteAuthorization`. New export is analyst; digest/catalogs are viewer. Only meta, session creation and OIDC entry/callback are unauthenticated. Unknown routes are fixed 404. | Go GET routes also accept HEAD; body/auth/role/audit rules still apply. No wildcard grants or service-role cookie shortcut. |
| Tenant scoping | `tenants.go`, `auth`, `tenant`, hub `tenants.go`; immutable startup partition maps, authenticated active tenant, tenant-scoped case/audit/index/hub stores; all-route token/OIDC isolation tests and new round 3 isolation checks. Local decoy/token catalogs exist only in local_tenant; remote origin collisions do not count as local hits. | Logical isolation only; one process, OS user, data directory and encryption key. No hostile-host boundary. Machine ownership/token selection precedes full signature verification, but never creates a tenant/path from input. |
| Host, Origin, CSRF | Console `security.go`, `oidc_handlers.go`; exact configured authority or loopback alias at actual port; forwarded headers ignored; strict same-origin cookie mutations and constant-time CSRF. Existing Host/CSRF/OIDC tests plus route body tests. | Absent Origin is permitted with valid CSRF for scripts. Signed machine hub accepts no cookies; CSRF/Origin and browser Host binding are not its authentication mechanism. Hub signatures bind method/path/body/time/nonce/node, not Host. This existing protocol limit was reviewed, not redesigned. |
| Session/cookie controls | `auth/auth.go`, session/OIDC handlers; HttpOnly, host-only, SameSite Strict (OIDC pre-login Lax), Secure under TLS, absolute expiry, rotation, logout and tenant switching. SSE checks expiry and revocation. | Local HTTP cookies lack Secure deliberately; non-loopback console requires TLS. OIDC tested with local fixtures only; no provider configuration review. |
| Timing and replay | Constant-time token/CSRF/HMAC comparisons; Ed25519 machine verification, exact duplicate-header checks, bounded skew/nonces and permanent revocation; hub auth/state/abuse/tenant tests. | Map-based lookup of opaque random session IDs is not an attempt to hide valid session existence. Evidence hashes prove payload consistency, not provenance. |
| Request/body/query bounds | Console 8192-byte URI, 16 KiB header cap, strict allowed/unique query values (512 bytes generic), bounded source/IDs/cursors, strict JSON duplicate/unknown rejection at 64 KiB, eight non-stream handlers. Hub 8 KiB headers, signed header validation before body, path-specific MaxBytesReader and strict protocol decoding, eight listener handlers. | Count admission limits active work, not an HTTP connection-count sandbox. Standard server timeouts remain important. No new public-listener load test. |
| Rate/resource bounds | Existing login/session quotas, hub per-remote 8192/minute across 4096 remotes, node/replay/dedup/evidence quotas and sampled rejection audit; SR-01 closes the explicit Bearer gap. | No global HTTP requests-per-second promise. Authorized reads use concurrency admission rather than a per-role rate limiter. Hub rejection audit is sampled/coalesced, not one durable record per bad packet. |
| Attachments and sensitive cache | New format and scope allowlists; fixed filename/type dictionaries; no raw query/source inserted into Content-Disposition. Rendering/size validation/audit precede bytes. `/api/` defaults to no-store and all hub error paths now install it. | CLI output path comes solely from the operator flag and uses exclusive creation. Output IO failure may leave a partial new file. No collector interoperability test. |
| Sensitive-read audit | Audit read/verify, reports and indicator/event downloads fail closed; SR-03 adds raw event detail. Notes and credentials are excluded from targets; origin-qualified event IDs are bounded and derived from validated identities. | Summary/list/overview/digest/catalog reads remain unaudited high-volume reads; they contain bounded projections or value-free configured metadata. Audit is plaintext, count/file bounded, internally hash chained, not tamper-proof to its filesystem owner. |
| SSE | Sixteen process-wide streams, 32 queued events each, five-second writes, fifteen-second heartbeat, expiry/shutdown/drop paths. One immutable observation encoding is shared only inside a tenant index; node filtering still happens per stream. Real loopback tenant/filter/expiry/capacity tests, race tests and shared-frame/slow-drop tests. | Slow or disconnected consumers can lose observations and must query the index. No replay queue/resume guarantee. Synthetic controlled-writer benchmark is not network saturation or p99 evidence. |
| Errors and static content | Fixed error codes/messages hide token, file, note and provider details in HTTP. Assets are startup snapshots with allowlisted names, traversal rejection, CSP/nosniff/ETags; arbitrary evidence remains data. Hub status is self-report, not attestation. | Existing state-save plus audit are separate transactions; mutation 503 can mean saved state, as documented. No changes to UI rendering/mock were made. |
| New data boundaries | Workspace exact maps have no OS/exec/network seam; pure format/digest code has no transport; JSON output escapes strings and Markdown reuses the neutraliser. Finding prose/guidance/mappings are static and pinned. | MCP can be explored by humans, scanners or agents. Markers are fake, but random provider-shaped strings cannot be proven collision-free offline. Exported native evidence remains sensitive redacted evidence. |

## Additional new-workspace regression

The new MCP connection sequence originally truncated a tool name before
honeytoken scrubbing. A configured marker longer than 128 bytes used as an
unknown tool name could therefore leave a partial marker in sequence metadata,
even though the full tool name was scrubbed. `TestSequenceRedactsBeforeTruncation`
failed first; sequence processing now scrubs before truncating. The synthetic
failing receipt is [sequence-redaction-red.txt](performance/2026-11-22/sequence-redaction-red.txt).
This was found in the new sensor implementation, outside the console/hub
perimeter, and adds no action or egress. Encoded result limits and duplicate
argument rejection also have regression coverage.

## Remaining scope limits

No new dependencies, egress destination, execution capability, enforcement action,
configuration mutation, credential migration or external publication was added.
The review did not fuzz the entire HTTP stack, examine TLS termination/proxies,
exercise external IdPs, assess OS/process compromise, establish hard tenancy,
measure adversarial saturation, validate real SIEM ingestion or provide a formal
proof. Existing optional egress and process-isolation limitations still apply.
