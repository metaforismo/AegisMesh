# AegisMesh threat model

Version: v0.2 development baseline. Method: STRIDE-per-trust-boundary plus agentic-specific threats. Living document.

## Assets

- A1 Evidence store (contains attacker payloads, synthetic credentials, operator environment hints)
- A2 Operator workstation/host running the runtime
- A3 Decoy configurations (persona definitions, response rules)
- A4 Admin endpoints (health/metrics/readiness)
- A5 Extension manifests and extension host
- A6 Integrity interpretation of the evidence chain (payload/hash consistency is not provenance)
- A7 Provider/webhook credential references and operator-configured outbound destinations
- A8 Release binaries, SBOMs, checksums, provenance statements, and build definitions
- A9 Recommendation reports and operator interpretation of their evidence links
- A10 Sensor-worker lifecycle, IPC projections, readiness state, and sibling availability
- A11 Node private identity and hub node/token/replay registry
- A12 Console account store (managed accounts, API key SHA-256 digests, OIDC identity directory key, preferences)
- A13 Managed API keys (`amk_` bearer tokens held by people and integrations)
- A14 Custom role definitions (permission sets stored with the accounts) and the console settings
  overlay (allowlisted overrides, accepted posture risks, change history)

## Trust boundaries

- TB1: Attacker network → sensor listeners (HTTP/TCP/MCP/SSH). Everything crossing this line is untrusted.
- TB2: Sensor runtime core → storage (evidence writes).
- TB3: Config files on disk → runtime (operator-controlled, but must be validated: configs may come from
  repos, migration imports, or other machines — treat as semi-trusted input).
- TB4: LLM provider (local deterministic or remote API) → policy layer. Provider output is untrusted data.
- TB5: Observer extensions ↔ extension supervisor (out-of-process; untrusted code by definition).
- TB6: Admin listener → operators/monitoring. Loopback-only by default.
- TB7: Runtime → operator-configured remote provider or webhook collector. Disabled by default; fixed destinations only.
- TB8: Source, module proxy, Actions, and container registries → CI/release runner → published artifacts.
- TB9: Local evidence store → recommendation engine → operator. Store contents and envelope metadata may
  be attacker-influenced or modified by a local writer; recommendation output must remain non-behavioral.
- TB10: Parent runtime ↔ optional same-binary sensor worker. The worker is a fault-containment process, not
  an untrusted extension or a general host sandbox.
- TB11: Outbound inventory agent → dedicated machine hub listener; all status is untrusted self-report.
- TB12: Console operator → hub inventory administration; existing role/CSRF/audit boundary.

## STRIDE summary per boundary

| Boundary | Threats | Mitigations in this batch |
|---|---|---|
| TB1 | Spoofing source IPs, DoS via slowloris/huge bodies/regex bombs, injection via logged payloads, credential probing, SSH decoy escape | No trust of client-supplied identity fields; HTTP/TCP/MCP inputs use server timeouts, byte caps, bounded loops, and redaction; the SSH boundary uses synthetic authentication only, bounded handshake/session/auth attempts and metadata, an in-memory Ed25519 host key, and rejects every channel/global request; sensor behavior has no attacker-controlled filesystem/exec capability |
| TB2 | Log/evidence forging after compromise, unbounded disk growth, plaintext disclosure or encrypted-segment/key loss | Envelope carries a SHA-256 consistency check over the observation payload; per-event sequence numbers from the writing process; retention enforces max count and max age; redaction is applied at event construction. Optional native age/X25519 framing authenticates event ciphertext at rest, requires explicit bounded owner-only read identities, and uses a persistent mode guard to reject later plaintext writes in an encrypted data directory. The payload hash is not writer authentication; encryption does not hide filesystem metadata or provide key recovery. |
| TB3 | Malicious config (SSRF-ish binds, privileged ports, regex abuse, huge allocations), path traversal via body or extension-manifest files, unsafe worker launch | Strict schema validation with unknown-field rejection; bind address policy check (public/privileged requires explicit opt-in flags); regex compile with length caps; body and extension-manifest files resolved relative to the config directory with traversal and real symlink containment checks; process isolation accepts only a boolean and launches a fixed same-binary worker with no config-derived command, path, environment, real provider credential, or provider destination; bounded fake markers cross only as data |
| TB4 | Prompt-injected provider output instructing follow-on actions, jailbreak content stored/replayed, provider SSRF | Provider output treated exactly like attacker input: size-capped, redacted, stored as quoted text; it can only ever become a decoy *response string* — there is no code path from provider output to exec, paths, config mutation, or enforcement; outbound provider URL is fixed by config, allowlisted scheme http(s), timeout-bounded |
| TB5 | Malicious extension code, manifest spoofing, output flooding, zombie processes, compromised extension artifact | Explicitly configured observer subprocesses only; strict bounded manifests; required sha256 digest plus optional ed25519 signature; exact `["observe"]` capability; identity-bound canonical handshake and event-linked acknowledgement; request/deadline/output caps; minimal environment; protocol violation revokes the process. Unknown/duplicate fields and untrusted error text are rejected, and no output reaches policy, evidence mutation, filesystem selection or enforcement |
| TB6 | Recon via metrics/health, header injection into admin responses | Separate loopback-only listener, no attacker-reachable data in responses, explicit opt-out documented but default on |
| TB7 | SSRF, DNS rebinding, secret disclosure, redirect abuse, data exfiltration, unbounded provider/collector cost | Outbound edges are opt-in and fixed by validated config; destination classification occurs before startup and at dial time; redirects/proxies are refused; credentials resolve before listeners bind and are never logged; requests, responses, queues, retries and time are bounded. Enabling either edge intentionally sends data outside the host |
| TB8 | Mutable build inputs, compromised actions/tools/base images, dependency substitution, excessive workflow authority, incomplete or misleading release evidence | Actions use full commit SHAs; Go tools use exact versions and checksum-database verification; container bases use verified multiarch digests; a static gate rejects mutable references; modules are downloaded and verified before offline readonly compilation; SBOM work is isolated from OIDC authority; the attestation job downloads named binaries and contains only GitHub-owned pinned actions. Checksums, SBOMs, provenance, and signatures remain distinct claims |
| TB9 | Malformed evidence, attacker text copied into guidance, false-positive escalation, metadata tampering, recommendation output becoming an action | Complete bounded input is structurally and payload-hash validated before filters/limit; malformed input yields no report; prose comes only from static catalog text; outputs say `recommendation`, `dry_run`, `proposed`, and `signal_not_incident`; no runtime, bus, LLM, extension, webhook, exec, path, config, production-mutation, or enforcement seam exists |
| TB10 | Worker protocol injection, forged event metadata, frame flooding, worker crash, orphaned descendants, false readiness | Fixed hidden same-binary invocation, minimal environment, private temporary working directory, canonical versioned stdio frames, bounded frames/queues, random challenge-bound readiness, strict identity/classification/redaction/nested-JSON validation, allowlisted declaration-first metrics, parent-owned event envelope, bounded concurrent shutdown and direct-child reap; Unix escalation signals the current process group; crash degrades readiness for that sensor while siblings continue, with no automatic restart in v0.2 |

## Agentic-specific threats

1. **Prompt injection through descriptions, schemas and returned content** — all three are untrusted prompt
   surfaces. AegisMesh serves static, config-reviewed tool definitions and canned synthetic results; observed
   traffic never rewrites them and returned content cannot invoke another tool or reach execution.
2. **Mutable-definition rug pulls and tool shadowing** — a compromised server can change a previously approved
   tool or influence selection of a more privileged tool. The shipped decoy is a server, not a general MCP
   client, and has no cross-server tool router. Future client/gateway work must pin complete definitions and
   isolate each server as its own security domain.
3. **Confused deputy, excessive permissions and token passthrough** — the shipped decoy has no downstream
   authority and implements no protected-resource authorization flow. Future authenticated MCP work must bind
   tokens to the server audience/resource (and issuer where applicable), reject over-scoped credentials, and
   obtain a separate token for any upstream API; inbound tokens must never be forwarded.
4. **Context over-sharing and indirect exfiltration** — MCP arguments and remote-provider prompts may contain
   sensitive context. Inputs are capped and redacted before storage; remote providers remain explicit egress.
   No component may encode captured context into a new destination or tool call.
5. **Extension/model supply-chain compromise** — digest/signature checks establish artifact identity, not
   benign behavior, and remote model behavior can change outside this repository. Extensions stay
   out-of-process and data-only; provider output stays size-capped, redacted and non-behavioral.
6. **Event spoofing / evidence poisoning** — an attacker who can reach sensors can inflate event volume or
   plant payloads. This inherent residual risk is mitigated by resource caps and integrity hashing, which
   proves what the sensor recorded rather than the attacker's identity or intent. Cross-host attestation is future work.
7. **Canary over-interpretation** — a `canary_invocation` is an observation that a tool was called. It can
   result from prompt injection, direct exploration, operator testing or misconfiguration; it is not proof of
   compromise and never triggers enforcement.
8. **Decoy escape** — decoys expose no interpreter, shell, exec, or file API; MCP "actions" return canned JSON.
   Escape surface is limited to the protocol parsers and Go runtime.
9. **Recommendation over-interpretation** — a deterministic proposal can still be wrong, conflicting, or
   based on benign testing. Recommendations link evidence for operator review, expose static false-positive
   and conflict notes, and never assert an incident or select an enforcement action.

## Recommendation read boundary

The recommendation engine verifies observation-payload hash consistency only.
Envelope ID, timestamp, sequence, sensor metadata, and classification are not
covered by that hash. A writer who can modify the evidence store may also
recompute the payload hash; this is not provenance authentication, a signature,
or chain of custody.

Every stored envelope is validated before filtering or limiting. Supported
detection and correlation shapes use strict bounded schemas, and correlation
contributor IDs become links only when matching verified raw envelopes are in
the same input. Observation content never supplies report prose: attacker paths,
hosts, tool names, payloads, summaries, and reasons are not copied. Output is a
local proposal only and has no path to runtime policy, the event bus, webhooks,
extensions, LLMs, filesystem selection, commands, configuration mutation, or
enforcement. Canary activation remains an observation, not proof of an incident.

## SSH deception sensor boundary

The shipped SSH sensor is an observation-only protocol surface. Its security
contract is:

- authentication is synthetic: password and public-key callbacks complete bounded protocol handshakes but
  never validate, reuse or log credentials; bounded password tuples produce memory-only distinctness digests (ADR-0021);
- usernames, credential contents and auth-attempt digests are omitted from evidence; only safe configured marker ids may appear in findings;
- one Ed25519 host key is generated per sensor instance and held in memory; no configured host-key
  file/path or persistent key lifecycle exists, so reconstructing the sensor rotates the advertised key;
- all channels and global requests are rejected, including shell, PTY, subsystem, SFTP, and forwarding
  requests; no filesystem, command execution, or outbound target is reachable through SSH;
- loopback and unprivileged listener defaults, handshake/session deadlines, authentication attempts,
  concurrent connections, and input metadata remain bounded and fail closed on invalid configuration;
- activity is an observation, not proof of a real account or incident, and cannot influence policy,
  configuration, execution, or enforcement.

## Per-sensor process boundary

`process_isolation` is a common opt-in boolean for HTTP, TCP, MCP, and SSH.
Omitted and `false` preserve the in-process path. With `true`, the parent
launches the same AegisMesh binary using a fixed hidden worker argument, a
minimal fixed environment, and a private temporary working directory. The
configuration cannot choose an executable, command, argument, path, or
environment entry. The parent materializes `body_file` content and sends no
paths, credentials, API keys, remote-provider destinations, models, or
credential references to the child. A local fallback's bounded static prompt
remains part of the sensor specification.

The worker protocol is versioned, canonical, newline-delimited JSON over
stdin/stdout with fixed frame, queue, observation, metric, redaction, and
deadline bounds. A random per-launch challenge binds readiness to the received
start frame. Startup is fail-closed until the worker handshake and
listener bind succeed. Worker observations are projections only: the allowed
classifications are `interaction` and `canary_invocation`, and the parent
creates the event ID, timestamp, sequence, integrity hash, and storage write.
Worker metadata cannot impersonate an authoritative event or select runtime
behavior. Metric names are allowlisted, declaration counts are capped, and an
operation must follow a matching declaration. An isolated HTTP sensor with
enabled remote LLM fallback is rejected
by configuration validation because the worker has no remote-provider
credential or destination authority.

An unexpected worker exit marks that sensor unhealthy and degrades readiness;
sibling sensors continue to serve. v0.2 does not restart the failed worker.
Shutdown closes workers concurrently under one bounded deadline and reaps each
direct worker. Unix escalation signals the worker's current process group. A
descendant can survive if the leader exits first or it deliberately creates a
new session; built-in workers do not intentionally spawn descendants. The
parent-worker edge is stdio-only and adds no external egress.

This boundary is fault/process containment, not a network, filesystem, CPU,
memory, syscall, or malware sandbox. The child keeps the same UID,
host/container namespace, filesystem view, and network policy. Container or
Kubernetes resource limits apply to the runtime and workers in aggregate.
Operators needing stronger isolation must configure it at the container or
host layer and must not interpret this setting as permission to execute
captured samples or attacker-supplied commands.

## Self-contained demo boundary

`aegismesh demo` accepts no config, path, port, credential, API key, URL or
destination. Its repository-owned scenario binds HTTP, TCP, MCP, SSH and admin
listeners to `127.0.0.1:0`; every resolved address is re-checked as an IP
loopback with an OS-assigned unprivileged port before a client connects. HTTP
clients ignore proxy environment variables and reject redirects; all network
requests, response bodies and TCP lines have explicit deadlines or byte caps.

The SSH username and password are fixed synthetic markers and the evidence
readback rejects them if redaction regresses. Success is buffered until Stop
returns, every bound listener is verified unreachable, all four envelopes pass
structural and observation-hash checks, one dry-run proposal exists, and the
private temporary workspace is removed. Filesystem cleanup calls are not given
a false wall-clock guarantee; their scope and retained evidence count are fixed
and removal failure suppresses success. No shell, `os/exec`, user-selected path,
extension, webhook, remote provider, external egress or enforcement seam is
reachable. The summary still describes observations, not an incident.

## Residual risks accepted in this batch

- In-process mode remains the default: a parser 0-day in Go's net stack can
  still crash the shared runtime (availability loss, not escape). Operators
  seeking fault containment must opt into the per-sensor worker boundary.
- Sensor and observer subprocesses are not resource or network sandboxes. The
  host bounds protocol I/O and lifecycle, but CPU, memory, filesystem,
  namespace, syscall, and network confinement remain host/container concerns.
- Fixed executable identity narrows the worker launch surface but does not
  attest the host binary or defeat a privileged local writer that replaces it.
  Host integrity, deployment immutability, and release provenance remain
  separate controls.
- Evidence remains plaintext by default. Optional native age/X25519 at-rest
  encryption protects event contents only; filenames, sizes, timestamps,
  exports and host metadata remain visible. Losing every identity required by
  retained encrypted segments is unrecoverable. The per-directory mode guard
  prevents accidental plaintext downgrade but is not host attestation or a
  filesystem sandbox. Encryption protects the storage medium, not a
  compromised runtime host or a stolen private identity. V3 checkpoint/seal
  controls authenticate the count and SHA-256 of ordered event records. Live
  reads return only an authenticated prefix, naming every open file and warning
  that later events may exist. Complete corrupt records and invalid controls
  fail closed; incomplete tails after a checkpoint are excluded explicitly.
  Newest-only openness is normal; older open files are interrupted-segment
  warnings, detected structurally by doctor without private identities.
  A medium writer can roll back an open file to an earlier checkpoint undetected.
  **Even a formerly sealed v3 file can be truncated to an earlier checkpoint and
  appear open**: without trusted external completion state this is indistinguishable.
  Use `--require-sealed` for strict truncation/completion detection. A present or
  required seal binds the full sequence; records after it fail. Historical v2
  has no checkpoint fallback and still requires a seal. Whole-file deletion,
  replacement and public-recipient forgery are outside the guarantee; this is
  consistency, not writer provenance. No automatic rewriting/migration occurs.
  Normal flushes publish checkpoints only after new events, without `fsync`;
  size, close, five-minute age from first event, or checkpoint space exhaustion
  seal the file. Empty files do not age out. Ten-minute retention scans are off
  append/flush, open one descriptor at a time, and can delay writes under the
  store mutex. They count interrupted v3 prefixes structurally and may delete
  whole closed files, never the active file. Damaged framing/no usable checkpoint
  or v2 incompleteness can block count retention. Retention is not a hard disk quota.
- Build provenance depends on GitHub-hosted runner, OIDC, Sigstore, registry,
  and source-control integrity. It covers named binary subjects only; current
  SBOM/checksum files are not attested, and no SLSA level or binary signature is
  claimed.
- Remote providers can improve realism but intentionally disclose bounded prompt context to the configured
  endpoint and can incur cost; the deterministic local provider remains the zero-egress default.

## Primary agentic-security references

- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
  for tool/schema/output poisoning, rug pulls, cross-server isolation and least privilege.
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
  for indirect prompt injection through tool results.
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
  for resource indicators, audience validation, token-passthrough prohibition and confused-deputy controls.

These are design references. Their presence does not imply that optional MCP
authorization or multi-server client behavior is implemented here.

## Explicitly out of scope (never build)

Autonomous exploitation, credential theft, persistence mechanisms, botnet participation, destructive
containment (e.g., firewall-dropping production IPs without approval), phishing delivery infrastructure,
execution of captured malware samples.

## Console trust boundary

The optional console adds an inbound authenticated evidence-reading surface on
its own HTTP server, never the sensor/admin mux. Host allowlisting (actual bound
port, configured hostname or loopback aliases) rejects DNS rebinding with 421;
forwarded headers never expand trust. Non-loopback binds require the public-bind
opt-in and TLS. Browsers have no cross-origin grant: cookie mutations require a
constant-time CSRF token check and matching Origin when supplied. Login also
checks Origin. Tokens are hashed and compared against every configured operator
digest; malformed/missing credentials never redirect. New login sessions rotate
any presented previous session, and SSE expires with the session or notices
revocation on its next heartbeat/event. Bearer credentials have no CSRF cookie.

The authenticated HTTP client and stored evidence are separate untrusted inputs.
JSON bodies are limited to 64 KiB, duplicate/unknown keys and deep structures
are rejected, URI length is capped at 8192 bytes, and queries reject unknown,
duplicate or malformed values. Cursors are HMAC-authenticated and tied to their
filters/process; they cannot select files or broaden queries. Eight concurrent
ordinary requests and sixteen SSE streams cap expensive work. Node storage
metadata refuses directories above 65536 entries instead of allocating an
unbounded listing; it does not read evidence payloads. Each stream has
32 queued summaries and a five-second per-write deadline; a lagging subscriber
is disconnected. Login state is capped at 4096 remote addresses and ten attempts
per address/minute; exhaustion denies new remote entries until expiry. Sessions
are capped at 1024 per tenant (32768 globally), with eviction confined to the same tenant. There is no distributed/edge DDoS protection. OIDC is opt-in; see ADR-0019 below.

Evidence strings are bounded JSON data and findings use catalog-authored prose.
Event detail preserves the native envelope and recomputes its observation hash;
that hash authenticates neither metadata nor writer identity. The embedded UI renders
evidence, investigation titles and note text safely as text. CSP prohibits inline execution, third-party connections and framing.
Static assets are snapshotted from an injected FS at startup with byte/count
limits: request paths index memory, never choose filesystem paths. Directory
listings and index fallbacks are absent. The runtime injects the embedded UI
(`internal/consoleui`); a server built without a UI FS exposes a notice only.

The runtime tap sees every successful authoritative append, including direct
correlation signals, and has no edge back to the bus, sensors, policy, extensions
or webhooks. No read identity enters the runtime. Encrypted evidence history is
live-only in the console; evictions affect the disposable index, never storage.
Host resource contention from bounded queries and snapshot allocation remains
possible; no hard total-process RSS or CPU isolation claim is made.

Investigations use a fixed state filename and server-generated IDs. Atomic
write/fsync/rename protects each snapshot, and audit records are fsynced with a
SHA-256 chain preserved across rotation. Neither request IDs nor evidence select
a path. State must be private; symlinks/special files are rejected, and rooted
file operations confine it. Same-UID local attackers and simultaneous writers to
one state directory are outside this model: operate one runtime per data/state
directory. A filesystem writer can rewrite an entire audit chain. Investigation
state and audit append are separate durability transactions: if the final audit
write fails, an investigation can already be saved; the API reports 503 and tells
the caller to inspect state before retrying. Audit quota is bounded and fails
closed; there is no automatic history deletion, repair or external anchoring.
Audit never stores credentials, CSRF/session values or note bodies. It records
failed logins, denied role/CSRF calls, investigations, audit reads/verifications;
ordinary evidence reads are deliberately not audited. Console state is plaintext
regardless of evidence encryption. No remote sensor control or enforcement endpoint exists. The optional logical tenant boundary is described below. Optional fleet enrollment has its own boundary below.


## Fleet inventory trust boundaries (ADR-0018)

A11 is the node private identity and hub node/token/replay registry. TB11 is the
outbound agent → dedicated hub machine listener. TB12 is the console operator →
hub inventory administration seam. The agent never opens a fleet inbound
listener. Configuration and all received status/response bytes remain data;
there is no path to configuration mutation, filesystem selection or execution.

| Threat | Implemented control and residual risk |
| --- | --- |
| Rogue agent | Per-node heartbeat spacing from the registered interval and isolated 64-entry nonce windows prevent one key from consuming another node's replay budget. Revoked/early heartbeats do constant work and no request-driven disk IO; signed enrollment retries are also spaced and unchanged intervals do not rewrite the registry. Heartbeats coalesce on a five-second flush cadence. Possession of an enrolled Ed25519 key is required for every heartbeat. Enrollment needs a one-use high-entropy expiring token plus request-bound proof of possession. Inventory is still self-reported: an enrolled rogue agent can lie about versions, sensors, counters or health. No evidence/incident provenance is inferred. |
| Unauthenticated network client | Method/path/content-type/header/body/skew validation runs before the hub mutex; signature verification holds no hub mutex (stored key lookup alone needs state). Rejections always increment bounded-code metrics. Only five anonymous rejection audit samples per minute plus one suppression-count summary reach disk from maintenance, outside the hub mutex. Source-IP throttling is capped at 4096 buckets, 8192 requests/minute each, with 429/Retry-After; ports/forwarded headers cannot bypass it. A full table fails closed for new remotes until expiry/pruning; shared NAT collateral throttling and distributed CPU/connection pressure remain possible. |
| Stolen enrollment token | Tokens have 256 bits of entropy, default one-hour/max 24-hour TTL, SHA-256-only persistence and atomic one-use consumption. References only, TLS beyond loopback, no secret/signature logging. A thief with an unused token can enroll their own key first; proof of possession does not prevent token theft. Delete outstanding tokens and inspect inventory. |
| Stolen node key | Owner-only seed/state, exact canonical request signatures, ±120-second clock window and bounded persistent replay cache prevent unauthenticated forgery and ordinary captured-request replay. A key thief can impersonate that node until admin revocation. Permanent key tombstones refuse heartbeat and re-enrollment. Rotation/attestation are proposed, not implemented. |
| Compromised hub | A hub can deny service, forge its own inventory/audit, disclose received metadata, or provide false acknowledgements. It cannot command nodes: no response field, dialer, config/file/code distribution, execution or enforcement channel exists. The agent accepts only a bounded matching-ID acknowledgement and never applies server-authored data. A compromised hub cannot recover private node keys from public keys/signatures. |
| SSRF/rebinding | Fixed validated origin; shared egress classifier at config, resolved-address and socket time; metadata/link-local denied permanently, private networks need fleet-specific opt-in, HTTP stays loopback even after DNS resolution. No redirects, proxies or insecure TLS option. System roots may be augmented by an explicit bounded CA bundle. DNS destination identity between independent connections is not pinned. |
| Replay/rollback | Each node retains at most 64 nonces until signed timestamp plus skew, without evicting live entries or sharing capacity. Replay windows and liveness coalesce at five-second intervals and orderly shutdown. Restart retains flushed entries; a crash may lose the most recent interval (longer under scheduler/IO stalls), reopening unflushed nonces within the remaining timestamp window, up to 240 seconds after receipt for future-dated requests. Inventory shows last flushed data until the next heartbeat. Durable token consumption/revocation remain synchronous. Same-UID/privileged disk rollback or valid whole-state rewriting remains outside the claim; no external state/audit anchor exists. Clock synchronization is operationally required. |
| Availability/resource pressure | Separate listeners, eight concurrent hub handlers, deadlines/header/body limits, finite registry/tokens/per-node nonces, source-IP rate limits, sampled rejection audits, five-second heartbeat snapshot coalescing and independent jittered agent loop. Hub outage leaves sensors/evidence operating. Snapshot fsync and audit can still contend for host disk/CPU; this is not a DDoS or host resource sandbox. Saturated replay/audit/state fails closed. |

TB11 carries inventory and, with separate explicit consent on both sides, redacted live evidence. Node names,
versions, uptime and activity counters can themselves be sensitive. Hub registry,
public keys, token hashes, replay state and audit are plaintext independently of
evidence encryption. A separate single-writer private state dir is required per
role. Audit and registry updates are separate transactions, so a 503 after save
requires state inspection before retry. Inventory authentication establishes key
possession, not trustworthy telemetry, tenant isolation or managed-service safety.


## Experimental evidence forwarding boundary (2026-11-15)

Best-effort forwarding with counted loss; local store authoritative. A compromised enrolled
node can flood within its quotas, forge its own observations or recompute every payload hash.
Signatures attribute submissions to key possession; payload verification on the hub establishes
consistency, not provenance. No incident, telemetry trust or attestation follows. The node ID
comes from the verified registry key, never its claimed name, instance or event metadata.

Whole-batch framing is strictly parsed under a 4 MiB/1,000-event bound. Individual envelopes
are size/schema/UTF-8/metadata/time/hash validated, invalid ones skipped and counted. Same-node
work uses a separate try-lock; five-second spacing, 1,000 events/second, 16 MiB/minute,
a 4,096-ID dedup window and 16 MiB retained bytes isolate one key. A 256 MiB aggregate
segment budget reserves conservative encryption/rotation space before append. Many colluding
nodes can exhaust it; shared handler/CPU/disk/NAT pressure remains possible. Duplicates older
than the window or after hub restart may append again. Node stream resets/gaps are not
attested; sequence gaps cannot expose a trailing loss without a later batch.

A compromised hub now learns **redacted evidence of every forwarding node**, including
correlation signals, stored addresses, payload snippets and whatever minimization leaves.
**Redaction is the control**: node at-rest encryption does not hide live plaintext from the
hub. TLS protects transit, and optional hub encryption protects its own storage medium;
neither protects against that endpoint's compromise. Forwarding requires explicit off-by-default
agent disclosure and hub reception flags. Raw pre-redaction traffic, config and private keys
are not forwarded. A compromised node can nevertheless put secrets or deceptive data in
its own signed evidence; the hub cannot prove upstream redaction was performed.

Per-node directories use only validated cryptographic IDs beneath the trusted hub root;
envelope bytes cannot select paths or reach commands, config mutation or enforcement.
Copies are data only. No cross-node correlation, history forwarding, deletion propagation,
tenancy isolation or hub-to-node traffic is implemented. Local evidence remains authoritative;
queue overflow/crash/offline loss leaves missing forwarded evidence on its original node.
Compromised hubs can falsely acknowledge or suppress submissions but cannot command agents.

## OIDC and logical tenant boundaries (ADR-0019/0020)

SSO via OIDC (experimental) adds TB13, console → configured IdP discovery/JWKS/
token endpoints, and TB14, browser → authorization callback. Logical tenant
isolation (experimental) adds TB15, operator session → selected data partition.
All three edges remain data-only and have no enforcement or sensor authority.

An IdP compromise, stolen IdP account or mis-mapped groups can grant any role and
membership that the operator explicitly mapped. Default-deny role/tenant mapping,
stable issuer+subject audit identity, bounded TTL and break-glass tokens limit
scope; they do not make the IdP trustworthy or instantly revoke existing
sessions. Name/email is presentation only. Provider-supplied errors, credentials,
access/refresh tokens and authorization codes never enter storage or audit.

Login CSRF is mitigated by independent random state/nonce/S256 verifier and a
short-lived HttpOnly SameSite=Lax pre-login cookie bound to server-side state.
Callbacks consume state once, including failed attempts. Another browser cannot
inject the callback into its session. Successful authentication and tenant
switches generate fresh session IDs/CSRF, preventing fixation and leaving old
cookies unusable. New sessions use SameSite=Strict and actual credential-capped
expiry. Logout terminates only the local session; the IdP login remains active.

Issuer URL policy runs without networking during validation/doctor. Only console
Start launches discovery; failures retry in the background without stopping
sensors. All discovered endpoints must retain the issuer scheme/authority,
redirects and proxies are refused, and actual resolved sockets pass shared
egress policy. Metadata/link-local are always denied, private egress needs its
own opt-in and cleartext is loopback-only. Bounded body/key/token sizes, timeouts,
key-cache refresh pacing and pending-state/login caps limit amplification. They
do not provide edge DDoS or total CPU/RSS guarantees.

Tenant confusion is mitigated by one pre-handler partition selection layer,
configuration-validated names, immutable node enrollment ownership, per-partition
stores and independently signed cursors. Claims/requests look up existing views;
they never construct filesystem paths or partitions. Every role, including admin,
is confined to one active tenant. Local sensors/rules/node metadata belong only
to local_tenant. Per-partition indexes isolate events, SSE, related-event lookup,
overview/sources/by_node counters, eviction and evidence references. Unknown and
foreign IDs use the same store lookup and 404 response; no global existence
probe runs. Switching invalidates old streams before another event is written.

Each tenant has its own audit hash chain/files; anonymous or denied identities
without a tenant use a separate authentication chain in multi-tenant configs.
Per-tenant investigation, token, node and forwarded-byte quotas prevent one
tenant from consuming a sibling's logical quota; a cap of 32 partitions also
bounds aggregate quotas. Shared request/stream admission, disk, GC,
scheduling and OS resources still allow cross-tenant availability/timing
inference. We claim equivalent absent-object timing classes, not constant-time
HTTP or elimination of traffic analysis.

Migration uses recoverable fixed-name directory renames, without rewriting
existing chain bytes. Conflicting migration directories fail closed for operator
inspection. One process must own each root. Logical isolation operates inside
one process, one OS user and one data directory, sharing the hub's evidence
encryption recipient and signing/egress configuration. Host/process compromise
crosses tenants. No per-tenant keys, billing, rate plans or self-service tenant
creation are implemented; this is not a hard hosted isolation boundary.

## Synthetic AI decoys and ephemeral auth distinctness (ADR-0021)

The `ai-decoy` scaffold serves only static synthetic AI-shaped responses.
There is no model, remote inference, download, key-management or instruction
execution path behind those endpoints. Honeytokens must be fake and planted
only in decoy material; real keys are never appropriate marker values.
Literal matching happens on acquired bounded input, before redaction/preview
truncation. Marker values never reach stored evidence; findings carry token
ids. New detection/correlation rules remain observations and cannot cause
response enforcement or changes to real assets.

SSH and HTTP authentication now derive memory-only length-framed SHA-256
attempt digests for live distinctness (COR-007). Bounded private worker IPC may
carry these digests; native JSON, storage, indexes, webhooks, extensions and
fleet forwarding cannot. Parent-authoritative append still precedes local
correlation. Host/process memory compromise can expose these transient data;
this is not a memory-secrecy guarantee. Digests are not durable password hashes
or proof of failed/valid authentication, and stored signals cannot reconstruct
attempt distinctness after restart.

Agent markers and short/regular request patterns can also be followed by a
human, scanner, scheduled monitor or ordinary client. Source IPs are not user
identities. Editorial framework references are not coverage or attribution.
See [ai-threat-detection.md](ai-threat-detection.md) for the exact premises,
thresholds, source/window semantics and false-match limitations.

## Round 3 boundary refinement (local, uncommitted; ADR-0023)

The MCP workspace is a static synthetic **lookup** API. TB1/TB3 do not gain a
real file, environment, query interpreter or execution capability: declared
keys compile into exact in-memory maps and write/exec-shaped calls are only
observed. Connection context caps step/sequence state and expires with the
connection. File/env content is synthetic; honeytoken values are deliberately
served but scrubbed before evidence previews/storage. Existing policy findings
retain their semantics; MCP-001..003 cannot enforce. See `mcp-environments.md`.

Console event downloads/digests are read-boundary projections, not a new TB7
network edge. Export destinations are stdout, an operator-chosen new local
file, or an authenticated operator-requested attachment. CEF/syslog escaping
prevents record/structured-data delimiter injection; OTLP is JSON format only.
ECS retains sensitive redacted native observations and requires analyst access.
Fixed filenames prevent header injection. No untrusted data selects an output
path, changes configuration or reaches enforcement. Markdown uses the shared
neutraliser. Source novelty, automation and technique relations describe only
retained sampled evidence, never incidents/actors or technique execution.

Local decoy/honeytoken catalogs expose IDs and static counts only in
local_tenant, never bodies or values; forwarded sensor/token collisions cannot
populate local-config counts. Raw event-detail reads are now audited before
bytes, even for viewers. Invalid Bearer attempts share a bounded process-wide
throttle table with distinct keys from browser login; hub early rejections
receive no-store/security headers. SSE frames are immutable, scoped to an index
partition and bounded by the unchanged stream/queue limits. This is logical
isolation within the same process, not isolation from a compromised host.
The review's reproduced findings, checked controls and untested surfaces are
in `security-review-2026-11.md`; it does not establish perimeter security.

## Managed accounts and API keys (ADR-0025)

Assets A12/A13. The console can now create principals, which ADR-0017 did not
allow. Mitigations by threat:

- **Spoofing with a stolen key.** Keys are 256-bit random `amk_` tokens shown
  once; only SHA-256 is stored, every key expires (≤365 days) and can be
  revoked or its account disabled with immediate effect for bearer use and for
  the sessions it opened. Failed bearer attempts share the per-address
  throttle. A key copied before revocation works until then; there is no per-key
  network restriction.
- **Elevation through the store.** Role values are a closed set ending at
  admin; creation, role and membership changes require an admin who is a member
  of `local_tenant`, and memberships must be declared tenants. The store never
  writes config operators. The last-admin guard refuses changes that would leave
  no administrator who can sign in; OIDC admins are not counted. A compromised
  admin can mint keys for any role up to admin: that is the admin's authority,
  recorded in the local audit chain.
- **Information disclosure.** Responses, logs and audit records never contain
  tokens or digests; key listings show a 4-character prefix only (24 of 256
  bits). Session listings show an HMAC handle, a fixed client family and the
  peer host, never cookie values or User-Agent text. OIDC identities are listed
  by a keyed hash of issuer and subject. Admins see principals and sessions of
  every tenant (metadata only, never evidence).
- **Tampering with state.** The store is strict-decoded and validated on load;
  corrupt, oversized or interrupted snapshots stop startup, and a snapshot
  changed by another writer makes later saves fail closed. A same-UID local
  attacker can still rewrite the file (for example insert a digest); this is the
  same out-of-scope local writer as for audit and investigations.
- **Repudiation.** Account, key, session, preference and export actions are
  appended with actor id, target id and outcome; export is recorded before any
  byte is sent. Offline CLI changes are recorded as `cli:local`.
- **Denial of service.** Bounded counts and bytes; `last_used_at` writes are
  coalesced to one per key per minute. Audit export holds the audit lock only
  while copying at most 10000 records.
- **Formula injection.** Audit CSV prefixes cells beginning with `= + - @`,
  TAB or CR, because display names are administrator-supplied text.

Untrusted data still never reaches exec, path selection, configuration or
enforcement: request fields select records inside one fixed-name file only, and
settings are read-only (ADR-0026 below narrows this). Sessions remain in memory
per process.

## Custom roles and the console settings overlay (ADR-0026)

Asset A14. Roles are now data rather than a fixed rank, and with
`console.settings_editing: console` an HTTP request can change a few console
settings. Mitigations by threat:

- **Privilege escalation through custom roles.** Roles combine only ids from a
  compiled-in catalogue; nothing can exceed built-in admin. A principal holding
  `accounts.manage`, `roles.manage` or `sessions.manage` cannot reach
  permissions it lacks: creating or re-roling an account to a wider role,
  touching or minting keys for an account holding more, creating or widening a
  role beyond the caller's set, editing or deleting a role holding more, and
  ending a more privileged session all answer 403 `exceeds_own_permissions`
  and are audited. `roles.manage` and `settings.manage` require
  `accounts.manage` (and reads), so no role changes behaviour without seeing
  who holds access. Built-in roles are immutable; assigned roles cannot be
  deleted; the last-admin guard counts principals able to manage both accounts
  and roles. Permissions resolve per request, so revoking a permission applies
  at the next request and ends open event streams at the next event or
  heartbeat. Config operators and OIDC mappings cannot name custom roles.
  Residual: a principal holding every permission (built-in admin or an
  equivalent custom role) still has full authority; POS-021 flags service
  accounts given high-risk permissions through custom roles.
- **Settings tampering.** Off by default. Only an allowlist of console-only
  keys (session lifetime ≥ 900 s, idle timeout, key lifetimes, banner,
  organization name, default window, posture acceptances) is editable; listeners,
  TLS, tenants, OIDC, storage, encryption, detection actions, fleet and
  sensors are not, and every other key answers 409 `not_editable`. Values are
  validated before storage and again before use, the config file is never
  written, and nothing reaches exec, path selection or enforcement. Each change
  needs `settings.manage`, CSRF and Origin checks for cookies, and a reason;
  it is audited and kept in a 500-entry history. Overrides that no longer
  validate are ignored at startup (POS-022, `settings` component degraded); a
  corrupt or foreign-modified overlay is not applied and not written. Turning
  editing off makes the file the only source again. Residual: a banner or
  organization name is administrator-supplied text that the UI must render as
  text; a same-UID local writer can edit the overlay like any console state.
- **Hiding risk by acceptance.** Accepting a posture check needs
  `settings.manage`, a reason and an expiry at most 180 days ahead; it is
  audited, shown with who accepted it and until when, counted separately, and
  lapses automatically. It never changes `ok`/`info` checks. Residual: an
  administrator can keep re-accepting a risk; the history shows it.
- **Insider risk.** Every role, setting and acceptance change is attributed to
  a stable principal id in the local audit chain, with the previous and new
  values (settings) or the permission diff (roles). Administrators remain
  trusted for their own permissions; the controls above stop partial
  administrators from widening their own reach, not a full administrator
  acting maliciously.
