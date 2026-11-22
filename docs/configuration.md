# Configuration reference

Schema: `aegismesh.io/v1alpha1` (strict decoding: unknown or misplaced fields
are rejected with the line number). Scaffold a valid example with
`aegismesh init`; validate any config with `aegismesh validate`.

## Top level

```yaml
api_version: aegismesh.io/v1alpha1   # required, exact string
runtime:    { instance_name, data_dir }
admin:      { enabled, listen }       # loopback-only invariant
security:   { allow_public_bind, allow_privileged_ports }
storage:    { max_file_bytes, max_event_bytes, encryption?, retention: { max_events, max_age_days } }
llm:        { provider, system_prompt?, api_key_env?, base_url? }
honeytokens: [ { id, value, kind } ] # optional synthetic markers; see below
sensors:    [ ... ]                   # 1..64 entries
```

### runtime

| field | default | notes |
|---|---|---|
| `instance_name` | `local` | stamped into every event envelope |
| `data_dir` | `./data` | relative paths resolve against the **config file's directory**, not the process CWD |

### admin

| field | default | notes |
|---|---|---|
| `enabled` | `true` | set `false` to disable entirely |
| `listen` | `127.0.0.1:9110` | **invariant:** must be loopback. Health/metrics are internal surface; this is not configurable permissively. |

Endpoints: `/healthz`, `/readyz`, `/metrics` (Prometheus text), `/version`.
`/readyz` returns ready only after every configured sensor listener has started;
it does not treat constructed but unbound sensors as available.

### security

Both flags default to `false`. Validation fails until you set them
deliberately:

- `allow_public_bind: true` — permit sensor binds beyond loopback (e.g.
  container-local `0.0.0.0` for Compose publishing).
- `allow_privileged_ports: true` — permit ports below 1024.

Port `0` is always allowed and means "OS assigns an ephemeral port" — useful
for parallel test runs; still subject to host-loopback rules.

### storage

| field | default | notes |
|---|---|---|
| `max_file_bytes` | `16777216` (16 MiB) | rotate evidence segment above this size |
| `max_event_bytes` | `262144` (256 KiB) | reject an encoded event above this size before it reaches a segment; hard maximum 1 MiB so every accepted record remains readable |
| `encryption.enabled` | `false` / omitted | write new evidence as bounded native age/X25519 `.jsonl.age` segments; once an encrypted data directory is initialized it refuses later plaintext writes |
| `encryption.recipient` | none | one native public `age1...` X25519 recipient; required when encryption is enabled; no passphrase, SSH recipient, plugin, KMS or private identity is accepted here |
| `retention.max_events` | `100000` | delete oldest closed segments beyond this, across plaintext/encrypted history |
| `retention.max_age_days` | `30` | delete segments older than this |

Periodic flush publishes buffered ciphertext and a v3 checkpoint to the OS
without `fsync`. It writes no checkpoint unless new frames arrived. Encrypted
mode seals on size rotation, close, a flush at the fixed five-minute age from
the first event, or when a checkpoint would consume reserved seal space. Empty
segments never age out; the next append after sealing opens a new file.
Live CLI reads return only the last authenticated checkpoint prefix with an
incompleteness notice; `--require-sealed` rejects any open segment. Older open
files are interrupted-segment warnings, also reported structurally by doctor.
Each checkpoint/seal is 250 bytes with pinned age/X25519 and counts against
`max_file_bytes`; the 1 KiB seal reserve is retained. No new cadence setting or
private runtime identity is introduced. Sealed v2 keeps its strict read semantics.
See [evidence-encryption.md](evidence-encryption.md) for the exact format and
rollback limits: a removed seal is indistinguishable from an open checkpointed
file unless completeness is required. Private identities are
read-time `--identity FILE` references only, never config fields or environment
key values. Existing plaintext is not migrated. See
[evidence-encryption.md](evidence-encryption.md) for exact bounds, mixed-history,
anti-downgrade and crash-recovery semantics.

### llm

| field | default | notes |
|---|---|---|
| `provider` | `local` | `local`, `ollama`, or `openai`; remote providers are opt-in and constructed fail closed |
| `base_url` | — | fixed OpenAI-compatible endpoint; loopback cleartext is allowed only for `ollama` |
| `model` | — | required remote model name |
| `api_key_env` | — | environment-variable name holding the credential |
| `api_key_file` | — | contained regular file path relative to the config directory |
| `timeout_seconds` | `20` | end-to-end remote call timeout; maximum 120 |
| `max_response_bytes` | `1048576` | remote response body cap; maximum 4 MiB |

Credentials are referenced, never stored inline. `AEGISMESH_LLM_API_KEY`
remains the highest-precedence compatibility override; otherwise the runtime
resolves `api_key_env` or `api_key_file` before any listener binds. Ollama may
omit a key. OpenAI-compatible remote construction fails closed without one.

Provider contract (internal/llm): the context governs blocking work only.
The local provider is a pure function and never fails because a context is
cancelled; remote adapters honor cancellation and the configured size/time bounds.

## Sensors

Common fields for all kinds:

```yaml
- id: http-admin-decoy     # unique, [a-z0-9][a-z0-9.-]{2,63}
  kind: http               # http | tcp | mcp | ssh
  listen: "127.0.0.1:8081"
  process_isolation: false # optional; exact default is in-process execution
```

### Optional per-sensor process isolation

`process_isolation` is a common boolean accepted by all four sensor kinds.
Omitted and explicit `false` are identical: the sensor is constructed and
served in the main runtime process. With `true`, the runtime launches one
same-binary hidden worker for that sensor. The parent uses a fixed executable
identity and argument, a minimal environment, and a private temporary working
directory; configuration cannot select a command, executable, path, or
environment entry.

An isolated sensor's `listen` host must be an IP literal or `localhost`.
This lets the parent validate the bound address reported by the worker without
performing DNS resolution or accepting a child-selected outbound target.

The parent resolves and materializes any configured `body_file` through a
root-contained, size-limited open before the worker starts, preserves its
response bytes, then clears file references. The worker receives only the
bounded typed sensor specification and detection settings needed to construct
the selected sensor. It receives no credential, API-key, provider destination,
provider model, extension, or filesystem-path setting. A bounded static prompt
for an enabled local fallback remains part of the sensor specification. An
isolated HTTP sensor with an enabled remote LLM fallback is rejected during
strict validation; use the deterministic local provider or disable that
fallback.

Parent and worker communicate over canonical, versioned, newline-delimited
JSON on stdin/stdout. Frames and queues are bounded. A per-launch random
challenge binds readiness to the received start frame. A worker must complete
that handshake and bind successfully before the sensor counts as started;
malformed protocol, handshake, or bind failure fails closed. The worker sends
only redaction-safe projections classified as `interaction` or
`canary_invocation`. Metric names are restricted to the first-party sensor and
policy set, declaration counts are capped, and operations require a matching
declaration. The parent creates the authoritative event envelope, including
event ID, time, sequence, and integrity hash, before storage.

If an isolated worker exits unexpectedly, its sensor becomes unhealthy and
readiness degrades; sibling sensors continue serving. v0.2 does not
automatically restart a crashed worker. Shutdown closes workers concurrently
within the runtime's bounded deadline and reaps each direct worker. On Unix,
shutdown escalation signals the worker's current process group. A descendant
can survive if the leader exits before escalation or the descendant creates a
new session; built-in workers do not intentionally spawn descendants.
When startup is cancelled or fails, `Start` may remain blocked for the fixed
termination grace while it reaps the direct worker; that cleanup extension is
bounded and avoids returning with an unsupervised child.

This setting is fault/process containment, not a general sandbox. It does not
provide network, filesystem, CPU, memory, syscall, or malware containment.
The worker keeps the same UID, container/host namespace, filesystem view, and
network policy as its parent. Kubernetes or container resource limits remain
the aggregate limit for the runtime and its workers. Enabling it creates no
new external egress.

### kind: http

```yaml
persona:
  server_header: "nginx/1.25.3"   # advertised in Server response header
max_body_bytes: 65536             # request bodies above this are truncated+recorded (cap 4 MiB)
rules:
  - name: admin-login             # slug
    path_regex: "^/admin(/.*)?$"  # RE2, 1..256 bytes
    methods: ["GET", "POST"]      # optional; empty = any method
    status: 200                   # 100..599
    headers: { Content-Type: "text/html; charset=utf-8" }
    body: "<html>...</html>"      # inline body, cap 64 KiB
    # body_file: ./bodies/x.html  # alternative to body
fallback:                          # used only when no rule matches the path
  enabled: true
  system_prompt: "boring internal admin panel"
  max_reply_chars: 2048
```

**Response precedence** (documented product semantics, enforced in
internal/policy):

1. First rule whose regex matches the path **and** whose method list permits
   the method (empty = any) answers. A methods-less catch-all therefore
   shadows everything below for its paths — that is what catch-all means.
2. Otherwise, if rules matched the path but rejected the method → **405**
   with an `Allow` header naming the configured methods.
3. Otherwise → LLM fallback when enabled.
4. Otherwise → builtin generic 404.

`GET` does not implicitly include `HEAD`; configure each method explicitly.

### kind: tcp

```yaml
banner: "build-cache FTP service ready\n"
session:
  max_line_bytes: 4096          # over-long lines drop the session (no truncation smuggling)
  idle_timeout_seconds: 60      # hard-capped at 3600
  max_session_seconds: 600      # hard-capped at 86400
tcp_rules:
  - name: ping
    line_regex: "^PING$"
    response: "+OK PONG\n"
```

Rules evaluate top-down; first match answers. Sessions end at EOF, deadline,
oversized line, or write failure. Every exchange emits one event containing a
bounded preview + SHA-256 of the last line — never the raw stream.

### kind: ssh

The SSH sensor is an authentication-only observation boundary. Omitting
`listen` uses `127.0.0.1:2222`. An omitted or empty `ssh` mapping uses the
defaults below. Explicit empty, null, or zero values for individual nested
settings are rejected rather than silently replaced with defaults; an
explicitly null `ssh` block is also rejected.

```yaml
- id: ssh-admin-decoy
  kind: ssh
  listen: "127.0.0.1:2222"
  ssh:
    server_version: "SSH-2.0-AegisMesh"
    handshake_timeout_seconds: 10  # default 10; hard cap 60
    max_session_seconds: 30        # default 30; hard cap 300
    max_auth_attempts: 3           # default 3; hard cap 6
```

Each sensor instance generates one Ed25519 host key and keeps it in memory.
There is deliberately no `host_key_file`, host-key path, or persisted key
configuration; reconstructing the sensor rotates the advertised key. Password
and public-key callbacks complete synthetic authentication only. They do not
validate, reuse or log credentials. Bounded username/password tuples now produce
memory-only distinctness digests for live correlation (ADR-0021). Usernames,
credential contents and those auth-attempt digests are omitted from evidence;
only configured synthetic-marker ids may appear in findings.

After synthetic authentication, every channel and global request is rejected.
The sensor exposes no shell, PTY, subsystem, SFTP, forwarding, filesystem, or
command-execution surface. Handshake/session deadlines, authentication
attempts, concurrent connections, and protocol metadata are bounded; fixed
input caps include username, password, and public-key fields. SSH evidence is
an observation of protocol activity, not proof of a real account or incident,
and creates no outbound target.

### kind: mcp

```yaml
path: /mcp                       # JSON-RPC endpoint path
server_name: build-cache-mcp
server_version: "1.2.3"
instructions: "Internal build cache tools."
tools:
  - name: read_build_log         # canary name; honest agents never call these
    description: "Read a CI build log."
    input_schema: |              # optional JSON Schema
      {"type":"object","properties":{"run_id":{"type":"string"}}}
    result_json: |               # canned synthetic result (valid JSON, cap 16 KiB)
      {"content":[{"type":"text","text":"ok"}]}
```

Protocol surface: `initialize`, `notifications/initialized` (202),
`ping`, `tools/list`, `tools/call`. Classification: listing/initializing is an
`interaction`; calling any tool (known or unknown) is a `canary_invocation`.
Nothing is ever executed — results are canned text.

## Extensions (observer, optional)

Out-of-process observer extensions receive a bounded stream of successfully
stored observations. The extension output contract is one exact event-linked
acknowledgement; no returned content can influence decoy behavior, evidence,
configuration or policy (ADR-0006 and ADR-0014).

```yaml
extensions:
  enabled: true
  manifests:                      # strict config-relative v1alpha1 manifest paths
    - ./extensions/observer/manifest.json
  queue_size: 256                 # per-extension delivery queue (16..4096); full = drop+count
  shutdown_flush_seconds: 2       # bounded drain window at shutdown (1..10)
  ed25519_pubkey_hex: ""          # optional: require signatures by this key
```

Semantics that matter:

- **Verification is fail-closed.** Every manifest must pass digest (sha256,
  mandatory) and — when `ed25519_pubkey_hex` is set — ed25519 signature checks
  before startup; any failure refuses to start the system. Manifest paths must
  be relative to and remain contained within the config directory, including
  after symlink resolution. Manifest files are regular, capped at 1 MiB, and
  strictly reject unknown, duplicate and trailing fields. Referenced artifacts
  must be regular, remain inside the manifest directory after symlink
  resolution, and are streamed through a 256 MiB verification cap.
- **Capability gate.** A v1alpha1 manifest must declare exactly
  `permissions: ["observe"]`; missing, repeated, mixed or response-influencing
  permissions are refused.
- **Delivery is best-effort by design.** Full queues drop (counter
  `aegismesh_extension_dropped_total`), slow/crashing/erroring extensions are
  revoked for the process lifetime (`aegismesh_extension_revoked_total`) — no
  restart storms. An observation is offered only after its authoritative store
  append succeeds; a failed append is never exposed as if it were evidence.
- **Lifecycle.** Extensions start after admin and before sensors; shutdown
  drains up to `shutdown_flush_seconds`, then stops every host regardless.
- Payloads are JSON: `{event_id, time, classification, sensor{...}, payload}`
  where `payload` is the same redaction-safe observation stored in evidence.
  The complete request is capped at 128 KiB. Success requires the canonical
  response `{"type":"response","id":"req-N","result":{"event_id":"...","accepted":true}}`;
  unknown, duplicate, reordered or additional response content revokes the
  process and is never returned to the runtime.
- Correlation-signal envelopes append directly to the store and are not offered
  to extensions. Enabling that delivery would be new egress and needs a
  separate architecture and approval decision.

## Webhook evidence stream (optional, off by default)

```yaml
webhook:
  enabled: true
  url: "https://collector.example.com/v1/events"
  hmac_secret_env: WEBHOOK_HMAC      # NAME of env var — or hmac_secret_file, never the value itself
  queue_size: 512                    # pending events (16..8192); full queue drops (counted)
  batch_size: 32                     # events per POST (1..256)
  flush_interval_seconds: 5          # partial-batch send after idle (1..60)
  timeout_seconds: 10                # per-attempt HTTP timeout (1..60)
  max_retries: 3                     # attempts per batch, exponential backoff + jitter (0..8)
  allow_loopback_http: false         # dev-only cleartext to loopback collectors
```

Delivery semantics (wired in the runtime):

- **Fail-closed startup**: an unresolvable HMAC reference refuses to start;
  with no reference at all the sink delivers unsigned batches (doctor warns).
- **Best-effort by design**: the evidence store stays authoritative. Batches
  are POSTed as `{"events":[...]}` with `X-AegisMesh-Signature: sha256=<hmac>`,
  a timestamp, and a batch id; per-event ids inside the body give collectors
  idempotency.
- **DNS-rebinding safe**: every connection target IP is re-checked against
  the egress policy at dial time; redirects are never followed; environment
  proxies are ignored.
- **Bounded**: queue drops (`aegismesh_webhook_dropped_queue_full_total`),
  retry exhaustion, and shutdown abandonment are all counted — silent loss is
  impossible by construction.

`doctor` reports readiness statically; pass `--probe-webhook` to send one
bounded signed test batch (explicit opt-in, never automatic).

## Correlation engine (optional, off by default)

```yaml
correlation:
  enabled: true
  disabled_rules: ["COR-004"]   # rule ids; unknown ids are rejected at load
  window_seconds: 600           # event-time lookback per source (60..3600)
  per_source_events: 64         # ring cap per source (8..512)
  max_sources: 4096             # tracked sources, oldest-first eviction (64..65536)
  automation_threshold: 8        # COR-005: 4..per_source_events; 0 = default 8
  credential_threshold: 8        # COR-007: 3..per_source_events; 0 = default 8
```

Turns per-source observation streams into signals — repeated injection
(COR-001), protocol hopping (COR-002), tool probing (COR-003), sustained
recon (COR-004), cadence (COR-005), AI-family enumeration (COR-006), credential
attempt distinctness (COR-007) and cross-sensor decoy-key replay (COR-008).
See the exact new predicates below and in ai-threat-detection.md. Semantics:

- **Event-time deterministic**: same input sequence always yields the same
  signals; late-but-in-window arrivals still count.
- **One fire per window per source/rule**; re-arming needs fresh evidence
  after the ring expires.
- **Bounded memory**: rings and source count are capped; eviction forgets
  cooldowns by design.
- **Observations only**: signals are operator-facing findings. They are not
  enforcement inputs and nothing acts on them automatically.

## Environment variable overrides

Applied after file parsing, before validation:

| variable | overrides |
|---|---|
| `AEGISMESH_DATA_DIR` | `runtime.data_dir` |
| `AEGISMESH_ADMIN_LISTEN` | `admin.listen` |
| `AEGISMESH_ADMIN_ENABLED` | `admin.enabled` (`true`/`false`) |
| `AEGISMESH_LOG_LEVEL` | log verbosity (`debug`, `info`, `warn`, `error`) |
| `AEGISMESH_LLM_API_KEY` | API key for remote providers (never logged) |
| `AEGISMESH_LLM_BASE_URL` | remote provider endpoint |

Secrets live in environment variables, never in `mesh.yaml` files that get
committed, exported, or shared in incident reviews.

## Operator console (optional)

The console is disabled by default and owns a separate listener and mux. It is
read-mostly, with a single default tenant unless configured otherwise. Writes include console sessions,
operator investigations, audit and optional fleet registry administration; no sensor or policy control
is exposed. The API contract is [architecture/console-api.md](architecture/console-api.md).

```yaml
console:
  enabled: false
  listen: 127.0.0.1:9120
  state_dir: ""                 # <runtime.data_dir>/console
  session_ttl_seconds: 3600      # 60..86400
  index_max_events: 50000        # 1000..500000
  tls_cert_file: ""              # certificate and key together
  tls_key_file: ""
  operators: []                  # 1..32 required when enabled
```

Generate a token with `aegismesh console token` and paste its `operators:` snippet
inside `console:`. Names use the existing 3..64 character lowercase slug grammar;
roles are `viewer`, `analyst`, `admin`. Only a 64-hex SHA-256 digest is stored in
configuration; names and digests must both be unique. `viewer` reads evidence,
`analyst` also writes investigations, and `admin` also reads/verifies audit.
There is no built-in/default password. Tokens do not expire automatically;
rotate configuration and restart to replace/revoke them. Sessions expire and are
lost on restart. They are bounded to 1024 per tenant (32768 globally), with oldest-expiring eviction.

`AEGISMESH_CONSOLE_ENABLED` and `AEGISMESH_CONSOLE_LISTEN` override the matching
fields. Credentials, TLS and limits stay in the file. Relative `state_dir` and
TLS file paths resolve against the config directory. Empty `state_dir` follows
the resolved data directory, including `AEGISMESH_DATA_DIR` overrides. State
must reside in a real private directory (0700) with regular private files (0600).
Unusable state, invalid TLS files or a bind failure abort startup.

Plain HTTP is accepted only on loopback. Public/wildcard binds require both
`security.allow_public_bind: true` and TLS files, including empty-host addresses
such as `:9120`. Privileged ports retain the
existing explicit opt-in requirement; port 0 supports OS assignment. `doctor`
checks the port and reports exposure; `validate --effective --json` includes a
non-secret console exposure summary. Reverse proxies must preserve an allowed
Host and the original HTTPS Origin; forwarded headers are deliberately ignored.

The disposable in-memory index retains at most `index_max_events`, with an
additional 64 MiB accounted envelope budget (encoded envelope size plus bounded
projection overhead). Oldest indexed entries are evicted at either limit and
`/node` reports `truncated`. This bounds retained data, not total process RSS.
Readable plaintext history is backfilled before serving. Corrupt skipped history
reports `unavailable`; a terminal reader error aborts startup. Encrypted storage
never receives a private identity in the runtime: its console history is always
`unavailable`, and only successfully appended live envelopes are indexed.
Storage append success is the existing acceptance boundary, not per-event fsync.
The node endpoint bounds physical storage metadata reads to 65536 directory
entries and reports 503 when this query bound is exceeded.

Investigation limits are 1000 cases, 100 notes/case, 200 event IDs/case,
200 Unicode characters/title, 4000 characters/note and 32 MiB total encoded state.
Audit rotates at 4 MiB to at most 128 segments, preserving the hash chain and
failing closed at quota; archive/export and restart with a deliberately managed
state directory when full. There is no automatic deletion or audit repair.
Audit and investigations are plaintext even when evidence encryption is enabled;
use an encrypted local volume when their confidentiality is required.

The operator UI is embedded in the binary (`internal/consoleui`; no build step,
no third-party code) and the runtime injects it through `console.Options.UI fs.FS`.
It is served only when `console.enabled` is true. A server constructed without a
UI FS serves a plain-text notice at `/`; the API is unaffected. Asset loading
is capped at 1024 files, 16 MiB/file and 32 MiB total, snapshotted at startup.
Only `/` serves `index.html`; deep links do not fall back to the index.

## Experimental fleet inventory (ADR-0018)

Both roles are off by default. This is experimental fleet inventory with
authenticated enrollment and heartbeats, with logical tenant isolation
(experimental) when configured. It is not a hosted service. Live evidence forwarding is a separate opt-in described below. Configure separate processes/data directories
for hub and agent. Operator configs reject simultaneous roles; package-level
synthetic integration tests can compose them. The hub cannot command nodes.

A hub may have `sensors: []` and run inventory only. Ordinary nodes and agents
still require at least one sensor. Hub example (configure console operator
authentication separately):

```yaml
fleet:
  hub:
    enabled: true
    listen: 127.0.0.1:9130
    state_dir: fleet-hub-state
```

Agent example, with the enrollment token placed in a **0600 regular file** next
to the config, never inline or in an argument:

```yaml
fleet:
  agent:
    enabled: true
    hub_url: http://127.0.0.1:9130
    state_dir: fleet-agent-state
    node_name: edge-node
    enrollment_token_file: enrollment.token
    heartbeat_interval_seconds: 30
```

| Field | Default / validation |
| --- | --- |
| `fleet.hub.enabled` | false; explicit inbound machine API opt-in |
| `fleet.hub.listen` | `127.0.0.1:9130`; unprivileged/loopback by default; non-loopback requires TLS and `security.allow_public_bind` |
| `fleet.hub.state_dir` | `<runtime.data_dir>/fleet-hub`; configured relative paths resolve from config directory |
| `fleet.hub.tls_cert_file`, `tls_key_file` | empty; paired PEM paths, relative to config directory; certificate/key loaded before listeners bind |
| `fleet.agent.enabled` | false; explicit outbound metadata disclosure opt-in |
| `fleet.agent.hub_url` | empty; required when enabled, origin-only http(s); HTTP loopback only; no credentials, query, fragment or path prefix |
| `fleet.agent.state_dir` | `<runtime.data_dir>/fleet-agent`; same resolution as hub; role directories must differ |
| `fleet.agent.node_name` | `runtime.instance_name`; immutable enrolled name, 3..64 character lowercase slug |
| `fleet.agent.enrollment_token_file` | empty; config-relative path confined by `os.Root`, no traversal or final symlink, mode 0600 regular file, at most 4096 bytes |
| `fleet.agent.enrollment_token_env` | empty; environment variable **name**, mutually exclusive with file; contents are never serialized |
| `fleet.agent.hub_ca_file` | empty; system roots otherwise; optional additional PEM bundle up to 1 MiB, checked before listeners bind |
| `fleet.agent.allow_private_egress` | false; explicit RFC1918/ULA allowance independent of LLM/webhook settings; metadata/link-local always denied |
| `fleet.agent.heartbeat_interval_seconds` | 30; 10..300; omitted/zero in the config file receives the default; an environment override of zero fails validation |

Every field supports `AEGISMESH_FLEET_` plus its uppercase nested path, such as
`AEGISMESH_FLEET_HUB_ENABLED`, `AEGISMESH_FLEET_HUB_TLS_CERT_FILE`,
`AEGISMESH_FLEET_AGENT_HUB_URL`, `AEGISMESH_FLEET_AGENT_ENROLLMENT_TOKEN_ENV`,
`AEGISMESH_FLEET_AGENT_ALLOW_PRIVATE_EGRESS` and
`AEGISMESH_FLEET_AGENT_HEARTBEAT_INTERVAL_SECONDS`. Overrides are applied before
validation. There is no inline token or insecure TLS override. `validate
--effective --json` reports every fleet setting and reference name, never the
referenced token. `doctor` checks static readiness without contacting the hub or
creating a node identity. Startup validates credential/CA material before binds.

Remove the enrollment reference after successful enrollment if desired: the
same key can restart and prove possession without a token. Keep its state dir
and node name stable. A missing/malformed configured reference still fails
preflight, even for a previously enrolled identity. No enrollment reference
means an unknown key cannot enroll. Back up the private identity; losing it
creates a new node identity requiring a new enrollment token. Revoked keys
cannot re-enroll, even with another token.

State directories must be real 0700 directories, state files regular 0600 files.
One runtime owns each data/state directory. Hub registry, token hashes, replay
state and audit are plaintext metadata even when evidence encryption is enabled.
No additional knobs control abuse limits: heartbeat spacing follows each node's
registered interval; replay windows hold 64 nonces per node; remote throttling
uses 4096 source-IP buckets and 8192 requests/minute each; rejection audit is
sampled globally (five/minute plus a suppression summary). Soft liveness/replay
state flushes every five seconds and on shutdown; durable changes save immediately.
A crash can lose the latest unflushed interval and reopen its nonces within the
signed timestamp window. See [fleet protocol](architecture/fleet-protocol.md) for
precise crash/replay, scheduler/IO, shared-NAT and audit-failure limitations.

## Experimental evidence forwarding (ADR-0018 amendment)

**Experimental; best-effort forwarding with counted loss; local store authoritative.**
The two consent switches are independent, strictly decoded booleans and default false:

```yaml
# Agent config: explicit disclosure of already redacted live evidence to its fixed hub.
fleet:
  agent:
    enabled: true
    hub_url: https://hub.example.test:9130
    node_name: edge-node
    forward_evidence:
      enabled: true
```

```yaml
# Separate hub config; sensor-less hubs are supported.
fleet:
  hub:
    enabled: true
    accept_evidence:
      enabled: true
```

The agent excerpt also requires the existing enrollment credential reference for a new
identity; public/private non-loopback destinations require TLS and the existing egress
opt-in where applicable. The hub excerpt uses its default loopback listener; use an explicit
certificate/key and public-bind consent for non-loopback exposure. No insecure TLS option exists.
Enabling a consent flag without its parent role is invalid. Unknown nested fields fail loading.
`AEGISMESH_FLEET_AGENT_FORWARD_EVIDENCE_ENABLED` and
`AEGISMESH_FLEET_HUB_ACCEPT_EVIDENCE_ENABLED` override the respective booleans.
`validate --effective --json` shows both, including off defaults, and `doctor` reports consent
and disclosure without probing the hub or generating an identity.

The queue is fixed at 4,096 events/16 MiB, batches at 1,000 events/4 MiB. Hub quotas are
five-second spacing, 1,000 events/second, 16 MiB request bytes/minute/node, 16 MiB retained
segment bytes/node and 256 MiB aggregate forwarded segments. These fixed bounds require no
new tuning fields. Copies live at `<resolved fleet.hub.state_dir>/tenants/<tenant>/evidence/<node id>/`,
with segments capped at 4 MiB (respecting smaller configured caps), a 1 MiB envelope ceiling, inherited storage count/age retention and
the hub's `storage.encryption` setting. Node encryption is independent and never supplies
its private read identity to the runtime. See architecture/fleet-protocol.md for conservative
reservations, dedup/crash windows, capacity refusal and in-flight queue accounting.

No plaintext disk spool is created. Overflow/crash/offline losses leave evidence only on
the node; hub retention and local retention do not propagate deletions. Redaction is the
control: a compromised hub learns redacted evidence from every forwarding node.

## SSO via OIDC (experimental) and logical tenant isolation (experimental)

The console remains opt-in. Without these settings there is exactly one tenant,
`default`, and existing token operators retain their roles and membership.
The IdP must support Authorization Code, S256 PKCE and RS256, ES256 or EdDSA ID
tokens. Configure its registered redirect exactly; the scheme must match console
TLS and the authority must match the actual console listener. Issuer discovery,
authorization, token and JWKS endpoints must share one scheme/authority in this
slice; cross-authority providers are unsupported.

```yaml
console:
  enabled: true
  listen: 127.0.0.1:9120
  token_login: true
  tenants: [default, bravo]
  local_tenant: default
  # Existing operators also need token_sha256; no raw token belongs in configuration.
  operators:
    - name: operator
      role: admin
      token_sha256: REPLACE_WITH_64_HEX_DIGEST
      tenants: [default, bravo]
  oidc:
    enabled: true
    display_name: Example identity
    issuer: https://idp.example.invalid
    client_id: aegismesh-console
    redirect_uri: http://127.0.0.1:9120/api/v1/auth/oidc/callback
    client_secret_env: AEGISMESH_IDP_SECRET
    # Alternatively client_secret_file: secrets/idp-secret (never both).
    # Omit both references for a public client using PKCE only.
    role_claim: groups
    role_mapping: {observers: viewer, responders: analyst, operators: admin}
    name_claim: email
    tenant_claim: organizations
    tenant_mapping: {organization-a: default, organization-b: bravo}
    allow_private_egress: false
```

| Field | Default and validation |
| --- | --- |
| `console.token_login` | true; false requires OIDC enabled and disables bearer as well as token-session login |
| `console.tenants` | `[default]`; at most 32 unique canonical slugs, 3..64 bytes, lowercase ASCII letters/digits/hyphens, starts/ends alphanumeric |
| `console.local_tenant` | `default`; must be declared; owns all local evidence, node/sensor/rule/agent views |
| `console.operators[].tenants` | `[default]`; at most 32 declared memberships; first is initially active |
| `console.oidc.enabled` | false; discovery runs only after console starts |
| `console.oidc.display_name` | `Single sign-on`; 1..64 printable bytes, rendered as text |
| `console.oidc.issuer` | empty; required when enabled, exact issuer up to 512 bytes; HTTPS, or HTTP loopback for development; no credentials/query/fragment |
| `console.oidc.client_id` | empty; required when enabled, 1..256 printable bytes |
| `console.oidc.client_secret_env` | empty; optional environment variable name, never the value |
| `console.oidc.client_secret_file` | empty; optional config-relative reference up to 4096 bytes, rooted containment, no final symlink, regular mode 0600, file at most 4096 bytes, value whitespace-trimmed; mutually exclusive with env |
| `console.oidc.redirect_uri` | empty; required exact callback URL `/api/v1/auth/oidc/callback`, at most 1024 bytes; no query/fragment or encoded path |
| `console.oidc.role_claim` | `groups`; exact claim name, 1..64 printable bytes; string or array of up to 64 strings of 1..128 bytes |
| `console.oidc.role_mapping` | empty; enabled OIDC requires 1..128 exact claim-value → viewer/analyst/admin mappings; highest role wins, no match denies |
| `console.oidc.name_claim` | `email`; 1..64-byte claim name; string at most 256 bytes, fallback sub; sanitized/truncated to 64 printable ASCII bytes |
| `console.oidc.tenant_claim` | `tenants`; same bounded string/array shape as roles; no declared match denies, even for a single tenant |
| `console.oidc.tenant_mapping` | empty; exact declared slug matching; when nonempty, at most 128 explicit claim-value → declared-slug entries, unmatched values ignored |
| `console.oidc.allow_private_egress` | false; explicit RFC1918/ULA permission independent of other egress flags; metadata/link-local always denied |

All new settings have environment overrides under `AEGISMESH_CONSOLE_` using
uppercase underscore paths, e.g. `TOKEN_LOGIN`, `LOCAL_TENANT`, `OIDC_ENABLED`,
`OIDC_ISSUER`, `OIDC_CLIENT_SECRET_ENV`, `OIDC_ALLOW_PRIVATE_EGRESS`.
`TENANTS`, `OPERATORS`, `OIDC_ROLE_MAPPING` and `OIDC_TENANT_MAPPING` accept strict
JSON (64 KiB maximum). `OPERATORS` replaces the complete operator list and allows
membership overrides; it still holds only digests. Booleans must parse as
booleans. The reference names themselves, not resolved secrets, are reported by
`validate --effective` and `doctor`. No inline `client_secret` field or raw-secret
override exists. A missing/unreadable confidential-client credential fails local
construction without exposing its contents. Discovery outages are different:
the console and sensors run, SSO reports unavailable and retries with 1..60-second
backoff. Token operators continue to work when enabled.

OIDC pending states are single-use, capped at 128 entries/two minutes and bound
to a short-lived browser cookie. Session TTL stays 3600 seconds by default,
60..86400 configurable, capped by actual ID token expiry. JWKS reuse is at most
five minutes with refresh attempts at most every five seconds per discovery
snapshot. Provider responses are capped at 256 KiB, ID tokens at 24 KiB and keys
at 32. Logout is local only; membership changes take effect at next login.

Tenant state lives under `<console-or-hub-state>/tenants/<tenant>/`; hub evidence
copies live under its tenant's `evidence/<node-id>/`. Legacy roots automatically
move, without rewriting data, into `tenants/default` through a fixed sibling
`.tenant-migration` directory. Startup resumes interrupted renames and refuses
conflicting destinations for operator inspection. Run one process per state
root. Keep backups before upgrading; do not point an older binary at the new
layout. Console/hub roots must be disjoint and cannot contain local evidence, configuration
or agent identity state. Unexpected legacy entries fail before any rename.
Removing a tenant from configuration leaves its retained state on disk.

Sessions are bounded to 1024 per active tenant/32768 globally, with tenant-local eviction.
Quotas are independent per tenant: 1000 investigations/32 MiB snapshots,
100 outstanding tokens, 1000 nodes including tombstones, 256 MiB forwarded
retention, 64 MiB accounted index bytes and existing audit segment bounds.
The 32-tenant cap bounds aggregate nodes/investigations to 32000, outstanding
tokens to 3200, forwarded retention to 8 GiB and accounted index to 2 GiB. These
are caps, not reservations; disk exhaustion and process overload cross tenants.
There is no cross-tenant administrator view. Logical isolation shares process,
OS user, data directory, hub encryption recipient and signing/egress policy;
host/process compromise crosses tenants. No per-tenant keys, billing, rate plans
or self-service creation are included. See ADR-0019/0020 and the exact API contract.

## Synthetic honeytokens and AI observations

`honeytokens` is an optional top-level list of at most 64 `{id, value, kind}`
entries. IDs are unique `[a-z0-9][a-z0-9-]{0,63}` slugs; values are unique
16..256 printable ASCII bytes without spaces. `kind` is exactly `credential`
or `agent_canary`; unknown fields fail validation. Never use real credentials.
Inbound acquired bytes are matched literally; token ids, not values, are kept
in HT-001/AGT-001 findings. Values are scrubbed before preview truncation,
including when detection is disabled.

`correlation.automation_threshold` (4..`per_source_events`) and
`correlation.credential_threshold` (3..`per_source_events`) each default to 8
when omitted or zero. They control COR-005 cadence and COR-007 distinct auth
attempts. COR-006 requires two AI families; COR-008 requires a prior interaction
from the same source with another sensor. `correlation.disabled_rules` now
accepts COR-001..COR-008; `detection.disabled_rules` additionally accepts
LLM-001..LLM-004, HT-001 and AGT-001. All new detection rules are observe-only,
including critical HT-001; existing severity/action semantics remain intact.

`init --profile ai-decoy` generates static AI HTTP responses with two synthetic
markers and random persona variation, local provider and no fallback. See
[ai-threat-detection.md](ai-threat-detection.md) for response surfaces, exact
predicates, resource limits, memory-only credential distinctness and caveats.
