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
storage:    { max_file_bytes, retention: { max_events, max_age_days } }
llm:        { provider, system_prompt?, api_key_env?, base_url? }
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
| `retention.max_events` | `100000` | delete oldest closed segments beyond this |
| `retention.max_age_days` | `30` | delete segments older than this |

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
validate, reuse, compare, hash, log, or retain real credentials. Usernames and
credential contents are omitted from evidence entirely, not hashed.

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
```

Turns per-source observation streams into signals — repeated injection
(COR-001), protocol hopping (COR-002), tool probing (COR-003), sustained
recon (COR-004). Semantics:

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
