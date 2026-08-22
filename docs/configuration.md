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
| `provider` | `local` | only `local` is implemented; anything else fails closed (`ErrNoAPIKey` without key) |
| `base_url` | — | remote adapter endpoint; unused until roadmap R2 |
| `model` | — | remote model name; unused until R2 |

The API key is read only from the environment variable
`AEGISMESH_LLM_API_KEY`; there is deliberately no config-file field for it.

Provider contract (internal/llm): the context governs blocking work only.
The local provider is a pure function and never fails because a context is
cancelled; remote adapters must honor cancellation.

## Sensors

Common fields for all kinds:

```yaml
- id: http-admin-decoy     # unique, [a-z0-9][a-z0-9.-]{2,63}
  kind: http               # http | tcp | mcp
  listen: "127.0.0.1:8081"
```

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

Out-of-process observer extensions receive a bounded stream of observations
(data-only; their replies are acks/errors and can never influence decoy
behavior, evidence, or policy — ADR-0006).

```yaml
extensions:
  enabled: true
  manifests:                      # ext.aegismesh.io/v1alpha1 manifest files
    - ./extensions/observer/manifest.json
  queue_size: 256                 # per-extension delivery queue (16..4096); full = drop+count
  shutdown_flush_seconds: 2       # bounded drain window at shutdown (1..10)
  ed25519_pubkey_hex: ""          # optional: require signatures by this key
```

Semantics that matter:

- **Verification is fail-closed.** Every manifest must pass digest (sha256,
  mandatory) and — when `ed25519_pubkey_hex` is set — ed25519 signature checks
  before startup; any failure refuses to start the system.
- **Capability gate.** Only extensions declaring the `observe` permission are
  wired today; anything else is refused with an explicit message.
- **Delivery is best-effort by design.** Full queues drop (counter
  `aegismesh_extension_dropped_total`), slow/crashing/erroring extensions are
  revoked for the process lifetime (`aegismesh_extension_revoked_total`) — no
  restart storms. Evidence storage is never affected.
- **Lifecycle.** Extensions start after admin and before sensors; shutdown
  drains up to `shutdown_flush_seconds`, then stops every host regardless.
- Payloads are JSON: `{event_id, time, classification, sensor{...}, payload}`
  where `payload` is the same redaction-safe observation stored in evidence.

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

Destination policy (validated at load, fail-closed): https required beyond
loopback; cloud metadata permanently denied; private-range collectors need
`security.allow_private_llm_egress: true` (the current opt-in covers LLM and
webhook egress alike). The evidence store stays authoritative — the webhook
is a best-effort stream and every drop is counted.

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
