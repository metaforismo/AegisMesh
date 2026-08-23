# Migrating from Beelzebub (clean-room importer)

`aegismesh migrate beelzebub FILE...` translates publicly documented
Beelzebub configuration shapes into AegisMesh configs. The importer was
written against the *documented YAML format only* — no Beelzebub code, tests,
or text were copied — and it is deliberately conservative: what cannot be
translated faithfully is reported, never approximated silently.

Run `aegismesh migrate beelzebub --help` for flags. Dry-run is the default.

## Document types

| source document | behavior |
|---|---|
| http service | translated to an `http` sensor |
| tcp service | translated to a `tcp` sensor |
| mcp service | translated to an `mcp` sensor |
| core file | report-only (logging/tracings/prometheus notes) |
| ssh service | maps only `protocol`, `address`, and a derived sensor id; command/auth/persona/key fields are reported unsupported |
| telnet service | **fully unsupported**; every field is listed and no sensor is emitted |
| anything else | detected as `unknown`, no output |

## HTTP mapping

| Beelzebub field | AegisMesh target | notes |
|---|---|---|
| `address` (`":8080"`) | `sensors[].listen` | empty host → explicit `127.0.0.1:`; see "bind policy" below |
| `commands[].regex` | `rules[].path_regex` | RE2-validated by AegisMesh config validation |
| `commands[].methods` | `rules[].methods` | verbatim list |
| `commands[].statusCode` | `rules[].status` | default 200 when absent |
| `commands[].handler` | `rules[].body` | inline body, 64 KiB cap |
| `commands[].headers` (`"K: V"` entries) | `rules[].headers` | malformed entries reported per-entry |

Approximated:

- `commands[].params` / query-style captures: **dropped** with a note;
  AegisMesh rules are static responses, not templates.
- `fallbackCommand`: reported unsupported — upstream fallback handlers are
  plugin-based. Use an `http.fallback` LLM block instead (review its output).

Unsupported (reported per field):

- `commands[].plugin` — in-process plugins have no equivalent by design.
- `tls`, `certFile`, `keyFile` — TLS termination is not part of decoy
  listeners in this release.

## TCP mapping

| Beelzebub field | AegisMesh target | notes |
|---|---|---|
| `banner` | `banner` | ≤ 4 KiB |
| `commands[].regex` + `.handler` | `tcp_rules[].line_regex` + `.response` | both required |
| `deadlineTimeoutSeconds` | `session.idle_timeout_seconds` | capped at 3600 |

Unsupported/reported:

- `serverName` — TCP personas are banner-only here; kept as a note.
- `passwordRegex` — credential-guessing flows belong to the authentication-only
  SSH sensor; AegisMesh TCP decoys never accept secrets.
- `commands[].plugin` — reported, skipped.

## MCP mapping

| Beelzebub field | AegisMesh target | notes |
|---|---|---|
| `serverName` | `server_name` | verbatim |
| `tools[].name/.description` | same | verbatim |
| `tools[].handler` (JSON) | `result_json` | must parse as JSON; ≤ 16 KiB |
| `tools[].params[]` | `input_schema` (minimal) | names → properties + required; **per-param descriptions dropped** and flagged as approximated |

## SSH mapping (authentication-only boundary)

The current official Beelzebub service examples define SSH documents with
`protocol`, `address`, command rules, `serverVersion`, `serverName`,
`passwordRegex`, `deadlineTimeoutSeconds`, and optional plugin configuration.
See the [official SSH configuration reference](https://github.com/beelzebub-labs/beelzebub#ssh-deception-service).

The importer now emits an AegisMesh SSH sensor only when the address is a
valid host/port. It translates only fields with a safe exact equivalent:

| Beelzebub field | AegisMesh target | notes |
|---|---|---|
| `protocol: ssh` | `sensors[].kind: ssh` | selects AegisMesh's authentication-only sensor |
| `address` | `sensors[].listen` | empty host becomes `127.0.0.1`; explicit public or privileged binds remain subject to strict validation |
| source filename | `sensors[].id` | deterministic `beelzebub-<stem>` id; this is provenance, not source configuration |

The following SSH behavior is reported as unsupported and is never copied into
the generated config:

- `commands[]` regexes, handlers, and plugins — AegisMesh SSH accepts no
  channel, shell, PTY, forwarding, or command.
- `passwordRegex` — AegisMesh records an authentication observation without
  validating, retaining, or reusing credentials.
- `serverName` and `serverVersion` — no safe exact persona mapping is assumed.
- `deadlineTimeoutSeconds` and plugin configuration — source semantics and
  response behavior are not imported or approximated.
- host-key fields or paths — AegisMesh generates an ephemeral in-memory
  Ed25519 host key per sensor instance; no path or key material is accepted by
  the importer.

Generated SSH configs therefore contain only `kind`, `id`, and `listen`; the
strict loader supplies bounded SSH defaults. Review the report before using a
privileged or non-loopback source address: validation fails until the operator
deliberately changes the relevant security policy.

## Bind policy (all kinds)

- Empty host (`":8080"`) becomes `127.0.0.1:8080`.
- Explicit hosts are preserved verbatim but always reported:
  non-loopback binds fail validation until you set
  `security.allow_public_bind: true` deliberately.
- Ports < 1024 produce a note naming `security.allow_privileged_ports`;
  nothing is ever enabled automatically.
- Emitted configs contain **no** security section at all — the strict loader
  round-trip is part of the importer's test suite.

## Credential safety gate

Before any translation, every source document is scanned for
credential-shaped keys (`api_key`, `secret`, `token`, `password`,
`private_key`, ...):

- **Inline material** (PEM blocks, long opaque blobs) refuses the whole
  import with a non-zero exit. The error names the offending path (e.g.
  `$.api_key`) but never the value.
- **References** (file paths, obvious placeholders like `changeme`) are
  reported as unsupported fields and carried over as nothing.

AegisMesh configs are meant for version control; credentials belong in
`llm.api_key_env` / `llm.api_key_file` references, resolved at runtime.

## Honest limitations

- This is an auditable MVP, not full parity. Upstream features without a
  safe equivalent (plugins, SSH command/Telnet simulation, TLS on decoys) are
  reported per-field so you can decide what to do manually.
- IDs derive from source filenames (`beelzebub-<stem>`); collisions get a
  numeric suffix and a note.
- Review every emitted rule before running: imported regexes and canned
  bodies become live decoy behavior under your name.
