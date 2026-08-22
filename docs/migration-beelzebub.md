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
| ssh / telnet service | **fully unsupported**; every field listed with the roadmap pointer |
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
- `passwordRegex` — credential-guessing flows belong to SSH decoys
  (roadmap); AegisMesh TCP decoys never accept secrets.
- `commands[].plugin` — reported, skipped.

## MCP mapping

| Beelzebub field | AegisMesh target | notes |
|---|---|---|
| `serverName` | `server_name` | verbatim |
| `tools[].name/.description` | same | verbatim |
| `tools[].handler` (JSON) | `result_json` | must parse as JSON; ≤ 16 KiB |
| `tools[].params[]` | `input_schema` (minimal) | names → properties + required; **per-param descriptions dropped** and flagged as approximated |

## Bind policy (all kinds)

- Empty host (`":8080"`) becomes `127.0.0.1:8080`.
- Explicit hosts are preserved verbatim but always reported:
  non-loopback binds fail validation until you set
  `security.allow_public_bind: true` deliberately.
- Ports < 1024 produce a note naming `security.allow_privileged_ports`;
  nothing is ever enabled automatically.
- Emitted configs contain **no** security section at all — the strict loader
  round-trip is part of the importer's test suite.

## Honest limitations

- This is an auditable MVP, not full parity. Upstream features without a
  safe equivalent (plugins, SSH/telnet simulation, TLS on decoys) are
  reported per-field so you can decide what to do manually.
- IDs derive from source filenames (`beelzebub-<stem>`); collisions get a
  numeric suffix and a note.
- Review every emitted rule before running: imported regexes and canned
  bodies become live decoy behavior under your name.
