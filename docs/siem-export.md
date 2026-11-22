# Local SIEM event files

`aegismesh export events --data-dir ./data --format cef` reads local evidence
through the same encrypted/checkpoint reader as `inspect`, verifies envelopes
and payload hashes, and writes a deterministic file encoding to stdout.
`--format` accepts `cef`, `syslog-rfc5424`, `otlp-json`, `ecs`; `--out FILE`
creates a new mode-0600 file and refuses existing files/symlinks. The only path
selector is the explicit operator flag. `--since RFC3339` selects an inclusive
lower timestamp bound after verification. `--identity FILE` is repeatable;
`--require-sealed` requires final encrypted seals. Open/checkpoint notices go
to stderr. There is no network transport, retry queue, collector URL or egress.

Every local input is verified before output, including events excluded by
`--since`. At most 8192 envelopes are read; exceeding that cap fails closed,
not silently truncates. Output is staged and capped at 2 MiB. Corrupt lines,
invalid envelopes and integrity failures suppress the whole output. Output
filesystem failures can leave an incomplete new file; no atomic-file guarantee
is made. Sort order is timestamp, authenticated origin, then event ID.

The analyst console route `/api/v1/export/events` uses exactly one of `session`,
`source`, `investigation`, `window`, plus `format`; scoping matches indicator
exports. It scans the newest 8192 summaries, resolves origin-qualified native
envelopes with no related-event traversal, and fails if any selected reference
was evicted before staging. A conservative 2 MiB native-input budget also
applies. No URI chooses a disk path. Successful downloads are audited before
bytes, use fixed allowlisted filenames and carry no-store/bounds headers.

CEF is newline-delimited CEF:0 with escaped header backslashes/pipes, extension
backslashes/equals and neutralised controls. It includes observation class,
summary, ID, source key as a custom string (not an asserted IP), node/sensor
IDs, timestamp in milliseconds and rule IDs. RFC 5424 uses facility local0
(16), APP-NAME `AegisMesh`, NILVALUE host/procid, MSGID `observation`, six
fractional timestamp digits and SD-ID `aegismesh@32473` (documentation PEN).
Structured data quotes, backslashes and closing brackets are escaped; all
variable line controls are replaced. This PEN is for example/file format use,
not a registered production enterprise identifier. Messages describe redacted
observations; no request body, prompt, argument preview or credential is copied
into CEF/syslog/OTLP. ECS preserves native redacted evidence.

| Highest catalog finding severity | CEF | Syslog severity | OTLP severityNumber |
| --- | ---: | ---: | ---: |
| none / info | 0 | 6 (informational) | 9 (INFO) |
| low | 1 | 5 (notice) | 9 (INFO) |
| medium | 4 | 4 (warning) | 13 (WARN) |
| high | 7 | 3 (error) | 17 (ERROR) |
| critical | 10 | 2 (critical) | 21 (FATAL) |

Severity describes the observation's catalog metadata, not a confirmed incident.
Correlation signals without detection severity use the none/info mapping.
OTLP uses INFO for both low and none/info; `severityText` retains the catalog
label. No field establishes SIEM incident severity.

**OTLP is format only; AegisMesh does not ship an OTLP exporter.** The JSON
file has `resourceLogs[].scopeLogs[].logRecords[]` with `timeUnixNano` as a
nanosecond decimal string, numeric severity, string body and typed string
attributes. Supported timestamps are Unix epoch through Go's signed-nanosecond
maximum (2262-04-11); others fail closed for this encoding. It is not OTLP/HTTP,
gRPC, delivery, acknowledgement or collector interoperability evidence.
ECS is NDJSON through `ecsexport`, with the unmodified native envelope and an
additional `aegismesh.node_id` field distinguishing colliding fleet IDs.
Golden/escaping/fuzz-seed tests prove local bytes; no external SIEM was tested.
