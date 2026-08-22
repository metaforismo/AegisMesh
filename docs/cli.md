# CLI reference

All commands accept `--log-level {debug|info|warn|error}`. Exit codes:
`0` success, `1` failure, `2` usage error. Human output goes to stdout;
errors and hints to stderr; most report commands support `--json`.

## aegismesh init

    init [--dir DIR] [--force]

Scaffold a safe local workspace: `mesh.yaml` (loopback binds, synthetic
personas), empty `data/`. Refuses to overwrite without `--force`.

## aegismesh doctor

    doctor --config FILE [--json]

Environment sanity checks: binary/version, config validity, data dir
existence and writability, port availability, admin reachability when
running. Non-zero exit if any check fails.

## aegismesh validate

    validate --config FILE [--effective] [--json]

Strict validation against the schema plus all policy invariants (loopback
binds, privileged ports, regex compilability, cap ranges, unique ids).
This is the same gate CI and `run` apply.

With `--effective`, also preview the resolved policy — provider and egress
classification (loopback/private/public/denied), detection rules with the
severity-to-action mapping and bounds, and per-sensor capabilities including
the MCP decoy surface. Still side-effect free: nothing is started, contacted,
or written.

## aegismesh run

    run --config FILE [--dry-run]

Start every sensor and block until SIGINT/SIGTERM. Graceful shutdown stops
intake, drains sensors, flushes evidence.

`--dry-run` binds every listener, proves the environment works, prints each
sensor's bind address, then shuts down — nothing is recorded, no decoy ever
answers. Use it before any production-ish deployment.

## aegismesh inspect

    inspect list   --data-dir DIR [--limit N] [--sensor ID] [--kind KIND] [--finding RULE_ID] [--verify]
    inspect show   --data-dir DIR --id EVENT_ID [--verify]
    inspect export --data-dir DIR --out FILE.ndjson [--verify]

Read-only access to evidence. `show` accepts ID prefixes (shortest unambiguous
match). `--verify` recomputes each event's integrity hash; corrupt lines are
skipped, counted, and reported — never silently dropped. `--finding PI-001`
filters to events where a named detection rule fired (rule ids are validated
against the registry before any file is read).

## aegismesh migrate

    migrate beelzebub FILE... [--out DIR] [--write] [--force]

Clean-room importer for Beelzebub YAML service documents (http/tcp/mcp;
core files produce a report only; ssh/telnet are reported fully unsupported).
Dry-run by default; `--write` emits `<stem>.aegismesh.yaml` per translatable
file, refusing overwrites without `--force`. Source documents containing
credential material (API keys, tokens, PEM blocks) refuse the import with a
non-zero exit; credential *references* (paths, placeholders) are reported as
unsupported and never carried over. Values are never echoed. See
docs/migration-beelzebub.md
for exact field mappings.

## aegismesh ext

    ext verify --manifest FILE [--pubkey KEYFILE]
    ext run    --manifest FILE --input JSON  [--pubkey KEYFILE]

Verify an extension manifest (sha256 digest required; optional ed25519
signature over the digest) or execute it under the out-of-process host with
handshake/deadline/output caps and revocation on violation.

## aegismesh version / completion

    version
    completion [bash|zsh|fish]
