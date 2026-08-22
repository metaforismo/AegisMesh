# Changelog

All notable changes to AegisMesh are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows semver (pre-1.0: breaking
changes bump MINOR).

## [Unreleased]

### Added

- Correlation signals (COR-001..COR-004) are now recorded as integrity-checked
  `correlation_signal` evidence envelopes in the local JSONL store, visible
  through the existing `inspect list/show/export`; signals remain observations
  only.

### Fixed

- MCP sensor returned an empty `{}` body (HTTP 200) for unparseable JSON-RPC
  instead of a proper parse-error object; protocol errors now always render
  complete JSON-RPC error envelopes, and notifications answer 202.
- Extension subprocesses inherited the operator's full environment (secret
  leak risk); they now run with a fixed minimal environment and the manifest
  directory as working directory.
- `ext verify` panicked when a public key was provided for an unsigned
  manifest; it now fails with a clear signature error.
- Redaction missed JSON-style credential keys (`"password": "..."`) and left
  artifacts from groupless patterns; per-pattern replacements plus a JSON-key
  rule close the gap.
- `migrate beelzebub` ignored its flags entirely (`--write`, `--out`,
  `--force` never parsed); interleaved flag/positional parsing implemented.
- Data race between sensor `Addr()`/`Close()` across goroutines; listener
  access is now synchronized in all three sensors.
- Runtime maintenance goroutine leaked after shutdown; it now terminates via
  a closed channel.
- Duplicate sensor ids from same-named import sources collided at emit time;
  deterministic suffixing with an explicit note.

### Changed

- Configuration now accepts port `0` ("OS assigns an ephemeral port");
  privileged-port policy applies only to ports 1..1023. Documented in
  docs/configuration.md.
- HTTP rule precedence, catch-all semantics, and the Provider context
  contract are documented explicitly where they are enforced.

## [v0.1.0] — 2026-08-22

First foundation batch: a complete, tested vertical slice of the deception runtime.

### Added

- CLI `aegismesh`: `init`, `doctor`, `validate`, `run`, `inspect` (list/show/export), `migrate beelzebub`,
  `version`, `completion`; human and JSON output modes; dry-run support.
- Schema-versioned configuration (`aegismesh.io/v1alpha1`) with strict validation, environment overrides,
  documented precedence, and secure defaults (loopback bind, unprivileged ports).
- Sensors: HTTP deception sensor; TCP deception sensor; MCP canary endpoint (JSON-RPC 2.0 over streamable
  HTTP POST) with synthetic canary tool semantics.
- Policy gate with static rules plus a deterministic local LLM provider (offline by default); provider
  output handled as untrusted data.
- Event envelope `aegismesh.event/v1`: non-enumerable IDs, RFC3339Nano timestamps, per-process sequence,
  SHA-256 payload integrity hash, redaction record. JSONL storage with size rotation and count/age retention.
- Loopback admin listener: `/healthz`, `/readyz`, `/metrics` (Prometheus text exposition), `/version`.
- Extension model: manifest schema `ext.aegismesh.io/v1alpha1`, digest (+optional ed25519) verification,
  out-of-process reference host with handshake/deadline/output-cap/revocation contract tests.
- Clean-room Beelzebub YAML importer (`aegismesh migrate beelzebub`): dry-run default, compatibility report
  with exact unsupported fields, sources never modified.
- Deployment: multi-stage non-root Dockerfile, docker compose demo, reviewable install script.
- CI: formatting, vet, build, race tests, fuzz seeds, govulncheck, secret scan, license check, SBOM,
  container build/scan where tooling permits; workflows pinned to immutable commit SHAs.

### Security

- Secure-by-default posture enforced in code: no exec path from untrusted input; bounded queues/bodies/
  sessions; redaction before storage; observation-vs-incident distinction encoded in the event envelope.
