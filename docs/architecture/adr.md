# Architecture decision records

Format: lightweight ADRs (Context / Decision / Consequences). Status: Accepted unless noted.

---

## ADR-0001: Single Go module, single binary, stdlib-first

Date: 2026-08-22

**Context.** Deception tooling must be easy to install and audit. Multi-binary/multi-module layouts raise
build complexity; heavy CLI frameworks add supply-chain surface.

**Decision.** One Go module (`github.com/metaforismo/aegismesh`), one binary, conventional `cmd/` +
`internal/` layout. CLI implemented on a small internal dispatcher over stdlib `flag`. The only third-party
dependency in the core is `gopkg.in/yaml.v3` (config parsing).

**Consequences.** Slightly more hand-written code (subcommand dispatch, metrics exposition) in exchange for
a tiny auditable dependency tree and reproducible builds. If a future need justifies it (e.g., OTLP
exporter), dependencies are added per ADR-0007's policy.

---

## ADR-0002: In-process sensors; out-of-process only for untrusted extensions

Date: 2026-08-22

**Context.** Two structurally distinct designs were considered: (A) one process hosting all sensors behind
an internal interface with strict capability boundaries; (B) a supervisor spawning each sensor as a separate
OS process for fault isolation.

**Decision.** A. First-party sensors are compiled into the trusted core — they contain no untrusted logic;
all inbound data is treated as data. OS-level isolation is reserved for *untrusted* code: third-party
extensions run as separate processes under the extension host (ADR-0006), never compiled into the binary.

**Consequences.** Simplest possible ops story (one binary, one config); a parser crash can take down all
sensors simultaneously (accepted residual risk, documented in THREAT-MODEL.md; revisiting per-sensor
isolation is roadmap item R8). The important security boundary (untrusted code/data vs. operator assets)
is preserved.

---

## ADR-0003: Schema-versioned YAML/JSON configuration with strict validation

Date: 2026-08-22

**Context.** Configs will be shared, migrated from other tools, and stored in VCS. Silent default changes
and unknown fields are classic footguns.

**Decision.** Single-file config with an explicit `api_version` field (currently `aegismesh.io/v1alpha1`).
Loading uses strict decoding (unknown/duplicated fields rejected), then a validation pass that fails closed
with actionable messages including file/field context. Environment overrides follow documented precedence:
flags > `AEGISMESH_*` env > config file > built-in defaults. Migration hooks are version-keyed functions.

**Consequences.** Every config shape change bumps the API version or ships a migration; slightly verbose
error handling; users get deterministic behavior across versions.

---

## ADR-0004: JSONL evidence store with integrity hashing and bounded retention

Date: 2026-08-22

**Context.** Options: embedded database (SQLite/Bolt), full event indexer, or newline-delimited JSON.

**Decision.** Durable JSONL files under the data dir: append-only, size-rotated, count/age-bounded by
retention policy. Each event envelope carries `schema`, random non-enumerable ID, RFC3339Nano timestamp,
monotonic sequence number, source identity, redaction record, and a SHA-256 hash over the canonical
observation payload. `inspect` reads them back; export emits NDJSON.

**Consequences.** Zero new dependencies, human-readable evidence, trivially greppable/streamable to SIEM.
No indexed queries at scale (fine for MVP volumes; an embedded store remains a future option if justified).
Tamper-evidence via hashing is per-event, not chain-of-custody attestation — stated honestly.

---

## ADR-0005: LLM output is untrusted data; deterministic local provider first

Date: 2026-08-22

**Context.** LLM-driven decoys are valuable but provider output is attacker-influenceable (prompt injection
via captured input) and cloud APIs break offline use.

**Decision.** Define a minimal `llm.Provider` interface. Ship a fully local deterministic provider that
derives persona-consistent canned responses without any model call (default; zero network). Remote providers
are opt-in adapters behind config, with fixed URLs, timeouts, scheme allowlisting, response size caps.
Provider output passes through the same redaction + size-cap pipeline as attacker input and can only become
decoy response text — never commands, paths, config values, or enforcement triggers.

**Consequences.** Demos/tests are reproducible offline; realism against humans depends on real providers
(roadmap); the untrusted-output pipeline is exercised by every test regardless of provider.

---

## ADR-0006: Capability manifests + digest verification for extensions, host not auto-started

Date: 2026-08-22

**Context.** Beelzebub-style in-process plugin compilation makes every plugin a full-privilege part of the
honeypot binary. WASM runtimes would be nice but pull large dependencies this early.

**Decision.** Extensions declare JSON manifests (`ext.aegismesh.io/v1alpha1`) with name/version/
permissions/transport; a lock record carries the sha256 artifact digest (required) and optional ed25519
signature (verified when a public key is configured). Extensions run as separate OS processes speaking
newline-delimited JSON on stdin/stdout through an explicit operator-invoked host command: version-negotiated
handshake, hard deadlines, stdout caps, revocation by kill. The runtime never spawns extensions implicitly.

**Consequences.** No untrusted code in-process. The runtime wiring now exists for the **data-only observer
path**: verified extensions declaring the `observe` permission receive bounded observation envelopes through a
supervised delivery queue (drop accounting, terminal revocation on violation, bounded shutdown flush) — see
`internal/extmanager`. Their replies are acks/errors and can never influence behavior, evidence, or policy.
Response-influencing wiring (`respond`) remains explicitly NOT implemented; WASM remains an option once a
small, well-audited runtime dependency is justified.

---

## ADR-0007: Apache-2.0 licensing, GPL-free dependency policy

Date: 2026-08-22

**Context.** The primary comparable project is GPL-3.0; some embedders cannot consume GPL runtimes. We want
maximum legitimate reuse of AegisMesh while keeping the whole stack open.

**Decision.** Apache-2.0 for all project code. Dependencies must be permissively licensed (MIT/BSD/Apache);
GPL/AGPL dependencies are rejected at review time; a license check step runs in CI over the resolved module
graph; NOTICE carries attribution. Any dependency that would force a license change requires a new ADR.

**Consequences.** Clean compatibility story for individuals and vendors alike; we forgo direct code reuse
from GPL honeypot projects — enforced anyway by our clean-room rule.

---

## ADR-0008: Hand-rolled Prometheus text exposition; OTel adapter seam deferred

Date: 2026-08-22

**Context.** Observability matters, but `prometheus/client_golang` + OpenTelemetry SDKs would multiply the
dependency tree before the product shape has settled.

**Decision.** Implement a minimal counter/gauge registry emitting valid Prometheus text format (v0.0.4
subset: HELP/TYPE/COUNTER/GAUGE lines) on the loopback admin listener. Structured logs use stdlib `log/slog`
(JSON handler) with stable keys so they remain ingestible by OTel collectors later. A tiny `observe.Meter`
interface is the seam where a real client library can land without touching sensor code.

**Conclusions.** Honest scoping: we claim "Prometheus-text-compatible metrics endpoint", not "full OTel
SDK". Swapping in client_golang later is localized to `internal/admin`.
