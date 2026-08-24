# Architecture decision records

Format: lightweight ADRs (Context / Decision / Consequences). Status: Accepted unless noted.

---

## ADR-0001: Single Go module, single binary, stdlib-first

Date: 2026-08-22

**Context.** Deception tooling must be easy to install and audit. Multi-binary/multi-module layouts raise
build complexity; heavy CLI frameworks add supply-chain surface.

**Decision.** One Go module (`github.com/metaforismo/aegismesh`), one binary, conventional `cmd/` +
`internal/` layout. CLI implemented on a small internal dispatcher over stdlib `flag`. At v0.1.0 the only
third-party dependency in the core is `gopkg.in/yaml.v3` (config parsing); later dependencies require a
separate ADR and license review.

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

## ADR-0006: Explicit verified manifests for out-of-process observers

Date: 2026-08-22

**Context.** Beelzebub-style in-process plugin compilation makes every plugin a full-privilege part of the
honeypot binary. WASM runtimes would be nice but pull large dependencies this early.

**Decision.** Extensions declare strict manifests (`ext.aegismesh.io/v1alpha1`) with
name/version/permissions/transport; a lock record carries the sha256 artifact
digest (required) and optional ed25519 signature (verified when a public key is
configured). The runtime performs no discovery. When an operator explicitly
enables extensions and lists manifests, it verifies and starts exactly that set
from config-relative, symlink-contained paths as separate processes speaking
newline-delimited JSON on stdin/stdout. The host
uses a version-and-identity-bound handshake, hard deadlines, per-frame output
caps, a minimal environment and process revocation on violation.

**Consequences.** No untrusted code in-process. The runtime wiring now exists for the **data-only observer
path**: verified extensions declaring exactly the `observe` permission receive
bounded observation projections through a supervised delivery queue. Their only
successful output is a canonical acknowledgement bound to the source event ID;
the host returns no extension-produced value to the runtime. Response-influencing
permissions are rejected by the schema. See ADR-0014 for the final live-policy
boundary. WASM remains an option only if a small audited runtime is justified.

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

---

## ADR-0009: ECS-compatible projection at the read boundary

Date: 2026-08-23

**Context.** Operators need SIEM-friendly evidence without changing the native
store or adding an outbound connector. Observation payloads differ by sensor and
are not a versioned cross-package mapping contract.

**Usage.** The existing native command remains unchanged. Operators opt into the
projection with `inspect export --profile ecs`; every projected row still
contains the complete native envelope.

**Decision.** `internal/ecsexport.Marshal` is one pure, I/O-free mapping boundary.
It validates the native envelope, maps only stable envelope-level facts, targets
a documented ECS version, and owns deterministic serialization. The CLI owns
streaming, staging and destination replacement. The native storage schema and
live runtime are untouched.

Two shapes were considered. A mapper inside `internal/event` would couple the
native evidence model to a downstream vendor schema. A generic exporter registry
inside `internal/cli` would expose a shallow abstraction for one real profile.
The dedicated package hides mapping/version policy behind one function and can
be removed or replaced without changing event or storage ownership.

**Consequences.** The first mapping is intentionally conservative and does not
interpret sensor-private observation JSON. We accept fewer normalized fields in
exchange for a stable contract and honest semantics. This adds no external
egress; a future connector or automatic upload is a separate architecture and
approval decision.

---

## ADR-0010: SSH sensor is an authentication-only synthetic decoy

Date: 2026-08-24

Status: Accepted and shipped.

**Context.** SSH is a useful protocol surface for observing scanner and credential-guessing behavior, but
an SSH server that accepts a channel can accidentally become a shell, filesystem, forwarding, or execution
boundary. A persistent host-key file would also add secret lifecycle, path, backup, and permission concerns
that are not required for an observation-only sensor.

**Decision.** Add an in-process `sshsensor` behind the existing `Sensor` interface. It uses
the pinned `golang.org/x/crypto/ssh` version `v0.55.0`; the resolved module
graph and licenses are verified in the introducing change. The sensor creates
one Ed25519 host key per sensor instance and keeps it in memory only. It has no configured host-key path or
persistent key material, so reconstructing the sensor rotates the advertised host key by design.

The SSH protocol boundary is deliberately narrow:

- password and public-key callbacks complete synthetic authentication only; no real credential is
  validated, reused, compared, hashed, logged, or retained;
- usernames and credential contents are omitted from evidence entirely, not hashed;
- handshake and session deadlines, authentication attempts, concurrent connections, and protocol metadata
  are bounded by validated configuration and fixed implementation caps;
- every channel and global request is rejected; no session, shell, PTY, subsystem, SFTP, forwarding,
  filesystem, or command-execution capability exists;
- the listener follows the common loopback and unprivileged-port defaults; it creates no outbound target.

The sensor emits bounded observation evidence for protocol outcomes only. Authentication is an observation
boundary, not proof of a real account or incident, and it cannot influence policy, configuration, execution,
or enforcement.

**Alternatives rejected.** A fake shell or PTY-backed host shell was rejected because it would create an
execution and filesystem escape surface. A configured or persisted host-key path was rejected because it
would create a new secret/path lifecycle without improving the sensor's observation contract. Rejecting all
authentication before protocol completion was also rejected: synthetic completion gives a more useful,
bounded protocol observation while still exposing no post-auth capability.

**Consequences.** Operators should expect host-key changes after each process restart and should not use the
sensor as a compatibility test for a stable SSH identity. The dependency is larger than a stdlib-only
listener, but implementing SSH transport and cryptographic verification from scratch would be less
auditable and less safe. No external egress is added.

**Verification.** The introducing change includes real loopback authentication
and rejection tests, invalid-proof and input/deadline/concurrency cases,
redaction assertions, deterministic startup/shutdown race tests, race and fuzz
coverage, `make lint test`, `go mod verify`, license and secret checks, and a
pinned vulnerability scan with the current Go 1.25.14 toolchain.

---

## ADR-0011: Release evidence is subject-scoped and privileged signing is isolated

Date: 2026-08-24

Status: Accepted.

**Context.** The initial release workflow named four platform SBOM files but
allowed the generator to scan the repository workspace. It also granted OIDC
and attestation authority to a job that executed a third-party SBOM action.
Checksums, inventories, provenance statements, and signatures answer different
questions and cannot safely be presented as interchangeable evidence.

**Decision.** Pin every GitHub Action to a full commit SHA, every build tool to
an exact version, and both container bases to verified multi-platform image
digests. A static CI gate rejects mutable replacements. Generate CycloneDX 1.6
application SBOMs with the target binary's build constraints, omit random
serial/timestamp fields, keep detected licenses as evidence, and validate the
typed reference graph with a bounded repository-owned stdlib tool.

Release authority is separated by job. Build and SBOM jobs are read-only. The
attestation job receives OIDC and attestation permissions, downloads one named
binary, and executes only pinned GitHub-owned actions. The publish job retains
the existing tag-only `contents: write` boundary, downloads only the eight
expected artifact names, and accepts exactly four nonempty binaries plus four
nonempty SBOMs. This prevents an unrelated artifact from being merged over an
attested filename. Pull requests never execute the tag-triggered attestation or
publication path.

**Consequences.** A checksum can detect changed bytes but has no signer. An SBOM
describes components but does not authenticate its subject. GitHub provenance
binds its named binary subject to the workflow identity but does not sign the
binary in the cosign/GPG sense, attest the SBOM/checksum, or establish a project
SLSA level. Tool and module acquisition remains explicit build-time egress;
compilation itself is offline and readonly. Actual provenance verification and
release publication remain NOT RUN until an operator separately approves and
executes a tag release.

---

## ADR-0012: Deterministic evidence-linked recommendations are a read-only dry-run boundary

Date: 2026-08-24

Status: Accepted.

**Context.** Operators need inspectable follow-up guidance without turning a
decoy observation into an incident claim or giving event, model, extension, or
configuration data authority over real assets. Existing `policy.Enforcer`
selects decoy responses and is therefore the wrong ownership boundary.

**Decision.** `internal/recommend` is a pure, deterministic package with event
and rule-catalog dependencies but no I/O or runtime dependency. The CLI reads a
bounded local evidence set, and the engine validates every envelope, supported
observation shape, and observation-payload hash before applying exact filters
and the final limit. Output is labeled `recommendation`, `dry_run`, `proposed`,
and `signal_not_incident`; all prose comes from static repository-owned catalog
text. A canary invocation remains reviewable without a detection block.

Correlation contributor IDs become evidence links only when the complete input
contains matching verified non-correlation envelopes. Unknown contributor IDs
are counted but never echoed. The package has no path to `Bus.Submit`, policy,
LLMs, extensions, webhooks, command execution, filesystem selection,
configuration mutation, or enforcement. Any future action connector or new
egress is a separate architecture and approval decision.

**Integrity boundary.** Evidence links carry the exact event ID and stored
payload hash after verifying `observation_payload_only` as
`payload_hash_consistent`. This is not a signature, writer authentication,
provenance proof, or chain-of-custody anchor. Envelope ID, timestamp, sequence,
sensor metadata, and classification are outside the payload hash even when used
for deterministic ordering, filters, or display.

**Consequences.** Invalid input fails the complete report with no stdout. Static
guidance cannot quote attacker-controlled paths, hosts, tools, payloads,
summaries, or reasons. Operators still decide whether a signal is benign,
conflicting, or worth action; AegisMesh does not make that decision for them.

---

## ADR-0013: The product demo is an owned loopback composition, not a configurable runner

Date: 2026-08-24

Status: Accepted.

**Context.** The shell walkthrough used fixed ports and external tools, omitted
SSH, and could not run concurrently. Accepting arbitrary config, paths, ports or
destinations in a replacement would turn onboarding into a new orchestration and
egress surface.

**Decision.** `internal/demo` owns one repository-defined synthetic scenario.
It uses `127.0.0.1:0`, the local provider, no webhook/extensions/correlation,
fixed bounded clients and a private temporary directory. Runtime exposes fresh
typed endpoint values through `System.Endpoints` without widening the sensor
interface; the demo independently rejects non-loopback, unassigned and
privileged results before connecting. HTTP redirects are refused. Success output
is buffered until Stop returns, every listener is unreachable, evidence/hash
verification and dry-run recommendation generation complete, and directory
cleanup finishes.

**Consequences.** Human and JSON summaries are deterministic because they omit
ports, paths, IDs, times and evidence content. The command has intentionally few
options: only `--json`. Custom deployments continue to use `init`, `validate`,
`run`, `inspect` and `recommend`; the demo is not a generic configuration runner
or production-readiness proof.

---

## ADR-0014: Observer acknowledgements close the extension live-policy boundary

Date: 2026-08-24

Status: Accepted.

**Context.** The v1alpha1 manifest reserved a `respond` permission and the host
exported a generic raw-message call. Runtime policy did not consume the result,
but those surfaces made a future accidental authority escalation too easy. A
compromised extension is untrusted code with no business deciding decoy output,
evidence meaning, configuration or actions against real assets.

**Decision.** v1alpha1 is observe-only. Manifests must declare exactly
`["observe"]`; unknown fields, duplicate JSON keys, extra documents and
response-influencing permissions fail closed. `Host` exposes `Observe`, not a
generic method call. It sends one bounded typed projection and accepts only the
canonical acknowledgement `{event_id, accepted:true}` for the same event.
Mismatched IDs, stray frames, extra fields, malformed or oversized output,
extension errors and deadlines revoke the process. Extension-produced bytes are
discarded at the host boundary and never become policy, evidence or CLI prose.

The authoritative primary append must succeed before an observation is offered
to any best-effort consumer. Correlation signals remain store-only; they are not
re-submitted through the bus or sent to extensions/webhooks. `ext run` is a
synthetic local protocol probe and reports only core-owned `accepted:true` and
`applied:false` metadata.

**Consequences.** There is no extension live-policy path in v0.2. Adding one
requires a new manifest/protocol version, ADR, explicit operator opt-in and a
separate approval for any new egress. Digest/signature checks identify an
artifact but do not make its behavior trusted. Direct-child process revocation
is not a resource or network sandbox; stronger OS isolation remains separate
work and cannot justify granting extension output runtime authority.
