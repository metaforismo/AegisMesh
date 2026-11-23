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

## ADR-0002: In-process sensors; out-of-process only for untrusted extensions (superseded)

Date: 2026-08-22

Status: Superseded by [ADR-0015](#adr-0015-optional-per-sensor-process-isolation-for-fault-containment).

**Context.** Two structurally distinct designs were considered: (A) one process hosting all sensors behind
an internal interface with strict capability boundaries; (B) a supervisor spawning each sensor as a separate
OS process for fault isolation.

**Historical decision.** A. First-party sensors were compiled into the trusted core — they contain no
untrusted logic; all inbound data is treated as data. OS-level isolation was reserved for *untrusted* code:
third-party extensions ran as separate processes under the extension host (ADR-0006), never compiled into the
binary.

**Consequences.** Simplest possible ops story (one binary, one config); a parser crash can take down all
sensors simultaneously (accepted residual risk, documented in THREAT-MODEL.md; revisiting per-sensor
isolation was roadmap item R8). The later opt-in worker mode and its narrower fault-containment claim are
defined by ADR-0015. The important security boundary (untrusted code/data vs. operator assets) remains
preserved.

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
the pinned `golang.org/x/crypto/ssh` version `v0.59.0`; the resolved module
graph and licenses are verified by the repository gates. The sensor creates
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
pinned vulnerability scan. The 2026-11-14 security refresh uses Go 1.27.4
and x/crypto v0.59.0; current results are recorded in `docs/verification.md`.

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

---

## ADR-0015: Optional per-sensor process isolation for fault containment

Date: 2026-08-24

Status: Accepted.

**Context.** A parser or protocol defect in one first-party sensor can
currently terminate the shared runtime or make all listeners unavailable.
The existing `Sensor` lifecycle seam is sufficient to supervise a worker, but
turning sensor configuration into a general process launcher would create a
new path from semi-trusted configuration to `os/exec`, filesystem selection,
or inherited credentials. A worker also must not be mistaken for a complete
security sandbox.

**Decision.** Add the common boolean `process_isolation` to every sensor kind.
Omitted and explicit `false` retain the exact in-process path. When `true`,
the runtime launches the same AegisMesh executable through a fixed hidden
worker argument, a minimal fixed environment, a private temporary working
directory, and a bounded canonical versioned stdio protocol. No command,
executable path, environment entry, provider credential, extension setting, or
filesystem path is selected by configuration or worker data.

The parent resolves and materializes `body_file` content before launch. The
worker receives only the bounded sensor specification and detection settings;
it does not read host files or resolve credentials. The sensor specification
may contain the bounded static prompt used by local fallback, but never a
provider destination, model, or credential reference. An isolated HTTP sensor
with enabled remote LLM fallback is rejected during configuration validation,
because the worker has no provider credential or remote-provider authority.
The worker must echo a per-launch random challenge received in the start frame
and bind before startup is reported. It may send only bounded redaction-safe
observations classified as `interaction` or `canary_invocation`. Metrics use a
fixed first-party name set, a declaration cap, and declaration-before-use. The
parent discards worker identity/time/sequence/integrity claims and constructs
the authoritative event envelope and storage submission.

All four sensor kinds are supported. An unexpected worker exit marks that
sensor unhealthy and degrades readiness while siblings continue. v0.2 does
not automatically restart workers. Shutdown closes workers concurrently under
one bounded deadline and reaps each direct process. Unix escalation signals
the worker's current process group. A descendant can survive if the leader
exits before escalation or the descendant creates a new session; built-in
workers do not intentionally spawn descendants, and stronger descendant
containment remains outside this claim.

This is fault/process containment only. It is not a network, filesystem, CPU,
memory, syscall, or malware sandbox: the worker retains the same UID,
container/host namespace, filesystem view, and network policy. Container or
Kubernetes resource limits remain aggregate limits for the runtime and its
workers. The mode adds no outbound destination or other external egress.

Startup failure and cancellation wait through the fixed termination grace to
reap the direct child. This can extend the caller's startup deadline by that
bounded cleanup interval; returning earlier would leave process ownership
ambiguous.

**Consequences.** An isolated sensor can fail without directly taking down
sibling listeners, at the cost of one bounded child process and IPC lifecycle
to supervise per enabled sensor. A worker crash is visible through readiness,
health/metrics, and runtime shutdown semantics rather than silently recovered.
Operators requiring stronger resource or namespace isolation must supply it at
the container/host layer; enabling this setting alone is not a malware
execution boundary. Protocol changes require a new protocol version and ADR.

## ADR-0016: Evidence encryption is optional native age/X25519 with an irreversible per-directory mode guard

**Status:** Accepted; implemented and merged (#73), with the v3 live-read
amendment merged in #77. Verification is recorded in `docs/verification.md`;
no release claim.

**Context.** The native JSONL store is intentionally local-first, but plaintext
evidence can contain sensitive attacker-controlled context. AegisMesh needs an
optional confidentiality layer without inventing cryptography, adding a key
service, changing the default offline posture, or allowing a configuration
mistake to silently resume plaintext writes after encryption was enabled.

**Decision (amended 2026-11-15, encrypted live reads).** The runtime holds only
one native public age/X25519 recipient. New `.jsonl.age` writes use
`aegismesh.ageframes/v3\n`; historical sealed v2 remains readable, unsealed v2
fails closed with v3 guidance, and v1/unknown versions are rejected. No in-place
migration or automatic rewrite occurs. See `docs/evidence-encryption.md` for
the exact binary layout: unchanged event frames, distinct checkpoint/seal markers,
and encrypted 42-byte controls binding version, kind, event count and running
SHA-256 over ordered event length/ciphertext records. Marker and encrypted kind
must agree. Age owns encryption and authentication; no new cipher is designed.

Every flush following new frames writes a checkpoint, unless age/space requires
a seal. Idle flushes write no checkpoints. Controls are bounded by 1 KiB including
framing, count toward `max_file_bytes`, and measure 250 bytes with pinned native
X25519 (about 4.12 MiB/day at five-second busy flush cadence). Size rotation,
close, a five-minute age from the first event checked at flush, or insufficient
checkpoint-plus-seal space seals the file. Empty files do not age out; only a
subsequent append opens a successor. There is no directory scan in append/flush,
and flush publishes to the OS without `fsync` or power-loss durability.

The read boundary accepts explicit bounded owner-only native X25519 identity
files only. It authenticates a file-size snapshot, then replays through the last
valid checkpoint/seal with bounded per-frame memory and revalidation. A successful
permissive read returns only that prefix and explicit typed open-segment status;
complete corrupt records and mismatched checkpoints fail closed even after a
valid checkpoint. Incomplete tails are excluded. CLI list/show/recommend JSON
carries `open_segments`; every accepted open file gets one stderr notice, while
exports preserve their NDJSON format. CLI output remains buffered/staged until
all reads succeed. `--require-sealed` restores strict exit-1 completeness checks;
legacy `Reader.ForEach` stays strict, while `ForEachVerified` returns notices.

An older open file in the existing mtime/name discovery order is an **interrupted
segment**, reported loudly by reads and as a doctor warning. Newest-only openness
is normal; it cannot alone prove whether a runtime is alive. Doctor and retention
scan structural framing/marker kinds without identities or authenticity claims.
Retention counts interrupted prefixes through their last structurally complete
checkpoint and may expire the whole file, but never deletes the active file.
Malformed framing or v2 incompleteness still blocks count retention. Retention
runs on the separate ten-minute cadence and can delay writes while holding the
store mutex; it is not a hard disk quota.

The plaintext path remains unchanged in new directories without encryption.
The owner-only persistent mode guard and existence of encrypted history refuse
later plaintext writes. Existing plaintext stays plaintext. Restart always opens
a new file and preserves prior files; key rotation changes the public recipient
while operators retain old read identities. Runtime/console never load private
identities. The console's encrypted-history-unavailable behavior is unchanged.

**Security consequences and decision flaw.** Checkpoints authenticate prefixes.
A storage-medium writer can roll an open file back to an earlier checkpoint
without detection, in addition to deleting/replacing whole files. The requested
claim that all sealed files retain full truncation detection under permissive
reads is impossible: removing the seal back to a prior checkpoint produces an
indistinguishable open v3 file. The read reports incompleteness; **strict
`--require-sealed` is needed to detect that loss of completion**. A trusted
external monotonic completion ledger could distinguish these cases, but is not
part of this change. A present/required seal binds the full event count/order;
records after it fail. Sealed v2 has no checkpoint fallback.

Anyone possessing the public recipient can still forge whole segments: this is
consistency, not writer provenance or chain of custody. Metadata and plaintext
exports remain visible. Compromised runtime hosts and stolen identities defeat
confidentiality; identity loss is unrecoverable. The mode guard is not host
attestation or isolation. This feature adds no egress, subprocess, command,
extension authority or enforcement action.

**Alternatives and synthesis.** Buffering a full pending flush in memory would
simplify callbacks but make memory depend on traffic/segment size. Staging to a
temporary file would add plaintext lifecycle and disk pressure. A two-pass read
through a fixed-size descriptor is selected: it costs a second decryption of the
verified prefix but bounds memory and keeps incomplete events out of callbacks.
A single age stream would still require private keys for structural event counts;
independent frames retain public-recipient-only writes and keyless retention.

## ADR-0017 — single-node read-mostly operator console

**Status:** implemented and merged: #74 (API) and #75 (embedded UI), with UI
polish in #78 and #81. Hosted CI passed on every PR head; no deployment or
production-readiness claim.

**Context and alternatives.** Operators need bounded interactive evidence queries
without changing sensor behavior or granting remote control. Two designs were
considered: a callback inside storage coupled to console projection, or a runtime
`indexedSink` wrapping the existing storage seam. The wrapper is selected because
it leaves storage independent and shares one serialized append/index ordering
between bus input and direct correlation persistence. The original fan-out still
receives raw successful appends only. No new signal egress is introduced.

**Decision.** `evidenceindex.Index` owns immutable envelope copies, deterministic
bounded projections, filtering with HMAC cursors, overview/source aggregation,
related-event lookup and bounded subscriber channels. `console.Server` takes
`Options{Config, Security, StateDir, Index, Runtime, Rules, Meter, UI}`. The narrow
`Runtime` interface returns `Node` and `Sensor` value snapshots only, reporting
node storage metadata errors as unavailable. Physical directory metadata reads
are capped at 65536 entries, without reading evidence payloads. It exposes
no control operation. `console/auth.Manager`, `console/audit.Log` and
`console/investigations.Store` independently own authentication/session state,
append-only hash chaining, and atomic operator annotation snapshots. Shared
`console/stateio` confines fixed state names to an `os.Root`.

The runtime constructs and backfills the index, builds a dedicated listener,
starts it next to admin/sensors, then closes HTTP/SSE before tearing down sensors
and draining the bus. Plaintext history uses the existing on-disk reader.
Encryption supplies only the public recipient, so history is `unavailable` and
the console indexes live successful appends. Corrupt skipped plaintext history
also reports `unavailable`; terminal backfill errors abort startup.

In-memory indexing avoids a second database, migration protocol and dependency;
it is intentionally disposable, capped by event count and a 64 MiB accounted
envelope budget. The latter safety extension can evict before the configured
count. API lists use bounded HMAC cursors; recommendations pass at most the latest
4096 indexed envelopes to the unchanged recommendation engine. The operator token
registry stores SHA-256 digests, sessions/CSRF secrets use 32 random bytes, and
all comparisons scan the complete registry. These are high-entropy tokens, not
human password hashes. Named viewer/analyst/admin roles avoid an unreviewed
identity provider. All new implementation uses the standard library; no module
or license surface was added.

**Consequences.** Login, authorization failures, investigation changes and audit
access are recorded without secrets or note bodies. Audit rotations preserve
continuity; quotas fail closed. Per-file fsync does not make investigation and
audit a single cross-file transaction. State may already be saved if audit append
fails; the response is explicit. Chain verification establishes internal
consistency only, not writer authenticity. Audit/notes remain plaintext.

**Embedded UI.** `internal/consoleui` embeds the operator UI with `go:embed`;
the runtime passes it through `Options.UI` (nil still serves a notice). It is
plain HTML, CSS and ES modules: no build step, so `go install` keeps working, and
no third-party code, so the dependency set is unchanged. It runs under the strict
CSP and renders evidence only as text. It is served only when `console.enabled`
is true.

**Deliberately omitted.** No SSO,
fleet, tenant boundary, remote sensor/policy/config control, evidence mutation,
autonomous enforcement, history decryption, external audit anchoring, exports,
search engine/database, distributed sessions or new outbound connection ships.
Last-write-wins investigation edits have no optimistic version check, as fixed
by the v1 contract. This decision does not claim production readiness.

## ADR-0018 — outbound-only experimental fleet identity and inventory

Date: 2026-11-15. Inventory merged in #76; experimental evidence forwarding
merged in #79. Both are experimental; see verification.md for what was run.

**Context and ownership.** The console's `Runtime` seam exposes value snapshots;
its evidence index is disposable and must not become an agent transport. The
runtime already owns authoritative store/bus ordering. A separate fleet service
with a second executable/database was considered, alongside same-binary role
composition with standard-library private snapshots. The latter keeps the
existing deployment model, dependency set and credential handling while making
machine and operator listeners independent. `fleet.hub.enabled` and
`fleet.agent.enabled` default off. Operator configs reject simultaneous roles;
tests may compose both packages in one process. A hub-only runtime may have
zero sensors, keeping the control plane separate from decoys. This is experimental fleet
inventory with authenticated enrollment and heartbeats. It is not multi-tenant,
is not a managed service. Evidence disclosure now requires separate consent on both sides.

**Permanent invariant.** Agents dial the hub. The hub never dials agents and has
no channel to send commands, configuration, files or code to a node. This is a
permanent trust invariant, not an unimplemented command stub. A compromised hub
can falsify its inventory, deny enrollment/acknowledgements and expose received
metadata and redacted evidence of every forwarding node; it cannot command nodes. Responses are strictly typed acknowledgements
and never enter sensors, paths, configuration mutation or execution.

**Shape and alternatives.** `identity.Load` owns the fixed private seed;
`protocol.Sign/Parse/Decode` own the wire schema and domain-separated canonical
bytes; `hub.Hub` owns atomic token consumption, registry, revocation and replay
state; `hub.Server` owns the dedicated bounded listener; `agent.Agent` owns its
fixed destination and asynchronous delivery loop. `runtime` injects trusted
state directories, status snapshots, metrics and audit; console handlers only
administer inventory. A storage callback coupled to the fleet transport would
make evidence latency depend on networking and is rejected. A runtime append
wrapper instead counts successful local appends, including direct correlation
signals, without serializing evidence into heartbeat data.

**Authentication and transport.** Each node generates Ed25519 locally; no shared
post-enrollment bearer secret exists. Enrollment signs the exact request-bound
challenge including token, name, key and reporting interval. Node ID is a
128-bit SHA-256 prefix; the full SHA-256 key fingerprint is displayed. Tokens
are one-use 256-bit random values, hash-only at rest, expire within 24 hours,
and are exposed once. Known keys retry idempotently; revoked keys retain a
permanent tombstone. Authentication includes exact body hash, method/path,
node ID, timestamp and nonce, with 120-second skew and isolated 64-entry
replay windows per node. Heartbeats and enrollment retries each enforce minimum
spacing from the registered interval before any replay mutation. Unchanged
re-enrollment retries cannot force a durable rewrite. Revoked or throttled nodes
perform constant work and no request-driven disk IO. Stateless validation and
signature verification occur outside the registry mutex; heartbeat verification
briefly copies the stored immutable public key under the mutex.

**Abuse resistance and persistence revision.** A fleet-wide nonce cap and
synchronous full snapshot per heartbeat allowed one enrolled rogue to deny
service to other nodes. Per-node replay budgets isolate that pressure. Durable
node/key/interval/revocation and token changes remain synchronous. Liveness,
reported counters/sensors/health and replay windows coalesce into a dirty snapshot
on a five-second background cadence using the injected clock, plus orderly
shutdown. This deliberately trades crash durability of the latest interval for
bounded write frequency. After restart inventory reflects the last flushed
snapshot until the next heartbeat. A crash may reopen unflushed nonces within
the remaining ±120-second signed-timestamp window (up to 240 seconds from
receipt for a future-dated request); flushed replay entries, consumed tokens and
revocation survive. Scheduler/IO stalls can extend the nominal five-second crash
loss interval. This is explicitly not crash-proof replay prevention.

Unauthenticated clients cannot trigger synchronous rejection audits: all rejects
increment fixed-label metrics, but at most five anonymous samples and one
suppression summary per minute are written by maintenance outside the hub mutex.
Shutdown drains pending audit counts; abrupt crashes can lose them. A separate
bounded 4096-entry source-IP limiter allows 8192 requests per minute per address
and returns 429 with `Retry-After`; it ignores ports and forwarding headers.
Fixed limits avoid new configuration and accommodate 1000 ten-second nodes on a
shared NAT. A full table fails closed for new addresses until periodic pruning.
These controls pace disk/CPU pressure, with no DDoS isolation promise.

TLS is mandatory outside loopback, with system roots or an additional PEM CA;
there is no insecure verification option. Agent traffic uses the webhook's
shared egress classification at config and socket time. A dedicated
`allow_private_egress` avoids widening LLM/webhook permissions. Metadata and
link-local remain denied, redirects/proxies are refused and time/bytes are
bounded. Sensor addresses and evidence content are omitted. Hub failures affect
inventory freshness, never sensor/store availability. Audit/state have separate
fsync transactions; disk/audit failures may leave a saved state with a failed
response and require inspection. Limits and exact encoding are in
[fleet-protocol.md](fleet-protocol.md).

**Residual risks.** Node status is a signed self-report, not attestation. A stolen
unused token can enroll an attacker's key first. A stolen node private key can
impersonate that node until revocation; TLS protects payload confidentiality,
not a compromised endpoint. A compromised host/hub writer can roll back or
rewrite local plaintext state and audit. A fully reconstructed valid snapshot
cannot be detected without external anchoring. Fleet inventory reveals host
names, versions, activity and topology hints. A shared NAT can be throttled and
a full remote table can temporarily deny new addresses. Bounded work and audit quotas
limit allocation but do not provide DDoS or host resource isolation. Permanent
tombstones count toward the node cap; there is no deletion/rotation escape hatch.

**Implemented and merged (#79) — experimental evidence forwarding.** Best-effort forwarding with counted loss;
local store authoritative. Agent and hub evidence consent default off. The post-successful-append
tap feeds a bounded memory ring, including direct correlation signals; a separate signed-batch
worker and HTTP transport isolate retry latency from storage and heartbeats. The alternatives
were synchronous storage-to-network callbacks (rejected for latency coupling) and an independent
queue with encrypted disk spooling (deferred: no runtime read identity and a plaintext spool would
defeat node encryption). This slice chooses a process-only ring and explicit crash/offline loss.
Disabled enqueue does no allocation; enabled enqueue serializes only stored redacted envelopes.

Canonical `/fleet/v1/evidence` signatures use the existing replay/revocation rules, with a separate
4 MiB/1,000-event batch cap. A random process stream ID scopes monotonic forwarding ranges.
The hub rejects malformed framing, skips/counts invalid envelopes, recomputes payload hashes,
and deduplicates each node's last 4,096 event IDs. Individual 16 MiB/minute and 1,000-event/second
budgets, five-second spacing and 16 MiB retention prevent one key exhausting the 256 MiB aggregate
segment cap. Per-node locks keep evidence IO outside the registry lock; conservative atomic byte
reservations bound concurrent appends. Full limits, retry behavior and crash/dedup caveats are in
[fleet-protocol.md](fleet-protocol.md). Storage copies inherit hub encryption and count/age retention;
origin metadata never alters native envelope bytes. Live index entries carry authenticated node ID,
with current registry names resolved at read time. Hash verification means consistency on the hub,
not provenance, attestation or trustworthy telemetry. Redaction is the confidentiality control;
a compromised hub now learns redacted evidence from all consenting nodes.

**Not implemented — cross-node correlation.** Forwarded data bypasses the local correlation and
recommendation inputs. Existing correlation links resolve only within one origin.
**Not implemented — historical forwarding.** Only live successful appends enter the queue.
**Not implemented — deletion propagation.** Node and hub retention remain independent.
**Not implemented — durable spool/offline guarantee.** Overflow drops oldest, counted; crashes and
stopping with queued events leave them only on the node. An in-flight eviction can still arrive.
**Not implemented — hub-to-node traffic.** Permanently forbidden; no dialer or command channel.
**Not implemented — multi-tenant evidence.** One operator trust domain only.

**Proposed, not implemented — key rotation.** A separately reviewed protocol must
bind old/new possession and preserve revocation/audit lineage, with offline
recovery policy. **Proposed, not implemented — mTLS/attestation.** Certificates
or platform measurements would require issuer, expiry and recovery ownership;
Ed25519 request authentication currently proves key possession only.

**Proposed, not implemented — remote configuration.** Any future configuration
workflow must be a separately operated, human-reviewed local import boundary.
It cannot use the hub-to-agent response channel, which is permanently forbidden.
**Proposed, not implemented — upgrades.** Local operator acquisition and signature
verification remain a separate supply-chain process; this hub cannot distribute
or initiate upgrades.

**Proposed, not implemented — multi-tenancy.** Tenant-scoped identities, storage,
quotas, authorization, residency and retention need separate isolation design;
current state has one operator trust domain. **Proposed, not implemented — SSO.**
OIDC/session and role binding need independent review; current console token
roles remain authoritative. Hosted service ownership, billing metering, regional
placement and service-level/offline guarantees are also proposed, not implemented.
The Apache-2.0 core and this self-hosted inventory slice do not establish any of
those managed-service properties.

## ADR-0019 — SSO via OIDC (experimental)

Date: 2026-11-15. Implemented and merged in #80. Supersedes ADR-0017's original no-SSO/no-
egress limitation for this explicitly enabled authentication edge only.

**Decision.** Opt-in Authorization Code with S256 PKCE, server-side state/nonce
and independent browser-binding cookie. Public clients use PKCE; confidential
clients resolve a bounded mode-0600 config-relative file or named environment
variable and use HTTP Basic at the token endpoint. No inline secret is accepted.
Existing high-entropy token operators remain break-glass authentication;
`token_login: false` disables bearer and token-session authentication only when
OIDC is configured. Both methods create the same ephemeral session/CSRF format.
Session expiry never exceeds ID-token expiry or configured TTL. Logout is local.

**Library decision.** A stdlib JOSE implementation would add security-critical
signature, key and claim parsing without an existing standard library OIDC
implementation. We select coreos/go-oidc v3.21.0, oauth2 v0.38.0 and go-jose/v4
v4.1.4. Application code owns only policy, bounded key acquisition, claim
mapping and browser/session lifecycle. go-oidc verifies signatures/issuer/audience
with an explicit RS256/ES256/EdDSA allowlist and a go-oidc StaticKeySet populated
from vetted go-jose JWK parsing. The wrapper additionally requires exact issuer
(including for Google), sub, nonce, exp, iat, nbf and azp for multiple audiences.
Thirty-second leeway applies to future iat/nbf; expiry is strict so sessions
cannot outlive credentials. RSA keys require 2048..8192 bits; ES256 uses P-256.
No signature skip, HMAC, none algorithm, distributed claim fetch or UserInfo call.

Discovery, authorization, token and JWKS endpoints must share the exact issuer
scheme and authority. This deliberately excludes providers with cross-authority
endpoints in this slice. All redirects and environment proxies are refused.
The shared egress classifier rejects metadata/link-local even with private
opt-in; private ranges require `console.oidc.allow_private_egress`. HTTP is only
accepted for loopback development. DNS is checked again at socket connection.
Responses are bounded to 256 KiB, headers to 16 KiB, network work to five seconds;
ID tokens to 24 KiB, claim objects to 64 fields, role/tenant values to 64 strings
of 128 bytes. JWKS has at most 32 public keys, five-minute maximum reuse and at
most one fetch attempt every five seconds on a snapshot, including unknown kids.
Unknown rotated kids may therefore be refused briefly rather than cause a storm.
Discovery runs only after console Start, retries 1s..60s with exponential backoff
and refreshes every fifteen minutes after success. Failures affect SSO, not
sensor startup or token authentication. Pending state stores at most 128 attempts
for two minutes and is consumed on any callback attempt for that state.

Authorization is explicit and default-deny: role_mapping maps exact values to
viewer/analyst/admin, highest role wins; tenant membership resolves only already-
declared partitions. Names default to email, fall back to sub, are bounded and
sanitized to 64 printable ASCII bytes. Audit retains the verified issuer/subject
pair independently of that mutable name. Unmapped identities are denied/audited.
The fixed error redirect never reflects provider prose. No return-to URL,
refresh token persistence, provider logout or dynamic client registration ships.

**Risks.** A compromised IdP or wrong operator group mapping can authorize an
attacker inside mapped tenants. Existing sessions do not poll for membership
changes; TTL or restart bounds revocation latency. The IdP learns console login
activity. The OIDC path has no authority over sensors, config or enforcement.

## ADR-0020 — logical tenant isolation (experimental)

Date: 2026-11-15. Implemented and merged in #80.

**Alternatives and ownership.** Adding tenant filters independently to handlers
would leave aggregate counters, SSE, ID references and quotas easy to miss. A
single shared store with filtered views also couples eviction and quota pressure.
We instead construct separate index, investigation, audit and hub-registry
partitions at startup, and select their view once in route dispatch. Handlers
receive that view through unbound route methods. No request or claim constructs
a path: membership can only select an existing configuration-validated view.
Machine routing selects a known node's immutable registry or an outstanding
minted token's registry; full signature/token validation still occurs inside it.
Unknown-key enrollment is serialized across partitions to prevent a concurrent
A/B enrollment from binding the same key twice. Hub registries never dial nodes.

**Decision.** At most 32 canonical 3..64-byte lowercase letter/digit/hyphen
slugs are declared in `console.tenants`. Omission means exactly `default`;
`local_tenant` defaults to `default`. Token operators default to `default` or
explicitly list memberships. OIDC requires a matching tenant_claim (default
`tenants`), optionally translated through tenant_mapping; no mapped membership
means denial. A session acts in one tenant; no admin override/all view exists.
Tenant switching rotates session ID and CSRF without extending expiry, records
only the departing tenant's action and invalidates the old stream credentials.

Local evidence, sensors, rules, node metadata and agent telemetry belong to
local_tenant. Fleet enrollment credentials, nodes, forwarded evidence, indexes,
investigations and audit chains belong to their registry tenant. Separate stores
mean foreign and absent IDs use identical normal lookup/error paths, without a
global existence query. Cursors have independent partition keys. SSE subscribes
only to the selected index, and checks invalidation before each event/heartbeat.
Authentication failures without a resolved tenant use an operator-inspected
`authentication/` audit chain when multiple tenants are declared.

Existing roots migrate through an atomic rename to the fixed sibling
`.tenant-migration`, recreation of the private root/tenants directories, then an
atomic rename to `tenants/default`. Directory fsyncs order these changes; startup
resumes after interruption and refuses conflicting destinations without deleting
data. Existing audit bytes and hashes are untouched. Console and hub migrations
are independent, not one cross-directory transaction. New state is under
`<console-or-hub-state>/tenants/<declared-slug>/`; forwarded copies are in that
hub partition's `evidence/<validated-node-id>/`. Local authoritative evidence and
agent private identity layout are unchanged. State roots cannot contain local
evidence/configuration/agent identity or overlap one another. Unexpected legacy
entries are refused before any rename to preserve an accidentally selected directory. Run one process per state root; concurrent
migration/writers are unsupported. Removing a tenant declaration does not delete
its retained directory or make its data visible elsewhere.

Quotas are independent per tenant: 1000 investigations (32 MiB snapshot),
100 outstanding credentials, 1000 nodes including tombstones, 256 MiB forwarded
retention and 64 MiB accounted index. Existing per-node budgets stay unchanged.
The validated 32-partition cap provides aggregate upper bounds of 32000 nodes/
investigations, 3200 tokens, 8 GiB forwarded retention and 2 GiB accounted index.
Session eviction is tenant-scoped (1024 per tenant, 32768 globally); request/stream admission remains process-bounded. These are upper
bounds rather than disk reservations; a full disk or process overload affects
all partitions. No new external database or module is needed for tenancy.

**Honest scope.** Logical isolation inside one process, one OS user and one data
directory. Tenants share the hub's evidence encryption recipient and signing/
egress configuration. A host or process compromise crosses tenants. This is not
a hard hosted isolation boundary. There are no per-tenant keys, billing, rate
plans, independent deployments or self-service tenant creation. Timing classes
for foreign IDs and absent IDs match, but constant-time HTTP response latency and
absence of shared-resource inference are not claimed. Old bare-ID investigation
references remain local-only; cross-node annotation semantics are deferred.
## ADR-0021 — synthetic AI service decoys, honeytokens and editorial mappings

**Status:** implemented in the uncommitted AI observation pack; verification is
recorded in `docs/verification.md`. **Date:** 2026-11-22.

**Context.** AI endpoint enumeration, small validation-shaped requests and
instruction-following interactions are useful defensive observations. Request
patterns alone cannot establish client identity, intent, stolen credentials or
compromise. Existing sensors already own byte limits, static responses and
redaction before the event bus; optional process workers preserve those seams.

**Decision.** Reuse static HTTP rules for an `ai-decoy` scaffold. Generate only
synthetic bodies, deployment persona variation and two crypto/rand markers.
No inference or model/key management backend exists. Add a bounded, immutable
literal honeytoken matcher through the injected policy enforcer. Sensors match
separate acquired fields before preview truncation, retain only safe token ids
in findings and replace values before evidence. Config is strictly decoded and
validated (64 markers, 16..256-byte printable values, unique ids/values, slug
ids, enumerated kinds). No configured regex, runtime-selected command/path,
configuration mutation or enforcement action is introduced.

Append LLM-001..004, HT-001 and AGT-001 after the published detection registry;
all are observe-only even under aggressive existing severity actions. Append
COR-005..008 to the existing bounded, opt-in correlation engine. Use event-time
predicates, the existing cooldown and contributing event IDs. Cadence is not an
AI attribution mechanism: scanners and scheduled clients may also match.
Replay means the same peer host previously interacted with another sensor,
not demonstrated disclosure by that sensor.

Credential stuffing needs distinctness without retaining secrets. Carry
length-framed SHA-256 digests only as ephemeral envelope metadata and private
worker IPC, strip them before all storage/index/export/fan-out paths, and feed
only the local correlation ring after a successful authoritative append. A
stored COR-007 signal cannot be independently recomputed from saved credential
values because neither values nor digests are saved. This explicit privacy
tradeoff is preferable to durable password-verification material.

Add catalog `frameworks` references from exactly the requested editorial
ATT&CK/ATLAS/OWASP LLM 2025 table, with a pinned test covering every rule and
empty cells. Expose them in CLI and console API; caller-owned slices cannot
mutate the registry. Mappings mean "relates to", never coverage/completeness or
compliance. AGT-001 mirrors a defender-planted instruction technique, not
established attacker use. Runtime framework content is never fetched.

**Rejected alternatives.** A bus-only matcher cannot recover dropped SSH
credentials or truncated previews. Regexes from configured markers add no
value over bounded literal matching. Persisting credential digests enables
unnecessary offline guessing and increases disclosure. A new response engine
or remote LLM adds execution/egress and state that static shapes do not need.

**Consequences.** Fake marker secrecy and uniqueness within operator-owned decoy
material are operational premises. A human or scanner can replay a marker.
NAT groups clients; rotating addresses split them. Shared `/v1/*` paths cannot
identify vLLM and default to `openai_compatible`. No unacquired, encoded or
cross-field marker matching is claimed. Existing sensor limits, event/storage
contracts and enforcement semantics for older rules are retained. New data is
additive and no dependency is added. Exact predicates and the synthetic
measurement scope are in `docs/ai-threat-detection.md`.

## ADR-0022 — bounded session stories, framework relations and operator downloads

**Status:** implemented locally, uncommitted; verification in `docs/verification.md`.

**Context.** Operators need a chronological account and portable observations
without granting the console another control or egress path. The disposable
index has count/byte bounds and incomplete history; source keys are not actors.

**Alternatives considered.** Implementing each projection directly in HTTP
handlers would couple transport, grouping and rendering and duplicate CLI
indicator behavior. Persisting sessions as another mutable index would add
backfill, eviction and transactional ownership. A shared pure projection over
one bounded snapshot provides the smaller interface and preserves read-only
console ownership.

**Decision.** `evidenceindex.Analysis()` copies at most 8192 newest summaries
and consistent index stats under one read lock. `evidenceview` groups source
sessions at an idle gap greater than 30 minutes, computes deterministic cadence,
explicit automation evidence and catalog relation counts. `indicatorexport`
renders conservative IP proposals in STIX/CSV/TXT for the HTTP and local CLI
seams. `evidencereport` owns inert Markdown; the console supplies already scoped
annotations, summaries and verified local dry-run recommendations. No new
dependency, configuration field, model call, sensor control or runtime egress.
The final wire contracts and formulas are in `console-api.md`.

Session IDs hash tenant/source/first retained origin+event; they are stable
only while that anchor remains first. List cursors bind an immutable snapshot
digest and selection under the tenant's process HMAC key; stale reads restart.
A 200-event timeline also bounds phase runs. Sensor/kind lists cap at 64 with
an explicit flag. Responses/downloads cap at 2 MiB, with no partial downloads;
STIX additionally stops object construction near 2048 objects. Source reports
and assessments disclose every omitted/capped count. Credential/provider output
and arbitrary observation text never become exec, paths, policy or enforcement.

Automation requires eight non-signal events; correlated outputs cannot create
fast timing evidence. Sub-second median or regular 1..30-second timing and
listed marker/signal predicates are observations, not verdicts. Framework
relations are catalog editorial references, not execution or completeness claims.
STIX notes carry origin-qualified evidence references and conservative 15/100
confidence; no automatic blocklist application or delivery connector exists.

Report data is bounded, JSON quoted on a single line inside fixed text fences;
only static strings supply Markdown headings. Existing recommendation generation
is local-only, verified and capped; missing/forwarded references are disclosed.
All successful sensitive downloads are audited before bytes are released.

**Review corrections carried forward.** Honeytokens use crypto/rand rejection
sampling in provider-shaped formats without a visible synthetic marker. They
are never registered or validated with a provider. It is impossible to prove
offline that random strings never collide with provider credentials; do not
claim that guarantee. Committed examples reject explicit unreplaced placeholders.
Generic `/version`, `/metrics`, `/sse` paths no longer identify AI surfaces.
COR-005 accepts sub-second upper medians, or medians <=30 seconds with its
at-most-one-outlier test; zero gaps are included with timestamp caveats.

**Consequences and deferred work.** Session reconstruction is sample-dependent,
not durable actor tracking. No complete-history, hard tenancy, external SIEM
interoperability, attribution or production-capacity claim is made. UI/dev mock
integration belongs to the frontend workstream. Native evidence remains the
source of truth. No push, tag, PR, merge, release or deployment is implied.

## ADR-0023 — static MCP environments, local SIEM formats and bounded digest

**Status:** implemented locally, uncommitted; final local checks in
`docs/verification.md`. No publication or deployment is implied.

**Grounding.** Sensors pass bounded interactions through the existing policy
engine before redacted authoritative append. The console index receives only
successful appends and partitions by authenticated tenant. `evidenceview`
already owns retained sessions; native envelopes remain authoritative.
`ecsexport` and Markdown neutralisation already define read boundaries.

**Two designs considered.** (A) Make each MCP tool a callback to arbitrary
workspace/file/query adapters, and implement format/digest logic separately in
CLI and HTTP. This expands authority and duplicates behavior. (B) Compile
strict declarative entries into exact in-memory maps, keep connection-local
observation state, and share pure render/analysis packages between CLI and
HTTP. B has the smaller authority surface and one testable format contract.
No new dependency, plugin, interpreter, transport or mutable environment is
needed. A persistent attacker-selected MCP session table was also rejected:
connection context bounds ownership without a new identity/retention protocol.

**Usage and module contract.** Operators declare `Sensor.Environment` or scaffold
`init --profile ai-decoy`; sensors expose only five fixed synthetic tools.
`eventexport.Render([]event.OriginEnvelope, format)` verifies and stages
bounded bytes. `digest.Build(Input)` consumes an anchored snapshot plus explicit
operator/recommendation counts; `digest.Render` emits JSON/inert Markdown.
Console handlers own authentication/scoping/audit; CLI owns explicit local
reader/identity/output flags. `DecoyCatalog` projects configuration to value-free
metadata before the console retains it. No handler receives token values.

**Decision.** Files/env/query results remain declared static data. Names are
exact map keys, never OS paths/environment access, SQL, regexes or commands.
A server-created HTTP connection owns up to 256 steps and the first 32 scrubbed
tool names. MCP-001..003 append to detection order and cannot select policy
actions; framework mappings use existing catalog IDs only. Replay reuses
HT-001/COR-008 without upgrading cross-sensor contact into proven disclosure.

Exports support CEF, RFC5424, OTLP JSON encoding and ECS locally; 8192 inputs,
2 MiB staged bytes, origin-qualified resolution, fixed attachment names and
audit-before-disclosure. OTLP is format only; no exporter/collector is added.
Digest compares adjacent sampled windows at one anchor; source novelty is
relative, automation is evidence-consistent, recommendations are unexecuted.
CLI investigation reads are fixed-name, bounded and read-only; unavailable state
is null, not a zero. New catalog APIs are local-tenant-only and value-free.

**Perimeter decisions.** Separately budget invalid Bearer attempts using the
existing bounded throttle state; install hub rejection headers at the response
writer; audit raw event detail before bytes, including viewer reads. The real
review and failing-first evidence are in `security-review-2026-11.md`.

**Measured performance.** Share one lazy immutable SSE frame per tenant/event,
leaving filtering/admission/write deadlines per subscriber. Resolve overview
node names once per origin after counting. Matching before/after harnesses,
including a real accepting hub and enrolled synthetic identities, are in
`performance/2026-11-22`. Keep allocation/latency evidence separate; a paced
SSE workload cannot show throughput gains and single-stream overhead remains.

**Consequences.** Data contracts are additive; overview rule severity is now
catalog severity rather than an unrelated highest finding. Native event schema
is unchanged, with optional MCP observation fields. Source histograms include
all retained events independently of page size; digest/catalog/session work
uses the bounded newest sample. No hard tenant, complete-history, real SIEM,
automation attribution, production performance or perimeter-security claim.
UI/mock changes remain outside this backend task.

## ADR-0024 — exact-prefix campaigns, hedged actor vocabulary and posture checks

**Status:** implemented on branch `feat/campaigns-posture`; not merged or released.

**Context.** Defenders want to know whether separate sources ran the same
playbook, whether a session looks scripted, agent-driven or human, and whether
their deployment can observe AI-specific behaviour at all. Inputs are limited to
the bounded index projection (newest 8192 summaries per tenant): redacted
one-line summaries, rule IDs, timestamps and sensor metadata. Everything is
attacker-influenced except catalog data and the configuration.

**Options considered for campaigns.** (A) Similarity scoring (n-gram Jaccard
or longest common prefix with a threshold, then clustering). It groups more
variants but needs pairwise comparison (O(n²) over 4096 sessions), produces
transitive groups that are hard to explain, and makes membership depend on
threshold tuning nobody has measured. (B) Exact fingerprint over a bounded
prefix of collapsed, normalised shapes. Linear, deterministic, explainable in
one sentence, trivially testable; misses near-variants. **Chosen: B.**
Fingerprint = first `min(len, 8)` kind/shape pairs, at least 3 steps, at least
2 distinct source keys; ID = `cmp_` + 48 bits of SHA-256(`[tenant,
fingerprint]`). `basis` states `same_step_sequence` or `same_step_prefix`
(and `same_client_family` when all members share one).

**Actor vocabulary.** `possibly_ai_agent`, `likely_automated`, `likely_human`,
`inconclusive`. Agent level needs a content-level, agent-specific signal (agent
canary followed, chained MCP tool calls after discovery, a request-shape error
corrected within 3 s); fast or regular timing alone is only
`likely_automated`. Human level needs positive evidence (irregular
multi-second think time or typo corrections); absence of automation is
inconclusive. Conflicts and fewer than 8 interactions are inconclusive. Every
signal is listed with `present` so the UI shows what was checked. The
existing `automation` field is unchanged for compatibility.

**Client family.** The projection keeps a closed-vocabulary family derived
from the HTTP User-Agent claim and the verified HTTP status, both unserialised.
Raw User-Agents are not retained in the index; the status removes the need to
parse attacker-controllable summary suffixes.

**Posture.** Checks run over `posture.Facts`, a value snapshot derived once
from the validated config (token values, operator digests, URLs and secret
references reduced to booleans, counts and IDs), plus counts from the analysis
snapshot. Only checks the config or evidence can decide were included: there
are no configurable redaction or evidence-verification settings, admin
listeners are forced to loopback, and console cleartext beyond loopback is
rejected at validation, so those are either omitted or reported as the
validated state. Non-local console tenants get evidence-only checks.

**Consequences and limits.** Additive API fields; no persistence, egress,
model or enforcement. Campaign IDs change if the fingerprint leaves the sample
and differ between CLI (`local`) and console tenants. Near-variant campaigns,
SSH command classes, MCP rejected calls and TCP banner classes are not
represented because the index projection lacks them. No accuracy,
false-positive or attribution claim is made; thresholds are documented
constants awaiting field evaluation.
