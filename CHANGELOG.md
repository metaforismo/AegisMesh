# Changelog

All notable changes to AegisMesh are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows semver (pre-1.0: breaking
changes bump MINOR). Numbers in parentheses are merged pull requests.

## [Unreleased]

### Added

- Console in-app notifications (ADR-0027): a per-tenant inbox derived from
  indexed evidence and console state, with no egress —
  `critical_observation`, `honeytoken_replay`, `agent_canary`,
  `new_campaign`, `posture_attention`, `account_security` (affected principal
  only) and `assignment`. Text comes from fixed templates (rule ids, counts,
  validated source keys and sensor ids only). 10-minute grouping, 20 new
  items per observation minute and 60 per wall minute with an overflow item,
  2,000-item ring, a persisted high-water mark so restarts neither duplicate
  nor resurrect items, per-principal read state and preferences, and
  `GET /api/v1/notifications/stream`. Audit actions `notification.read`,
  `notification.preferences`.
- Investigation workspace: `origin`, `assignee` (validated against tenant
  principals holding `investigations.read`; `investigation.assign` audit),
  a bounded activity log, a computed `summary`, list filters `status` and
  `assignee`, per-item `event_count` and `max_severity`;
  `POST /api/v1/campaigns/{id}/investigation` and
  `POST /api/v1/sessions/{id}/investigation` with bounded round-robin
  evidence and a templated first note; `GET /api/v1/investigations/assignees`;
  campaign detail `event_ids_sample`. Investigation snapshot schema v2 (legacy
  files migrate in memory and are rewritten on the next change).

- Console, round 7: folding caveats (Techniques, Rules, Fleet), one
  humanised relative time ("10 min ago", "yesterday 14:03", then the date),
  organisation on every print and on the digest, posture acceptance
  following the server's `acceptable`/`acceptable_reason`, "Synthetic" on
  seeded events, grouped identical recommendations, "Report and exports"
  on an investigation. Scale: paged lists append instead of redrawing and
  stop at 2,000 rows, a campaign score folds beyond 14 lanes or steps,
  Overview sums sensors beyond the busiest eight, "+N" sensor chips, large
  changes as multiples. The first screen's module graph is preloaded in
  full; `screen:<route>` User Timing measures.
- Dev mock: `--scale large` (~50k events, 640 sources, 47 sensors, 36
  playbooks, 6,000 audit records), `--posture-acceptable off`.

- Console: permission-driven navigation and actions (from `/me.permissions`).
  Roles in Administration: built-in and custom roles, holders, risk summary;
  a role page with the permission matrix, live can/cannot summary, the
  dependency rules with a fix, a diff before saving, duplicate built-ins,
  typed delete. Account role picker lists custom roles; Profile lists your
  permissions. Settings edit in place where the server allows (reason
  required, file value shown, revert, server answer after save), an
  explanation when editing is off, a change history. Organisation name in
  the top bar; sign-in banner on sign-in and once per session. Posture:
  accept risk with a reason and an end date (≤180 days), its own group and
  count. Audit: grouped action filter, settings changes as from → to.
- Dev mock: contract r6 (`mock-roles.mjs`), `--round6 off`,
  `--settings-editing off`.
- Console permissions and custom roles (ADR-0026): an 18-id permission
  catalogue (`/api/v1/permissions`) behind every route, built-in roles pinned
  to their previous access, custom roles for managed accounts
  (`/api/v1/admin/roles`, accounts store v2 with v1 migration and backup),
  `/me` `permissions` and `role_name`, `builtin`/`in_use` guards, a last-admin
  guard across roles and 403 `exceeds_own_permissions` against escalation.
- `console.settings_editing: console` (default `off`): audited, reasoned
  overrides of an allowlist of console settings in a state-dir overlay, live
  where possible, with history; 409 `editing_disabled`/`not_editable`
  otherwise. New file fields `key_max_days`, `key_default_days`,
  `sign_in_banner`, `organization_name`, `default_window`; `/meta` shows the
  banner and organization name. `aegismesh demo` enables editing.
- Posture: accepted risk with reason and ≤180-day expiry
  (`/api/v1/posture/{check_id}/accept`, `accepted` status and count, CLI reads
  it read-only), checks POS-020..022, `settings` system component, audit
  actions `role.*`, `settings.update|revert`, `posture.accept|unaccept`.

- Console: Settings (`g ,`, account menu, palette). Your account: profile and
  what your role allows, preferences (UTC or local time, default window,
  density, theme, reduce motion; saved to the account or this browser,
  optimistic with rollback), your sessions, API keys shown once. Admins:
  accounts (configured, single sign-on, managed), account detail, every
  session, read-only effective settings, audit export, system health. One
  confirmation dialog with typed match; older servers get a plain state.
- Dev mock: contract r5 (`mock-accounts.mjs`), `--round5 off`, `--fail-prefs`.
- Console accounts and access (ADR-0025): managed person/service accounts with
  `amk_` API keys (SHA-256 stored, shown once, 1..365-day expiry, revocable),
  `/api/v1/me` with preferences, sessions and own keys, `/api/v1/admin/accounts`
  and `/admin/sessions` with `last_admin`/`not_managed` guards, read-only
  `/admin/settings` with value provenance, bounded `/admin/audit/export`
  (JSONL/CSV, formula-neutralised), `/api/v1/system` component status, stable
  principal ids, a seen-OIDC-identity directory and POS-019 break-glass check.
- `console.session_idle_seconds` (default 1800, 0 disables) ends inactive sessions.
- `aegismesh accounts list|disable|enable|key revoke --state-dir DIR`: offline,
  audited break-glass for managed accounts.

- Console: Campaigns list and detail (a lane-per-session score of shared steps,
  basis, stages, automation mix, caveats), the actor profile on sessions as a
  checklist of signals present or not observed, and a Posture review grouped
  by area with attention first; all degrade to an "older server" state on 404.
- Console: sidebar grouped as Observe, Understand, Deception, Operate; `g m`,
  `g p`, `g u`; shortcut sheet generated from the navigation; per-screen tab
  titles; print stylesheet for the session story and campaign detail.
- Hedged session actor profiles with ten always-listed signals; campaigns that
  group sessions from at least two sources by an exact eight-step redacted
  shape fingerprint; `campaigns` CLI and `/api/v1/campaigns[/{id}]` (ADR-0024).
- Posture review POS-001..018 over a secret-free config snapshot and the
  retained sample: `posture --config` and `/api/v1/posture`. Advisory only.
- Documented digest 503 conditions and why `open_investigations` can be null.

- Bounded synthetic MCP workspaces with exact in-memory lookup tools,
  per-connection sequences, observe-only MCP-001..003 and a multi-step demo.
- Local CEF/RFC5424/OTLP-JSON/ECS event files and audited analyst attachments;
  OTLP is format only, with no exporter or new network egress.
- On-demand Markdown/JSON digest, value-free configured decoy/honeytoken APIs,
  static rule descriptions/guidance/observe-only flags, overview index occupancy
  and catalog titles/severities, event/session links and retained-source gap histograms.

- Tenant-scoped source sessions with capped timelines/phases, cadence and explicit
  automation observations; catalog framework relation counts, including zeros.
- Analyst STIX 2.1/CSV/TXT indicator and Markdown observation-report attachments,
  audited before download; local `export indicators` with verified reads and
  golden tests. Bounded snapshots, conservative confidence and no new egress.

- `init --profile ai-decoy`: static synthetic Ollama, OpenAI-compatible,
  LiteLLM and vLLM HTTP shapes with deployment variation and two fake markers;
  no model, provider fallback or management backend.
- Strict bounded `honeytokens` configuration, redaction before preview,
  `honeytoken new`, and observe-only LLM-001..004, HT-001 and AGT-001 findings.
- Opt-in COR-005..008 cadence, AI enumeration, memory-only credential
  distinctness and cross-sensor replay observations, with validated thresholds.
- Editorial framework references in the rule catalog, CLI and rules API;
  pinned mapping table, synthetic benign/attack-shaped corpus, and an expanded
  loopback-only demo. See ADR-0021 and `docs/ai-threat-detection.md`.

### Changed

- After an append, sessions are regrouped only for the source keys whose
  events changed (byte-identical to a full recompute, proven by a randomized
  equivalence test); see docs/performance/2026-11-27.
- Brand: the shield mark is replaced by a net closed around a lure, with a
  serif wordmark, a scheme-aware favicon and files in `site/assets/brand/`.
- Landing: console pictures and the share image retaken from the redesigned
  console (same files and sizes).

- Landing page (`site/index.html`) redesigned: one screen per section, dark
  console identity, real console screenshots from the synthetic dev mock, a
  CSS-only hero entrance and statement; still no script, web font or external
  request. Vendors four MIT stylesheets; see `site/CREDITS.md`.
- Console redesign (data-terminal style): flat panels and controls with no
  resting shadows, gradients or glass; one selection mark (a 1px cobalt line)
  for the current screen, time window and tab; round flat buttons; readout
  labels in sentence case; nothing under 11px; skeletons without shimmer. The
  Overview leads with the brief beside a divided count list, then the chart,
  then what to read next; paired panels end level. Session hero rebalanced;
  tempo labels never overlap.

### Fixed

- Console: the first-run tour no longer covers the counts beside the brief
  (1440 and 375px); peer counts keep their 1px dividers; phone cards lead
  with the row's identity; 10px rule ids in technique cells; tabs wrap on
  phones; Audit shows records first; the Overview chart redraws after a
  large resize.
- Console audit pass: one severity mark (also for "no finding" and
  correlation-rule "Signal"), one table time format (relative with absolute
  UTC), one duration and number formatter, sortable headers on tables whose
  rows are all loaded, wide tables scroll in place instead of widening the
  page, failed screens keep their heading and offer a next step (older
  server, missing object), layout-matched skeletons, 40px+ targets at phone
  widths, print always light, light severity fills and signal green raised to
  3:1 (checked by a token contrast test).

- Release SBOM generation for targets other than the build host. The generator
  was started with `go run` under the target's `GOOS`/`GOARCH`, so it was
  cross-compiled and could not execute; the tag-triggered release workflow
  failed at the first cross-platform SBOM and published nothing. The generator
  is now built for the host and run with the target's build constraints.
- Bounded invalid Bearer authentication attempts, security headers on hub
  capacity rejection, and audit-before-disclosure for raw event detail reads;
  see `docs/security-review-2026-11.md` for scope and failing-first tests.
- Shared SSE observation encoding and per-origin overview name resolution,
  measured locally with an accepting hub; no capacity/throughput claim.

- Provider-shaped random honeytokens use unbiased crypto/rand selection; the
  checked-in AI-decoy template rejects unreplaced placeholders. No offline
  guarantee against a provider-side random collision is claimed.
- Generic version/metrics/SSE paths no longer establish AI surface families.
  COR-005 now includes sub-second bursts and documents zero-gap caveats.
- Expanded dense AI rule/config literals and named helpers for readability.

### Compatibility

- Existing rule IDs/order and their enforcement actions are preserved. The nine
  appended detection rules never enforce. HT-001 adds `critical` severity to
  catalog/evidence; JSON rule metadata adds a `frameworks` list. Native finding
  metadata may include `ai_family`, `credential_class`, `token_id`.
- Demo now records eleven observations and eight dry-run proposals. COR-007
  distinctness cannot be replayed from disk; no auth-attempt digests persist.

## [v0.2.0] — 2026-11-16

This release adds a fourth (SSH) sensor, deterministic dry-run recommendations, optional evidence
encryption, an authenticated operator console with an embedded UI, and several experimental
multi-node and identity features. It is an early platform: nothing here is a production-readiness
claim, and features marked experimental have not been exercised beyond the checks recorded in
[docs/verification.md](docs/verification.md).

### Upgrade notes

- **Minimum Go is 1.27.4** (`go.mod`, CI, release workflow and the container builder). Older
  toolchains cannot build this version.
- **Encrypted segments are written as container v3** (authenticated checkpoints). Encryption is
  opt-in; plaintext remains the default for data directories that have never enabled it. Sealed v2
  segments written by pre-release builds remain readable; unfinished v2 segments fail closed with
  guidance. There is no in-place migration.
- **Console and fleet-hub state moves under `tenants/default`** automatically on first start with
  this version (no data is rewritten; an interrupted move resumes). Take a backup first; this
  changelog documents no downgrade path.
- **New direct dependencies** (all Apache-2.0 or BSD): `filippo.io/age` v1.3.2,
  `github.com/coreos/go-oidc/v3` v3.21.0, `golang.org/x/oauth2` v0.38.0 and
  `github.com/go-jose/go-jose/v4` v4.1.4, plus `golang.org/x/crypto` v0.59.0 (SSH). See
  [docs/license-policy.md](docs/license-policy.md).
- No tag, release, container image, binary signature or provenance attestation for v0.2.0 existed
  when this entry was written; see [docs/RELEASE.md](docs/RELEASE.md).

### Added

Sensors, detection and responses

- Authentication-only SSH deception sensor: synthetic password/public-key authentication, in-memory
  Ed25519 host key per sensor instance, bounded sessions, and unconditional rejection of channels
  and global requests (#46).
- Optional per-sensor `process_isolation` running a fixed same-binary worker over a bounded stdio
  protocol. Fault containment only, not a sandbox; off by default (#54).
- Deterministic detection rules for prompt-injection and abuse patterns, attached to HTTP, TCP and
  MCP observations and stored as evidence (#3, #50).
- Opt-in OpenAI-compatible and Ollama response providers with destination classification, redirect
  and proxy refusal, and time/byte caps; provider output stays untrusted data (#6).
- Outbound destination policy for every self-initiated connection (cloud-metadata ranges always
  denied, private ranges opt-in) (#4).
- Policy actions on detection findings, limited to decoy response behavior, and a hardened MCP
  JSON-RPC gateway with decoy resources and prompts (#7, #8).
- Correlation engine, off by default: COR-001..COR-004 signals recorded as `correlation_signal`
  evidence, observations only (#18-#22, #40).
- Opt-in HMAC-signed webhook evidence stream with bounded queue, counted drops and DNS-rebinding-safe
  dialing (#15-#17).
- Data-only observer extensions: digest-verified out-of-process processes that receive stored
  observations and may return only an event-linked acknowledgement (#14, #53).

CLI

- `aegismesh demo` (one-command synthetic HTTP/TCP/MCP/SSH scenario on OS-assigned loopback ports)
  and `demo --console` (#52).
- `aegismesh recommend`: deterministic, evidence-linked, dry-run-only operator guidance (#51).
- `inspect export --profile ecs`: ECS-compatible local projection that preserves the native
  envelope; `inspect list --classification` and `--finding` filters (#11, #41, #43).
- `aegismesh rules list|explain|test` over one rule catalog, with offline evaluation of supplied
  text (#23-#29).
- `aegismesh healthcheck --live|--ready` for shell-less exec probes (#37).
- `init` provider profiles, `validate --effective` policy preview and `doctor` readiness reporting
  (#10, #11); credential safety gate for `migrate beelzebub` (#12).
- `console token` and `console hash` for generating operator credentials (#74).

Evidence at rest

- Opt-in age/X25519 evidence encryption with explicit read identities, key rotation, mixed-history
  retention, and fail-closed handling of wrong keys, corruption and plaintext downgrade (#73).
- Encrypted container v3 with authenticated checkpoints: `inspect` and `recommend` read an open
  segment through its last checkpoint with explicit incompleteness notices; `--require-sealed` demands
  strict completeness; `doctor` warns about interrupted segments without keys (#77).

Operator console

- Operator console API, disabled by default: viewer/analyst/admin token roles, ephemeral sessions
  with CSRF protection, bounded in-memory evidence index, live SSE stream, operator investigations
  and a hash-chained private audit log. It cannot control sensors or change policy, configuration or
  evidence (#74).
- Embedded console UI served by the same listener when `console.enabled` is true: plain HTML, CSS and
  ES modules, no build step, no third-party code, strict CSP, evidence rendered as text only; `make
  ui-test` runs its tests (#75).
- Console UI polish: elevation, icons, sparklines, event side panel with keyboard navigation, command
  palette, and documented motion rules (#78).
- Static landing page and design-system reference under `site/` (#75). Not deployed anywhere.

Experimental, opt-in multi-node and identity features

- **Fleet inventory (experimental):** hub and agent roles in the same binary, private Ed25519 node
  identities, one-time enrollment tokens, signed heartbeats, permanent revocation and a console
  inventory screen. The hub cannot command nodes (#76).
- **Evidence forwarding (experimental):** agent to hub, off by default on both ends. Best effort with
  counted loss, a memory-only oldest-drop queue (4,096 events / 16 MiB) and no on-disk spool; the
  local store stays authoritative. Hub copies inherit hub encryption; the console shows evidence
  origin, per-node counts and forwarding state (#79, #81).
- **Single sign-on via OpenID Connect (experimental):** Authorization Code with PKCE (S256), explicit
  role and tenant mappings, bounded provider egress. Operator-token login stays enabled unless
  `token_login: false`; logout is local only. Exercised only against local test providers (#80).
- **Logical tenant isolation (experimental):** up to 32 declared tenants, one active tenant per
  session, partitioned indexes, investigations, audit and fleet registries, independent quotas. One
  process, OS user, data directory and encryption recipient are still shared (#80, #81).

Deployment and supply chain

- Helm chart with values schema, default-on ingress NetworkPolicy, opt-in PodDisruptionBudget,
  dedicated ServiceAccount and exec probes; contract-tested, not run against a real cluster
  (#30-#39).
- `make bench` and [docs/architecture/performance.md](docs/architecture/performance.md): opt-in
  backend benchmarks and a measured performance pass with stated limits (#82).

### Changed

- **Go 1.27.4 is the minimum toolchain** and is pinned across local gates, CI, releases and the
  container builder; local tools derive it from `go.mod` (#72).
- Dependencies: `golang.org/x/crypto` v0.59.0, `golang.org/x/sys` v0.50.0, plus the new modules listed
  in the upgrade notes (#72, #73, #80).
- Encrypted segments are written as container v3 (#77).
- Console and fleet-hub state is stored under `tenants/<tenant>/`; legacy state migrates into
  `tenants/default` (#80).
- Console static assets other than the index are served gzip-compressed with strong ETags and
  `304` support; the index stays `no-store`. Per-sensor overview buckets are capped at 64 (#80).
- Console evidence queries and overview use secondary indexes and snapshots instead of full scans.
  Measured on synthetic data; several worst cases and noisy controls are documented rather than hidden
  (#82).
- Configuration accepts port `0` (OS-assigned ephemeral port); the privileged-port policy applies only
  to ports 1..1023.
- Release, SBOM and workflow definitions use immutable references (full-SHA Actions, digest-pinned
  base images, pinned Go tools) and a deterministic CycloneDX SBOM check (#47).
- HTTP rule precedence, catch-all semantics and the provider context contract are documented where
  they are enforced.

### Fixed

- Verified export and segment reads now fail closed on metadata, open or scan errors instead of
  skipping evidence; export no longer risks overwriting source evidence (#43, #44).
- Historical encrypted v2 segments require authenticated completion footers, rejecting truncation at
  frame boundaries and changed record order. Malformed authenticated event JSON fails closed instead
  of being skipped.
- Storage enforces one shared 1 MiB maximum stored-envelope boundary across configuration,
  plaintext/encrypted writers and readers, so no accepted write is unreadable at the configured limit.
- `storage.max_event_bytes` is an actual runtime/store bound rather than a validation-only setting;
  oversized envelopes are rejected before segment mutation (#56).
- MCP sensor returned an empty `{}` body (HTTP 200) for unparseable JSON-RPC; protocol errors now
  always render complete JSON-RPC error envelopes, and notifications answer 202.
- `ext verify` panicked when a public key was provided for an unsigned manifest; it now fails with a
  clear signature error.
- `migrate beelzebub` ignored its flags (`--write`, `--out`, `--force`); interleaved flag/positional
  parsing is implemented.
- Data race between sensor `Addr()`/`Close()` across goroutines; listener access is synchronized in
  all sensors, and producer shutdown is serialized.
- `/readyz` no longer reports ready before sensor startup completes; runtime status counts listeners
  only after each successful start.
- Runtime maintenance goroutine leaked after shutdown; it now terminates via a closed channel and is
  joined before storage closes.
- Duplicate sensor ids from same-named import sources collided at emit time; deterministic suffixing
  with an explicit note.

### Security

- Go 1.27.4 and `golang.org/x/crypto` v0.59.0 replace the unsupported Go 1.25 line and include the SSH
  fixes for GO-2026-6354 and GO-2026-6355 (#72). `make vuln` runs the pinned govulncheck.
- Extension subprocesses inherited the operator's full environment; they now run with a fixed minimal
  environment and the manifest directory as working directory.
- Redaction missed JSON-style credential keys (`"password": "..."`) and left artifacts from groupless
  patterns; per-pattern replacements plus a JSON-key rule close the gap.
- Importer refuses inline credential material in Beelzebub sources (#12).
- Untrusted input still has no path to `os/exec`, filesystem path selection, configuration mutation or
  enforcement; observer extension output is acknowledgement-only (#53).

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
