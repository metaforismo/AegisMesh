# AegisMesh

**A fully open-source, local-first, secure-by-default deception, detection, and evidence platform for
human and agentic attackers.**

AegisMesh deploys bounded HTTP, TCP, authentication-only SSH, and MCP decoys and
records every interaction as redacted, integrity-checked evidence on your own
machine. It runs offline by default and never executes attacker input. Response
recommendations are deterministic, local, and dry-run only; the shipped runtime
never acts on real assets.

> AegisMesh is an independent implementation in the deception-technology problem space. It contains no code
> or text from other honeypot projects. Inspiration and differences are documented in
> [docs/research/competitive-landscape.md](docs/research/competitive-landscape.md).

## Status

This is **v0.2.0**, an early platform with no production-readiness claim. Build it from source: no
container image, signed binary or provenance attestation has been published, and the landing page under
`site/` is a static file that is not hosted anywhere (see [docs/RELEASE.md](docs/RELEASE.md)).
The capabilities described here are backed by the checks recorded in
[docs/verification.md](docs/verification.md); what was not run or not verified is listed there too. Changes since v0.1.0
are in [CHANGELOG.md](CHANGELOG.md), and the plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

- Console source sessions, catalog technique observations, conservative STIX/CSV/TXT
  indicator downloads and Markdown observation reports; deterministic and bounded,
  with proposed recommendations only. See [API contracts](docs/architecture/console-api.md)
  and [`export indicators`](docs/cli.md). Frontend integration is separate.
- Static AI-service decoy profile, synthetic credential/agent markers and
  observe-only AI request/cadence/replay signals, with editorial framework
  references and a checked-in synthetic corpus. See
  [AI observations](docs/ai-threat-detection.md); no AI-client attribution or
  field false-positive claim is implied.

Optional capabilities below are **off by default**. Those marked *experimental* have been exercised only
with the checks recorded in the verification ledger and carry the limits stated next to them.


## Five-minute demo

Requires Go 1.27.4. Local gates, CI, releases, and the container builder use
the same security-patched toolchain; local tools derive it from `go.mod`.

```bash
git clone https://github.com/metaforismo/AegisMesh && cd AegisMesh
make build

# one self-contained HTTP/TCP/MCP/SSH-to-evidence scenario
./bin/aegismesh demo

# the same deterministic result as typed JSON
./bin/aegismesh demo --json

# the same scenario behind the operator console on an OS-assigned loopback port (Ctrl-C to stop)
./bin/aegismesh demo --console

# the same, preceded by ~2,000 (small) or 50,000 (large) seeded synthetic observations over 7 days
./bin/aegismesh demo --console --seed small
```

`demo` accepts no config, path, port, credential, API key or destination.
It uses synthetic data and OS-assigned loopback ports, verifies every recorded
observation hash, produces eight dry-run recommendations, then stops and removes
its private temporary workspace. It requires no cloud service, `curl`, `nc`,
privileged port or external network access. `make demo` invokes the same path.
`demo --console` keeps the scenario available until Ctrl-C and prints the console
URL and a fresh token once. `--seed small|large` adds clearly marked (`"synthetic": true`),
deterministic generated history from documentation-range addresses so the
console shows scale; see [docs/cli.md](docs/cli.md#demo---console---seed-smalllarge).

For a persistent workspace and manual protocol exploration:

```bash
# 1) scaffold a safe local workspace (synthetic data only)
./bin/aegismesh init --dir /tmp/aegismesh-demo

# 2) sanity-check the environment (ports free, data dir writable, config valid)
./bin/aegismesh doctor --config /tmp/aegismesh-demo/mesh.yaml

# 3) validate strictly (CI-grade)
./bin/aegismesh validate --config /tmp/aegismesh-demo/mesh.yaml

# 4) run (Ctrl-C to stop; all listeners bind 127.0.0.1 on unprivileged ports)
./bin/aegismesh run --config /tmp/aegismesh-demo/mesh.yaml
```

In a second terminal:

```bash
# trigger the HTTP decoy
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/admin/login

# trigger the TCP decoy
printf 'PING\r\n' | nc 127.0.0.1 6399

# call the MCP canary tool (this should NEVER happen from an honest agent)
curl -s -X POST http://127.0.0.1:8090/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canary:prod-db-export","arguments":{"query":"all"}}}'

# inspect what was recorded (observation ≠ incident; see docs)
./bin/aegismesh inspect list --data-dir /tmp/aegismesh-demo/data --limit 5

# produce local operator-review proposals; this never enforces an action
./bin/aegismesh recommend --data-dir /tmp/aegismesh-demo/data
```

Or with Docker: `docker compose -f deploy/compose/docker-compose.yaml up` (see
[deploy README](deploy/compose/README.md)).

## What ships

| Area | What ships |
|---|---|
| Sensors | `http`, `tcp`, authentication-only `ssh`, and `mcp` (JSON-RPC 2.0 over streamable HTTP POST). The SSH sensor completes synthetic authentication, records bounded metadata, rejects every channel and global request, and exposes no shell, PTY, SFTP, forwarding or filesystem ([ADR-0010](docs/architecture/adr.md)) |
| Process isolation | Opt-in `process_isolation: true` per sensor runs a fixed same-binary worker with a minimal environment and a bounded stdio protocol. Fault containment only: the worker keeps the runtime's OS identity and namespaces; it is not a network, filesystem, CPU, memory or malware sandbox |
| Responses | Static config rules and a deterministic local provider; opt-in OpenAI-compatible and Ollama adapters keep provider output untrusted |
| Detection | Deterministic prompt-injection/abuse rules, observe-only AI and honeytoken findings, and opt-in correlation signals (COR-001..COR-008). Editorial framework references and synthetic corpus checks; observations, never verdicts. `aegismesh rules` lists and tests them |
| Evidence | Versioned native envelope, integrity hashes, redaction before storage, rotation/retention, opt-in local ECS-compatible export that preserves the native envelope |
| Recommendations | Deterministic, evidence-linked operator-review proposals from verified local evidence; dry-run only, no enforcement, no new egress |
| Behaviour review | Hedged per-session actor profiles (`likely_automated`, `possibly_ai_agent`, `likely_human`, `inconclusive`) listing every evaluated signal; campaigns grouping sessions from different sources with the same redacted step sequence (`aegismesh campaigns`, `/api/v1/campaigns`); fixed configuration/evidence posture checks POS-001..022 (`aegismesh posture`, `/api/v1/posture`). Observations, never attribution or a security guarantee |
| Extensions and webhooks | Explicitly configured, digest-verified observer processes may return only an event-linked acknowledgement; opt-in HMAC-signed webhook delivery with a bounded queue and counted drops |
| Observability | Loopback admin listener: `/healthz`, `/readyz`, `/metrics` (Prometheus text format), `/version`; structured JSON logs via `log/slog` |
| Packaging | Dockerfile, Compose demo and a contract-tested Helm chart. The chart is not verified in a real cluster ([docs/deploy/kubernetes.md](docs/deploy/kubernetes.md)) |
| Migration | Clean-room `aegismesh migrate beelzebub` importer: dry-run default, never touches sources, exact unsupported-field report |
| Access administration | Console-managed person and service accounts with expiring, revocable API keys (SHA-256 stored, shown once); session listing, revocation and idle timeout; effective settings with provenance; bounded, audited audit export; component status. Config-file operators stay the break-glass path; no passwords, no SCIM ([ADR-0025](docs/architecture/adr.md)) |
| Roles and settings | An 18-permission catalogue behind every console route; custom roles for managed accounts that can never exceed the creator's own permissions; opt-in (`console.settings_editing: console`) editing of a fixed allowlist of console settings (session and key lifetimes, idle timeout, sign-in banner, organization name, default window) in an audited overlay that never writes the config file; time-limited acceptance of posture risks. Nothing touching sensors, listeners, TLS, storage, detection actions, fleet, tenants or OIDC is editable ([ADR-0026](docs/architecture/adr.md)) |

## Optional capabilities

### Operator console

An authenticated web console and HTTP API inside the same binary. **Opt-in** (`console.enabled`, default
off), on its own listener (default `127.0.0.1:9120`). Operators sign in with named viewer, analyst or
admin tokens (`aegismesh console token` generates one). It shows a bounded in-memory evidence index
(default 50,000 events), a live stream, investigations and a hash-chained audit trail, plus derived
views: attacker sessions with an actor profile (signals checked, present or not), campaigns (several
sources that followed the same steps; similar behaviour, not attribution) and a posture review of the
running configuration (not a security guarantee), where a known risk can be accepted for a while
with a reason (it stays listed, never "fixed"). What each operator sees and can do follows their role's
permissions. Settings shows your profile and permissions, preferences (UTC or local time, default
window, theme), your sessions and API keys; administrators manage console-managed accounts, built-in
and custom roles (a permission matrix with a diff before saving), sessions and keys, and read the
effective settings. A short allowlist of console settings (session and key lifetimes, organisation
name, sign-in banner, default window) can be changed in place with a reason when the config file
allows it, with a change history; everything else stays file-driven. These need a server that
provides the account endpoints; an older server says so. The UI is plain
HTML, CSS and ES modules embedded in the binary: no build step, no third-party code, evidence rendered
as text only.

**Limits:** it cannot control sensors or change policy, configuration or evidence. It is single-node
unless the experimental features below are enabled. With evidence encryption on, the console shows only
evidence observed since process start. Investigations and audit are plaintext. The UI has been checked
in Chromium only. See [configuration](docs/configuration.md#operator-console-optional), the
[API contract](docs/architecture/console-api.md) and the [design system](docs/design-system.md).

### Accounts and access administration

Admins who are members of the local tenant can create **managed accounts** (people or services) in the
console and issue them **API keys**: `amk_` tokens shown once, stored as SHA-256, expiring after 1..365
days (default 90) and revocable. Everyone can list and end their own sessions and set UI preferences;
admins can list and end any session, see the effective settings with where each value comes from, and
download the audit trail as JSONL or CSV. `aegismesh accounts` disables accounts or revokes keys offline.

**Limits:** config-file operators remain read-only and authoritative; only a short allowlist of console
settings can change in the console, and only when the config file turns editing on; custom roles apply
to managed accounts (configured operators and single sign-on mappings use the built-in roles); sessions
are in memory, so a restart signs everyone out and nothing is shared between processes. There is no
password login, SCIM provisioning or MFA beyond the IdP. Account state is
plaintext like investigations. See [the API](docs/architecture/console-api.md#accounts-access-and-settings-adr-0025)
and [ADR-0025](docs/architecture/adr.md).

### Evidence encryption at rest

Native age/X25519 encryption of stored evidence. **Opt-in**: evidence stays plaintext unless you
configure a public recipient. The private identity is supplied only for local reads (`--identity`),
never to the runtime. Encrypted segments carry authenticated checkpoints, so `inspect` and `recommend`
can read a running node through its last checkpoint with an explicit incompleteness notice;
`--require-sealed` demands a complete, sealed history. Not labelled experimental.

**Limits:** it protects the storage medium, not a compromised host or a stolen identity; file names,
sizes and timing stay visible; there is no key recovery, so keep backups; a truncated tail can look like
an open segment unless you use `--require-sealed`. See
[docs/evidence-encryption.md](docs/evidence-encryption.md).

### Fleet inventory (experimental)

The same binary can run as an inventory **hub** or an outbound reporting **agent**. **Opt-in**, both
roles off by default, on a separate machine listener (default `127.0.0.1:9130`). Agents enroll once with a
one-time token and send heartbeats signed with their own Ed25519 key; the console lists nodes and their
self-reported health.

**Limits:** the hub can never command, configure or dial a node. Status is self-reported, not attested.
It is not a managed service, and hub state is plaintext. See
[fleet configuration](docs/configuration.md#experimental-fleet-inventory-adr-0018), the
[operator API](docs/architecture/console-api.md#experimental-fleet-inventory-additions-adr-0018) and the
[wire protocol](docs/architecture/fleet-protocol.md).

### Evidence forwarding (experimental)

An enrolled agent can forward copies of its redacted evidence to a hub, so one console lists and counts
observations by node. **Opt-in on both ends** (disclosure on the agent, reception on the hub; both off
by default).

**Limits:** best effort with counted loss. The agent queue is memory-only (4,096 events / 16 MiB,
oldest dropped) and there is no on-disk spool, no historical forwarding and no cross-node correlation.
The node's local store stays authoritative. The hub checks payload hashes, which show consistency, not
provenance. See [forwarding configuration](docs/configuration.md#experimental-evidence-forwarding-adr-0018-amendment)
and the [protocol](docs/architecture/fleet-protocol.md).

### Single sign-on and tenants (experimental)

**SSO via OpenID Connect** signs operators in with Authorization Code and PKCE and maps identity claims
to the same roles. **Logical tenant isolation** splits console indexes, investigations, audit and fleet
registries into up to 32 declared tenants; a session acts in one tenant at a time. **Opt-in**: without
configuration there is one `default` tenant and token login only.

**Limits:** OIDC has been exercised only against local test providers, never a real identity provider.
Token login stays enabled unless `token_login: false`; logout is local and does not end the provider
session. Tenants are logical only: one process, OS user, data directory and encryption recipient are
shared, so host or process compromise crosses tenants. See
[SSO and tenants configuration](docs/configuration.md#sso-via-oidc-experimental-and-logical-tenant-isolation-experimental)
and [ADR-0019/0020](docs/architecture/adr.md).

## Not shipped

Telnet and database sensors; OTLP or automatic SIEM export; autonomous response or enforcement; a
durable (on-disk) forwarding spool; cross-node correlation; hard tenant separation (per-tenant keys or
processes); a hosted control plane or managed service; verified real-cluster Kubernetes support; a
published image, signed binaries or provenance attestations; a hosted landing page. See
[docs/ROADMAP.md](docs/ROADMAP.md).

## Security posture

Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Highlights:

- Decoys are non-production by definition; default bind is loopback on unprivileged ports.
- Inbound bytes, LLM output and extension output are data only: there is **no code path to shell
  execution, filesystem paths, or configuration mutation** from any of them. Only fixed same-binary
  sensor workers and explicitly configured, verified observer processes are ever spawned.
- Events are observations, not proof of compromise. The data model enforces this distinction.
- Report vulnerabilities per [SECURITY.md](SECURITY.md).

## Repository layout

```text
cmd/aegismesh                   entrypoint
internal/*                      sensors, runtime, storage, console, fleet, cli, sensor workers, extensions, migration
docs/                           brief, threat model, ADRs, roadmap, verification
deploy/                         Dockerfile, compose demo, Helm chart
examples/demo/                  demo config + scripted walkthrough
scripts/                        build/demo/scans helpers
site/                           static landing page and design-system reference (not hosted)
```

## Documentation

| doc | contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | full config reference (schema, precedence, env overrides) |
| [docs/cli.md](docs/cli.md) | every command and flag |
| [docs/architecture/console-api.md](docs/architecture/console-api.md) | operator console API contract |
| [docs/architecture/fleet-protocol.md](docs/architecture/fleet-protocol.md) | fleet and forwarding wire protocol, quotas and limits |
| [docs/architecture/performance.md](docs/architecture/performance.md) | measured backend performance, `make bench`, unmeasured cases |
| [docs/ecs-export.md](docs/ecs-export.md) | stable ECS-compatible evidence mapping and limits |
| [docs/evidence-encryption.md](docs/evidence-encryption.md) | age/X25519 at-rest encryption, identity handling, rotation and recovery limits |
| [docs/design-system.md](docs/design-system.md) | console UI and site design system |
| [docs/canary-model.md](docs/canary-model.md) | MCP canary/operator model |
| [docs/migration-beelzebub.md](docs/migration-beelzebub.md) | importer field mappings, exact supported/approximated/unsupported |
| [docs/troubleshooting.md](docs/troubleshooting.md) | symptom → cause → fix |
| [docs/FAQ.md](docs/FAQ.md) | positioning, evidence, provider questions |
| [deploy/helm/aegismesh/README.md](deploy/helm/aegismesh/README.md) | Helm chart operator runbook, current Kubernetes packaging path |
| [docs/deploy/kubernetes.md](docs/deploy/kubernetes.md) | Kubernetes verified-vs-untested boundary map and support preconditions |
| [docs/verification.md](docs/verification.md) | what was run, with results; what was not run |
| [docs/HANDOFF.md](docs/HANDOFF.md) | current state, invariants and next priorities for maintainers |

## Contributing & governance

Apache-2.0 licensed (see [LICENSE](LICENSE), [NOTICE](NOTICE)). Start with
[CONTRIBUTING.md](CONTRIBUTING.md), the [release process](docs/RELEASE.md), and the
[license/supply-chain policy](docs/license-policy.md). Agents: read [AGENTS.md](AGENTS.md) first.


### Round 3 local backend additions

The current uncommitted backend branch adds [synthetic MCP workspaces](docs/mcp-environments.md),
[local SIEM event formats](docs/siem-export.md), on-demand `digest --since 24h|7d`,
and the [console contract additions](docs/architecture/console-api.md#round-3-additions-local-uncommitted).
These are bounded observation tools: no shell/filesystem-backed workspace,
automatic delivery or new network egress. OTLP is format only; AegisMesh does
not ship an OTLP exporter. The console/hub [review scope and fixes](docs/security-review-2026-11.md)
and [synthetic performance measurements](docs/architecture/performance.md) are
separate from production, release or deployment evidence. See [verification](docs/verification.md).
