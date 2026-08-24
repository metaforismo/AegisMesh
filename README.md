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

The v0.1.0 foundation shipped three sensors, CLI, evidence storage, admin
endpoints, and the extension contract. Current `master` adds a fourth,
authentication-only SSH sensor and deterministic local dry-run recommendations;
this remains an early platform and carries no production-readiness claim. See
[docs/ROADMAP.md](docs/ROADMAP.md).
The finite v0.2 PR train and stop condition are in
[docs/DELIVERY-PLAN.md](docs/DELIVERY-PLAN.md). Everything below is verified by
the commands shown; see [docs/verification.md](docs/verification.md).

The SSH sensor completes synthetic password or public-key authentication,
records only bounded metadata, and rejects every channel and global request.
It exposes no shell, PTY, SFTP, forwarding, filesystem, or command path; see
[ADR-0010](docs/architecture/adr.md).

## Five-minute demo

Requires Go 1.25.14 or newer. The patch-level floor includes all current Go
1.25 security fixes plus the latest network-library maintenance release.

```bash
git clone https://github.com/metaforismo/AegisMesh && cd AegisMesh
make build

# one self-contained HTTP/TCP/MCP/SSH-to-evidence scenario
./bin/aegismesh demo

# the same deterministic result as typed JSON
./bin/aegismesh demo --json
```

The command accepts no config, path, port, credential, API key or destination.
It uses synthetic data and OS-assigned loopback ports, verifies every recorded
observation hash, produces one dry-run recommendation, then stops and removes
its private temporary workspace. It requires no cloud service, `curl`, `nc`,
privileged port or external network access. `make demo` invokes the same path.

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

## Current verified core

| Area | What ships |
|---|---|
| Sensors | `http`, `tcp`, authentication-only `ssh`, and `mcp` (JSON-RPC 2.0 over streamable HTTP POST) |
| Responses | Static config rules + deterministic local provider; opt-in OpenAI-compatible and Ollama adapters keep provider output untrusted |
| Evidence | Versioned native envelope, integrity checks, rotation/retention, plus opt-in local ECS-compatible export that preserves the native envelope |
| Recommendations | Deterministic, evidence-linked operator-review proposals from verified local evidence; dry-run only, with no enforcement or new egress |
| Demo | One-command synthetic HTTP/TCP/MCP/SSH scenario on OS-assigned loopback ports with integrity-verified evidence, a dry-run proposal and complete cleanup |
| Observability | Loopback admin listener: `/healthz`, `/readyz`, `/metrics` (Prometheus text format), `/version`; structured JSON logs via `log/slog` |
| Safety | Loopback + unprivileged-port defaults validated by `doctor`; strict schema validation; byte/time caps everywhere; no exec anywhere |
| Extensions | Digest-verified out-of-process observer extensions receive bounded data-only events; they cannot influence policy or responses |
| Migration | Clean-room `aegismesh migrate beelzebub` importer: dry-run default, never touches sources, exact unsupported-field report |

## Security posture

Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Highlights:

- Decoys are non-production by definition; default bind is loopback on unprivileged ports.
- Inbound bytes and LLM output are data only — there is **no code path to shell execution, filesystem
  paths, or configuration mutation** from either.
- Events are observations, not proof of compromise. The data model enforces this distinction.
- Report vulnerabilities per [SECURITY.md](SECURITY.md).

## Repository layout

```text
cmd/aegismesh                   entrypoint
internal/*                      sensors, runtime, storage, cli, extensions, migration
docs/                           brief, threat model, ADRs, roadmap, verification
deploy/                         Dockerfile, compose demo, Helm chart
examples/demo/                  demo config + scripted walkthrough
scripts/                        build/demo/scans helpers
```

## Documentation

| doc | contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | full config reference (schema, precedence, env overrides) |
| [docs/cli.md](docs/cli.md) | every command and flag |
| [docs/ecs-export.md](docs/ecs-export.md) | stable ECS-compatible evidence mapping and limits |
| [docs/DELIVERY-PLAN.md](docs/DELIVERY-PLAN.md) | finite v0.2 PR train, acceptance gates and completion predicate |
| [docs/canary-model.md](docs/canary-model.md) | MCP canary/operator model |
| [docs/migration-beelzebub.md](docs/migration-beelzebub.md) | importer field mappings, exact supported/approximated/unsupported |
| [docs/troubleshooting.md](docs/troubleshooting.md) | symptom → cause → fix |
| [docs/FAQ.md](docs/FAQ.md) | positioning, evidence, provider questions |
| [deploy/helm/aegismesh/README.md](deploy/helm/aegismesh/README.md) | Helm chart operator runbook — current Kubernetes packaging path |
| [docs/deploy/kubernetes.md](docs/deploy/kubernetes.md) | Kubernetes verified-vs-untested boundary map and support preconditions |

## Contributing & governance

Apache-2.0 licensed (see [LICENSE](LICENSE), [NOTICE](NOTICE)). Start with
[CONTRIBUTING.md](CONTRIBUTING.md), the [release process](docs/RELEASE.md), and the
[license/supply-chain policy](docs/license-policy.md). Agents: read [AGENTS.md](AGENTS.md) first.
