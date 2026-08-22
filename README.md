# AegisMesh

**A fully open-source, local-first, secure-by-default deception, detection, and evidence platform for
human and agentic attackers.**

AegisMesh deploys believable decoy services — HTTP endpoints, TCP services, and MCP canary tools that no
honest agent should ever call — and records every interaction as bounded, redacted, integrity-checked
evidence on your own machine. It runs offline. It never executes attacker input. Response automation starts
as dry-run recommendations that require explicit operator approval.

> AegisMesh is an independent implementation in the deception-technology problem space. It contains no code
> or text from other honeypot projects. Inspiration and differences are documented in
> [docs/research/competitive-landscape.md](docs/research/competitive-landscape.md).

## Status

Early foundation release (v0.1.0): a complete, tested vertical slice — three sensors, CLI, evidence store,
admin endpoints, extension contract — not yet a full platform. See [docs/ROADMAP.md](docs/ROADMAP.md).
Everything below is verified by the commands shown; see [docs/verification.md](docs/verification.md).

## Five-minute demo

Requires Go 1.25+.

```bash
git clone https://github.com/metaforismo/AegisMesh && cd AegisMesh
make build

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
```

Or with Docker: `docker compose -f deploy/compose/docker-compose.yaml up` (see
[deploy README](deploy/compose/README.md)).

## What is inside batch 1

| Area | What ships |
|---|---|
| Sensors | `http`, `tcp`, `mcp` (JSON-RPC 2.0 over streamable HTTP POST) |
| Responses | Static config rules + deterministic local LLM provider (offline by default); provider output treated as untrusted data |
| Evidence | Versioned envelope (`aegismesh.event/v1`) with SHA-256 payload integrity, per-process sequence numbers, redaction record; JSONL store with rotation + retention |
| Observability | Loopback admin listener: `/healthz`, `/readyz`, `/metrics` (Prometheus text format), `/version`; structured JSON logs via `log/slog` |
| Safety | Loopback + unprivileged-port defaults validated by `doctor`; strict schema validation; byte/time caps everywhere; no exec anywhere |
| Extensions | Out-of-process host behind digest-verified manifests (`ext.aegismesh.io/v1alpha1`) — contract-tested, not yet wired into live policy |
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
deploy/                         Dockerfile, compose demo
examples/demo/                  demo config + scripted walkthrough
scripts/                        build/demo/scans helpers
```

## Documentation

| doc | contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | full config reference (schema, precedence, env overrides) |
| [docs/cli.md](docs/cli.md) | every command and flag |
| [docs/canary-model.md](docs/canary-model.md) | MCP canary/operator model |
| [docs/migration-beelzebub.md](docs/migration-beelzebub.md) | importer field mappings, exact supported/approximated/unsupported |
| [docs/troubleshooting.md](docs/troubleshooting.md) | symptom → cause → fix |
| [docs/FAQ.md](docs/FAQ.md) | positioning, evidence, provider questions |
| [docs/deploy/kubernetes.md](docs/deploy/kubernetes.md) | K8s direction (not yet supported — honestly labeled) |

## Contributing & governance

Apache-2.0 licensed (see [LICENSE](LICENSE), [NOTICE](NOTICE)). Start with
[CONTRIBUTING.md](CONTRIBUTING.md), the [release process](docs/RELEASE.md), and the
[license/supply-chain policy](docs/license-policy.md). Agents: read [AGENTS.md](AGENTS.md) first.
