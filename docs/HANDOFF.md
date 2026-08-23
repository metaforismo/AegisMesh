# HANDOFF — current verified state

Read `AGENTS.md`, then `docs/BACKLOG.md`, then `docs/ROADMAP.md`.

## Current state

The foundation and secure-intelligence layers ship HTTP/TCP/MCP sensors,
detection and bounded correlation, native JSONL evidence, local and opt-in
remote providers, a bounded signed webhook, data-only observer extensions,
rule inspection/testing, Docker/Compose and contract-tested Helm packaging.
Batch 2 R3 adds a local ECS-compatible export profile while preserving the
native envelope. Exact current commands and evidence live in
`docs/verification.md`.

## Non-obvious decisions

- Provider output and extension output are untrusted data. Neither can select
  commands, paths, configuration, or enforcement actions.
- The authoritative store append precedes best-effort webhook, extension and
  correlation offers. Derived correlation signals append directly to storage;
  never republish them through `Bus.Submit`.
- Observer extensions are live but data-only. Response-influencing extension
  wiring remains unimplemented by ADR-0006.
- Native evidence remains the source contract. ECS-compatible export is a
  read-boundary projection and nests the complete native envelope.
- Verified export stages output and changes the destination only after all
  records pass structural and integrity checks. It refuses direct, symbolic and
  hard-linked paths to source evidence segments.
- Port `0` means an OS-assigned ephemeral port. Admin remains loopback-only.
- Extensions inherit only `AEGISMESH_EXTENSION=1` and use the manifest
  directory as their working directory.

## Known gaps and boundaries

- No SSH/Telnet sensor, decoy-listener TLS, at-rest encryption, response
  recommendation engine, distributed mesh, or web console.
- No autonomous enforcement against real assets.
- Helm is real packaging with contract tests; real-cluster support is not verified.
- Correlation signals do not reach webhook or observer extensions. Enabling that
  would be new external egress and requires explicit approval.
- `golangci-lint`, `govulncheck`, local CycloneDX tooling and cosign may be
  unavailable locally; record BLOCKED rather than inferring CI results.
- Open PR/issue state was BLOCKED in the 2026-08-23 development run because the
  GitHub API could not connect. Re-check before relying on that state.

## Exact remaining work

`docs/BACKLOG.md` is authoritative. P0 export correctness, lifecycle races and
claim drift are closed. The next P1 vertical slice is the SSH deception sensor;
architecture must pin its synthetic-authentication boundary, host-key lifecycle,
resource caps and dependency/license decision before code. The dry-run
recommendation model and at-rest encryption remain separate later slices.

## Commands that matter

```text
make lint test
go test -race -count=20 ./internal/event ./internal/webhook ./internal/extmanager
go test ./internal/ecsexport ./internal/cli -run 'TestMarshal|TestInspectExport' -count=1
make fuzz-seed
make helm-contract
./scripts/license-check.sh
./scripts/secrets-scan.sh
```

## Suggested skills

Use `$research` for primary-source refreshes, `$architect` and `$blast-radius`
for new trust boundaries, `$diagnosing-bugs` for red-capable regressions,
`$deslop` on each task diff, and `$show-me-your-work` plus `$handoff` for the
verification trail.
