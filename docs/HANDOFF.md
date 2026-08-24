# HANDOFF — current verified state

Read `AGENTS.md`, then `docs/BACKLOG.md`, then `docs/ROADMAP.md`.

## Current state

The foundation and secure-intelligence layers ship HTTP/TCP/MCP sensors plus
an authentication-only SSH sensor,
detection and bounded correlation, native JSONL evidence, local and opt-in
remote providers, a bounded signed webhook, data-only observer extensions,
rule inspection/testing, Docker/Compose and contract-tested Helm packaging.
Batch 2 R3 adds a local ECS-compatible export profile while preserving the
native envelope. Batch 2 R1 adds synthetic password/public-key SSH
authentication with per-instance ephemeral Ed25519 keys, bounded resources,
and unconditional rejection of every channel and global request. Exact current
commands and evidence live in `docs/verification.md`.

The supply-chain slice pins Actions, SBOM/vulnerability tools, and both
container bases; generates deterministic platform-specific CycloneDX 1.6
application inventories; validates their reference graph; and isolates
tag-triggered OIDC authority in a binary-only attestation job. It does not
publish, sign, or attest anything during pull requests.

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
  hard-linked paths to source evidence segments, and any segment read failure
  aborts the export without changing the destination.
- Port `0` means an OS-assigned ephemeral port. Admin remains loopback-only.
- `/readyz` counts only successfully started sensor listeners; extension startup
  completes before sensor readiness can become true.
- Extensions inherit only `AEGISMESH_EXTENSION=1` and use the manifest
  directory as their working directory.

## Known gaps and boundaries

- No Telnet/database sensor, decoy-listener TLS, at-rest encryption, response
  recommendation engine, distributed mesh, or web console.
- No autonomous enforcement against real assets.
- Helm is real packaging with contract tests; real-cluster support is not verified.
- Correlation signals do not reach webhook or observer extensions. Enabling that
  would be new external egress and requires explicit approval.
- `golangci-lint` and cosign may be unavailable locally; record BLOCKED rather
  than inferring results. `make vuln` and `make sbom` use exact Go tool
  versions and fail closed if acquisition fails.
- No v0.2 tag, GitHub release, provenance statement, or binary signature has
  been created. The release workflow is readiness evidence; executing its
  external writes remains a separate approval.
- GitHub authentication and API access were available on 2026-08-24. Public
  PR/issue state remains mutable; re-check before relying on the captured list.

## Exact remaining work

`docs/BACKLOG.md` is authoritative. P0 export correctness, lifecycle races,
claim drift, ECS export, the SSH deception slice, and supply-chain hardening are
closed through PR #47: local gates passed and independent CI generated,
validated, and reproduced the real application SBOM while also passing the
pinned vulnerability scan. The next ordered slice is the dry-run recommendation
model, followed by the self-contained demo. At-rest encryption, the extension
live-policy boundary, and process isolation remain separate later slices in the
finite v0.2 delivery plan.

## Commands that matter

```text
make lint test
go test -race -count=20 ./internal/event ./internal/webhook ./internal/extmanager
go test ./internal/ecsexport ./internal/cli -run 'TestMarshal|TestInspectExport' -count=1
make fuzz-seed
make helm-contract
make supply-chain-check
make sbom sbom-check
make vuln
./scripts/license-check.sh
./scripts/secrets-scan.sh
```

## Suggested skills

Use `$research` for primary-source refreshes, `$architect` and `$blast-radius`
for new trust boundaries, `$diagnosing-bugs` for red-capable regressions,
`$deslop` on each task diff, and `$show-me-your-work` plus `$handoff` for the
verification trail.
