# HANDOFF — where this project stands and what to do next

Read AGENTS.md first. Then this file. Then docs/ROADMAP.md.

## State (end of batch 1, v0.1.0)

Complete tested vertical slice: three sensors (HTTP/TCP/MCP), policy gate
with deterministic local LLM provider, event envelope + JSONL evidence store,
loopback admin listener, full CLI, extension manifest/verify/host with
contract tests, clean-room Beelzebub importer, packaging (Dockerfile/compose/
install script), CI + release workflows pinned by action SHAs.

Evidence: docs/verification.md (exact commands; PASS/FAIL/BLOCKED/NOT RUN).

## Non-obvious decisions (the "why" behind the code)

- **Provider context contract** (internal/llm): ctx governs *blocking work*
  only. `Local` is a pure function and must not fail on a cancelled ctx;
  future remote adapters MUST honor it. Documented on the interface — keep
  new providers consistent.
- **HTTP rule precedence** (internal/policy.Resolve doc): first full
  path+method match wins; methods-less catch-alls legitimately shadow 405
  and fallback; 405 carries Allow; fallback only for unmatched paths; GET ≠
  HEAD. Tests in httpsensor pin all of this.
- **Importer bind policy**: empty hosts forced to loopback; explicit hosts
  preserved verbatim but always reported with the exact opt-in flag name;
  emitted configs never contain a security section.
- **Extensions get no environment inheritance** (only
  `AEGISMESH_EXTENSION=1`) and cwd = manifest dir. Don't "fix" this back to
  os.Environ().
- Port `0` is valid config meaning OS-assigned ephemeral port.
- macOS note: copied Apple-signed binaries get SIGKILLed; ext tests use sh
  shims instead of copying /bin/cat.

## Known gaps (honest)

- No TLS termination on decoy listeners.
- Remote LLM adapters absent (fail closed); local provider only.
- Extensions are contract-tested but not wired into live policy resolution.
- Kubernetes is a direction document, not supported.
- golangci-lint/govulncheck/syft/cosign not run locally (BLOCKED entries);
  CI covers govulncheck + SBOM on push/tag.
- Evidence tamper-evident (hashes), not tamper-proof (no anchor yet).

## Suggested next steps (R1..R8 in ROADMAP)

Start with R2 (remote provider) or R1 (SSH sensor) — both slot into existing
seams (`llm.Provider`, `sensor.Sensor`). Each new parser gets a fuzz target
on day one; each new listener follows the tcp/mcp test patterns (bounded
stream reads, explicit sync, no sleeps where synchronization works).

## Commands that matter

    make build test lint        # daily loop
    make fuzz-seed              # bounded fuzz smoke
    ./scripts/demo.sh           # end-to-end proof
    ./scripts/license-check.sh && ./scripts/secrets-scan.sh
