# Verification ledger

Current evidence is kept first. The detailed cumulative ledger through
2026-08-24 is preserved in
[`verification-history-through-2026-08-24.md`](verification-history-through-2026-08-24.md).

Vocabulary: **PASS** means the named command or external check actually ran and
succeeded; **FAIL** means it ran and failed; **BLOCKED** means the required tool,
checkout, permission or environment was unavailable; **NOT RUN** means the
check or external action was deliberately not executed. Evidence from hosted CI
does not turn an unavailable local command into a local PASS.

## 2026-08-31 — repository ground truth and PR #54 truth-sync

| Check | Command / evidence | Status |
|---|---|---|
| Requested local checkout | `test -d /Users/francescogiannicola/Documents/ChatGPT/AegisMesh`; search mounted work areas | BLOCKED — the macOS path is not mounted in this Linux execution environment and no alternate AegisMesh checkout was present |
| Local toolchain | `go version` | BLOCKED for repository gates — available Go is `go1.23.2 linux/amd64`, below the module requirement `go 1.25.14`; no source checkout is available to test |
| Public repository identity | GitHub repository metadata and branch/commit queries | PASS — `metaforismo/AegisMesh`, default branch `master`, baseline `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4` |
| Process-isolation merge | PR #54 metadata | PASS — PR #54 is merged; head `6ded0223235fbb383f65accf762aa67fe481e316`, merge commit `eef2b93c5e6bad06c03fe3e400094aedbe0ec9d4` |
| PR #54 hosted CI | workflow run `32717789361` | PASS — `fmt, vet, build, test (-race)` including Linux/Darwin cross-build; eight bounded fuzz targets; Helm contract; pinned `govulncheck`; dependency-license and secret checks; deterministic CycloneDX generation and validation all concluded `success` |
| Exa connector probe | one `web_search_exa` call and one `web_fetch_exa` call | PASS — both connector functions returned results; historical blocked entries remain archived as historical environment facts |
| Public maintenance queue | GitHub open PR and issue queries | PASS — no open issues; open Dependabot PRs #48 and #49 require policy-aware review |
| Local `make lint test` | unavailable checkout and insufficient local Go version | BLOCKED — not run in this environment; PR #54 hosted CI remains independent evidence for its exact head only |
| Documentation-only dependency/egress review | compare proposed truth-sync paths with runtime/module files | PASS — no `go.mod`, `go.sum`, runtime destination, provider, webhook or extension behavior changes in this block |
| Release, tag, signing, image and cluster actions | external-state review | NOT RUN — no release publication, tag, signature, attestation execution, image publication, repository-setting change or Kubernetes deployment was performed |

## Required evidence for the next implementation slice

Optional evidence-at-rest encryption is not complete until the exact PR head has:

- focused config, storage, reader and CLI tests;
- wrong-key, corruption, truncation, restart, rotation, retention and recovery
  integration cases;
- affected-package `go test -race`;
- `make lint test` and applicable bounded fuzzing;
- `go mod verify`, dependency-license, secret, vulnerability and deterministic
  CycloneDX checks;
- documentation, ADR, threat-model, backlog and handoff truth-sync;
- all required hosted jobs green before merge.

Release publication and real-cluster operation remain separate `NOT RUN` actions
unless explicitly authorized at action time.
