# Verification ledger

Current evidence is kept first. The detailed cumulative ledger through
2026-08-24 is preserved in
[`verification-history-through-2026-08-24.md`](verification-history-through-2026-08-24.md).

Vocabulary: **PASS** means the named command or external check actually ran and
succeeded; **FAIL** means it ran and failed; **BLOCKED** means the required tool,
checkout, permission or environment was unavailable; **NOT RUN** means the
check or external action was deliberately not executed. Evidence from hosted CI
does not turn an unavailable local command into a local PASS.

## 2026-11-14 — steady-traffic encryption segment review

Candidate remains uncommitted on `feat/evidence-at-rest-encryption`, based on
`c64b58f29373ac475ec6a44ce692722062c5dfba`, macOS arm64 / Go **1.27.4**.
This entry supersedes the unconditional flush/seal policy in the earlier recovery
receipt below. No commit, push, branch switch, `gh`, staging, hosted CI, merge,
publication or deployment was performed.

**Changed behavior.** Ordinary flushes publish buffered ciphertext to the OS and
keep the segment open. The fixed `maxEncryptedSegmentAge = 5 * time.Minute`
starts at the first successful event append; only size rotation, close or a flush
at that age seals. Empty segments never age out, repeated aged flushes leave the
sealed bytes unchanged, and a successor opens only on the next accepted append.
Five minutes balances near-live read delay with at most 288 age-driven seals/day
under steady traffic instead of 17,280. Size rotation and restarts add files.
This preserves the existing non-`fsync` flush contract; power-loss durability is
not claimed. No runtime timer or configuration field changed.

**Regression evidence.** Injected-clock tests cover 60 interleaved appends/flushes
inside the age window with exactly one segment, observable ciphertext bytes after
each flush, active-reader/count "not sealed" errors, an exact-boundary seal that
verifies every event and footer, repeated seals producing no additional bytes or
files, successor age reset, empty idle flushes across 100 minutes, first append
after idle, and byte-for-byte plaintext output across age bounds. Existing
size-rotation, active-retention, restart, corruption/truncation and concurrent
append/flush/retention tests remain in the race suite. Runtime wiring now proves
that flush leaves evidence unsealed and close makes it readable.

**Related resource review.** An unfit encrypted frame could previously rotate a
populated/sealed segment before rejection. Such frames now fail the fresh-segment
header/frame/footer fit check before any seal/rotation; a regression checks ten
rejections both before and after an age seal without creating a successor or
changing the original event count. Append/flush do no directory listing or
retention scan. The writer holds one segment descriptor and closes it before
opening the successor. Encryption is in memory; identity loading is bounded to
eight files and closes each read. Read/count/alias checks open segments one at a
time. CLI export creates one staged file per explicit export, removes it on error,
and syncs once per export, not once per event. There is no per-event `fsync`.

Retention still lists/sorts all segments and scans their frames every ten minutes;
it holds the store mutex, so a large pass can delay writes/flushes. Size rotation
is proportional to accepted bytes, retention can overshoot between passes, and a
damaged closed segment blocks count retention. These are documented limits, not
a hard disk quota or an absolute daily file cap. Active evidence is unreadable
until sealed, normally within five minutes of the first event plus the next
five-second flush (longer if maintenance stalls). Full-directory inspection can
still fail on a new active successor: stop the runtime or inspect a separate
sealed-only snapshot. Documentation, configuration reference, ADR-0016, threat
model, CLI/data-flow guidance, roadmap and handoff now describe these boundaries.

| Command | Result and captured output |
|---|---|
| `GOTOOLCHAIN=go1.27.4 go test -race -count=1 ./internal/storage ./internal/runtime` | **PASS**, exit 0 after all code/test edits: storage `ok` (4.431 s), runtime `ok` (15.679 s). |
| `make lint test` | **PASS**, exit 0 after all code/test edits: gofmt check, `go vet ./...`, `go test -race ./...`; all packages passed. Storage `ok` (4.692 s), runtime `ok` (15.999 s). Make reported `golangci-lint not installed; skipped (vet+fmt ran)`; no separate lint execution is claimed. |
| `make fuzz-seed` | **PASS**, exit 0: all nine 15-second targets passed. `FuzzEncryptedFrameStructure`: 479969 executions, 20 new interesting inputs, no failure (`ok`, 16.372 s). |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0, `No vulnerabilities found.` |
| `git diff --check` | **PASS**, exit 0 after the final documentation/ledger update; no whitespace errors. |

## 2026-11-14 — evidence-at-rest encryption recovery and review

Candidate: uncommitted `feat/evidence-at-rest-encryption` on
`c64b58f29373ac475ec6a44ce692722062c5dfba` (reviewed but unmerged toolchain
upgrade). Host: macOS arm64, Go **1.27.4**. No commit, push, reset, branch
checkout, `gh`, hosted workflow, publication or deployment was performed.
The index is unchanged. PR number: **pending**. PR #58 is closed/unmerged and
its patch is draft provenance, not review or exact-head CI evidence.

### Recovery and defects corrected

Fifteen `git show origin/codex/evidence-at-rest-age-v2:.codex/encryption-v2.partNN`
reads were concatenated outside the repository in `$TMPDIR`. Verified SHA-256:
`4fc51a53fe6e7aa89c3e9d7925d0afdff6fd84f47786861d5474093c753c26c7`.
Split sizes/digests also matched the source workflow:

| Patch | Bytes | SHA-256 |
|---|---:|---|
| `01-runtime.patch` | 56285 | `658a31a84f272994045376572b085f8e4de72e015572d758a3294f3093d5e992` |
| `02-tests.patch` | 49399 | `9455112109ecf3c3b9dd183e629ff91067edde2a8e8e3be79031f15b1d33f7be` |
| `03-docs.patch` | 42380 | `f6cfbc5933271b5e71707678c6f17da44d833b774b8486b8ef9b5d00f802de94` |

The runtime and tests applied without three-way conflicts. Module files were
resolved by retaining the current toolchain/x/* versions and acquiring age
v1.3.2. The docs patch conflicted in license-policy/verification; those files
were reconciled manually without importing historical PASS claims. Neither
`.codex` chunks nor the reconstruction workflow was added.

- **FAIL reproduced, then fixed:**
  `go test ./internal/storage -run TestEncryptedFrameBoundaryTruncationFailsClosed -count=1`
  exited 1 on the recovered implementation: it accepted truncation at byte 23
  (header only) and byte 605 (complete event boundary). Independent event
  ciphertexts did not establish segment completion. The v2 format adds an
  age-authenticated footer binding count and ordered framed-ciphertext digest.
  Initially flush/rotation/close sealed the segment; the steady-traffic review
  above supersedes the unconditional flush policy.
- Exact-match `inspect show` stopped early, bypassing later encrypted failures;
  it now consumes all input before emitting output. Authenticated but empty or
  malformed event JSON was silently skipped; encrypted records now fail closed.
- Identity diagnostics could echo an inline private value used as a filename
  or rejected flag value. Diagnostics now suppress identity values, and the
  loader rejects inline identities. The byte limit is enforced on actual file
  reads as well as metadata, covering concurrent growth and comment suffixes.
- Dedicated encryption configuration matrices were absent. Added YAML/JSON
  field/default/invalid/unknown/inline-identity cases and identity-flag matrices
  across all four read commands (including repetition and positional input), plus mixed ordering,
  counting, age/count retention, active-segment protection, concurrency,
  interrupted restart and real buffered-file failure regressions.
- The draft did not complete resolved-graph license review. All fourteen
  modules were reviewed; the scanner now uses Go-resolved module directories
  (including uppercase escaping), with a checksum-pinned README grant for the
  upstream CCTV test-only module's selected 0BSD option. No CC0/Unlicense grant
  is selected. See `license-policy.md` for versions, justification and hashes.
- Diff-scoped deslop review removed a redundant plaintext byte copy, obsolete
  early-stop handling and an unbounded guard-creation retry. It preserved
  trust-boundary validation and the existing plaintext representation.

### Commands executed on this candidate

| Command | Result and captured output |
|---|---|
| `go test ./internal/event ./internal/storage ./internal/config ./internal/cli ./internal/runtime ./internal/agekey -count=1` | **PASS**, exit 0; all six packages `ok`. Additional matrix/mixed-retention tests added later are included in the final race runs below. |
| `go test -race ./internal/storage ./internal/config ./internal/cli ./internal/runtime ./internal/agekey -count=1` | **PASS**, exit 0 on final runtime/test code; all five packages `ok` (output below). Includes concurrent encrypted append/flush/retention. |
| `make lint test` | **PASS**, exit 0, repeated after final code/test changes: formatting, `go vet ./...`, `go test -race ./...`; 30 test packages `ok`. `golangci-lint` is not installed; Make explicitly reported `skipped (vet+fmt ran)`. No unavailable tool was relabeled as run. |
| `make fuzz-seed` | **PASS**, exit 0, nine targets at 15 s each (158.97 s total). New `FuzzEncryptedFrameStructure` exercises framing/counting and age decryption with a valid sealed seed; 736929 executions, 220 new interesting inputs, no failure. Target is listed in both CI and Makefile. |
| `make vuln` | **PASS**, exit 0: pinned govulncheck v1.7.0, `No vulnerabilities found.` |
| `make license-check secrets-scan` | **PASS**, exit 0: `license-check: ok — 14 module(s) within policy`; `secrets-scan: ok`. New untracked files were also checked separately for secret-shaped values; all identities in tests are generated, not literals. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `make sbom sbom-check` in the linked worktree | **BLOCKED by tool/layout**, make exit 2: pinned generator returned `failed to determine version of main module: git: reference not found`. The second target is not reached by this failed invocation. This reproduces the base branch's known limitation, not a successful local generation. |
| `make sbom sbom-check` in an identical-source ordinary temporary clone | **PASS**, exit 0: `sbom.sh: wrote dist/sbom-aegismesh.cdx.json (darwin/arm64, cgo=1)`; `SBOM valid`. An initial shared-object clone attempt exited 2 (`git: object not found`); materializing its objects with `git -C "$SNAPSHOT" repack -a` resolved that temporary-clone limitation. Original worktree Git metadata was untouched. |
| Repeat ordinary-clone `make sbom sbom-check` plus SHA-256 comparison | **PASS**, exit 0, identical JSON SHA-256 `20be56525e9fcc61fea0ddbf860f4e7d96cc63c0eb95df62604dfee593b907da`. Generator warned `no licenses detected module=std@go1.27.4`; heuristic license evidence remains distinct from the explicit dependency review. |
| `make sbom-check` in the worktree against the copied snapshot artifact | **PASS**, exit 0: `SBOM valid`. The artifact stays ignored under `dist/`; this does not relabel direct worktree generation as PASS. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `git diff --check` | **PASS**, exit 0, no output (repeated after documentation). |
| `make build` | **PASS**, exit 0; native binary built with existing Makefile version flags. |
| `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$TMPDIR/.../aegismesh-linux-arm64" ./cmd/aegismesh` | **PASS**, exit 0. |
| `CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "$TMPDIR/.../aegismesh-darwin-arm64" ./cmd/aegismesh` | **PASS**, exit 0. |
| `sh -n scripts/license-check.sh`; `./scripts/check-supply-chain_test.sh` | **PASS**, exits 0; `check-supply-chain_test: ok`. |
| Human review, exact-head hosted CI and merge | **NOT RUN**; changes remain uncommitted for the orchestrator. |
| Explicit `make helm-contract` | **NOT RUN** in this encryption slice; chart behavior did not change. The normal guarded package tests ran under `make test`; they are not a live Helm receipt. |

Final focused race stdout:

```text
ok  	github.com/metaforismo/aegismesh/internal/storage	2.868s
ok  	github.com/metaforismo/aegismesh/internal/config	2.742s
ok  	github.com/metaforismo/aegismesh/internal/cli	5.396s
ok  	github.com/metaforismo/aegismesh/internal/runtime	15.332s
ok  	github.com/metaforismo/aegismesh/internal/agekey	2.123s
```

The SBOM fallback was created by a local shared/no-hardlink clone, then a
SHA-256-verified overlay of 232 tracked/untracked working-source files, then
materialization of Git objects in that temporary clone. Runtime, module and
check source matches the final worktree code; documentation receipts were
updated afterwards. No commit or fabricated version/tag was created. It uses
the unchanged pinned generator and validator. The application SBOM contains
age v1.3.2, hpke v0.4.0, x/crypto v0.59.0, yaml v3.0.1 and std go1.27.4.
Graph-only upstream test dependencies are separately covered by license review.

### Acceptance evidence map

| Contract | Behavioral evidence |
|---|---|
| Disabled filenames and bytes unchanged | `TestEncryptionDisabledPreservesPlaintextRecord` compares encoded bytes/newline and suffix; existing storage/CLI tests pass. |
| Recipient validation before readiness | `TestStorageEncryptionConfigMatrix` (YAML and JSON), `TestParseRecipient`, `TestBuildRejectsInvalidEncryptionBeforeCreatingDataDir`. |
| Read-only bounded identities, no inline secrets or diagnostic disclosure | `TestLoadIdentityFile`, FIFO rejection, config unknown-identity fields, duplicate/alias CLI tests, `TestIdentityArgumentsNeverEchoInlinePrivateKey`. File-only references are deliberately supported; no identity env-value or inline config surface exists. |
| Missing/wrong identities, corruption/truncation fail closed | Recovered storage/CLI matrices, new frame-boundary/footer/order tests and `TestEncryptedShowValidatesPastExactMatch`; failed exports leave targets untouched. |
| Restart, rotation and partial failures never downgrade | `TestEncryptedRestartCreatesIndependentSegments`, key-rotation tests, `TestEncryptedFlushSealsAndNextAppendRotates`, `TestEncryptedRestartAfterInterruptedWriteAndWriteFailure`, persistent guard/history checks. |
| Mixed history, retention, ordering and protected active segment | `TestMixedHistoryOrderingCountingAndRetention` checks unchanged plaintext, exact 2/2/1 counts, sorted output, count deletion, age deletion and old encrypted active preservation; concurrent append/flush/retention regression. |
| Bounded records/frames and concurrency | Exact stored-envelope boundary tests, length-prefix rejection, fuzz target and final affected/full race runs. |
| No added external destination, key service, captured-data path or exec | Source/diff review of agekey/config/runtime/storage/CLI wiring: only explicit operator data/identity/output paths and native X25519 library constructors. Manual traffic is loopback only. |

### Manual built-binary transcript summary

**PASS**, repeated after the final runtime edits. A private temporary workspace
was created; a small Go helper using age v1.3.2 generated two X25519 identities
into owner-only files without printing private values. Only the public recipient
entered `mesh.json`. A native built binary ran one HTTP sensor on an unprivileged
loopback port; two synthetic requests returned HTTP 200. SIGINT exited 0.

```text
aegismesh run --config TEMP/mesh.json
GET http://127.0.0.1:PORT/encryption-manual-marker-1 -> 200
GET http://127.0.0.1:PORT/encryption-manual-marker-2 -> 200
SIGINT -> exit 0; one .jsonl.age segment; zero .jsonl segments
inspect list --identity TEMP/identity.txt --verify --json -> exit 0, 2 events, both integrity_ok=true
inspect list [no identity] -> exit 1, empty stdout, requires at least one identity file
inspect list --identity TEMP/wrong.txt -> exit 1, empty stdout, did not match any supplied identity
inspect show --id EVENT --identity TEMP/identity.txt -> exit 0, verified=true
recommend --identity TEMP/identity.txt -> exit 0, dry-run report (0 recommendations)
inspect export [missing/wrong identity] -> exit 1, empty stdout, existing output unchanged
inspect export --identity TEMP/identity.txt -> exit 0, 2 events exported
run --config TEMP/mesh.json --dry-run [encryption enabled] -> exit 0; new encrypted segment
inspect list --identity TEMP/identity.txt --json -> exit 0, still 2 events
run --config TEMP/mesh.json --dry-run [encryption removed] -> exit 1, refusing plaintext writes
```

Every segment was checked for absent marker and envelope-schema plaintext bytes;
no plaintext `.jsonl` segment existed before or after restart/downgrade attempts.
Logs/transcript were checked against both generated private values. Temporary
private identity files were removed after the run. Exported synthetic NDJSON is
explicit plaintext outside the data directory.

### Remaining limits

Encryption protects contents on storage media, not a compromised runtime host or
stolen identity. Names, sizes, timing, logs and exports remain visible. Existing
plaintext is not migrated; lost keys cannot be recovered. The directory is for
one runtime writer; there is no cross-process lock. Readers require a completed
footer; live unfinished writes and crash-unsealed segments fail closed. There
is no automatic salvage or whole-file deletion/replacement detection, and anyone
holding the public recipient can create new ciphertext: this is confidentiality
and consistency, not writer provenance. Count retention validates framing without
private keys; it cannot authenticate ciphertext. The low-level reader may invoke
callbacks before a later failure; CLI outputs remain buffered/staged until the
complete read succeeds. Direct linked-worktree SBOM generation, human review and
exact-head CI/merge remain open as stated above.

## 2026-11-14 — whole-repository Go security refresh

Baseline: clean `security/go-toolchain-vuln-fixes` at `01579d3`. Local host:
macOS arm64. Selected Go **1.27.4**, `golang.org/x/crypto` **v0.59.0** and
`golang.org/x/sys` **v0.50.0**. The public Go proxy returned these latest
module releases; x/crypto selects x/net v0.62.0, x/term v0.48.0 and x/text
v0.44.0. Both upgraded modules retain BSD-3-Clause licenses. No runtime
module was added. The SSH advisories
[GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) were fixed in v0.56.0.
[Go release history](https://go.dev/doc/devel/release#go1.27.4) identifies
the selected security patch. No fallback to Go 1.26 was made.

Make and the standalone SBOM script derive their exact toolchain from the
module's `go` directive. Formatting uses that toolchain's gofmt. Every CI and
release `setup-go` step already uses `go-version-file: go.mod`; those workflows
need no duplicate version edit. Extension fixture modules use the same version.
Govulncheck v1.7.0 and CycloneDX GoMod v1.10.0 remain pinned.

| Command / check | Result and captured output |
|---|---|
| Baseline `make vuln` before edits | **FAIL**, make exit 2 (scanner exit 3): `Your code is affected by 14 vulnerabilities from 1 module and the Go standard library.` Also reported 1 imported-package and 3 module-only findings. |
| Docker Hub registry index resolution | **PASS**: authenticated GET of `https://registry-1.docker.io/v2/library/golang/manifests/1.27.4-alpine` returned an OCI multi-platform index; `Docker-Content-Digest` matched SHA-256 of the response bytes: `sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf`. Index includes Linux amd64 and arm64. |
| `GOTOOLCHAIN=go1.27.4 go version` | **PASS**, exit 0: `go version go1.27.4 darwin/arm64`. |
| `GOTOOLCHAIN=go1.27.4 go get golang.org/x/crypto@v0.59.0 golang.org/x/sys@v0.50.0` | **PASS**, exit 0: upgraded x/crypto v0.55.0 to v0.59.0 and x/sys v0.47.0 to v0.50.0. |
| `go mod tidy` | **PASS**, exit 0; module graph and checksums refreshed under Go 1.27.4. |
| `go mod verify` | **PASS**, exit 0: `all modules verified`. |
| `make lint test` | **PASS**, exit 0: gofmt, `go vet ./...` and `go test -race ./...` across all packages; `golangci-lint` is not installed locally (documented fallback). One earlier run under heavy concurrent host load failed `TestHostHandshakeFailures/echoes_wrong_frame_type` on its fixed 2 s handshake timeout; the test passed 6/6 in isolation (`-race -count=6`) and in the clean full rerun. Recorded as a pre-existing load-sensitive test, not changed here. |
| `make vuln` | **PASS**, exit 0: `No vulnerabilities found.` (govulncheck v1.7.0 under Go 1.27.4). |
| `make fuzz-seed` | **PASS**, exit 0: all eight bounded targets. |
| `make supply-chain-check` | **PASS**, exit 0: `supply-chain-check: ok`. |
| `./scripts/check-supply-chain_test.sh` | **PASS**, exit 0. Checker and fixtures needed no version-specific change. |
| `make license-check secrets-scan` | **PASS**, exit 0: `license-check: ok — 7 module(s) within policy` / `secrets-scan: ok`. |
| `make helm-contract` | **PASS**, exit 0 with Helm `v4.2.2`. |
| `make sbom sbom-check` | **BLOCKED** locally: the pinned CycloneDX generator fails with `failed to determine version of main module: git: reference not found` inside a linked `git worktree`, which is where this change was prepared. Hosted CI on the pull-request head is the acceptance evidence for this gate. |
| `sh -n scripts/sbom.sh` / `git diff --check` | **PASS**, exit 0. |

An earlier attempt in the same session was interrupted by a full disk; every
gate above was rerun afterwards. No tests or gates were weakened. Historical
ledgers were left intact. No tag, release publication, container
build/publication or deployment was performed.

## 2026-08-31 — storage `max_event_bytes` enforcement

| Check | Command / evidence | Status |
|---|---|---|
| Isolated source and toolchain | exact `master` source snapshot with temporary branch-only workflow removed; `/mnt/data/aegismesh-workspace/toolchain/x64/bin/go version` | PASS — source matches public `52b6ead` outside the removed temporary workflow; Go `1.25.14 linux/amd64` |
| Red implementation audit | compare config default/validation, `runtime.Build` and `storage.Options` | FAIL before fix — `storage.max_event_bytes` was never passed to or enforced by the store |
| Focused storage regressions | `go test ./internal/storage -run 'Test(MaxEventBytes|OversizeEventRejected|AppendAndReadBack)' -count=1 -v` | PASS |
| Runtime wiring regression | `go test ./internal/runtime -run TestBuildWiresStorageMaxEventBytes -count=1 -v` | PASS |
| Affected race suite | `go test -race -count=1 ./internal/storage ./internal/runtime` | PASS |
| Repository-wide local gate | two `make lint test` attempts, the second with a warm cache | BLOCKED — `go vet ./...` passed and the race run completed through 23 packages before this execution wrapper terminated the still-running aggregate command; affected packages and additional sensor packages passed separately, and exact-head PR CI remains the authoritative aggregate gate |
| Dependency and egress change | `git diff -- go.mod go.sum`; runtime destination review | PASS — no dependency, secret, provider, webhook, extension or destination changed |
| Module, supply-chain, license and secret checks | `go mod verify`; `make supply-chain-check`; offline cached `make license-check`; `make secrets-scan` | PASS — seven resolved modules remained within policy; no module graph changed |
| Helm contract locally | `make helm-contract` | BLOCKED — no Helm binary is installed in this environment; the unchanged chart remains covered by required PR CI |
| Release and repository administration | publication, tag, signing, settings and cluster actions | NOT RUN |

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
