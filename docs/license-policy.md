# License and dependency policy

## Project license

Apache-2.0 for all first-party code. See LICENSE and NOTICE. No open-core split: every capability in the
product lives in this repository under the same license.

## Dependency rules

1. Allowed licenses: Apache-2.0, MIT, BSD-0/2/3-Clause, ISC. Everything else (GPL/LGPL/AGPL/SSPL/unlicensed)
   is rejected.
2. Every dependency needs a recorded justification: what it does, why stdlib is insufficient, who reviewed
   it. Recorded below.
3. Prefer zero dependencies. A new one requires an ADR note in its introducing PR.
4. `go.sum` is security-sensitive; changes are reviewed like code.
5. CI runs a license check over the resolved module graph (`scripts/license-check.sh`).

## Current direct third-party dependencies

| Module | Version | License | Why |
|---|---|---|---|
| `filippo.io/age` | `v1.3.2` | BSD-3-Clause | Maintained native age/X25519 authenticated encryption; stdlib has no age format implementation (ADR-0016) |
| gopkg.in/yaml.v3 | v3.0.1 | MIT (+Apache-2.0 portions) | Config parsing; YAML is a user-facing requirement and stdlib has none |
| `golang.org/x/crypto` (`ssh` package) | `v0.59.0` | BSD-3-Clause | Maintained SSH transport and cryptographic protocol implementation; the standard library has no SSH server implementation |

The v0.1.0 release used only the YAML module. The SSH slice adds the pinned
`x/crypto` module. Metrics exposition, CLI dispatch, JSON-RPC/MCP handling,
plaintext JSONL storage and crypto digests/signatures remain standard-library code
deliberately (ADR-0001, ADR-0008).

## Resolved SSH dependency review

The resolved graph also contains the transitive modules selected by
`x/crypto`: `golang.org/x/net v0.62.0`, `golang.org/x/sys v0.50.0`,
`golang.org/x/term v0.48.0`, and `golang.org/x/text v0.44.0`, plus the existing
YAML test dependency `gopkg.in/check.v1`. All seven non-main modules passed the
repository's allowed-license scan and `go mod verify`.

Go 1.27.4 and `x/crypto v0.59.0` replace the unsupported Go 1.25 line
and include the SSH fixes for `GO-2026-6354` and `GO-2026-6355` (fixed upstream
in v0.56.0). Pinned `govulncheck v1.7.0` remains the reachable-vulnerability
gate; current execution results and blockers are in `docs/verification.md`.
A future imported or reachable advisory blocks the dependency; no silent
fallback may be substituted without amending ADR-0010.

## Evidence encryption dependency review (2026-11-14)

Reviewer: Codex implementation review, pending orchestrator/human PR review.
The introducing PR is **pending**; this record must be linked in its description.
[Upstream releases](https://github.com/FiloSottile/age/releases) and the Go
module proxy both select **age v1.3.2**, requiring Go >=1.25; the current Go
**1.27.4**, x/crypto **v0.59.0**, and x/sys **v0.50.0** are preserved.
The [age LICENSE](https://github.com/FiloSottile/age/blob/v1.3.2/LICENSE) is
BSD-3-Clause; downloaded LICENSE SHA-256:
`c5d65279d02955c0fc2294ae417c3add650d228f4f5c82bd6d531fc26c89cd96`.
Only native X25519 constructors are used; no plugin, SSH recipient, passphrase,
KMS, command, key lookup, or network behavior is enabled.

The full resolved graph contains fourteen non-main modules. In addition to the
seven baseline modules above, the new graph requirements are:

| Module/version | License | Boundary / evidence |
|---|---|---|
| `filippo.io/age v1.3.2` | BSD-3-Clause | Runtime format/encryption; LICENSE above |
| `filippo.io/hpke v0.4.0` | BSD-3-Clause | age runtime dependency; module LICENSE |
| `filippo.io/edwards25519 v1.2.0` | BSD-3-Clause | Graph-only for our native X25519 import; module LICENSE |
| `filippo.io/nistec v0.0.4` | BSD-3-Clause | Graph-only; module LICENSE |
| `github.com/rogpeppe/go-internal v1.16.0` | BSD-3-Clause | Upstream test graph only; module LICENSE |
| `golang.org/x/tools v0.49.0` | BSD-3-Clause | Upstream test/tool graph only; module LICENSE |
| `c2sp.org/CCTV/age v0.0.0-20260829155415-4448f2097b2d` | 0BSD (selected option) | Upstream age test vectors only; embedded README license |

The CCTV submodule has no standalone LICENSE. Its
[pinned README license](https://github.com/C2SP/CCTV/blob/4448f2097b2d/age/README.md#license)
offers **0BSD**, CC0, or Unlicense for the vectors and top-level files. We select
**0BSD**, within the BSD-only family, and explicitly add it to this policy;
CC0 and Unlicense are not approved alternatives. We do not import the vector
generator's internal code or run upstream module tests. The license scanner
checks this exact module/version against README SHA-256
`fdbd4b06044f3803c72bdaf2df7681fdce3a45a326a2898e75640eae906606ad`
before recognizing its embedded grant. Module directories come from Go's
resolved `Dir`, preserving uppercase-module cache escaping.

The common Go BSD LICENSE SHA-256 is
`911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`
(hpke, nistec, and x/*). edwards25519:
`2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067`;
go-internal:
`4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20`.
These are inspected license texts, not conclusions inferred from an SBOM.
Current gate execution is recorded in [verification.md](verification.md).

## SBOM and provenance strategy

- SBOM: local, CI, and release paths use
  `cyclonedx-gomod@v1.10.0 app` to emit deterministic CycloneDX 1.6 JSON under
  the corresponding platform build constraints. License detection stays in the
  specification's evidence field; AegisMesh does not promote a heuristic match
  to an asserted license. The repository-owned validator checks the root,
  references, uniqueness, and dependency relationships and fails closed.
- Provenance: a separate tag-triggered job receives OIDC/attestation authority,
  downloads only the named binaries, and creates GitHub build-provenance
  attestations. This is evidence about those binary subjects, not about the
  SBOM/checksum files and not a blanket SLSA level claim.
- Signing: `SHA256SUMS.txt` and binaries are not cosign-signed. Checksums and
  GitHub attestations are distinct controls and are described separately.

## Build and release tooling review

These tools do not enter the runtime module graph. They remain security-sensitive
because CI executes them, so versions and immutable identities are reviewed in
the same PR that changes them.

| Tool or base | Immutable identity | License evidence | Purpose and boundary |
|---|---|---|---|
| CycloneDX GoMod | `v1.10.0` through the Go checksum database | Apache-2.0 | Build-only application dependency inventory; no runtime import |
| `golang.org/x/vuln/cmd/govulncheck` | `v1.7.0` | BSD-3-Clause | Build-only reachable-vulnerability gate |
| Go builder image | `golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf` | upstream Go/Alpine notices | Build environment only; multi-platform index resolved from Docker Hub |
| Distroless runtime image | `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` | upstream Distroless/Debian notices | Minimal runtime filesystem; multi-platform index resolved from GCR |
| GitHub Actions | full 40-character commit SHAs in workflow files | upstream action repositories | CI orchestration; a static gate rejects mutable references |

Image digests establish exact bytes, not license conclusions or security. Their
platform manifests and upstream notices must be re-reviewed when Dependabot
proposes a digest update.

## Attribution process

- New vendored/adapted snippets (even small ones) go to NOTICE with origin URL, license, and date.
- Clean-room rule: no GPL source, config samples, docs wording, or branding from other projects; concept
  inspirations documented in docs/research/competitive-landscape.md instead.
