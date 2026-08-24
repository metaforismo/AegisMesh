# License and dependency policy

## Project license

Apache-2.0 for all first-party code. See LICENSE and NOTICE. No open-core split: every capability in the
product lives in this repository under the same license.

## Dependency rules

1. Allowed licenses: Apache-2.0, MIT, BSD-2/3-Clause, ISC. Everything else (GPL/LGPL/AGPL/SSPL/unlicensed)
   is rejected.
2. Every dependency needs a recorded justification: what it does, why stdlib is insufficient, who reviewed
   it. Recorded below.
3. Prefer zero dependencies. A new one requires an ADR note in its introducing PR.
4. `go.sum` is security-sensitive; changes are reviewed like code.
5. CI runs a license check over the resolved module graph (`scripts/license-check.sh`).

## Current direct third-party dependencies

| Module | Version | License | Why |
|---|---|---|---|
| gopkg.in/yaml.v3 | v3.0.1 | MIT (+Apache-2.0 portions) | Config parsing; YAML is a user-facing requirement and stdlib has none |
| `golang.org/x/crypto` (`ssh` package) | `v0.55.0` | BSD-3-Clause | Maintained SSH transport and cryptographic protocol implementation; the standard library has no SSH server implementation |

The v0.1.0 release used only the YAML module. The SSH slice adds the pinned
`x/crypto` module. Metrics exposition, CLI dispatch, JSON-RPC/MCP handling,
JSONL storage, and crypto digests/signatures remain standard-library code
deliberately (ADR-0001, ADR-0008).

## Resolved SSH dependency review

The resolved graph also contains the transitive modules selected by
`x/crypto`: `golang.org/x/net v0.57.0`, `golang.org/x/sys v0.47.0`,
`golang.org/x/term v0.45.0`, and `golang.org/x/text v0.41.0`, plus the existing
YAML test dependency `gopkg.in/check.v1`. All seven non-main modules passed the
repository's allowed-license scan and `go mod verify`.

Pinned `govulncheck v1.7.0` reports no reachable symbol or imported-package
vulnerability with Go 1.25.14. It reports the module-only advisory
`GO-2026-5932` for the unmaintained `x/crypto/openpgp` package; AegisMesh does
not import or call that package. A future imported or reachable advisory blocks
the dependency; no silent fallback may be substituted without amending
ADR-0010.

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
| Go builder image | `golang:1.25.14-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59` | upstream Go/Alpine notices | Build environment only; multi-platform index resolved from Docker Hub |
| Distroless runtime image | `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` | upstream Distroless/Debian notices | Minimal runtime filesystem; multi-platform index resolved from GCR |
| GitHub Actions | full 40-character commit SHAs in workflow files | upstream action repositories | CI orchestration; a static gate rejects mutable references |

Image digests establish exact bytes, not license conclusions or security. Their
platform manifests and upstream notices must be re-reviewed when Dependabot
proposes a digest update.

## Attribution process

- New vendored/adapted snippets (even small ones) go to NOTICE with origin URL, license, and date.
- Clean-room rule: no GPL source, config samples, docs wording, or branding from other projects; concept
  inspirations documented in docs/research/competitive-landscape.md instead.
