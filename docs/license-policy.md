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

- SBOM: the tag-triggered release workflow emits CycloneDX JSON for every binary with
  `anchore/sbom-action`. `scripts/sbom.sh` is a local helper that exits BLOCKED
  unless Syft or cyclonedx-gomod is already installed; it never fabricates output.
- Provenance: tag-triggered release binaries receive GitHub build-provenance
  attestations. This is evidence about the named binary subjects, not a blanket
  SLSA level claim for the repository or its dependencies.
- Signing: `SHA256SUMS.txt` and binaries are not cosign-signed. Checksums and
  GitHub attestations are distinct controls and are described separately.

## Attribution process

- New vendored/adapted snippets (even small ones) go to NOTICE with origin URL, license, and date.
- Clean-room rule: no GPL source, config samples, docs wording, or branding from other projects; concept
  inspirations documented in docs/research/competitive-landscape.md instead.
