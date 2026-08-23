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

## Current third-party dependencies

| Module | Version | License | Why |
|---|---|---|---|
| gopkg.in/yaml.v3 | v3.0.1 | MIT (+Apache-2.0 portions) | Config parsing; YAML is a user-facing requirement and stdlib has none |

That is the entire list at v0.1.0. Metrics exposition, CLI dispatch, JSON-RPC/MCP handling, JSONL storage,
and crypto digests/signatures are implemented on the standard library deliberately (ADR-0001, ADR-0008).

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
