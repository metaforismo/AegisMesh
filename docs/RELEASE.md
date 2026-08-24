# Release process

The pipeline below is a release-readiness contract. This slice validates its
structure and local artifact path, but does not create a tag, attestation, or
GitHub release. Those external writes require separate action-time approval.

## Versioning

Semantic versioning, `vMAJOR.MINOR.PATCH`. Pre-releases may use `-rc.N`.
Pre-1.0, breaking changes bump MINOR and are called out in the changelog.

The config schema (`aegismesh.io/v1alpha1`) gates compatibility: while a
release supports only v1alpha1 configs, MINOR bumps must accept every config
the previous MINOR accepted. Schema fields are removed only across a MINOR
bump pre-1.0 (MAJOR after), with a changelog warning one release ahead when
feasible.

## Cutting a release

1. Ensure CI is green on master (fmt, vet, tests with race, fuzz seeds, Helm
   contract, module integrity, pinned govulncheck, license/secret scans, SBOM
   contract, and immutable-reference checks).
2. Update CHANGELOG.md: new section with date, changes grouped
   Added/Changed/Fixed/Security.
3. After explicit publication approval, create and push a SemVer tag. Sign the
   tag only when an operator has separately configured and approved a signing
   identity; the workflow does not treat an unsigned tag as signed. The
   `release` workflow builds linux/darwin × amd64/arm64 static binaries,
   generates `SHA256SUMS.txt`, a CycloneDX 1.6 SBOM per build configuration,
   creates GitHub build-provenance attestations for the binary subjects, and
   publishes a GitHub release. None of those tag-triggered writes run for a PR.
4. Local equivalent: `make release VERSION=vX.Y.Z` acquires the exact Go
   1.25.14 toolchain and pinned SBOM generator, then produces binaries and
   inventories under `dist/` (`-trimpath`, version stamped from git describe).
   CI remains the source of attestations and published artifacts.

## Reproducibility contract

- Go is pinned by `go.mod`; container bases are pinned to verified multi-platform
  image-index digests.
- Dependency and tool acquisition are explicit preparation steps. Release
  compilation runs with `GOTOOLCHAIN=local`, `GOPROXY=off`, and
  `-mod=readonly` after `go mod verify`.
- CycloneDX generation uses the same `GOOS`, `GOARCH`, and `CGO_ENABLED` build
  constraints as its corresponding binary and omits random serials and
  timestamps. This is deterministic inventory, not a claim that binaries from
  different hosts are byte-for-byte reproducible.
- Binaries embed version metadata via ldflags; `aegismesh version` prints it.

## Supply-chain properties (and their current limits)

| property | how | status |
|---|---|---|
| Builds | Four static binaries; verified module cache, then offline readonly compile; Docker bases pinned by multiarch digest | implemented; container execution still depends on an available Docker daemon |
| Checksums | Exact four binaries plus exact four SBOMs in `SHA256SUMS.txt`; no wildcard discovery | implemented; checksum is integrity metadata, not a signature |
| SBOM | `cyclonedx-gomod@v1.10.0 app`, CycloneDX 1.6, platform build constraints, license evidence, repository validator | implemented locally and in CI; detected licenses remain evidence rather than assertions |
| Provenance | Separate least-privilege job uses `actions/attest-build-provenance` for named binary subjects | tag-only; no SBOM/checksum attestation and no repository-wide SLSA level claim |
| Binary signing | none | do not claim cosign, GPG, or signed releases |
| Immutable references | full-SHA Actions, digest-pinned Docker bases, pinned Go tools; static regression gate | enforced in CI and before a tag release |

## Verifying a download locally

    sha256sum --check --ignore-missing SHA256SUMS.txt
    gh attestation verify ./aegismesh-linux-amd64 \
      -R metaforismo/AegisMesh \
      --signer-workflow metaforismo/AegisMesh/.github/workflows/release.yml \
      --source-ref refs/tags/vX.Y.Z \
      --source-digest EXPECTED_40_HEX_COMMIT

Resolve `EXPECTED_40_HEX_COMMIT` from the reviewed tag before verification.
Repository and workflow identity alone are insufficient because another run of
the same workflow can legitimately attest a different artifact.

## Local tooling honesty note

`golangci-lint` and cosign may be absent locally. Formatting/vet use the
documented Makefile fallback; `make release`, `make vuln`, and `make sbom`
select Go 1.25.14 and acquire exact pinned Go tool versions through the public
Go proxy and checksum database. They fail closed if acquisition or validation
fails. A local SBOM PASS does not imply a tag-triggered provenance or
publication PASS.
Evidence is recorded only at the boundary where the command actually ran.
