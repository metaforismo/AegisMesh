# Release process

Status for v0.1.0: the pipeline below is defined and CI-enforced where the
environment allows. Steps that require tools not present on the release
operator's machine are marked honestly; CI performs them so local installs
are not required.

## Versioning

Semantic versioning, `vMAJOR.MINOR.PATCH`. Pre-releases may use `-rc.N`.
Pre-1.0, breaking changes bump MINOR and are called out in the changelog.

The config schema (`aegismesh.io/v1alpha1`) gates compatibility: while a
release supports only v1alpha1 configs, MINOR bumps must accept every config
the previous MINOR accepted. Schema fields are removed only across a MINOR
bump pre-1.0 (MAJOR after), with a changelog warning one release ahead when
feasible.

## Cutting a release

1. Ensure CI is green on master (fmt, vet, tests with race, fuzz seeds,
   govulncheck, license/secret scans).
2. Update CHANGELOG.md: new section with date, changes grouped
   Added/Changed/Fixed/Security.
3. Tag: `git tag -s vX.Y.Z -m "AegisMesh vX.Y.Z" && git push origin vX.Y.Z`.
   The `release` workflow builds linux/darwin × amd64/arm64 static binaries,
   generates `SHA256SUMS.txt`, a CycloneDX SBOM per platform, and SLSA build
   provenance attestations, then publishes a GitHub release with all of it.
4. Local equivalent: `make release VERSION=vX.Y.Z` produces binaries under
   `dist/` (`-trimpath`, version stamped from git describe) — CI remains the
   source of attestations and published artifacts.

## Reproducibility contract

- Builds pin Go via go.mod; CI uses the same major.minor as go.mod.
- No build step fetches remote content at compile time.
- Binaries embed version metadata via ldflags; `aegismesh version` prints it.

## Supply-chain properties (and their current limits)

| property | how | status |
|---|---|---|
| Builds | `CGO_ENABLED=0 -trimpath -ldflags "-s -w"`; version stamped from tag | done |
| Checksums | SHA256SUMS.txt over binaries + SBOMs | done |
| SBOM | anchore/sbom-action, CycloneDX JSON per artifact | done (CI) |
| Provenance | actions/attest-build-provenance (SLSA) | done (CI); verify with `gh attestation verify` |
| Binary signing | keyless cosign signing is **planned**; attestations currently provide tamper-evidence | roadmap — do not claim signed releases yet |
| Actions pinned by SHA | enforced in both workflows | done |

## Verifying a download locally

    sha256sum --check --ignore-missing SHA256SUMS.txt
    gh attestation verify ./aegismesh-linux-amd64 -R metaforismo/aegismesh

## Local tooling honesty note

golangci-lint, govulncheck, syft/sbom-tool, trivy, and cosign were **not
installed** in the original development environment; local runs recorded
BLOCKED entries in docs/verification.md with fallbacks (gofmt+vet, scripted
license/secret scans). CI runs govulncheck and SBOM generation on every
push/tag, so evidence accumulates there rather than being fabricated
locally.
