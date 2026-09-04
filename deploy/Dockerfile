# AegisMesh container image.
#
# Build:   docker build -t aegismesh:local -f deploy/Dockerfile .
# Run:     see deploy/compose/docker-compose.yaml
#
# Security posture:
#   - Multi-stage; final image contains only the static binary and CA certs.
#   - Runs as an unprivileged user (uid 10001), no shell, no package manager.
#   - No secrets baked in; configuration is mounted at runtime.
#   - CGO_ENABLED=0 for a fully static binary (works on distroless/scratch).

FROM golang:1.26.8-alpine@sha256:34efdd6036c92e155c8b0162a5da7626586b612ea636590035602c970eece564 AS build
WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN GOTOOLCHAIN=local go mod download && GOTOOLCHAIN=local go mod verify

COPY cmd/ cmd/
COPY internal/ internal/
# No .git context in image builds; stamp an explicit version rather than a
# misleading pseudo-version. Release pipelines override via --build-arg.
ARG VERSION=container
RUN GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X github.com/metaforismo/aegismesh/internal/version.Version=${VERSION}" \
    -o /out/aegismesh ./cmd/aegismesh

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="AegisMesh" \
      org.opencontainers.image.description="Local-first deception, detection, and evidence platform" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/metaforismo/aegismesh"

COPY --from=build /out/aegismesh /aegismesh

# Unprivileged runtime identity; data dir is expected as a volume mount.
USER 10001:10001
WORKDIR /workspace
VOLUME ["/workspace"]

ENTRYPOINT ["/aegismesh"]
