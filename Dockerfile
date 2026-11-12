# SPDX-License-Identifier: MPL-2.0
# Copyright 2026 Ned McHugh
#
# Builds Transporter for every supported platform inside a container, so a
# developer needs only a Docker engine (docs/DECISIONS.md D-9.7). Run it
# through scripts/docker-build.sh, which copies the binaries out to dist/.
#
# The Go image is pinned by digest (pulled 2026-11-12) and matches the
# toolchain line in go.mod. GOTOOLCHAIN=local stops the go command from
# downloading a different toolchain, so the pinned image is what builds.
# The builder runs on the host's own architecture (BUILDPLATFORM): Go
# cross-compiles pure-Go code (CGO_ENABLED=0) to every target without
# emulation.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly

WORKDIR /src

# Download modules in their own layer, so source edits don't refetch them.
# go mod verify checks the downloads against go.sum.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Only what the binary is built from, so edits to docs, tests or tools
# don't invalidate the build cache.
COPY cmd/ cmd/
COPY internal/ internal/
COPY LICENSE NOTICE THIRD_PARTY_LICENSES ./

# VERSION comes from the wrapper script (git describe on the host), since
# .git is not sent into the build.
ARG VERSION=dev
# Same platform list as CROSS in the Makefile.
ARG PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

RUN set -eu; \
    mkdir -p /out; \
    for p in $PLATFORMS; do \
        os=${p%/*}; arch=${p#*/}; ext=; \
        [ "$os" = windows ] && ext=.exe; \
        echo "build $os/$arch"; \
        GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
            -ldflags "-s -w -X github.com/nedmchugh/transporter/internal/meta.Version=$VERSION" \
            -o "/out/transporter-$os-$arch$ext" ./cmd/transporter; \
    done; \
    cp LICENSE NOTICE THIRD_PARTY_LICENSES /out/; \
    cd /out && sha256sum transporter-* > SHA256SUMS

# The artifacts alone, in an empty image the script copies them out of.
FROM scratch AS artifacts
COPY --from=build /out/ /out/
