# Makefile for Transporter. CI (.github/workflows/ci.yml) calls these targets,
# so local runs and CI perform the same checks (CI-7).

GO            ?= go
GOBIN         := $(shell $(GO) env GOPATH)/bin
BIN           := bin/transporter
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS       := -s -w -X github.com/nedmchugh/transporter/internal/meta.Version=$(VERSION)

# Pinned tool versions (see docs/DECISIONS.md, section 1.7).
GOLANGCI_LINT_VERSION := v2.15.0
GOLANGCI_LINT         ?= $(GOBIN)/golangci-lint
GO_LICENSES           := $(GO) run github.com/google/go-licenses/v2@v2.0.1
GOVULNCHECK           := $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0
# Markdown lint runs from the upstream container image by default, so no
# local Node install is needed. The image is pinned by digest (verified by
# pulling the v0.24.0 tag on 2026-11-11), matching the version CI's action
# uses. Set MARKDOWNLINT to use a different command instead, e.g.
#   make docs-check MARKDOWNLINT=markdownlint-cli2
DOCKER                ?= docker
MARKDOWNLINT_IMAGE    := docker.io/davidanson/markdownlint-cli2:v0.24.0@sha256:70ead7c0352d22d04bbe612cd96b54ec591538d8f4626cafe391bb2ecf3639ca
MARKDOWNLINT          ?=
LYCHEE                ?= lychee

# LIC-3 allowlist, as SPDX identifiers understood by go-licenses.
ALLOWED_LICENSES := MIT,BSD-2-Clause,BSD-3-Clause,ISC,Apache-2.0,MPL-2.0,0BSD,Unlicense,CC0-1.0

# Coverage policy (docs/testing.md): statement coverage over internal/...,
# excluding the test-support package internal/testutil.
COVER_MIN  ?= 85
COVER_PKGS := $(shell $(GO) list ./internal/... | grep -v /internal/testutil | paste -sd, -)

FUZZTIME ?= 30s
CROSS    := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build build-cross docker-build test test-short e2e fuzz lint cover tidy tidy-check \
        vuln docs-check license-check third-party ci clean

all: build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/transporter

# Cross-compiles every platform inside Docker into dist/docker/, so only a
# Docker engine is needed (scripts/docker-build.sh, Dockerfile).
docker-build:
	scripts/docker-build.sh

build-cross:
	@set -e; for p in $(CROSS); do \
		echo "build $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} CGO_ENABLED=0 $(GO) build -trimpath -o /dev/null ./cmd/transporter; \
		GOOS=$${p%/*} GOARCH=$${p#*/} CGO_ENABLED=0 $(GO) vet ./...; \
	done

test:
	$(GO) test -race -shuffle=on ./...

test-short:
	$(GO) test -race -shuffle=on -short ./...

# End-to-end tests build the real binary and run it as subprocesses (TEST-8).
e2e:
	$(GO) test -tags e2e -race -shuffle=on -count=1 -timeout 30m ./test/e2e/...

# Runs every fuzz target for FUZZTIME (TEST-4). CI's fuzz-smoke job uses 30s.
fuzz:
	@set -e; for pkg in $$($(GO) list ./...); do \
		for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
			echo "fuzz $$pkg $$f ($(FUZZTIME))"; \
			$(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg; \
		done; \
	done

lint:
	@out=$$(find . -name '*.go' -not -path './obsolete/*' -not -path './.git/*' -print0 | xargs -0 gofmt -l); \
		if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	$(GOLANGCI_LINT) run ./...

cover:
	$(GO) test -race -shuffle=on -covermode=atomic -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out ./...
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
		echo "internal/... statement coverage: $$total% (minimum $(COVER_MIN)%)"; \
		awk -v t=$$total -v m=$(COVER_MIN) 'BEGIN { exit (t+0 >= m+0) ? 0 : 1 }' || \
		{ echo "coverage below $(COVER_MIN)%"; exit 1; }

tidy:
	$(GO) mod tidy

# Fails if go.mod/go.sum are not tidy or the module cache does not verify.
tidy-check:
	$(GO) mod tidy -diff
	$(GO) mod verify

vuln:
	$(GOVULNCHECK) ./...

# Requirements-to-tests table check (TEST-1), Markdown lint and link
# check. Outside CI, missing tools are skipped with a
# note; in CI (CI=true) they are required.
docs-check:
	$(GO) run ./tools/reqcheck .
	@# The container gets the repository read-only and no network. SELinux
	@# labels are disabled for this container rather than relabelling the
	@# checkout (:Z would change labels on the user's files).
	@if [ -n "$(MARKDOWNLINT)" ]; then \
		$(MARKDOWNLINT) '**/*.md' '#obsolete' '#node_modules'; \
	elif command -v $(DOCKER) >/dev/null 2>&1; then \
		$(DOCKER) run --rm --network none --security-opt label=disable \
			--user "$$(id -u):$$(id -g)" -v "$(CURDIR):/workdir:ro" \
			$(MARKDOWNLINT_IMAGE) '**/*.md' '#obsolete' '#node_modules'; \
	elif [ "$$CI" = "true" ]; then echo "docs-check: $(DOCKER) not installed"; exit 1; \
	else echo "docs-check: $(DOCKER) not installed, skipping Markdown lint"; fi
	@if command -v $(LYCHEE) >/dev/null 2>&1 || [ -x $(GOBIN)/lychee ]; then \
		L=$$(command -v $(LYCHEE) || echo $(GOBIN)/lychee); \
		$$L --offline --no-progress --include-fragments --exclude-path obsolete '**/*.md'; \
	elif [ "$$CI" = "true" ]; then echo "$(LYCHEE) not installed"; exit 1; \
	else echo "docs-check: $(LYCHEE) not installed, skipping link check"; fi

# LIC-2/LIC-4/LIC-6: SPDX headers, dependency license allowlist, and that
# every dependency of the binary is listed in THIRD_PARTY_LICENSES.
license-check:
	$(GO) run ./tools/spdxcheck .
	$(GO_LICENSES) check ./cmd/transporter --allowed_licenses=$(ALLOWED_LICENSES)
	@scripts/gen-third-party.sh | diff -u THIRD_PARTY_LICENSES - >/dev/null || \
		{ echo "THIRD_PARTY_LICENSES is out of date: run 'make third-party'"; exit 1; }

third-party:
	scripts/gen-third-party.sh > THIRD_PARTY_LICENSES

# Everything CI checks, in one command (CI-7).
ci: lint license-check tidy-check cover e2e build-cross vuln docs-check
	$(MAKE) fuzz FUZZTIME=$(FUZZTIME)

clean:
	rm -rf bin dist coverage.out coverage.html
