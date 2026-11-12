#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright 2026 Ned McHugh
#
# Builds Transporter for Linux, macOS and Windows (amd64 and arm64) inside
# Docker and copies the binaries to an output directory, so nothing but a
# Docker engine is needed on the machine (docs/DECISIONS.md D-9.7).
#
# Usage: scripts/docker-build.sh [OUTPUT_DIR]     (default: dist/docker)
#
# Environment: DOCKER (default: docker) names the engine's CLI;
# VERSION overrides the version stamped into the binaries.
set -eu

cd "$(dirname "$0")/.."
OUT=${1:-dist/docker}
DOCKER=${DOCKER:-docker}
IMAGE=transporter-build:local

die() { echo "docker-build: $*" >&2; exit 1; }

# The engine must be installed and reachable; docker info fails when the
# daemon is stopped or this user may not use it.
command -v "$DOCKER" >/dev/null 2>&1 ||
	die "'$DOCKER' not found. Install Docker (https://docs.docker.com/get-docker/) or set DOCKER."
"$DOCKER" info >/dev/null 2>&1 ||
	die "cannot reach the Docker engine. Start it, and check that this user may use it (for example membership of the docker group)."

# Version from git on the host, when available; the build itself has no .git.
if [ -z "${VERSION:-}" ]; then
	VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
fi

echo "docker-build: building $VERSION"
"$DOCKER" build --target artifacts --build-arg "VERSION=$VERSION" -t "$IMAGE" .

# Copy the files out of a container created (never started) from the
# artifacts image. The image is empty apart from them, so the command given
# to create is a placeholder that never runs.
cid=$("$DOCKER" create "$IMAGE" /none)
trap '"$DOCKER" rm "$cid" >/dev/null 2>&1 || true' EXIT
rm -rf "$OUT"
mkdir -p "$OUT"
"$DOCKER" cp "$cid:/out/." "$OUT/"

# Point at the binary for this machine.
case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
MINGW* | MSYS* | CYGWIN*) os=windows ;;
*) os= ;;
esac
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) arch= ;;
esac
echo "docker-build: binaries are in $OUT/"
ls -l "$OUT"
if [ -n "$os" ] && [ -n "$arch" ]; then
	ext=
	[ "$os" = windows ] && ext=.exe
	echo "docker-build: for this machine use $OUT/transporter-$os-$arch$ext"
fi
