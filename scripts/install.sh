#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright 2026 Ned McHugh
#
# Builds Transporter for this machine's OS and architecture and installs it
# as /usr/local/bin/transporter (docs/DECISIONS.md D-9.12).
#
# The build runs as the invoking user. Root is used for one step only: the
# copy into /usr/local/bin, through sudo (or doas). The script checks that
# it can get root before it builds anything, so a missing permission fails
# in seconds rather than after the build.
#
# Usage: scripts/install.sh [--docker | --local]
#   --docker  build inside Docker with scripts/docker-build.sh (default);
#             needs only a Docker engine
#   --local   build with the Go toolchain and make on this machine
#
# Environment: DOCKER (default: docker) and GO (default: go) name the
# tools; VERSION overrides the version stamped into the binary.
set -eu

TARGET=/usr/local/bin/transporter

die() { echo "install: $*" >&2; exit 1; }

usage() {
	sed -n 's/^# \{0,1\}//; /^Usage:/,/^$/p' "$0" | sed '$d'
}

mode=docker
for arg in "$@"; do
	case $arg in
	--docker) mode=docker ;;
	--local) mode=local ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument '$arg'" ;;
	esac
done

cd "$(dirname "$0")/.."

# 1. The platform. Only systems with /usr/local/bin are supported.
case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
MINGW* | MSYS* | CYGWIN*) die "Windows has no /usr/local/bin; run scripts/docker-build.sh and put transporter-windows-*.exe on your PATH." ;;
*) die "unsupported operating system '$(uname -s)'." ;;
esac
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture '$(uname -m)'; supported are amd64 and arm64." ;;
esac
echo "install: platform $os/$arch, mode $mode"

# 2. Root for the copy, checked before building. Run as root under sudo or
# doas, the build would run elevated too (and leave root-owned files in
# the checkout), so that is refused. A plain root shell (for example in a
# container) needs no elevation.
if [ "$(id -u)" -eq 0 ]; then
	invoker=${SUDO_USER:-${DOAS_USER:-}}
	if [ -n "$invoker" ] && [ "$invoker" != root ]; then
		die "run this script as $invoker, without sudo or doas: it builds as you and asks for root only to copy the binary into $(dirname "$TARGET")."
	fi
	elevate=
elif command -v sudo >/dev/null 2>&1; then
	elevate=sudo
	echo "install: root is needed to write $TARGET; checking sudo (it may ask for your password)"
	sudo -v || die "this user cannot use sudo, which is needed to write $TARGET."
elif command -v doas >/dev/null 2>&1; then
	elevate=doas
	echo "install: root is needed to write $TARGET; checking doas (it may ask for your password)"
	doas true || die "this user cannot use doas, which is needed to write $TARGET."
else
	die "root is needed to write $TARGET, and neither sudo nor doas is installed. Run this script as root, or install the binary by hand."
fi

# 3. The build, as the invoking user.
case $mode in
docker)
	# docker-build.sh checks that the engine is installed and reachable.
	scripts/docker-build.sh dist/docker
	bin=dist/docker/transporter-$os-$arch
	[ -f "$bin" ] || die "the Docker build did not produce $bin."
	# Check the binary against the build's checksum list.
	if command -v sha256sum >/dev/null 2>&1; then
		sum() { sha256sum "$1"; }
	elif command -v shasum >/dev/null 2>&1; then
		sum() { shasum -a 256 "$1"; }
	else
		die "neither sha256sum nor shasum is installed, so $bin cannot be checked."
	fi
	want=$(awk -v f="transporter-$os-$arch" '$2 == f || $2 == "*" f { print $1 }' dist/docker/SHA256SUMS)
	got=$(sum "$bin" | awk '{ print $1 }')
	if [ -z "$want" ] || [ "$want" != "$got" ]; then
		die "checksum mismatch for $bin."
	fi
	;;
local)
	GO=${GO:-go}
	command -v "$GO" >/dev/null 2>&1 ||
		die "'$GO' not found. Install Go 1.26 or newer (https://go.dev/dl/), set GO, or use the default Docker build."
	command -v make >/dev/null 2>&1 ||
		die "'make' not found. Install it, or use the default Docker build."
	# GOOS and GOARCH are set explicitly, so a GOOS or GOARCH left in the
	# environment or in go env cannot produce a binary for another machine.
	if [ -n "${VERSION:-}" ]; then
		GOOS=$os GOARCH=$arch CGO_ENABLED=0 make build GO="$GO" VERSION="$VERSION"
	else
		GOOS=$os GOARCH=$arch CGO_ENABLED=0 make build GO="$GO"
	fi
	bin=bin/transporter
	[ -f "$bin" ] || die "the local build did not produce $bin."
	;;
esac

# The binary must run here before it is installed.
"./$bin" --version >/dev/null 2>&1 || die "$bin does not run on this machine."

# 4. The copy, the only elevated step. install(1) sets the mode and
# replaces an existing file, including one that is currently running.
echo "install: installing $bin as $TARGET"
$elevate mkdir -p "$(dirname "$TARGET")"
$elevate install -m 0755 "$bin" "$TARGET"

echo "install: installed $("$TARGET" --version)"
case :$PATH: in
*:"$(dirname "$TARGET")":*) ;;
*) echo "install: note: $(dirname "$TARGET") is not on your PATH." ;;
esac
