#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright 2026 Ned McHugh
#
# Prints the release notes for one version: its section of CHANGELOG.md,
# without the version heading, and a link to the full changelog at that
# tag. The release workflow passes the result to GoReleaser
# (--release-notes), so release notes are written once, in the changelog.
# Fails if the version has no section or the section is empty, so a tag
# pushed before the changelog is updated stops the release before it
# builds anything.
#
# Usage: scripts/release-notes.sh [VERSION] [CHANGELOG]
#   VERSION is "0.1.0" or "v0.1.0"; the default is the newest released
#   section (the first after [Unreleased]). CHANGELOG defaults to
#   CHANGELOG.md.
set -eu
version=${1:-}
file=${2:-CHANGELOG.md}
version=${version#v}
if [ -z "$version" ]; then
	version=$(sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' "$file" | head -n 1)
	if [ -z "$version" ]; then
		echo "release-notes: no released version in $file" >&2
		exit 1
	fi
fi
# The section runs from "## [VERSION]" to the next "## [" heading or the
# link references at the end. Leading and trailing blank lines are
# dropped, and runs of blank lines are squeezed to one.
notes=$(awk -v want="## [$version]" '
	index($0, want) == 1 && (length($0) == length(want) || substr($0, length(want) + 1, 1) == " ") { found = 1; next }
	found && (/^## \[/ || /^\[[^]]+\]: /) { exit }
	found {
		if ($0 ~ /^[[:space:]]*$/) { if (started) blank = 1; next }
		if (blank) print ""
		print
		started = 1
		blank = 0
	}
' "$file")
if [ -z "$notes" ]; then
	echo "release-notes: $file has no section, or an empty one, for version $version" >&2
	exit 1
fi
printf '%s\n\nSee [CHANGELOG.md](https://github.com/nedmchugh/transporter/blob/v%s/CHANGELOG.md) for the full history.\n' "$notes" "$version"
