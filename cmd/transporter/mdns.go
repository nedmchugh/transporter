// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"log/slog"

	"github.com/OWNER/transporter/internal/code"
	"github.com/OWNER/transporter/internal/discover"
)

// advertise announces the receiver via mDNS until ctx ends; the returned
// function stops it. Failures only disable discovery (the sender can still
// use --to), so they are logged, not fatal.
func advertise(ctx context.Context, port int, tag [code.TagSize]byte, log *slog.Logger) func() {
	return func() {}
}

// browse finds a receiver advertising tag (DISC-2).
func browse(ctx context.Context, tag [code.TagSize]byte) (string, error) {
	return "", discover.ErrNotFound
}
