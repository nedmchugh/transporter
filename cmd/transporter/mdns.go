// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"log/slog"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/discover"
)

// advertise announces the receiver via mDNS until ctx ends; the returned
// function stops it. Failure only disables discovery (the sender can still
// use --to), so it is logged as a warning, not fatal.
func advertise(ctx context.Context, port int, tag [code.TagSize]byte, log *slog.Logger) func() {
	var adv discover.Advertiser = discover.MDNS{Logger: log}
	c, err := adv.Advertise(ctx, port, tag)
	if err != nil {
		log.Warn("mDNS advertisement failed; senders must use --to", "err", err)
		return func() {}
	}
	return func() { _ = c.Close() }
}

// browse finds a receiver advertising tag (DISC-2, DISC-3).
func browse(ctx context.Context, tag [code.TagSize]byte, log *slog.Logger) (string, error) {
	var b discover.Browser = discover.MDNS{Logger: log}
	return b.Find(ctx, tag, discover.DefaultTimeout)
}
