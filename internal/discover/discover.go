// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package discover finds receivers on the local network with mDNS/DNS-SD
// (DISC-1 to DISC-5). The mDNS library is used only behind the Advertiser
// and Browser interfaces, so it can be replaced without touching callers.
package discover

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/OWNER/transporter/internal/code"
)

// Service is the DNS-SD service type (DISC-1). It is a wire constant.
const Service = "_transporter._tcp"

// DefaultTimeout is how long the sender looks for a receiver (DISC-3).
const DefaultTimeout = 5 * time.Second

// TagKey is the TXT record key holding the hex discovery tag.
const TagKey = "tag"

// ErrNotFound means no receiver with the right tag answered in time.
var ErrNotFound = errors.New("no matching receiver found on the local network")

// Advertiser announces a receiver.
type Advertiser interface {
	// Advertise announces port with the discovery tag until ctx is done
	// or Close is called. The code itself is never advertised (CODE-7).
	Advertise(ctx context.Context, port int, tag [code.TagSize]byte) (Closer, error)
}

// Closer stops an advertisement.
type Closer interface{ Close() error }

// Browser finds a receiver.
type Browser interface {
	// Find returns "host:port" of a receiver advertising tag.
	Find(ctx context.Context, tag [code.TagSize]byte, timeout time.Duration) (string, error)
}

// TagText encodes a tag for the TXT record.
func TagText(tag [code.TagSize]byte) string { return TagKey + "=" + hex.EncodeToString(tag[:]) }
