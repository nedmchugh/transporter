// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/discover"
)

// TestDiscoveryMessages covers DISC-3 and DISC-7: the timeout in the
// message adds up the enabled methods, and the hint names the usual cause
// of each.
func TestDiscoveryMessages(t *testing.T) {
	both := discovery{mdns: true, sweep: true, sweepPort: 29873}
	if got := discoveryTimeout(both); got != 8*time.Second {
		t.Fatalf("timeout %v", got)
	}
	if got := discoveryTimeout(discovery{sweep: true}); got != discover.SweepTimeout {
		t.Fatalf("sweep-only timeout %v", got)
	}
	h := discoveryHint(both)
	for _, want := range []string{"--to HOST:PORT", "mDNS is often blocked", "UDP port 29873"} {
		if !strings.Contains(h, want) {
			t.Errorf("hint lacks %q: %s", want, h)
		}
	}
	if h := discoveryHint(discovery{mdns: true}); strings.Contains(h, "sweep") {
		t.Errorf("mDNS-only hint mentions the sweep: %s", h)
	}
	if h := discoveryHint(discovery{sweep: true, sweepPort: 4001}); strings.Contains(h, "mDNS") || !strings.Contains(h, "UDP port 4001") {
		t.Errorf("sweep-only hint: %s", h)
	}

	if got := reason(discover.ErrNotFound); got != "no answer" {
		t.Errorf("reason %q", got)
	}
	if got := reason(fmt.Errorf("%w: %w", discover.ErrNotFound, errors.New("no route"))); got != "no answer (no route)" {
		t.Errorf("reason %q", got)
	}
	if !errors.Is(notFound("x"), discover.ErrNotFound) {
		t.Error("notFound does not match ErrNotFound")
	}
}
