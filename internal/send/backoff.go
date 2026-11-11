// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package send

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// Backoff parameters (REL-1).
const (
	DefaultBackoffBase   = time.Second
	DefaultBackoffFactor = 2.0
	DefaultBackoffCap    = 30 * time.Second
	// DefaultRetryTimeout is the retry budget (SND-3, REL-1).
	DefaultRetryTimeout = 10 * time.Minute
)

// Backoff computes reconnect delays: exponential backoff with full jitter
// (REL-1). The delay before retry n (0-based) is uniform in
// [0, min(Cap, Base*Factor^n)).
type Backoff struct {
	Base   time.Duration
	Factor float64
	Cap    time.Duration
	// Rand returns a float in [0, 1). Nil uses math/rand/v2; jitter does
	// not need a cryptographic source.
	Rand func() float64
}

// DefaultBackoff returns the REL-1 schedule.
func DefaultBackoff() Backoff {
	return Backoff{Base: DefaultBackoffBase, Factor: DefaultBackoffFactor, Cap: DefaultBackoffCap}
}

// Ceiling returns the upper bound of the delay before retry n.
func (b Backoff) Ceiling(n int) time.Duration {
	c := float64(b.Base) * math.Pow(b.Factor, float64(n))
	if c > float64(b.Cap) || math.IsInf(c, 0) || math.IsNaN(c) {
		return b.Cap
	}
	return time.Duration(c)
}

// Delay returns the jittered delay before retry n.
func (b Backoff) Delay(n int) time.Duration {
	r := b.Rand
	if r == nil {
		r = rand.Float64
	}
	return time.Duration(r() * float64(b.Ceiling(n)))
}

// Sleeper waits for d or until ctx is done. Tests inject a fake.
type Sleeper func(ctx context.Context, d time.Duration) error

// RealSleep is the production Sleeper.
func RealSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
