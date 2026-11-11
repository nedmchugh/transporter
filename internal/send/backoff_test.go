// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package send

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/testutil"
)

// TestBackoffSchedule covers REL-1 and TEST-2: base 1 s, factor 2, cap 30 s,
// with full jitter in [0, ceiling).
func TestBackoffSchedule(t *testing.T) {
	b := DefaultBackoff()
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if got := b.Ceiling(i); got != w*time.Second {
			t.Errorf("ceiling(%d) = %v, want %v", i, got, w*time.Second)
		}
	}
	if b.Ceiling(10000) != 30*time.Second {
		t.Fatal("ceiling overflow not capped")
	}
	for _, r := range []float64{0, 0.25, 0.999999} {
		b.Rand = func() float64 { return r }
		for i := range 8 {
			d := b.Delay(i)
			if d < 0 || d >= b.Ceiling(i) {
				t.Fatalf("delay %v outside [0, %v)", d, b.Ceiling(i))
			}
			if want := time.Duration(r * float64(b.Ceiling(i))); d != want {
				t.Fatalf("delay %v, want %v", d, want)
			}
		}
	}
	// With the real source, samples spread over the whole range.
	b.Rand = nil
	var lo, hi bool
	for range 1000 {
		d := b.Delay(3)
		if d < 0 || d >= 8*time.Second {
			t.Fatalf("delay %v out of range", d)
		}
		lo = lo || d < 2*time.Second
		hi = hi || d > 6*time.Second
	}
	if !lo || !hi {
		t.Fatal("jitter does not cover the range")
	}
}

func TestRealSleep(t *testing.T) {
	if err := RealSleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RealSleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestRetryBudget covers REL-1 and REL-4: transient failures are retried
// with backoff until the budget is spent (exit 4); --retry-timeout 0 means
// no retry; the backoff sequence grows between failures.
func TestRetryBudget(t *testing.T) {
	testutil.CheckLeaks(t)
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f": "x"})
	refused := func(context.Context, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	}
	var mu sync.Mutex
	var sleeps []time.Duration
	sleeper := func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return RealSleep(ctx, time.Millisecond)
	}
	start := time.Now()
	sum, err := runSend(t, "127.0.0.1:1", []string{filepath.Join(src, "f")}, func(o *Options) {
		o.Dial = refused
		o.RetryTimeout = 150 * time.Millisecond
		o.Sleep = sleeper
		o.Backoff = &Backoff{Base: time.Millisecond, Factor: 2, Cap: 8 * time.Millisecond, Rand: func() float64 { return 0.999 }}
	})
	if fail.KindOf(err) != fail.Network || fail.KindOf(err).ExitCode() != 4 {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) < 150*time.Millisecond || sum.Retries == 0 || sum.Retries != len(sleeps) {
		t.Fatalf("retries %d, sleeps %d", sum.Retries, len(sleeps))
	}
	for i := 1; i < min(4, len(sleeps)); i++ {
		if sleeps[i] <= sleeps[i-1] {
			t.Fatalf("backoff not growing: %v", sleeps)
		}
	}
	for _, d := range sleeps {
		if d > 8*time.Millisecond {
			t.Fatalf("delay %v above cap", d)
		}
	}

	sum, err = runSend(t, "127.0.0.1:1", []string{filepath.Join(src, "f")}, func(o *Options) {
		o.Dial = refused
		o.RetryTimeout = 0
	})
	if fail.KindOf(err) != fail.Network || sum.Retries != 0 {
		t.Fatalf("no-retry: %v, %d retries", err, sum.Retries)
	}
	if fail.HintOf(err) == "" {
		t.Fatal("no hint for disabled retries")
	}
}

// TestRetryInterrupted covers REL-7 for the sender: cancelling during a
// backoff wait reports an interruption (exit 130).
func TestRetryInterrupted(t *testing.T) {
	testutil.CheckLeaks(t)
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f": "x"})
	list := mustWalk(t, filepath.Join(src, "f"))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := Run(ctx, Options{
		List: list, Addr: "127.0.0.1:1", Pairer: testPairer(t, testCode), RetryTimeout: time.Minute,
		Dial: func(context.Context, string) (net.Conn, error) { return nil, errors.New("refused") },
	})
	if fail.KindOf(err) != fail.Interrupted || fail.KindOf(err).ExitCode() != 130 {
		t.Fatalf("got %v", err)
	}
}
