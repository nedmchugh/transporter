// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package progress

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestPlainOutput covers CLI-2: without a terminal, output is periodic plain
// lines with no control characters, even for hostile file names.
func TestPlainOutput(t *testing.T) {
	var buf lockedBuf
	tr := New(&buf, false)
	tr.SetTotals(2, 1000)
	tr.SetCurrent("evil\x1b[2Jname")
	tr.AddBytes(500)
	tr.FileDone()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx, 10*time.Millisecond); close(done) }()
	time.Sleep(60 * time.Millisecond)
	tr.Notef("retrying in %v", time.Second)
	cancel()
	<-done
	out := buf.String()
	if !strings.Contains(out, "progress: ") || !strings.Contains(out, "500 B / 1000 B (50%)") || !strings.Contains(out, "1/2 files") {
		t.Fatalf("output %q", out)
	}
	if !strings.Contains(out, "retrying in 1s\n") {
		t.Fatalf("note missing: %q", out)
	}
	for _, r := range out {
		if r < 32 && r != '\n' {
			t.Fatalf("control character %q in plain output %q", r, out)
		}
	}
}

// TestTTYOutput covers CLI-2 on a terminal: a single rewritten line.
func TestTTYOutput(t *testing.T) {
	var buf lockedBuf
	tr := New(&buf, true)
	tr.SetTotals(1, 10<<20)
	tr.SetCurrent(strings.Repeat("long-name/", 20))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx, 0); close(done) }()
	for range 5 {
		tr.AddBytes(1 << 20)
		time.Sleep(TTYInterval / 2)
	}
	_, _ = tr.Writer().Write([]byte("log line\n"))
	cancel()
	<-done
	out := buf.String()
	if !strings.Contains(out, "\r") || !strings.Contains(out, "\x1b[K") || !strings.Contains(out, "log line\n") {
		t.Fatalf("output %q", out)
	}
	if !strings.Contains(out, "/s") {
		t.Fatalf("no rate: %q", out)
	}
	for _, line := range strings.Split(out, "\r") {
		if len([]rune(line)) > 110 {
			t.Fatalf("line too long: %q", line)
		}
	}
}

func TestSnapshotETA(t *testing.T) {
	tr := New(nil, false)
	tr.SetTotals(1, 1000)
	tr.lastAt = time.Now().Add(-time.Second)
	tr.AddBytes(100)
	s := tr.Snapshot()
	if !s.HaveRate || !s.HaveETA || s.ETA < 5*time.Second || s.ETA > 15*time.Second {
		t.Fatalf("snapshot %+v", s)
	}
	if !strings.Contains(s.Line(), "ETA") {
		t.Fatal(s.Line())
	}
}

func TestNilTracker(t *testing.T) {
	var tr *Tracker
	tr.SetTotals(1, 1)
	tr.AddBytes(1)
	tr.FileDone()
	tr.SetCurrent("x")
	tr.Notef("x")
	tr.Run(context.Background(), 0)
	if tr.Snapshot() != (Snapshot{}) {
		t.Fatal("nil snapshot")
	}
}

func TestFormat(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB", 3 << 40: "3.0 TiB"} {
		if got := Bytes(n); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", n, got, want)
		}
	}
	for d, want := range map[time.Duration]string{-time.Second: "0:00", 59 * time.Second: "0:59", 61 * time.Second: "1:01", 3723 * time.Second: "1:02:03"} {
		if got := Duration(d); got != want {
			t.Errorf("Duration(%v) = %q, want %q", d, got, want)
		}
	}
}
