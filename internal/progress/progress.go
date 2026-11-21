// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package progress tracks transfer progress and renders it to stderr
// (CLI-2): on a terminal as a single updating status line, otherwise as
// periodic plain lines with no control characters.
package progress

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nedmchugh/transporter/internal/proto"
)

// Default render intervals.
const (
	TTYInterval   = 200 * time.Millisecond
	PlainInterval = 5 * time.Second
)

// Tracker accumulates progress. All methods are safe for concurrent use and
// do nothing on a nil *Tracker, so callers need not check.
type Tracker struct {
	totalBytes atomic.Int64
	doneBytes  atomic.Int64
	totalFiles atomic.Int64
	doneFiles  atomic.Int64
	current    atomic.Pointer[string]
	start      time.Time

	mu       sync.Mutex // guards output and rate state
	w        io.Writer
	tty      bool
	lineLen  int
	rate     float64 // bytes/s, smoothed
	lastAt   time.Time
	lastDone int64
}

// New returns a Tracker writing to w. tty selects the terminal style.
func New(w io.Writer, tty bool) *Tracker {
	now := time.Now()
	return &Tracker{w: w, tty: tty, start: now, lastAt: now}
}

// SetTotals sets the number of files and bytes expected.
func (t *Tracker) SetTotals(files, bytes int64) {
	if t == nil {
		return
	}
	t.totalFiles.Store(files)
	t.totalBytes.Store(bytes)
}

// AddBytes records n bytes transferred.
func (t *Tracker) AddBytes(n int64) {
	if t != nil {
		t.doneBytes.Add(n)
	}
}

// AddPresent records n bytes that were already in place: a file skipped as
// already complete, or the prefix a resumed file continues from. They count
// as done but not toward the rate, so the rate and ETA reflect bytes that
// actually move; adding a batch of complete files at once would otherwise
// show a huge rate.
func (t *Tracker) AddPresent(n int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.doneBytes.Add(n)
	t.lastDone += n
}

// Restart zeroes the done counts at the start of a connection. Each
// connection accounts for every file again (as present, resumed or sent),
// so without it a reconnect counted files finished on an earlier
// connection, and resumed prefixes, twice. Totals, the start time and the
// rate are kept.
func (t *Tracker) Restart() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.doneBytes.Store(0)
	t.doneFiles.Store(0)
	t.lastDone = 0
}

// FileDone records one finished file.
func (t *Tracker) FileDone() {
	if t != nil {
		t.doneFiles.Add(1)
	}
}

// SetCurrent sets the name of the file being transferred.
func (t *Tracker) SetCurrent(name string) {
	if t != nil {
		t.current.Store(&name)
	}
}

// Notef prints a message line (for example a retry notice) without
// corrupting the status line.
func (t *Tracker) Notef(format string, args ...any) {
	if t == nil || t.w == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clearLocked()
	fmt.Fprintf(t.w, format+"\n", args...)
}

// Writer returns an io.Writer for log output that shares the terminal with
// the status line: each write first clears the line, so log messages and
// progress never interleave mid-line.
func (t *Tracker) Writer() io.Writer { return lineWriter{t} }

type lineWriter struct{ t *Tracker }

func (w lineWriter) Write(p []byte) (int, error) {
	w.t.mu.Lock()
	defer w.t.mu.Unlock()
	w.t.clearLocked()
	return w.t.w.Write(p)
}

// Snapshot is a point-in-time view of progress.
type Snapshot struct {
	Current               string
	DoneBytes, TotalBytes int64
	DoneFiles, TotalFiles int64
	Rate                  float64 // bytes per second
	ETA                   time.Duration
	Elapsed               time.Duration
	HaveRate, HaveETA     bool
}

// Snapshot returns the current progress, updating the smoothed rate.
func (t *Tracker) Snapshot() Snapshot {
	if t == nil {
		return Snapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked(time.Now())
}

func (t *Tracker) snapshotLocked(now time.Time) Snapshot {
	done := t.doneBytes.Load()
	if dt := now.Sub(t.lastAt).Seconds(); dt >= 0.1 {
		inst := float64(done-t.lastDone) / dt
		if t.rate == 0 {
			t.rate = inst
		} else {
			// Exponential smoothing keeps the display steady when chunk
			// timing is bursty.
			t.rate = 0.7*t.rate + 0.3*inst
		}
		t.lastAt, t.lastDone = now, done
	}
	s := Snapshot{
		DoneBytes: done, TotalBytes: t.totalBytes.Load(),
		DoneFiles: t.doneFiles.Load(), TotalFiles: t.totalFiles.Load(),
		Rate: t.rate, HaveRate: t.rate > 0, Elapsed: now.Sub(t.start),
	}
	if c := t.current.Load(); c != nil {
		s.Current = *c
	}
	if s.HaveRate && s.TotalBytes > s.DoneBytes {
		s.ETA = time.Duration(float64(s.TotalBytes-s.DoneBytes) / s.Rate * float64(time.Second))
		s.HaveETA = true
	}
	return s
}

// Line formats s as one status line.
func (s Snapshot) Line() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s / %s", Bytes(s.DoneBytes), Bytes(s.TotalBytes))
	if s.TotalBytes > 0 {
		fmt.Fprintf(&sb, " (%d%%)", s.DoneBytes*100/s.TotalBytes)
	}
	fmt.Fprintf(&sb, ", %d/%d files", s.DoneFiles, s.TotalFiles)
	if s.HaveRate {
		fmt.Fprintf(&sb, ", %s/s", Bytes(int64(s.Rate)))
	}
	if s.HaveETA {
		fmt.Fprintf(&sb, ", ETA %s", Duration(s.ETA))
	}
	if s.Current != "" {
		fmt.Fprintf(&sb, ", %s", proto.Printable(s.Current))
	}
	return sb.String()
}

// Run renders progress every interval (or the default for the output
// style) until ctx is done, then clears the status line.
func (t *Tracker) Run(ctx context.Context, interval time.Duration) {
	if t == nil || t.w == nil {
		return
	}
	if interval <= 0 {
		interval = PlainInterval
		if t.tty {
			interval = TTYInterval
		}
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.clearLocked()
			t.mu.Unlock()
			return
		case now := <-tick.C:
			t.render(now)
		}
	}
}

func (t *Tracker) render(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	line := t.snapshotLocked(now).Line()
	if !t.tty {
		fmt.Fprintln(t.w, "progress: "+line)
		return
	}
	// Truncate so the line never wraps (a wrapped line cannot be
	// rewritten with \r). 100 columns is a conservative width.
	if r := []rune(line); len(r) > 100 {
		line = string(r[:99]) + "…"
	}
	fmt.Fprintf(t.w, "\r%s\x1b[K", line)
	t.lineLen = len(line)
}

func (t *Tracker) clearLocked() {
	if t.tty && t.lineLen > 0 {
		fmt.Fprint(t.w, "\r\x1b[K")
		t.lineLen = 0
	}
}

// Bytes formats n with binary units.
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Duration formats d as h:mm:ss or m:ss.
func Duration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d.Round(time.Second) / time.Second)
	h, m, sec := s/3600, (s/60)%60, s%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, sec)
	}
	return fmt.Sprintf("%d:%02d", m, sec)
}
