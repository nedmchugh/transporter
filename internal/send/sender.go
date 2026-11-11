// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package send implements the sending side: it connects to the receiver
// (the sender is always the initiator, SND-7), sends the manifest, streams
// the files the receiver needs with bounded pipelining (XFER-6), and
// reconnects with backoff after transient failures (REL-1, REL-2).
package send

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/manifest"
	"github.com/nedmchugh/transporter/internal/pairing"
	"github.com/nedmchugh/transporter/internal/progress"
	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/secure"
)

// Defaults.
const (
	// DialTimeout bounds one TCP connection attempt.
	DialTimeout = 10 * time.Second
	// ProgressBytes is how much file data one connection must send to
	// count as forward progress, besides receiving an ACK (D-5.14).
	ProgressBytes = 1 << 20
)

// Options configures a send.
type Options struct {
	// List is the walked manifest (manifest.Walk).
	List *manifest.List
	// Addr is the receiver's host:port. If empty, Resolve is used.
	Addr string
	// Resolve finds the receiver's address (mDNS discovery).
	Resolve func(ctx context.Context) (string, error)
	// Pairer supplies the handshake secret.
	Pairer pairing.Pairer
	// Verify requests content-hash comparison (RES-2).
	Verify bool
	// RetryTimeout is the retry budget; zero disables retries (REL-1).
	RetryTimeout time.Duration
	// Dial opens a connection. Nil uses net.Dialer with TCP keepalive.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Link overrides heartbeat and dead-connection timings (tests).
	Link proto.LinkConfig
	// Backoff overrides the reconnect schedule (tests).
	Backoff *Backoff
	// Sleep overrides waiting between attempts (tests).
	Sleep Sleeper
	// Logger receives diagnostics. Nil discards them.
	Logger *slog.Logger
	// Progress, if set, is updated as data is sent.
	Progress *progress.Tracker
}

// FileIssue is a per-file problem in the summary.
type FileIssue struct {
	Path string
	Msg  string
}

// Summary describes the outcome of a send (CLI-3).
type Summary struct {
	Transferred int
	Bytes       int64
	Skipped     int
	Conflicts   []string
	Errors      []FileIssue
	Integrity   []string
	Warnings    []string
	// NotTransferred lists files with no outcome yet, for example after an
	// interruption (REL-7).
	NotTransferred []string
	Retries        int
	Elapsed        time.Duration
	// Receiver holds the receiver's totals from its final DONE (PROTO-7),
	// or nil if the session did not complete.
	Receiver *proto.Done
}

// Kind returns the failure kind implied by per-file outcomes (CLI-8).
func (s *Summary) Kind() fail.Kind {
	switch {
	case len(s.Integrity) > 0:
		return fail.Integrity
	case len(s.Conflicts) > 0 || len(s.Errors) > 0:
		return fail.Partial
	}
	return fail.None
}

type outcome uint8

const (
	oNone outcome = iota
	oTransferred
	oSkipped
	oConflict
	oError
	oIntegrity
)

// fileState is per-session state for one entry. It survives reconnects.
type fileState struct {
	outcome  outcome
	msg      string // for oError
	attempts int    // hash mismatches seen (XFER-4)
}

// sender holds session state across connections.
type sender struct {
	opts      Options
	log       *slog.Logger
	items     []manifest.Item
	sessionID [proto.SessionIDSize]byte

	// connected records whether any connection got past the handshake,
	// which changes the most useful hint on failure (CLI-4).
	connected bool

	// resolved caches the discovered address: reconnects go to the same
	// receiver without repeating discovery, which could fail transiently.
	resolved string

	mu    sync.Mutex
	files []fileState
	bytes int64
}

// Run performs the transfer. It returns a summary even on failure; the
// error is classified with package fail.
func Run(ctx context.Context, opts Options) (*Summary, error) {
	start := time.Now()
	s := &sender{opts: opts, log: opts.Logger}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if opts.List == nil || opts.Pairer == nil {
		return nil, errors.New("send: List and Pairer are required")
	}
	s.items = opts.List.Items
	s.files = make([]fileState, len(s.items))
	if _, err := rand.Read(s.sessionID[:]); err != nil {
		return nil, fmt.Errorf("generating session id: %w", err)
	}
	var files int64
	for _, it := range s.items {
		if it.Type == proto.EntryFile {
			files++
		}
	}
	opts.Progress.SetTotals(files, int64(opts.List.TotalBytes))

	done, retries, err := s.retryLoop(ctx)
	sum := s.summary()
	sum.Retries = retries
	sum.Receiver = done
	sum.Elapsed = time.Since(start)
	return sum, err
}

// retryLoop runs connection attempts until success, a fatal error, or the
// retry budget is spent (REL-1, REL-4, D-5.14).
func (s *sender) retryLoop(ctx context.Context) (*proto.Done, int, error) {
	bo := DefaultBackoff()
	if s.opts.Backoff != nil {
		bo = *s.opts.Backoff
	}
	sleep := s.opts.Sleep
	if sleep == nil {
		sleep = RealSleep
	}
	var (
		failures    int
		retries     int
		streakStart time.Time
	)
	for {
		done, progressed, err := s.attempt(ctx)
		if err == nil {
			return done, retries, nil
		}
		if ctx.Err() != nil {
			return nil, retries, fail.New(fail.Interrupted, "interrupted", "run the same command again to resume; the receiver keeps partial files", nil)
		}
		if !fail.Transient(err) {
			return nil, retries, err
		}
		if progressed {
			failures, streakStart = 0, time.Time{}
		}
		if s.opts.RetryTimeout <= 0 {
			return nil, retries, fail.New(fail.Network, "the connection failed and retries are disabled",
				"remove --retry-timeout 0 to retry automatically", err)
		}
		now := time.Now()
		if streakStart.IsZero() {
			streakStart = now
		}
		left := s.opts.RetryTimeout - now.Sub(streakStart)
		if left <= 0 {
			hint := "check that the receiver is still running and reachable, or raise --retry-timeout"
			if !s.connected {
				hint = "check that the receiver is running and that the address matches one it printed; a firewall may be blocking the port"
			}
			return nil, retries, fail.New(fail.Network,
				fmt.Sprintf("gave up after retrying for %v", s.opts.RetryTimeout.Round(time.Second)), hint, err)
		}
		wait := min(bo.Delay(failures), left)
		failures++
		retries++
		s.opts.Progress.Notef("connection problem: %v; retrying in %.1fs", err, wait.Seconds())
		s.log.Info("retrying", "attempt", retries, "wait", wait, "err", err)
		if err := sleep(ctx, wait); err != nil {
			return nil, retries, fail.New(fail.Interrupted, "interrupted", "run the same command again to resume", nil)
		}
	}
}

func netErr(what string, err error) error {
	if errors.Is(err, proto.ErrMalformed) {
		return fail.New(fail.Protocol, "the receiver sent a malformed message", "", err)
	}
	return fail.New(fail.Network, what, "", err)
}

// attempt makes one connection and runs the session on it. progressed
// reports whether it made forward progress (D-5.14).
func (s *sender) attempt(ctx context.Context) (done *proto.Done, progressed bool, err error) {
	addr := s.opts.Addr
	if addr == "" {
		addr = s.resolved
	}
	if addr == "" {
		if s.opts.Resolve == nil {
			return nil, false, fail.New(fail.Usage, "no receiver address", "use --to HOST:PORT", nil)
		}
		addr, err = s.opts.Resolve(ctx)
		if err != nil {
			return nil, false, err
		}
		s.resolved = addr
	}
	dial := s.opts.Dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: DialTimeout, KeepAlive: 15 * time.Second}
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	raw, err := dial(ctx, addr)
	if err != nil {
		return nil, false, fail.New(fail.Network, "cannot connect to "+addr, "", err)
	}
	sc, err := secure.Client(ctx, raw, s.opts.Pairer)
	if err != nil {
		if errors.Is(err, secure.ErrAuthFailed) {
			return nil, false, fail.New(fail.Auth, "authentication failed",
				"the code may be wrong, or "+addr+" may be a different receiver; check the code the receiver printed", nil)
		}
		return nil, false, fail.New(fail.Network, "connection lost during the handshake", "", err)
	}
	s.connected = true
	link := proto.NewLink(sc, s.opts.Link)
	defer func() { _ = link.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = link.Close() })
	defer stop()
	s.log.Info("connected", "receiver", addr)
	c := &sconn{s: s, link: link, notify: make(chan struct{}, 1)}
	done, err = c.run(ctx)
	return done, c.progressed(), err
}

func (s *sender) setOutcome(i uint32, o outcome, msg string) {
	s.files[i].outcome = o
	s.files[i].msg = msg
}

func (s *sender) summary() *Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := &Summary{Bytes: s.bytes}
	for _, p := range s.opts.List.Problems {
		if p.Kind == manifest.Skipped {
			sum.Warnings = append(sum.Warnings, p.String())
		} else {
			sum.Errors = append(sum.Errors, FileIssue{Path: proto.Printable(p.Local), Msg: p.Msg})
		}
	}
	for i, f := range s.files {
		it := s.items[i]
		switch f.outcome {
		case oTransferred:
			sum.Transferred++
		case oSkipped:
			if it.Type == proto.EntryFile {
				sum.Skipped++
			}
		case oConflict:
			sum.Conflicts = append(sum.Conflicts, it.Path)
		case oError:
			sum.Errors = append(sum.Errors, FileIssue{Path: it.Path, Msg: f.msg})
		case oIntegrity:
			sum.Integrity = append(sum.Integrity, it.Path)
		case oNone:
			if it.Type == proto.EntryFile {
				sum.NotTransferred = append(sum.NotTransferred, it.Path)
			}
		}
	}
	return sum
}

// readPrefix hashes the first n bytes of f (XFER-1: on resume the final hash
// covers the whole file).
func readPrefix(w io.Writer, f io.Reader, n uint64) error {
	k, err := io.CopyN(w, f, int64(n))
	if err == nil && uint64(k) != n {
		err = io.ErrUnexpectedEOF
	}
	return err
}
