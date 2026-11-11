// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package recv implements the receiving side: it accepts connections,
// authenticates them, serves one session at a time, and writes files into
// the destination directory through os.Root (SEC-9).
//
// The destination directory is the only persisted state (RES-1): partial
// files are kept as NAME.part next to their final name and reused on resume.
package recv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/meta"
	"github.com/nedmchugh/transporter/internal/pairing"
	"github.com/nedmchugh/transporter/internal/progress"
	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/secure"
)

// Defaults (RCV-3, RCV-8, D-5.15).
const (
	DefaultIdleTimeout    = 10 * time.Minute
	DefaultMaxUnauth      = 4
	DefaultFinalizers     = 4
	DefaultLingerAfterEnd = 5 * time.Second
	// abortTimeout bounds how long a final ERROR message may take to send.
	abortTimeout = time.Second
)

// Options configures a Receiver.
type Options struct {
	// Dest is the destination directory. It is created if absent.
	Dest string
	// Pairer supplies the handshake secret.
	Pairer pairing.Pairer
	// Overwrite replaces existing files that differ (XFER-7).
	Overwrite bool
	// Verify compares content hashes instead of the quick check (RES-2).
	Verify bool
	// IdleTimeout ends the receiver after this long without authenticated
	// activity (RCV-7). Zero disables it.
	IdleTimeout time.Duration
	// MaxUnauth limits concurrent unauthenticated connections (RCV-8).
	MaxUnauth int
	// Link overrides heartbeat and dead-connection timings (tests).
	Link proto.LinkConfig
	// Finalizers is the number of goroutines that verify and rename
	// completed files, so fsync latency overlaps with receiving.
	Finalizers int
	// Linger is how long to wait for the sender to close after DONE.
	Linger time.Duration
	// MaxEntries overrides proto.MaxEntries when positive (tests).
	MaxEntries int
	// Logger receives diagnostics. Nil discards them.
	Logger *slog.Logger
	// Progress, if set, is updated as data arrives.
	Progress *progress.Tracker
}

// FileIssue is a per-file problem listed in the summary.
type FileIssue struct {
	Path string
	Code proto.Code
}

// Summary describes the outcome of a receive (CLI-3).
type Summary struct {
	Transferred int
	Bytes       int64
	Skipped     int
	Conflicts   []string
	Errors      []FileIssue
	Integrity   []string
	// StrayParts lists .part files in the destination for paths not in
	// the manifest; they are left untouched (RES-4).
	StrayParts []string
	// NotTransferred lists manifest files with no outcome yet, for example
	// after an interruption (REL-7).
	NotTransferred []string
	Elapsed        time.Duration
	// Connections counts authenticated connections.
	Connections int
}

// Kind returns the failure kind implied by per-file outcomes (CLI-8).
func (s *Summary) Kind() fail.Kind {
	switch {
	case s == nil:
		return fail.None
	case len(s.Integrity) > 0:
		return fail.Integrity
	case len(s.Conflicts) > 0 || len(s.Errors) > 0:
		return fail.Partial
	}
	return fail.None
}

// Receiver serves one transfer into a destination directory.
type Receiver struct {
	opts  Options
	root  *os.Root
	log   *slog.Logger
	start time.Time

	lastActivity atomic.Int64

	mu     sync.Mutex
	active *activeConn
	sess   *session
	conns  int

	wg      sync.WaitGroup
	doneCh  chan *Summary
	fatalCh chan error
}

type activeConn struct {
	id     [proto.SessionIDSize]byte
	cancel context.CancelFunc
	done   chan struct{}
}

// New prepares the destination and returns a Receiver. It creates Dest if
// needed (RCV-1) and checks that it is writable, so that a read-only
// destination fails before the user starts the sender (exit 5).
func New(opts Options) (*Receiver, error) {
	if opts.Pairer == nil {
		return nil, errors.New("recv: no pairer")
	}
	if opts.MaxUnauth <= 0 {
		opts.MaxUnauth = DefaultMaxUnauth
	}
	if opts.Finalizers <= 0 {
		opts.Finalizers = DefaultFinalizers
	}
	if opts.Linger <= 0 {
		opts.Linger = DefaultLingerAfterEnd
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.Dest == "" {
		opts.Dest = "."
	}
	// Creating the destination itself is the one operation that cannot
	// go through os.Root, because the root does not exist yet.
	if err := os.MkdirAll(opts.Dest, 0o755); err != nil { //nolint:gosec // G301: RCV-1 specifies 0755 (masked by the umask)
		return nil, fail.New(fail.FS, fmt.Sprintf("cannot create the destination directory %s", proto.Printable(opts.Dest)),
			"check the path and your permissions", unwrapPath(err))
	}
	root, err := os.OpenRoot(opts.Dest)
	if err != nil {
		return nil, fail.New(fail.FS, fmt.Sprintf("cannot open the destination directory %s", proto.Printable(opts.Dest)),
			"check that it is a directory you can access", unwrapPath(err))
	}
	if err := probeWritable(root); err != nil {
		_ = root.Close()
		return nil, fail.New(fail.FS, fmt.Sprintf("the destination directory %s is not writable", proto.Printable(opts.Dest)),
			"choose a directory you can write to, or fix its permissions", unwrapPath(err))
	}
	return &Receiver{
		opts:    opts,
		root:    root,
		log:     log,
		doneCh:  make(chan *Summary, 1),
		fatalCh: make(chan error, 1),
	}, nil
}

// probeWritable creates and removes a uniquely named empty file. The file is
// created and deleted in this run, so RES-1 and RES-4 are respected.
func probeWritable(root *os.Root) error {
	var b [8]byte
	_, _ = rand.Read(b[:])
	name := "." + meta.Name + "-write-test-" + hex.EncodeToString(b[:])
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = f.Close()
	return root.Remove(name)
}

// Close releases the destination directory handle.
func (r *Receiver) Close() error { return r.root.Close() }

// errIdle is the cancellation cause when the idle timeout expires.
var errIdle = errors.New("idle timeout")

// Run accepts connections on ln until a session completes, a fatal error
// occurs, the idle timeout expires, or ctx is cancelled. It always returns a
// summary of what was done; the error (classified with package fail) says
// why it stopped if not by successful completion.
func (r *Receiver) Run(ctx context.Context, ln net.Listener) (*Summary, error) {
	r.start = time.Now()
	parent := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stopLn := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stopLn()

	r.touch()
	if r.opts.IdleTimeout > 0 {
		r.wg.Add(1)
		go r.idleWatch(ctx, cancel)
	}
	acceptErr := make(chan error, 1)
	go func() { acceptErr <- r.acceptLoop(ctx, ln) }()

	var sum *Summary
	var result error
	select {
	case sum = <-r.doneCh:
	case result = <-r.fatalCh:
	case <-ctx.Done():
	case err := <-acceptErr:
		acceptErr <- err
		result = fail.New(fail.Network, "the listener stopped", "", err)
	}
	if result == nil && sum == nil {
		switch cause := context.Cause(ctx); {
		case errors.Is(cause, errIdle):
			result = fail.New(fail.Network, fmt.Sprintf("no sender activity for %v; giving up", r.opts.IdleTimeout),
				"start the sender sooner, or use --idle-timeout to wait longer (0 waits forever)", nil)
		case parent.Err() != nil:
			result = fail.New(fail.Interrupted, "interrupted", "run the same command again to resume; partial files were kept", nil)
		default:
			result = fail.New(fail.Internal, "receiver stopped unexpectedly", "", cause)
		}
	}
	cancel(result)
	_ = ln.Close()
	if err := <-acceptErr; err != nil {
		r.log.Debug("accept loop ended", "err", err)
	}
	r.wg.Wait()
	if sum == nil {
		sum = r.summary()
	}
	return sum, result
}

func (r *Receiver) touch() { r.lastActivity.Store(time.Now().UnixNano()) }

func (r *Receiver) idleWatch(ctx context.Context, cancel context.CancelCauseFunc) {
	defer r.wg.Done()
	tick := time.NewTicker(min(r.opts.IdleTimeout/4, time.Second))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			if now.Sub(time.Unix(0, r.lastActivity.Load())) >= r.opts.IdleTimeout {
				cancel(errIdle)
				return
			}
		}
	}
}

func (r *Receiver) acceptLoop(ctx context.Context, ln net.Listener) error {
	// The semaphore slot is taken before Accept, so connections beyond the
	// limit wait in the kernel backlog instead of being closed, which the
	// sender would read as an authentication rejection (D-4.2, RCV-8).
	sem := make(chan struct{}, r.opts.MaxUnauth)
	for {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		c, err := ln.Accept()
		if err != nil {
			<-sem
			if ctx.Err() != nil {
				return nil //nolint:nilerr // Accept fails because the listener was closed on shutdown
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		r.wg.Add(1)
		go r.handle(ctx, c, sem)
	}
}

// handle authenticates one connection and serves it. Failed handshakes are
// logged at debug level only and never end the receiver (RCV-8).
func (r *Receiver) handle(ctx context.Context, c net.Conn, sem chan struct{}) {
	defer r.wg.Done()
	remote := c.RemoteAddr().String()
	sc, err := secure.Server(ctx, c, r.opts.Pairer)
	<-sem
	if err != nil {
		r.log.Debug("handshake failed", "remote", remote, "auth", errors.Is(err, secure.ErrAuthFailed))
		return
	}
	r.touch()
	r.log.Info("sender authenticated", "remote", remote)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	cfg := r.opts.Link
	cfg.OnReceive = r.touch
	link := proto.NewLink(sc, cfg)
	defer func() { _ = link.Close() }()
	// On shutdown, tell the sender why before closing (best effort).
	stop := context.AfterFunc(connCtx, func() {
		if ctx.Err() != nil {
			link.Abort(proto.Error{Code: proto.CodeInterrupted, Fatal: true, Message: "the receiver is shutting down"}, abortTimeout)
			return
		}
		_ = link.Close()
	})
	defer stop()

	err = r.serve(connCtx, connCancel, link)
	switch k := fail.KindOf(err); {
	case err == nil:
	case k == fail.Network || ctx.Err() != nil || connCtx.Err() != nil:
		r.log.Info("connection ended", "remote", remote, "err", err)
	default:
		r.log.Error("fatal error", "remote", remote, "err", err)
		r.fatal(err)
	}
}

func (r *Receiver) fatal(err error) {
	select {
	case r.fatalCh <- err:
	default:
	}
}

// serve runs the session protocol on an authenticated link.
func (r *Receiver) serve(ctx context.Context, cancel context.CancelFunc, link *proto.Link) error {
	m, err := link.Recv()
	if err != nil {
		return netErr(err)
	}
	hello, ok := m.(proto.Hello)
	if !ok {
		return violation(link, "expected HELLO, got %v", m.Type())
	}
	if hello.Version != proto.Version {
		msg := fmt.Sprintf("protocol version mismatch: this receiver speaks version %d, the sender speaks version %d", proto.Version, hello.Version)
		link.Abort(proto.Error{Code: proto.CodeVersion, Fatal: true, Message: msg}, abortTimeout)
		return fail.New(fail.Protocol, msg, fail.SameVersionHint, nil)
	}
	ac, sess, ok := r.acquire(ctx, hello.SessionID, cancel)
	if !ok {
		// Another session is active (RCV-5).
		r.log.Info("rejected connection from another session: busy")
		_ = link.Send(proto.Busy{})
		return nil
	}
	defer r.release(ac)
	verify := r.opts.Verify || hello.Flags&proto.FlagVerify != 0
	var flags uint32
	if r.opts.Verify {
		flags |= proto.FlagVerify
	}
	if err := link.Send(proto.Hello{Version: proto.Version, SessionID: hello.SessionID, Flags: flags}); err != nil {
		return netErr(err)
	}
	c := newConn(r, link, sess, verify)
	return c.run(ctx)
}

// acquire makes this connection the active one for its session. A
// connection with the same session_id supersedes the current one, which is
// cancelled and awaited first so two connections never write the same files
// (RCV-5). A different session_id is refused while a connection is active
// (docs/DECISIONS.md D-5.13).
func (r *Receiver) acquire(ctx context.Context, id [proto.SessionIDSize]byte, cancel context.CancelFunc) (*activeConn, *session, bool) {
	for {
		r.mu.Lock()
		if old := r.active; old != nil {
			r.mu.Unlock()
			if old.id != id {
				return nil, nil, false
			}
			r.log.Info("new connection for the same session; replacing the old one")
			old.cancel()
			select {
			case <-old.done:
			case <-ctx.Done():
				return nil, nil, false
			}
			continue
		}
		ac := &activeConn{id: id, cancel: cancel, done: make(chan struct{})}
		r.active = ac
		if r.sess == nil || r.sess.id != id {
			r.sess = newSession(id)
		}
		r.conns++
		sess := r.sess
		r.mu.Unlock()
		return ac, sess, true
	}
}

func (r *Receiver) release(ac *activeConn) {
	r.mu.Lock()
	if r.active == ac {
		r.active = nil
	}
	r.mu.Unlock()
	close(ac.done)
}

// complete records a successful session and stops the receiver (RCV-6).
func (r *Receiver) complete() {
	select {
	case r.doneCh <- r.summary():
	default:
	}
}

func (r *Receiver) summary() *Summary {
	r.mu.Lock()
	sess, conns := r.sess, r.conns
	r.mu.Unlock()
	s := &Summary{Connections: conns}
	if !r.start.IsZero() {
		s.Elapsed = time.Since(r.start)
	}
	if sess != nil {
		sess.fill(s)
		s.StrayParts = strayParts(r.root, sess.entries)
	}
	return s
}

// netErr classifies an error from the link as a network failure. Link
// errors are either I/O errors, timeouts, or malformed messages; the latter
// are protocol violations.
func netErr(err error) error {
	if errors.Is(err, proto.ErrMalformed) {
		return fail.New(fail.Protocol, "the sender sent a malformed message", "", err)
	}
	if errors.Is(err, io.EOF) {
		return fail.New(fail.Network, "the sender disconnected", "", err)
	}
	return fail.New(fail.Network, "connection lost", "", err)
}

// violation reports a protocol violation to the peer and returns it as a
// fatal error (SEC-13).
func violation(link *proto.Link, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	link.Abort(proto.Error{Code: proto.CodeProtocol, Fatal: true, Message: "protocol violation: " + msg}, abortTimeout)
	return fail.New(fail.Protocol, "protocol violation by the sender: "+msg, fail.SameVersionHint, nil)
}

func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
