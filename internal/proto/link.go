// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package proto

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Default liveness settings (REL-3).
const (
	// DefaultHeartbeat is how long a connection may go without an outgoing
	// frame before a HEARTBEAT is sent.
	DefaultHeartbeat = 15 * time.Second
	// DefaultDeadAfter is how long a read or write may block before the
	// connection is considered dead.
	DefaultDeadAfter = 45 * time.Second
)

// FrameConn is the frame-level connection a Link runs over. *secure.Conn
// implements it; tests may use other implementations (DEL-3).
type FrameConn interface {
	ReadFrame() ([]byte, error)
	WriteFrame(p []byte) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

// LinkConfig configures a Link. Zero durations select the defaults.
type LinkConfig struct {
	Heartbeat time.Duration
	DeadAfter time.Duration
	// OnReceive, if set, is called after every frame received (including
	// heartbeats). The receiver uses it for its idle timer (RCV-7).
	OnReceive func()
}

// ErrLinkClosed is returned by Send and Recv after Close.
var ErrLinkClosed = errors.New("link closed")

// Link exchanges messages over a FrameConn, sends heartbeats when the
// connection is idle, and applies read and write deadlines so no call blocks
// indefinitely on a dead connection (REL-3).
//
// Recv must be called from a single goroutine. Send is safe for concurrent
// use. Close stops the heartbeat goroutine and closes the connection; after
// Close returns, no goroutine started by the Link is running (REL-6).
type Link struct {
	fc  FrameConn
	cfg LinkConfig

	wmu       sync.Mutex
	wbuf      []byte
	lastWrite atomic.Int64 // unix nanoseconds

	closeOnce sync.Once
	closed    chan struct{}
	done      chan struct{}
}

// NewLink wraps fc and starts the heartbeat goroutine.
func NewLink(fc FrameConn, cfg LinkConfig) *Link {
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = DefaultHeartbeat
	}
	if cfg.DeadAfter <= 0 {
		cfg.DeadAfter = DefaultDeadAfter
	}
	l := &Link{
		fc:     fc,
		cfg:    cfg,
		wbuf:   make([]byte, 0, MaxMessage),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	l.lastWrite.Store(time.Now().UnixNano())
	go l.heartbeat()
	return l
}

func (l *Link) heartbeat() {
	defer close(l.done)
	// Check at a fraction of the interval so an idle connection sends a
	// heartbeat within about 1.25 intervals of its last write.
	t := time.NewTicker(l.cfg.Heartbeat / 4)
	defer t.Stop()
	for {
		select {
		case <-l.closed:
			return
		case now := <-t.C:
			if now.Sub(time.Unix(0, l.lastWrite.Load())) < l.cfg.Heartbeat {
				continue
			}
			if err := l.Send(Heartbeat{}); err != nil {
				// The connection is broken; closing it unblocks the
				// reader, which reports the error to the session.
				_ = l.fc.Close()
				return
			}
		}
	}
}

// Send encodes and writes one message.
func (l *Link) Send(m Message) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.wbuf = Append(l.wbuf[:0], m)
	return l.writeLocked(l.wbuf)
}

// SendEncoded writes one already-encoded message (for example a CHUNK built
// with AppendChunkHeader). The caller must not modify b during the call.
func (l *Link) SendEncoded(b []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.writeLocked(b)
}

func (l *Link) writeLocked(b []byte) error {
	select {
	case <-l.closed:
		return ErrLinkClosed
	default:
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("message of %d bytes exceeds the %d-byte limit", len(b), MaxMessage)
	}
	if err := l.fc.SetWriteDeadline(time.Now().Add(l.cfg.DeadAfter)); err != nil {
		return err
	}
	if err := l.fc.WriteFrame(b); err != nil {
		return err
	}
	l.lastWrite.Store(time.Now().UnixNano())
	return nil
}

// Recv returns the next message other than HEARTBEAT. Slices in the result
// alias the connection's read buffer and are valid until the next Recv.
func (l *Link) Recv() (Message, error) {
	for {
		if err := l.fc.SetReadDeadline(time.Now().Add(l.cfg.DeadAfter)); err != nil {
			return nil, l.closedOr(err)
		}
		f, err := l.fc.ReadFrame()
		if err != nil {
			return nil, l.closedOr(err)
		}
		if l.cfg.OnReceive != nil {
			l.cfg.OnReceive()
		}
		m, err := Decode(f)
		if err != nil {
			return nil, err
		}
		if _, ok := m.(Heartbeat); ok {
			continue
		}
		return m, nil
	}
}

// Abort makes a best-effort attempt to send m (typically a fatal ERROR)
// within timeout, then closes the link. It never blocks much longer than
// timeout: a write already stuck on a dead connection is cut short by moving
// the write deadline, and Close unblocks anything left.
//
// If the message was written and the connection supports it, the close is
// graceful (see gracefulCloser), so the peer can read the message; that
// adds at most timeout.
func (l *Link) Abort(m Message, timeout time.Duration) {
	_ = l.fc.SetWriteDeadline(time.Now().Add(timeout))
	sent := make(chan struct{})
	wrote := false // written before sent is closed
	go func() {
		defer close(sent)
		l.wmu.Lock()
		defer l.wmu.Unlock()
		select {
		case <-l.closed:
			return
		default:
		}
		l.wbuf = Append(l.wbuf[:0], m)
		if l.fc.SetWriteDeadline(time.Now().Add(timeout)) == nil {
			wrote = l.fc.WriteFrame(l.wbuf) == nil
		}
	}()
	t := time.NewTimer(2 * timeout)
	select {
	case <-sent:
	case <-t.C:
	}
	t.Stop()
	select {
	case <-sent:
		if gc, ok := l.fc.(gracefulCloser); ok && wrote {
			_ = l.closeWith(func() error { return gc.CloseGracefully(timeout) })
			break
		}
		_ = l.Close()
	default:
		_ = l.Close()
	}
	<-sent
}

// gracefulCloser is implemented by connections that can close without
// losing a final message still in flight to the peer (*secure.Conn).
type gracefulCloser interface {
	CloseGracefully(timeout time.Duration) error
}

// closedOr reports ErrLinkClosed if the error was caused by Close, so
// callers can tell a local shutdown from a network failure.
func (l *Link) closedOr(err error) error {
	select {
	case <-l.closed:
		return ErrLinkClosed
	default:
		return err
	}
}

// Close closes the connection and waits for the heartbeat goroutine.
func (l *Link) Close() error { return l.closeWith(l.fc.Close) }

// closeWith marks the link closed (stopping heartbeats and making later
// operations report ErrLinkClosed), closes the connection with closeFn,
// and waits for the heartbeat goroutine. Only the first call has effect.
func (l *Link) closeWith(closeFn func() error) error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = closeFn()
	})
	<-l.done
	return err
}
