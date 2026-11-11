// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package testutil

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ErrInjected is returned by FaultConn operations after an injected drop.
// It reports itself as a network error that is not a timeout, like a
// connection reset.
var ErrInjected = &injectedError{}

type injectedError struct{}

func (*injectedError) Error() string   { return "testutil: injected connection drop" }
func (*injectedError) Timeout() bool   { return false }
func (*injectedError) Temporary() bool { return false }

// Faults configures a FaultConn (TEST-7). Byte counts are cumulative over the
// connection's lifetime; zero disables a fault.
type Faults struct {
	// DropAfterWrite closes the connection once this many bytes have been
	// written. The write that crosses the limit is truncated at it.
	DropAfterWrite int64
	// DropAfterRead closes the connection once this many bytes have been
	// read. The read that crosses the limit is truncated at it.
	DropAfterRead int64
	// StallWriteAfter makes writes block, without closing, once this many
	// bytes have been written. Stalled writes end only at the write
	// deadline (os.ErrDeadlineExceeded) or Close.
	StallWriteAfter int64
	// StallReadAfter is the read-side equivalent of StallWriteAfter.
	StallReadAfter int64
	// CorruptWriteByte flips the bits of the Nth written byte (1-based).
	CorruptWriteByte int64
	// CorruptReadByte flips the bits of the Nth read byte (1-based).
	CorruptReadByte int64
	// Delay is added before every read and write.
	Delay time.Duration
}

// FaultConn wraps a net.Conn and injects faults. It is safe for one reader
// and one writer concurrently, like net.Conn.
type FaultConn struct {
	net.Conn
	f Faults

	written, read atomic.Int64
	dropped       atomic.Bool

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	closed        chan struct{}
	closeOnce     sync.Once
}

// NewFaultConn wraps c.
func NewFaultConn(c net.Conn, f Faults) *FaultConn {
	return &FaultConn{Conn: c, f: f, closed: make(chan struct{})}
}

// Written and ReadCount return the bytes passed through so far.
func (c *FaultConn) Written() int64 { return c.written.Load() }

// ReadCount returns the number of bytes read so far.
func (c *FaultConn) ReadCount() int64 { return c.read.Load() }

// Dropped reports whether an injected drop has happened.
func (c *FaultConn) Dropped() bool { return c.dropped.Load() }

func (c *FaultConn) drop() {
	c.dropped.Store(true)
	_ = c.Close()
}

// stall blocks until the deadline passes or the connection closes.
func (c *FaultConn) stall(read bool) error {
	for {
		c.mu.Lock()
		d := c.writeDeadline
		if read {
			d = c.readDeadline
		}
		c.mu.Unlock()
		wait := time.Hour
		if !d.IsZero() {
			wait = time.Until(d)
			if wait <= 0 {
				return os.ErrDeadlineExceeded
			}
		}
		// Re-check periodically so a deadline moved later is honored.
		t := time.NewTimer(min(wait, 50*time.Millisecond))
		select {
		case <-c.closed:
			t.Stop()
			return net.ErrClosed
		case <-t.C:
		}
	}
}

func (c *FaultConn) Write(p []byte) (int, error) {
	if c.dropped.Load() {
		return 0, ErrInjected
	}
	if c.f.Delay > 0 {
		time.Sleep(c.f.Delay)
	}
	start := c.written.Load()
	if c.f.StallWriteAfter > 0 && start >= c.f.StallWriteAfter {
		return 0, c.stall(false)
	}
	n := int64(len(p))
	limit := n
	if c.f.DropAfterWrite > 0 && start+n >= c.f.DropAfterWrite {
		limit = c.f.DropAfterWrite - start
	}
	if c.f.StallWriteAfter > 0 && start+limit > c.f.StallWriteAfter {
		limit = c.f.StallWriteAfter - start
	}
	buf := p[:limit]
	if k := c.f.CorruptWriteByte; k > start && k <= start+limit {
		buf = append([]byte(nil), buf...)
		buf[k-start-1] ^= 0xFF
	}
	w, err := c.Conn.Write(buf)
	c.written.Add(int64(w))
	if err != nil {
		return w, err
	}
	if c.f.DropAfterWrite > 0 && c.written.Load() >= c.f.DropAfterWrite {
		c.drop()
		return w, ErrInjected
	}
	if int64(w) < n {
		return w, c.stall(false)
	}
	return w, nil
}

func (c *FaultConn) Read(p []byte) (int, error) {
	if c.dropped.Load() {
		return 0, ErrInjected
	}
	if c.f.Delay > 0 {
		time.Sleep(c.f.Delay)
	}
	start := c.read.Load()
	if c.f.StallReadAfter > 0 && start >= c.f.StallReadAfter {
		return 0, c.stall(true)
	}
	if c.f.DropAfterRead > 0 && start >= c.f.DropAfterRead {
		c.drop()
		return 0, ErrInjected
	}
	limit := int64(len(p))
	if c.f.DropAfterRead > 0 {
		limit = min(limit, c.f.DropAfterRead-start)
	}
	if c.f.StallReadAfter > 0 {
		limit = min(limit, c.f.StallReadAfter-start)
	}
	n, err := c.Conn.Read(p[:limit])
	if k := c.f.CorruptReadByte; k > start && k <= start+int64(n) {
		p[k-start-1] ^= 0xFF
	}
	c.read.Add(int64(n))
	return n, err
}

// SetDeadline sets both deadlines on the wrapper and the wrapped conn.
func (c *FaultConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = t, t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *FaultConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *FaultConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

// Close closes the connection and releases stalled operations.
func (c *FaultConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	err := c.Conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
