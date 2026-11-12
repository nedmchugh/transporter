// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package testutil

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// CutMode says what a Proxy does when it interrupts a connection.
type CutMode int

const (
	// Reset closes both sides with RST, like a network failure.
	Reset CutMode = iota
	// HalfDead resets the client side but leaves the server side open and
	// silent, so the server does not notice the failure until its own
	// dead-connection timeout (used to test session supersession, RCV-5).
	HalfDead
)

// CutPolicy decides, for the n-th accepted connection (0-based), after how
// many client-to-server bytes to interrupt it (0: never) and how.
type CutPolicy func(n int) (after int64, mode CutMode)

// Proxy is a TCP proxy that interrupts connections according to a policy
// (TEST-7, TEST-8 scenario 5).
type Proxy struct {
	ln     net.Listener
	target string
	policy CutPolicy

	accepted atomic.Int64
	cuts     atomic.Int64

	mu     sync.Mutex
	conns  []net.Conn
	closed bool
	wg     sync.WaitGroup
}

// NewProxy listens on a loopback port and forwards to target. It is closed
// when the test ends.
func NewProxy(t testing.TB, target string, policy CutPolicy) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{ln: ln, target: target, policy: policy}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(p.Close)
	return p
}

// Addr is the proxy's listening address.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Accepted returns the number of connections accepted so far.
func (p *Proxy) Accepted() int { return int(p.accepted.Load()) }

// Cuts returns the number of connections interrupted so far.
func (p *Proxy) Cuts() int { return int(p.cuts.Load()) }

// Close stops the proxy and closes every connection.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	_ = p.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	p.wg.Wait()
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return false
	}
	p.conns = append(p.conns, c)
	return true
}

func (p *Proxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		n := int(p.accepted.Add(1)) - 1
		s, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		if !p.track(c) || !p.track(s) {
			_ = s.Close()
			continue
		}
		after, mode := int64(0), Reset
		if p.policy != nil {
			after, mode = p.policy(n)
		}
		p.wg.Add(2)
		go p.forward(c, s, after, mode)
		go func() {
			defer p.wg.Done()
			_, _ = io.Copy(c, s)
			closeWrite(c)
		}()
	}
}

// forward copies client to server, cutting after the configured bytes.
func (p *Proxy) forward(c, s net.Conn, after int64, mode CutMode) {
	defer p.wg.Done()
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := c.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			cut := after > 0 && total+int64(n) >= after
			if cut {
				chunk = buf[:after-total]
			}
			if _, werr := s.Write(chunk); werr != nil {
				return
			}
			total += int64(len(chunk))
			if cut {
				p.cuts.Add(1)
				reset(c)
				if mode == Reset {
					reset(s)
				}
				// In HalfDead mode s stays open until Close.
				return
			}
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				closeWrite(s)
			}
			return
		}
	}
}

// reset closes c with an RST rather than a FIN, which is how a network
// failure looks to the endpoint (a FIN after the handshake's first message
// would read as an authentication rejection, docs/DECISIONS.md D-4.1).
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	_ = c.Close()
}
