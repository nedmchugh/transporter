// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recv

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/secure"
	"github.com/nedmchugh/transporter/internal/testutil"
)

// TestBusy covers RCV-5 and D-5.13: a different session_id is refused with
// BUSY while a session's connection is active, and accepted once that
// connection has ended.
func TestBusy(t *testing.T) {
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), nil)
	a := dialClient(t, h.addr, 1) // session 1, now active

	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := secure.Client(context.Background(), raw, testPairer(t))
	if err != nil {
		t.Fatal(err)
	}
	link := proto.NewLink(sc, fastLink)
	_ = link.Send(proto.Hello{Version: proto.Version, SessionID: [16]byte{2}})
	m, err := link.Recv()
	if err != nil || m.Type() != proto.TypeBusy {
		t.Fatalf("expected BUSY, got %#v %v", m, err)
	}
	_ = link.Close()

	// End session 1's connection; session 2 is then accepted and can
	// complete.
	_ = a.link.Close()
	var b *client
	deadline := time.Now().Add(5 * time.Second)
	for b == nil {
		b = tryClient(t, h.addr, 2)
		if b == nil {
			if time.Now().After(deadline) {
				t.Fatal("session 2 never accepted")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, m := range manifestOf() {
		b.send(m)
	}
	b.send(proto.Done{})
	if _, ok := b.recv().(proto.Done); !ok {
		t.Fatal("no DONE")
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
}

// tryClient is dialClient that returns nil on BUSY.
func tryClient(t *testing.T, addr string, sid byte) *client {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := secure.Client(context.Background(), raw, testPairer(t))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, link: proto.NewLink(sc, fastLink)}
	c.send(proto.Hello{Version: proto.Version, SessionID: [16]byte{sid}})
	if m := c.recv(); m == nil || m.Type() != proto.TypeHello {
		_ = c.link.Close()
		return nil
	}
	t.Cleanup(func() { _ = c.link.Close() })
	return c
}

// TestFailedHandshakesHarmless covers RCV-8: wrong codes, garbage and
// half-open connections do not stop the receiver, do not leak goroutines,
// and reveal nothing; a legitimate sender still gets through.
func TestFailedHandshakesHarmless(t *testing.T) {
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), nil)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", h.addr)
			if err != nil {
				return
			}
			defer c.Close()
			switch i % 3 {
			case 0: // garbage
				_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
			case 1: // valid-looking frame with junk
				_, _ = c.Write(append([]byte{0, 48}, make([]byte, 48)...))
			case 2: // connect and close
			}
			buf := make([]byte, 16)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if n, _ := c.Read(buf); n != 0 {
				t.Errorf("receiver sent %d bytes to an unauthenticated peer", n)
			}
		}()
	}
	wg.Wait()
	c := dialClient(t, h.addr, 3)
	for _, m := range manifestOf() {
		c.send(m)
	}
	c.send(proto.Done{})
	if _, ok := c.recv().(proto.Done); !ok {
		t.Fatal("legitimate sender failed after hostile connections")
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
}

// TestUnauthenticatedLimit covers RCV-8 and D-4.2: with MaxUnauth idle
// connections open, a further connection waits (it is not closed, which a
// sender would read as an authentication rejection) and proceeds once a
// slot frees.
func TestUnauthenticatedLimit(t *testing.T) {
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), func(o *Options) { o.MaxUnauth = 2 })
	var idle []net.Conn
	for range 2 {
		c, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	time.Sleep(100 * time.Millisecond) // let the receiver accept both
	result := make(chan error, 1)
	go func() {
		raw, err := net.Dial("tcp", h.addr)
		if err != nil {
			result <- err
			return
		}
		sc, err := secure.Client(context.Background(), raw, testPairer(t))
		if err == nil {
			_ = sc.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("handshake finished while all slots were taken: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_ = idle[0].Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("handshake after a slot freed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not proceed after a slot freed")
	}
	_ = idle[1].Close()
}
