// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package secure

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/OWNER/transporter/internal/code"
	"github.com/OWNER/transporter/internal/pairing"
	"github.com/OWNER/transporter/internal/testutil"
)

const (
	codeA = "abandon-ability-able-about-above-absent-absorb-abstract-absurd"
	codeB = "zoo-zone-zero-youth-young-yellow-year-wrong-write"
)

func pairer(t testing.TB, s string) pairing.Pairer {
	t.Helper()
	c, err := code.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pairing.NewCodePairer(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type result struct {
	c   *Conn
	err error
}

// connect runs Client and Server concurrently over the given raw conns.
func connect(t testing.TB, ctx context.Context, cr, sr net.Conn, cp, sp pairing.Pairer) (client, server result) {
	t.Helper()
	ch := make(chan result, 1)
	go func() {
		c, err := Server(ctx, sr, sp)
		ch <- result{c, err}
	}()
	c, err := Client(ctx, cr, cp)
	client = result{c, err}
	server = <-ch
	t.Cleanup(func() {
		for _, r := range []result{client, server} {
			if r.c != nil {
				_ = r.c.Close()
			}
		}
		_ = cr.Close()
		_ = sr.Close()
	})
	return client, server
}

// TestHandshakeSuccess covers SEC-1 and TEST-3 (right code).
func TestHandshakeSuccess(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
	if c.err != nil || s.err != nil {
		t.Fatalf("client %v, server %v", c.err, s.err)
	}
	exchange(t, c.c, s.c, []byte("hello"))
	exchange(t, s.c, c.c, []byte("world"))
	if c.c.RemoteAddr() == nil || c.c.LocalAddr() == nil {
		t.Fatal("addresses missing")
	}
}

func exchange(t *testing.T, from, to *Conn, msg []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- from.WriteFrame(msg) }()
	got, err := to.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestHandshakeWrongCode covers REL-5, SEC-4 and TEST-3 (wrong code): both
// sides see a generic authentication failure, and the server sends nothing.
func TestHandshakeWrongCode(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeB))
	if !errors.Is(c.err, ErrAuthFailed) {
		t.Fatalf("client: %v", c.err)
	}
	if !errors.Is(s.err, ErrAuthFailed) {
		t.Fatalf("server: %v", s.err)
	}
	if c.c != nil || s.c != nil {
		t.Fatal("connection returned on failure")
	}
}

// TestHandshakePrologueMismatch covers SEC-3: a peer using a different
// prologue (another protocol version) fails cleanly.
func TestHandshakePrologueMismatch(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	defer cr.Close()
	errc := make(chan error, 1)
	go func() {
		_, err := Server(context.Background(), sr, pairer(t, codeA))
		errc <- err
	}()
	psk, _ := pairer(t, codeA).HandshakeKey(context.Background(), nil, pairing.Initiator)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeNN, Initiator: true,
		Prologue: []byte("transporter/2"), PresharedKey: psk[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRaw(cr, msg); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("server: %v", err)
	}
	// The server closed without sending anything (SEC-4).
	if n, err := cr.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("server sent data: n=%d err=%v", n, err)
	}
}

// TestHandshakeOversizedMessage covers SEC-7 for handshake frames.
func TestHandshakeOversizedMessage(t *testing.T) {
	testutil.CheckLeaks(t)
	for _, n := range []uint16{0, maxHandshakeFrame + 1, 0xFFFF} {
		cr, sr := net.Pipe()
		errc := make(chan error, 1)
		go func() {
			_, err := Server(context.Background(), sr, pairer(t, codeA))
			errc <- err
		}()
		go func() { _, _ = cr.Write(binary.BigEndian.AppendUint16(nil, n)) }()
		if err := <-errc; !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("len %d: %v", n, err)
		}
		_ = cr.Close()
	}
}

// TestHandshakeDeadline covers SEC-4 and REL-3: a peer that never answers
// does not block the handshake beyond its deadline, and the failure is a
// timeout, not an authentication failure.
func TestHandshakeDeadline(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	defer sr.Close()
	// Drain whatever the client sends but never reply.
	go func() { _, _ = io.Copy(io.Discard, sr) }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Client(ctx, cr, pairer(t, codeA))
	if err == nil || errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want timeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v, want deadline error", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("handshake deadline not honored")
	}
}

// TestHandshakeCancel checks that cancelling the context aborts a handshake
// blocked on the network.
func TestHandshakeCancel(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	defer sr.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := Server(ctx, cr, pairer(t, codeA))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	// An already-cancelled context fails before any I/O.
	cr2, sr2 := net.Pipe()
	defer sr2.Close()
	if _, err := Client(ctx, cr2, pairer(t, codeA)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled: %v", err)
	}
}

// TestHandshakeFaults covers TEST-7 "drop during handshake": drops and
// partial messages are network errors (retried), not authentication
// failures. A clean close after message 1 is the documented rejection
// signal (docs/DECISIONS.md D-4.1).
func TestHandshakeFaults(t *testing.T) {
	testutil.CheckLeaks(t)
	tests := []struct {
		name     string
		client   testutil.Faults
		server   testutil.Faults
		wantAuth bool
	}{
		{name: "client write drop", client: testutil.Faults{DropAfterWrite: 10}},
		{name: "client read drop", client: testutil.Faults{DropAfterRead: 5}},
		{name: "server write drop mid-reply", server: testutil.Faults{DropAfterWrite: 20}},
		{name: "corrupted message 1", client: testutil.Faults{CorruptWriteByte: 30}, wantAuth: true},
		{name: "corrupted message 2", client: testutil.Faults{CorruptReadByte: 30}, wantAuth: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			cr := testutil.NewFaultConn(a, tc.client)
			sr := testutil.NewFaultConn(b, tc.server)
			c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
			if c.err == nil {
				t.Fatalf("client succeeded (server err %v)", s.err)
			}
			if got := errors.Is(c.err, ErrAuthFailed); got != tc.wantAuth {
				t.Fatalf("client error %v: auth=%v, want %v", c.err, got, tc.wantAuth)
			}
		})
	}
}

// relay is a frame-aware man-in-the-middle between a client pipe and a
// server pipe. mutate may return the frames to forward in place of each
// client-to-server transport frame (index counts transport frames only).
type relay struct {
	mu     sync.Mutex
	frames [][]byte // copies of every client->server frame seen
}

func startRelay(t *testing.T, mutate func(index int, frame []byte, seen [][]byte) [][]byte) (clientSide, serverSide net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe() // client <-> relay
	s1, s2 := net.Pipe() // relay <-> server
	r := &relay{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client -> server, with mutation after the handshake
		defer wg.Done()
		defer s1.Close()
		for i := 0; ; i++ {
			f, err := readWire(c2)
			if err != nil {
				return
			}
			out := [][]byte{f}
			if i > 0 && mutate != nil { // frame 0 is handshake message 1
				r.mu.Lock()
				out = mutate(i-1, f, r.frames)
				r.frames = append(r.frames, f)
				r.mu.Unlock()
			}
			for _, o := range out {
				if _, err := s1.Write(o); err != nil {
					return
				}
			}
		}
	}()
	go func() { // server -> client, unmodified
		defer wg.Done()
		defer c2.Close()
		_, _ = io.Copy(c2, s1)
	}()
	t.Cleanup(func() {
		_ = c1.Close()
		_ = s2.Close()
		_ = c2.Close()
		_ = s1.Close()
		wg.Wait()
	})
	return c1, s2
}

// readWire reads one whole frame including its length prefix.
func readWire(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, 2+int(binary.BigEndian.Uint16(hdr[:])))
	copy(buf, hdr[:])
	_, err := io.ReadFull(r, buf[2:])
	return buf, err
}

// TestFrameTampering covers SEC-7 and TEST-3: tampered, replayed and
// reordered frames fail authentication and terminate the connection.
func TestFrameTampering(t *testing.T) {
	testutil.CheckLeaks(t)
	tests := []struct {
		name   string
		mutate func(i int, f []byte, seen [][]byte) [][]byte
		// goodBefore is how many frames are delivered intact before the
		// failure.
		goodBefore int
	}{
		{"tampered", func(i int, f []byte, _ [][]byte) [][]byte {
			if i == 1 {
				g := append([]byte(nil), f...)
				g[len(g)-1] ^= 1
				return [][]byte{g}
			}
			return [][]byte{f}
		}, 1},
		{"replayed", func(i int, f []byte, seen [][]byte) [][]byte {
			if i == 1 {
				return [][]byte{seen[0]}
			}
			return [][]byte{f}
		}, 1},
		{"reordered", func(i int, f []byte, seen [][]byte) [][]byte {
			switch i {
			case 0:
				return nil // hold back frame 0
			case 1:
				return [][]byte{f, seen[0]}
			}
			return [][]byte{f}
		}, 0},
		{"truncated tag", func(i int, f []byte, _ [][]byte) [][]byte {
			g := append([]byte(nil), f[:len(f)-1]...)
			binary.BigEndian.PutUint16(g, uint16(len(g)-2))
			return [][]byte{g}
		}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, sr := startRelay(t, tc.mutate)
			c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
			if c.err != nil || s.err != nil {
				t.Fatalf("handshake: %v / %v", c.err, s.err)
			}
			go func() {
				for i := range 4 {
					if c.c.WriteFrame([]byte(fmt.Sprintf("frame %d", i))) != nil {
						return
					}
				}
			}()
			for i := range tc.goodBefore {
				got, err := s.c.ReadFrame()
				if err != nil || string(got) != fmt.Sprintf("frame %d", i) {
					t.Fatalf("frame %d: %q %v", i, got, err)
				}
			}
			_, err := s.c.ReadFrame()
			if !errors.Is(err, ErrFrameAuth) {
				t.Fatalf("got %v, want ErrFrameAuth", err)
			}
			// The error is sticky and the connection is closed.
			if _, err2 := s.c.ReadFrame(); !errors.Is(err2, ErrFrameAuth) {
				t.Fatalf("second read: %v", err2)
			}
			if err := s.c.WriteFrame([]byte("x")); err == nil {
				t.Fatal("write succeeded on closed connection")
			}
		})
	}
}

// rawPeer completes a handshake as the client but returns the raw conn so a
// test can write arbitrary bytes to the server.
func rawPeer(t *testing.T) (raw net.Conn, server *Conn) {
	t.Helper()
	cr, sr := net.Pipe()
	c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
	if c.err != nil || s.err != nil {
		t.Fatal(c.err, s.err)
	}
	return c.c.raw, s.c
}

// TestHandshakeCleanCloseIsRejection documents docs/DECISIONS.md D-4.1: a
// peer that reads message 1 and closes cleanly is reported as an
// authentication failure, because that is what a receiver with another code
// does.
func TestHandshakeCleanCloseIsRejection(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	go func() {
		_, _ = io.ReadFull(sr, make([]byte, 50))
		_ = sr.Close()
	}()
	if _, err := Client(context.Background(), cr, pairer(t, codeA)); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v", err)
	}
}

// TestFrameLengthLimits covers SEC-7 and TEST-3: zero-length, too-short and
// oversized frames are rejected from the header alone.
func TestFrameLengthLimits(t *testing.T) {
	testutil.CheckLeaks(t)
	for _, n := range []int{0, 1, TagSize, MaxFrame + 1, 0xFFFF} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			raw, s := rawPeer(t)
			go func() { _, _ = raw.Write(binary.BigEndian.AppendUint16(nil, uint16(n))) }()
			if _, err := s.ReadFrame(); !errors.Is(err, ErrFrameSize) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// TestFrameTruncated: EOF in the middle of a frame is not a clean EOF.
func TestFrameTruncated(t *testing.T) {
	testutil.CheckLeaks(t)
	raw, s := rawPeer(t)
	go func() {
		_, _ = raw.Write([]byte{0, 40, 1, 2, 3})
		_ = raw.Close()
	}()
	if _, err := s.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
	// A clean close at a frame boundary is io.EOF.
	raw2, s2 := rawPeer(t)
	_ = raw2.Close()
	if _, err := s2.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v", err)
	}
}

// TestPlaintextSize covers SEC-7: plaintext limits on the sending side.
func TestPlaintextSize(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
	if c.err != nil || s.err != nil {
		t.Fatal(c.err, s.err)
	}
	if err := c.c.WriteFrame(nil); !errors.Is(err, ErrPlaintextSize) {
		t.Fatalf("empty: %v", err)
	}
	if err := c.c.WriteFrame(make([]byte, MaxPlaintext+1)); !errors.Is(err, ErrPlaintextSize) {
		t.Fatalf("oversized: %v", err)
	}
	big := bytes.Repeat([]byte{7}, MaxPlaintext)
	exchange(t, c.c, s.c, big)
}

// TestFrameDeadlines covers REL-3 and TEST-3: read and write deadlines are
// honored on an established connection.
func TestFrameDeadlines(t *testing.T) {
	testutil.CheckLeaks(t)
	cr, sr := net.Pipe()
	c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
	if c.err != nil || s.err != nil {
		t.Fatal(c.err, s.err)
	}
	_ = s.c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := s.c.ReadFrame(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: %v", err)
	}
	// net.Pipe writes block until read; nobody reads on the client side.
	_ = s.c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	if err := s.c.WriteFrame([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write: %v", err)
	}
	// Write errors are sticky (the nonce may have advanced).
	if err := s.c.WriteFrame([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("sticky write: %v", err)
	}
}

// TestConcurrentReadWrite covers TEST-3 "concurrent read/write is
// race-free": both sides read and write at once, with several writers.
func TestConcurrentReadWrite(t *testing.T) {
	testutil.CheckLeaks(t)
	a, b := net.Pipe()
	c, s := connect(t, context.Background(), a, b, pairer(t, codeA), pairer(t, codeA))
	if c.err != nil || s.err != nil {
		t.Fatal(c.err, s.err)
	}
	const writers, perWriter = 4, 200
	var wg sync.WaitGroup
	for _, conn := range []*Conn{c.c, s.c} {
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				msg := bytes.Repeat([]byte{byte(w)}, 100+w)
				for range perWriter {
					if err := conn.WriteFrame(msg); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
	}
	read := func(conn *Conn) {
		defer wg.Done()
		for range writers * perWriter {
			f, err := conn.ReadFrame()
			if err != nil {
				t.Error(err)
				return
			}
			if len(f) != 100+int(f[0]) {
				t.Errorf("frame of len %d for writer %d", len(f), f[0])
			}
		}
	}
	wg.Add(2)
	go read(c.c)
	go read(s.c)
	wg.Wait()
}

// TestFreshKeysPerConnection covers SEC-5: two connections with the same code
// produce different ciphertext for the same plaintext.
func TestFreshKeysPerConnection(t *testing.T) {
	testutil.CheckLeaks(t)
	var captured [][]byte
	var mu sync.Mutex
	for range 2 {
		cr, sr := startRelay(t, func(i int, f []byte, _ [][]byte) [][]byte {
			mu.Lock()
			captured = append(captured, append([]byte(nil), f...))
			mu.Unlock()
			return [][]byte{f}
		})
		c, s := connect(t, context.Background(), cr, sr, pairer(t, codeA), pairer(t, codeA))
		if c.err != nil || s.err != nil {
			t.Fatal(c.err, s.err)
		}
		exchange(t, c.c, s.c, []byte("same plaintext"))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 2 || bytes.Equal(captured[0], captured[1]) {
		t.Fatalf("ciphertexts equal across connections (%d captured)", len(captured))
	}
}

// failingPairer exercises the error path for key retrieval.
type failingPairer struct{ pairing.Pairer }

func (failingPairer) HandshakeKey(context.Context, io.ReadWriter, pairing.Role) ([32]byte, error) {
	return [32]byte{}, errors.New("no key")
}

func TestPairerError(t *testing.T) {
	cr, sr := net.Pipe()
	defer sr.Close()
	if _, err := Client(context.Background(), cr, failingPairer{}); err == nil {
		t.Fatal("expected error")
	}
}

// FuzzReadFrame covers TEST-4 for the frame reader: arbitrary bytes after a
// valid handshake never panic and never yield a frame (without the key,
// nothing authenticates).
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0xFF, 0xFF})
	f.Add([]byte{0, 17, 1, 2, 3})
	f.Add(append([]byte{0, 20}, make([]byte, 20)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		dec, err := testDecryptor()
		if err != nil {
			t.Fatal(err)
		}
		c := &Conn{raw: &bufConn{Reader: bytes.NewReader(data)}, rbuf: make([]byte, MaxFrame), dec: dec}
		for range 4 {
			if _, err := c.ReadFrame(); err == nil {
				t.Fatal("random bytes authenticated")
			} else {
				return
			}
		}
	})
}

// testDecryptor returns a cipher state with a fixed random key.
func testDecryptor() (*noise.CipherState, error) {
	var k [32]byte
	copy(k[:], "fuzz key fuzz key fuzz key 12345")
	return noise.UnsafeNewCipherState(cipherSuite, k, 0), nil
}

// bufConn is a net.Conn reading from a buffer; writes are discarded.
type bufConn struct {
	io.Reader
	net.Conn
}

func (b *bufConn) Read(p []byte) (int, error)  { return b.Reader.Read(p) }
func (b *bufConn) Write(p []byte) (int, error) { return len(p), nil }
func (b *bufConn) Close() error                { return nil }
