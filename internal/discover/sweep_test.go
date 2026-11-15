// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package discover

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/testutil"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// startResponder answers sweep probes for tag on 127.0.0.1 at a free port.
func startResponder(t *testing.T, tcpPort int, tag [code.TagSize]byte) *responder {
	t.Helper()
	r, err := Sweep{Bind: "127.0.0.1"}.listenAny(context.Background(), tcpPort, tag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// listenAny is listen on a free port (Port is ignored).
func (s Sweep) listenAny(ctx context.Context, tcpPort int, tag [code.TagSize]byte) (*responder, error) {
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(s.Bind, "0"))
	if err != nil {
		return nil, err
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	s.Port = port
	return s.listen(ctx, tcpPort, tag)
}

func sweepLoopback(port uint16) Sweep {
	return Sweep{Port: int(port), Targets: func() []netip.Addr { return []netip.Addr{loopback} }}
}

func TestSweepConstants(t *testing.T) {
	if SweepPort != 29873 || SweepTimeout != 3*time.Second {
		t.Fatal("DISC-6/DISC-7 constants changed")
	}
	if replySize >= probeSize {
		t.Fatalf("reply (%d bytes) must be shorter than probe (%d bytes): no amplification", replySize, probeSize)
	}
}

// TestSweepWire covers the probe and reply format (docs/protocol.md
// section 9) and that malformed packets are rejected.
func TestSweepWire(t *testing.T) {
	tag := [code.TagSize]byte{1, 2, 3, 4}
	nonce := [nonceSize]byte{9, 8, 7, 6, 5, 4, 3, 2}
	p := makeProbe(tag, nonce)
	want := append([]byte("TRSQ\x01\x01\x02\x03\x04"), nonce[:]...)
	if !bytes.Equal(p, want) {
		t.Fatalf("probe %x, want %x", p, want)
	}
	if got, ok := parseProbe(p, tag); !ok || got != nonce {
		t.Fatal("probe does not parse")
	}
	bad := map[string][]byte{
		"other tag":   makeProbe([code.TagSize]byte{1, 2, 3, 5}, nonce),
		"short":       p[:len(p)-1],
		"long":        append(slices.Clone(p), 0),
		"magic":       append([]byte("TRSX"), p[4:]...),
		"version":     append(append([]byte("TRSQ"), 2), p[5:]...),
		"reply magic": append([]byte("TRSR"), p[4:]...),
	}
	for name, b := range bad {
		if _, ok := parseProbe(b, tag); ok {
			t.Errorf("probe %s accepted", name)
		}
	}

	reply := append(append([]byte("TRSR\x01"), nonce[:]...), 0xa0, 0x95)
	if port, ok := parseReply(reply, nonce); !ok || port != 41109 {
		t.Fatalf("reply: port %d ok %v", port, ok)
	}
	badReplies := map[string][]byte{
		"other nonce": append(append([]byte("TRSR\x01"), 0, 8, 7, 6, 5, 4, 3, 2), 0xa0, 0x95),
		"port 0":      append(append([]byte("TRSR\x01"), nonce[:]...), 0, 0),
		"short":       reply[:len(reply)-1],
		"probe":       p,
	}
	for name, b := range badReplies {
		if _, ok := parseReply(b, nonce); ok {
			t.Errorf("reply %s accepted", name)
		}
	}
}

// FuzzSweepPacket checks that the packet parsers never panic and accept
// only packets of the exact format.
func FuzzSweepPacket(f *testing.F) {
	tag := [code.TagSize]byte{1, 2, 3, 4}
	nonce := [nonceSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	f.Add(makeProbe(tag, nonce))
	f.Add(append(append([]byte("TRSR\x01"), nonce[:]...), 0x12, 0x34))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if n, ok := parseProbe(b, tag); ok && !bytes.Equal(b, makeProbe(tag, n)) {
			t.Fatalf("accepted a non-canonical probe %x", b)
		}
		if port, ok := parseReply(b, nonce); ok && (len(b) != replySize || port == 0) {
			t.Fatalf("accepted a bad reply %x", b)
		}
	})
}

// TestSubnetHosts covers DISC-8: which addresses of a subnet are probed.
func TestSubnetHosts(t *testing.T) {
	tests := []struct {
		prefix      string
		n           int
		first, last string
	}{
		{"192.168.1.20/24", 254, "192.168.1.1", "192.168.1.254"},
		{"10.0.0.5/30", 2, "10.0.0.5", "10.0.0.6"},
		{"10.0.0.4/31", 2, "10.0.0.4", "10.0.0.5"},
		{"10.0.0.4/32", 0, "", ""},
		{"10.1.6.9/22", 1022, "10.1.4.1", "10.1.7.254"},
		// Larger than /22: only the /22 around the address, all of it.
		{"172.16.37.9/16", 1024, "172.16.36.0", "172.16.39.255"},
		{"10.200.3.3/8", 1024, "10.200.0.0", "10.200.3.255"},
	}
	for _, tc := range tests {
		got := subnetHosts(netip.MustParsePrefix(tc.prefix))
		if len(got) != tc.n {
			t.Errorf("%s: %d hosts, want %d", tc.prefix, len(got), tc.n)
			continue
		}
		if tc.n > 0 && (got[0].String() != tc.first || got[len(got)-1].String() != tc.last) {
			t.Errorf("%s: %v to %v, want %s to %s", tc.prefix, got[0], got[len(got)-1], tc.first, tc.last)
		}
	}
	if subnetHosts(netip.MustParsePrefix("2001:db8::1/120")) != nil {
		t.Error("IPv6 subnets must not be swept")
	}
}

// TestSweepTargets covers DISC-8: loopback first, local addresses left out,
// overlapping subnets probed once, and the total capped.
func TestSweepTargets(t *testing.T) {
	got := sweepTargets([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.20/24"),
		netip.MustParsePrefix("192.168.1.21/24"), // a second address, same subnet
		netip.MustParsePrefix("10.0.0.1/30"),
	})
	if got[0] != loopback {
		t.Fatalf("first target %v, want 127.0.0.1", got[0])
	}
	if len(got) != 1+252+1 {
		t.Fatalf("%d targets", len(got))
	}
	for _, own := range []string{"192.168.1.20", "192.168.1.21", "10.0.0.1"} {
		if slices.Contains(got, netip.MustParseAddr(own)) {
			t.Errorf("probes its own address %s", own)
		}
	}
	seen := map[netip.Addr]bool{}
	for _, a := range got {
		if seen[a] {
			t.Fatalf("%v probed twice", a)
		}
		seen[a] = true
	}
	var many []netip.Prefix
	for i := range 10 {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i * 4), 0, 1}), 16))
	}
	if n := len(sweepTargets(many)); n != maxSweepTargets {
		t.Fatalf("%d targets, want the cap %d", n, maxSweepTargets)
	}
	if len(SweepTargets()) == 0 {
		t.Fatal("SweepTargets is empty; it always includes 127.0.0.1")
	}
}

// TestSweepFind covers DISC-7 and DISC-2: the sender finds the responder
// with its tag, and a responder with another tag does not answer.
func TestSweepFind(t *testing.T) {
	testutil.CheckLeaks(t)
	tag := [code.TagSize]byte{1, 2, 3, 4}
	r := startResponder(t, 41111, tag)
	s := sweepLoopback(r.addr().Port())
	addr, err := s.Find(context.Background(), tag, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:41111" {
		t.Fatalf("found %s", addr)
	}
	start := time.Now()
	_, err = s.Find(context.Background(), [code.TagSize]byte{5, 6, 7, 8}, 300*time.Millisecond)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tag: %v", err)
	}
	if took := time.Since(start); took < 300*time.Millisecond || took > 2*time.Second {
		t.Fatalf("gave up after %v, want the 300ms timeout", took)
	}
}

// TestSweepLateReceiver covers DISC-7: a receiver that starts after the
// first round is found by a later round.
func TestSweepLateReceiver(t *testing.T) {
	tag := [code.TagSize]byte{4, 3, 2, 1}
	// Reserve a port, release it, and start the responder there later.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	go func() {
		time.Sleep(sweepRound + 200*time.Millisecond)
		r, err := Sweep{Bind: "127.0.0.1", Port: port}.listen(context.Background(), 42222, tag)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { _ = r.Close() })
	}()
	addr, err := sweepLoopback(uint16(port)).Find(context.Background(), tag, 3*time.Second) //nolint:gosec // a port
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:42222" {
		t.Fatalf("found %s", addr)
	}
}

// TestResponderIgnoresJunk covers DISC-6: the responder answers only a
// well-formed probe with its tag, and the answer echoes the nonce.
func TestResponderIgnoresJunk(t *testing.T) {
	testutil.CheckLeaks(t)
	tag := [code.TagSize]byte{7, 7, 7, 7}
	r := startResponder(t, 40000, tag)
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(r.addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	nonce := [nonceSize]byte{1, 1, 2, 3, 5, 8, 13, 21}
	for _, junk := range [][]byte{
		[]byte("hello"),
		makeProbe([code.TagSize]byte{7, 7, 7, 8}, nonce),
		append(makeProbe(tag, nonce), 0),
	} {
		if _, err := c.Write(junk); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var buf [64]byte
	if n, err := c.Read(buf[:]); err == nil {
		t.Fatalf("answered junk: %x", buf[:n])
	}
	if _, err := c.Write(makeProbe(tag, nonce)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if port, ok := parseReply(buf[:n], nonce); !ok || port != 40000 {
		t.Fatalf("reply %x", buf[:n])
	}
}

// TestResponderClose checks that Close releases the port and that a
// cancelled context stops the responder.
func TestResponderClose(t *testing.T) {
	testutil.CheckLeaks(t)
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Sweep{Bind: "127.0.0.1"}.listenAny(ctx, 40001, [code.TagSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	port := r.addr().Port()
	cancel()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r2, err := Sweep{Bind: "127.0.0.1", Port: int(port)}.listen(context.Background(), 40001, [code.TagSize]byte{})
	if err != nil {
		t.Fatalf("port not released: %v", err)
	}
	_ = r2.Close()
}

func TestResponderRejects(t *testing.T) {
	if _, err := (Sweep{Bind: "::1"}).Advertise(context.Background(), 4000, [code.TagSize]byte{}); err == nil {
		t.Error("accepted an IPv6 bind address")
	}
	if _, err := (Sweep{}).Advertise(context.Background(), 0, [code.TagSize]byte{}); err == nil {
		t.Error("accepted TCP port 0")
	}
}
