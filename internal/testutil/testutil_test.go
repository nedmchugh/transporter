// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package testutil

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestFaultConnDropAfterWrite(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	c := NewFaultConn(a, Faults{DropAfterWrite: 5})
	n, err := c.Write([]byte("0123456789"))
	if n != 5 || !errors.Is(err, ErrInjected) || !c.Dropped() || c.Written() != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, ErrInjected) {
		t.Fatalf("after drop: %v", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || ne.Timeout() {
		t.Fatal("ErrInjected should be a non-timeout net.Error")
	}
}

func TestFaultConnReadFaults(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go func() { _, _ = b.Write([]byte("abcdefgh")) }()
	c := NewFaultConn(a, Faults{DropAfterRead: 4, CorruptReadByte: 2})
	buf := make([]byte, 8)
	n, err := io.ReadFull(c, buf[:4])
	if err != nil || n != 4 || string(buf[:4]) != "a\x9dcd" {
		t.Fatalf("n=%d err=%v %q", n, err, buf[:n])
	}
	if _, err := c.Read(buf); !errors.Is(err, ErrInjected) {
		t.Fatalf("got %v", err)
	}
	if c.ReadCount() != 4 {
		t.Fatal(c.ReadCount())
	}
}

func TestFaultConnCorruptWrite(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewFaultConn(a, Faults{CorruptWriteByte: 1})
	orig := []byte("ab")
	go func() { _, _ = c.Write(orig) }()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 'a'^0xFF || buf[1] != 'b' || orig[0] != 'a' {
		t.Fatalf("got %q (orig %q)", buf, orig)
	}
}

func TestFaultConnStall(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	c := NewFaultConn(a, Faults{StallWriteAfter: 2, StallReadAfter: 1, Delay: time.Millisecond})
	_ = c.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if n, err := c.Write([]byte("abcd")); n != 2 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	go func() { _, _ = b.Write([]byte("xy")) }()
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 4)
	if n, err := c.Read(buf); n != 1 || err != nil {
		t.Fatalf("read n=%d err=%v", n, err)
	}
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled read: %v", err)
	}
	// Close releases a stall without a deadline.
	_ = c.SetWriteDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("z")); done <- err }()
	time.Sleep(20 * time.Millisecond)
	_ = c.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// TestLeakDetection checks that the leak checker notices a goroutine started
// by project code and ignores ones that exit.
func TestLeakDetection(t *testing.T) {
	before := goroutines()
	stop := make(chan struct{})
	started := make(chan struct{})
	go func() { close(started); <-stop }()
	<-started
	if len(leakedSince(before)) != 1 {
		t.Fatal("leak not detected")
	}
	close(stop)
	deadline := time.Now().Add(2 * time.Second)
	for len(leakedSince(before)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("goroutine still reported after exit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if isProjectGoroutine("goroutine 1 [running]:\nmain.main()") {
		t.Fatal("goroutine without creator counted")
	}
}
