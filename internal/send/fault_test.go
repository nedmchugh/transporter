// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package send

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OWNER/transporter/internal/fail"
	"github.com/OWNER/transporter/internal/proto"
	"github.com/OWNER/transporter/internal/recv"
	"github.com/OWNER/transporter/internal/testutil"
)

// faultDial wraps each connection attempt n with the faults returned by
// policy(n).
func faultDial(policy func(n int) testutil.Faults) (func(context.Context, string) (net.Conn, error), *atomic.Int64) {
	var n atomic.Int64
	return func(ctx context.Context, addr string) (net.Conn, error) {
		i := int(n.Add(1)) - 1
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return testutil.NewFaultConn(c, policy(i)), nil
	}, &n
}

// faultTree writes a tree with one multi-chunk file and many small files.
func faultTree(t *testing.T, small int) string {
	t.Helper()
	src := t.TempDir()
	testutil.RandomFile(t, filepath.Join(src, "t", "big.bin"), 2<<20, 11)
	files := map[string]string{}
	for i := range small {
		files[fmt.Sprintf("t/small/%04d.txt", i)] = fmt.Sprintf("file %d", i)
	}
	testutil.WriteTree(t, src, files)
	return src
}

// TestFaultInjection covers TEST-7, REL-1, REL-2, REL-3, REL-6 and D-4.3:
// after each fault the sender reconnects with a fresh handshake, rebuilds
// state from the destination, and completes with an identical tree and no
// leaked goroutines.
func TestFaultInjection(t *testing.T) {
	tests := []struct {
		name   string
		small  int
		policy func(n int) testutil.Faults
	}{
		{"drop during handshake", 5, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{DropAfterWrite: 10}
			}
			return testutil.Faults{}
		}},
		{"drop during manifest", 500, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{DropAfterWrite: 3000}
			}
			return testutil.Faults{}
		}},
		{"drop mid-chunk", 5, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{DropAfterWrite: 300_000}
			}
			return testutil.Faults{}
		}},
		{"drop while reading acks", 50, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{DropAfterRead: 400}
			}
			return testutil.Faults{}
		}},
		{"flaky link", 20, func(n int) testutil.Faults {
			if n < 12 {
				return testutil.Faults{DropAfterWrite: 200_000 + int64(n)*1000}
			}
			return testutil.Faults{}
		}},
		{"stalled write without close", 5, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{StallWriteAfter: 200_000}
			}
			return testutil.Faults{}
		}},
		{"stalled read without close", 5, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{StallReadAfter: 60}
			}
			return testutil.Faults{}
		}},
		{"corrupted ciphertext", 5, func(n int) testutil.Faults {
			if n == 0 {
				return testutil.Faults{CorruptWriteByte: 100_000}
			}
			return testutil.Faults{}
		}},
		{"slow link", 30, func(int) testutil.Faults { return testutil.Faults{Delay: time.Millisecond} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testutil.CheckLeaks(t)
			src, dst := faultTree(t, tc.small), t.TempDir()
			h := startReceiver(t, dst, nil)
			dial, attempts := faultDial(tc.policy)
			start := time.Now()
			sum, err := runSend(t, h.addr, []string{filepath.Join(src, "t")}, func(o *Options) {
				o.Dial = dial
				o.RetryTimeout = 20 * time.Second
				o.Link = proto.LinkConfig{Heartbeat: 100 * time.Millisecond, DeadAfter: time.Second}
			})
			if err != nil {
				t.Fatalf("send: %v (after %d attempts)", err, attempts.Load())
			}
			if _, err := h.wait(t); err != nil {
				t.Fatal(err)
			}
			testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mtime: true})
			if tc.name != "slow link" && sum.Retries == 0 {
				t.Fatal("fault did not cause a retry")
			}
			t.Logf("%d attempts, %d retries, %v", attempts.Load(), sum.Retries, time.Since(start))
		})
	}
}

// TestReceiverRestartBetweenAttempts covers TEST-7 "receiver restart
// between attempts" and REL-2: the receiver process (same code, same
// destination, same address) is replaced mid-transfer; the sender
// reconnects and the new receiver reuses the .part file.
func TestReceiverRestartBetweenAttempts(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	const size = 8 << 20
	testutil.RandomFile(t, filepath.Join(src, "big.bin"), size, 12)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	newRecv := func() *recv.Receiver {
		r, err := recv.New(recv.Options{Dest: dst, Pairer: testPairer(t, testCode), Link: fastLink, Linger: 100 * time.Millisecond, Logger: testLogger(t)})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r1 := newRecv()
	ctx1, stop1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { _, err := r1.Run(ctx1, ln); done1 <- err }()

	dial, _ := faultDial(func(int) testutil.Faults { return testutil.Faults{Delay: 2 * time.Millisecond} })
	sent := make(chan struct {
		sum *Summary
		err error
	}, 1)
	go func() {
		s, err := runSend(t, addr, []string{filepath.Join(src, "big.bin")}, func(o *Options) {
			o.Dial = dial
			o.RetryTimeout = 20 * time.Second
		})
		sent <- struct {
			sum *Summary
			err error
		}{s, err}
	}()
	part := filepath.Join(dst, "big.bin.part")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if fi, err := os.Stat(part); err == nil && fi.Size() >= 1<<20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(".part did not grow")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop1() // the first receiver shuts down (it tells the sender)
	if err := <-done1; fail.KindOf(err) != fail.Interrupted {
		t.Fatalf("first receiver: %v", err)
	}
	_ = r1.Close()

	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("relisten on %s: %v", addr, err)
	}
	r2 := newRecv()
	defer r2.Close()
	ctx2, stop2 := context.WithCancel(context.Background())
	defer stop2()
	done2 := make(chan *recv.Summary, 1)
	go func() { s, _ := r2.Run(ctx2, ln2); done2 <- s }()

	res := <-sent
	if res.err != nil {
		t.Fatalf("send: %v", res.err)
	}
	rs := <-done2
	if rs.Transferred != 1 || rs.Bytes >= size {
		t.Fatalf("second receiver %+v: .part not reused", rs)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestSupersession covers RCV-5 and REL-2: after a network failure that the
// receiver has not noticed (its side of the old connection stays open), a
// reconnect with the same session_id replaces the old connection at once,
// rather than after the receiver's dead-connection timeout.
func TestSupersession(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := faultTree(t, 5), t.TempDir()
	h := startReceiver(t, dst, func(o *recv.Options) {
		o.Link = proto.LinkConfig{Heartbeat: time.Second, DeadAfter: 60 * time.Second}
	})
	proxy := testutil.NewProxy(t, h.addr, func(n int) (int64, testutil.CutMode) {
		if n == 0 {
			return 500_000, testutil.HalfDead
		}
		return 0, testutil.Reset
	})
	start := time.Now()
	sum, err := runSend(t, proxy.Addr(), []string{filepath.Join(src, "t")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := h.wait(t)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("took %v: the old connection was not superseded", took)
	}
	if proxy.Cuts() != 1 || sum.Retries < 1 || rs.Connections != 2 {
		t.Fatalf("cuts %d, retries %d, connections %d", proxy.Cuts(), sum.Retries, rs.Connections)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestProxyFlakyLink covers TEST-8 scenario 5 in-process: repeated
// interruptions with RST through a TCP proxy.
func TestProxyFlakyLink(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := faultTree(t, 50), t.TempDir()
	h := startReceiver(t, dst, nil)
	proxy := testutil.NewProxy(t, h.addr, func(n int) (int64, testutil.CutMode) {
		if n < 6 {
			return 400_000, testutil.Reset
		}
		return 0, testutil.Reset
	})
	sum, err := runSend(t, proxy.Addr(), []string{filepath.Join(src, "t")}, func(o *Options) { o.RetryTimeout = 20 * time.Second })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	if proxy.Cuts() < 2 || sum.Retries < 2 {
		t.Fatalf("cuts %d retries %d", proxy.Cuts(), sum.Retries)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mtime: true})
}
