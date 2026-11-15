// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

//go:build e2e

package e2e

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/discover"
	"github.com/nedmchugh/transporter/internal/testutil"
)

// multicastWorks checks whether mDNS works here at all (DISC-5).
func multicastWorks(t *testing.T) bool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := discover.MDNS{}
	tag := [4]byte{0xe2, 0xe0, 0x01, 0x02}
	c, err := m.Advertise(ctx, 1, tag)
	if err != nil {
		return false
	}
	defer c.Close()
	_, err = m.Find(ctx, tag, 3*time.Second)
	return err == nil
}

// TestE2EDiscovery covers TEST-8 scenario 11 (DISC-1, DISC-2, SND-7): the
// sender finds the receiver by mDNS without --to. Skipped when multicast is
// unavailable, as in many CI environments (DISC-5).
func TestE2EDiscovery(t *testing.T) {
	if !multicastWorks(t) {
		t.Skip("multicast/mDNS is unavailable in this environment (DISC-5)")
	}
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"found.txt": "via mDNS"})
	r := startReceiverRaw(t, "receive", dst) // advertises; listens on all interfaces
	res := runSender(t, nil, nil, r.code, filepath.Join(src, "found.txt"))
	if res.exit != 0 {
		t.Fatalf("exit %d\n%s", res.exit, res.stderr)
	}
	if r.wait(t, 30*time.Second) != 0 {
		t.Fatal("receiver failed")
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestE2EDiscoveryFails covers DISC-3, DISC-4 and DISC-7: without --to and
// with no matching receiver, the sender tries mDNS and then the UDP sweep,
// gives up after both timeouts with exit 4, and suggests --to, naming the
// usual cause of each failure.
func TestE2EDiscoveryFails(t *testing.T) {
	t.Parallel()
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f": "x"})
	start := time.Now()
	res := runSender(t, nil, nil, "abandon-ability-able-about-above-absent-absorb-abstract-absurd", filepath.Join(src, "f"))
	took := time.Since(start)
	if res.exit != 4 {
		t.Fatalf("exit %d\n%s", res.exit, res.stderr)
	}
	want := discover.DefaultTimeout + discover.SweepTimeout
	if took < want || took > want+10*time.Second {
		t.Fatalf("took %v, want about %v", took, want)
	}
	for _, want := range []string{"--to HOST:PORT", "mDNS is often blocked", "UDP port 29873", "could not find the receiver", "within 8s"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("message lacks %q:\n%s", want, res.stderr)
		}
	}
}

// freeUDPPort returns a UDP port that was free a moment ago, so the sweep
// tests do not depend on the fixed default port (TEST-8).
func freeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
}

// TestE2ESweep covers DISC-6 to DISC-9 (TEST-8 scenario 11): with mDNS off
// on both sides and no --to, the sender finds the receiver with the UDP
// sweep, here over loopback, which the sweep always probes.
func TestE2ESweep(t *testing.T) {
	t.Parallel()
	port := freeUDPPort(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"swept.txt": "via the UDP sweep"})
	r := startReceiverRaw(t, "receive", "--bind", "127.0.0.1", "--no-mdns", "--sweep-port", port, dst)
	res := runSender(t, nil, nil, "--no-mdns", "--sweep-port", port, r.code, filepath.Join(src, "swept.txt"))
	if res.exit != 0 {
		t.Fatalf("exit %d\n%s\nreceiver:\n%s", res.exit, res.stderr, r.stderr)
	}
	if r.wait(t, 30*time.Second) != 0 {
		t.Fatal("receiver failed")
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestE2ESweepDisabled covers DISC-9: a receiver started with --no-sweep
// does not answer the sweep, so the sender gives up after the sweep
// timeout with exit 4 and a hint that names the sweep port.
func TestE2ESweepDisabled(t *testing.T) {
	t.Parallel()
	port := freeUDPPort(t)
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f": "x"})
	r := startReceiverRaw(t, "receive", "--bind", "127.0.0.1", "--no-mdns", "--no-sweep", "--sweep-port", port, t.TempDir())
	start := time.Now()
	res := runSender(t, nil, nil, "--no-mdns", "--sweep-port", port, r.code, filepath.Join(src, "f"))
	took := time.Since(start)
	if res.exit != 4 {
		t.Fatalf("exit %d\n%s", res.exit, res.stderr)
	}
	if took < discover.SweepTimeout || took > discover.SweepTimeout+10*time.Second {
		t.Fatalf("took %v, want about %v", took, discover.SweepTimeout)
	}
	for _, want := range []string{"UDP port " + port, "UDP sweep: no answer", "within 3s"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("message lacks %q:\n%s", want, res.stderr)
		}
	}
	if strings.Contains(res.stderr, "mDNS is often blocked") {
		t.Errorf("mDNS was off, but the hint mentions it:\n%s", res.stderr)
	}
}

// TestE2ECodeNeverLogged covers TEST-9, CODE-7 and SEC-15: at every
// verbosity, including a run with retries and a mistyped code, the code
// appears in no output except the receiver's single banner line.
func TestE2ECodeNeverLogged(t *testing.T) {
	t.Parallel()
	for _, verbosity := range [][]string{nil, {"-v"}, {"-v", "-v"}} {
		t.Run(strings.Join(append([]string{"v"}, verbosity...), ""), func(t *testing.T) {
			t.Parallel()
			src, dst := t.TempDir(), t.TempDir()
			testutil.RandomFile(t, filepath.Join(src, "d", "big.bin"), 8<<20, 1)
			testutil.WriteTree(t, src, map[string]string{"d/small.txt": "small"})
			r := startReceiver(t, append(verbosity, dst)...)
			proxy := testutil.NewProxy(t, r.addr(), func(n int) (int64, testutil.CutMode) {
				if n == 0 {
					return 1 << 20, testutil.Reset
				}
				return 0, testutil.Reset
			})
			words := strings.Split(r.code, "-")
			typo := strings.Join(append(append([]string{}, words[:8]...), "zzzzzz"), "-")
			bad := runSender(t, nil, nil, append(verbosity, "--to", proxy.Addr(), typo, filepath.Join(src, "d"))...)
			if bad.exit != 2 {
				t.Fatalf("typo exit %d\n%s", bad.exit, bad.stderr)
			}
			good := runSender(t, nil, nil, append(verbosity, "--to", proxy.Addr(), r.code, filepath.Join(src, "d"))...)
			if good.exit != 0 {
				t.Fatalf("exit %d\n%s", good.exit, good.stderr)
			}
			if r.wait(t, time.Minute) != 0 {
				t.Fatal("receiver failed")
			}
			forms := []string{r.code, strings.ReplaceAll(r.code, "-", " "), strings.ToUpper(r.code), typo, strings.Join(words[:8], "-")}
			outputs := map[string]string{
				"receiver stderr": r.stderr.String(),
				"sender stdout":   good.stdout + bad.stdout,
				"sender stderr":   good.stderr + bad.stderr,
			}
			for name, out := range outputs {
				for _, f := range forms {
					if strings.Contains(out, f) {
						t.Errorf("%s contains the code (%q):\n%s", name, f, out)
					}
				}
			}
			banner := r.stdout.String()
			if n := strings.Count(banner, r.code); n != 1 || !strings.Contains(banner, "Code: "+r.code+"\n") {
				t.Fatalf("receiver stdout has the code %d times:\n%s", n, banner)
			}
			if len(verbosity) == 2 && (!strings.Contains(r.stderr.String(), "level=DEBUG") || !strings.Contains(good.stderr, "level=DEBUG")) {
				t.Fatal("debug logging was not enabled; the test would prove nothing")
			}
		})
	}
}
