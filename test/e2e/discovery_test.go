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
	"path/filepath"
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

// TestE2EDiscoveryFails covers DISC-3 and DISC-4: without --to and with no
// matching receiver, the sender gives up after the discovery timeout with
// exit 4 and suggests --to, mentioning that mDNS is often blocked.
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
	if took < discover.DefaultTimeout || took > discover.DefaultTimeout+10*time.Second {
		t.Fatalf("took %v, want about %v", took, discover.DefaultTimeout)
	}
	for _, want := range []string{"--to HOST:PORT", "mDNS is often blocked", "could not find the receiver"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("message lacks %q:\n%s", want, res.stderr)
		}
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
