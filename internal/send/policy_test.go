// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package send

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/recv"
	"github.com/nedmchugh/transporter/internal/testutil"
)

var baseTime = time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)

func writeAt(t *testing.T, path, content string, mt time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestOverwritePolicy covers XFER-7, RES-2 (quick check with 2 s tolerance)
// and CLI-8 (conflicts give exit 7).
func TestOverwritePolicy(t *testing.T) {
	testutil.CheckLeaks(t)
	tests := []struct {
		name       string
		destText   string
		destMtime  time.Time
		overwrite  bool
		verify     bool // on the sender
		recvVerify bool // on the receiver
		wantText   string
		wantSkip   bool
		wantConf   bool
	}{
		{name: "identical is skipped", destText: "same", destMtime: baseTime, wantText: "same", wantSkip: true},
		{name: "within tolerance is skipped", destText: "SAME", destMtime: baseTime.Add(1500 * time.Millisecond), wantText: "SAME", wantSkip: true},
		{name: "outside tolerance is a conflict", destText: "same", destMtime: baseTime.Add(3 * time.Second), wantText: "same", wantConf: true},
		{name: "different size is a conflict", destText: "different", destMtime: baseTime, wantText: "different", wantConf: true},
		{name: "overwrite replaces", destText: "different", destMtime: baseTime, overwrite: true, wantText: "same"},
		{name: "verify catches same size and mtime", destText: "SAME", destMtime: baseTime, verify: true, wantText: "SAME", wantConf: true},
		{name: "verify from receiver side", destText: "SAME", destMtime: baseTime, recvVerify: true, wantText: "SAME", wantConf: true},
		{name: "verify skips equal content despite mtime", destText: "same", destMtime: baseTime.Add(time.Hour), verify: true, wantText: "same", wantSkip: true},
		{name: "verify with overwrite replaces", destText: "SAME", destMtime: baseTime, verify: true, overwrite: true, wantText: "same"},
		{name: "verify with different size", destText: "longer!", destMtime: baseTime, verify: true, wantText: "longer!", wantConf: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			writeAt(t, filepath.Join(src, "f.txt"), "same", baseTime)
			writeAt(t, filepath.Join(dst, "f.txt"), tc.destText, tc.destMtime)
			h := startReceiver(t, dst, func(o *recv.Options) { o.Overwrite = tc.overwrite; o.Verify = tc.recvVerify })
			sum, err := runSend(t, h.addr, []string{filepath.Join(src, "f.txt")}, func(o *Options) { o.Verify = tc.verify })
			if err != nil {
				t.Fatal(err)
			}
			rs, rerr := h.wait(t)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if got := readFile(t, filepath.Join(dst, "f.txt")); got != tc.wantText {
				t.Fatalf("destination has %q, want %q", got, tc.wantText)
			}
			if (sum.Skipped == 1) != tc.wantSkip || (len(sum.Conflicts) == 1) != tc.wantConf {
				t.Fatalf("sender summary %+v", sum)
			}
			if (rs.Skipped == 1) != tc.wantSkip || (len(rs.Conflicts) == 1) != tc.wantConf {
				t.Fatalf("receiver summary %+v", rs)
			}
			wantKind := fail.None
			if tc.wantConf {
				wantKind = fail.Partial
			}
			if sum.Kind() != wantKind || rs.Kind() != wantKind {
				t.Fatalf("kinds %v / %v, want %v", sum.Kind(), rs.Kind(), wantKind)
			}
			if !tc.wantSkip && !tc.wantConf {
				if fi, _ := os.Stat(filepath.Join(dst, "f.txt")); !fi.ModTime().Equal(baseTime) {
					t.Fatalf("mtime not applied: %v", fi.ModTime())
				}
			}
		})
	}
}

// TestRerunSkipsEverything covers RES-1 and RES-2: a second run against the
// same destination transfers nothing.
func TestRerunSkipsEverything(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"t/a": "1", "t/b/c": "2", "t/e/": ""})
	for range 2 {
		h := startReceiver(t, dst, nil)
		if _, err := runSend(t, h.addr, []string{filepath.Join(src, "t")}, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := h.wait(t); err != nil {
			t.Fatal(err)
		}
	}
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{filepath.Join(src, "t")}, nil)
	if err != nil || sum.Transferred != 0 || sum.Skipped != 2 {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mtime: true})
}
