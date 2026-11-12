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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/testutil"
)

// TestE2ESingleFile covers TEST-8 scenario 1 (single file), RCV-2, RCV-6
// and PROTO-7.
func TestE2ESingleFile(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"hello.txt": "hello, world\n"})
	r := startReceiver(t, dst)
	res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "hello.txt"))
	if res.exit != 0 {
		t.Fatalf("sender exit %d", res.exit)
	}
	if code := r.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("receiver exit %d", code)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mode: true, Mtime: true})
}

// TestE2ELargeFile covers TEST-8 scenario 1 (large file, 64 MiB; 256 MiB
// without -short) and SND-4/NFR-4 indirectly (the sender streams).
func TestE2ELargeFile(t *testing.T) {
	t.Parallel()
	size := int64(64 << 20)
	if !testing.Short() {
		size = 256 << 20
	}
	src, dst := t.TempDir(), t.TempDir()
	testutil.RandomFile(t, filepath.Join(src, "large.bin"), size, 42)
	r := startReceiver(t, dst)
	res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "large.bin"))
	if res.exit != 0 {
		t.Fatalf("sender exit %d", res.exit)
	}
	if code := r.wait(t, time.Minute); code != 0 {
		t.Fatalf("receiver exit %d", code)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mode: true, Mtime: true})
	if _, err := os.Stat(filepath.Join(dst, "large.bin.part")); !os.IsNotExist(err) {
		t.Fatal(".part file left behind")
	}
}
