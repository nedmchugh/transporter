// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package send

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/OWNER/transporter/internal/proto"
	"github.com/OWNER/transporter/internal/recv"
	"github.com/OWNER/transporter/internal/testutil"
)

// copyPrefix writes the first n bytes of src to dst, followed by tail.
func copyPrefix(t *testing.T, src, dst string, n int64, tail []byte) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(out, in, n); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write(tail); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestResumeFromPart covers XFER-1, XFER-2, RES-1 and RES-3: an existing
// .part with a valid prefix and a torn tail is resumed from the last chunk
// boundary, only the remainder is sent, and the result is byte-identical.
func TestResumeFromPart(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	const size = 10*proto.ChunkSize + 77
	p := filepath.Join(src, "big.bin")
	testutil.RandomFile(t, p, size, 7)
	// 4 full chunks plus 1000 bytes of a torn fifth chunk, with garbage
	// at the end of the torn part (a crash can leave anything there).
	torn := make([]byte, 1000)
	for i := range torn {
		torn[i] = 0xAA
	}
	copyPrefix(t, p, filepath.Join(dst, "big.bin.part"), 4*proto.ChunkSize, torn)
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Transferred != 1 || sum.Bytes != size-4*proto.ChunkSize {
		t.Fatalf("summary %+v: want only %d bytes sent", sum, size-4*proto.ChunkSize)
	}
	rs, err := h.wait(t)
	if err != nil || rs.Bytes != size-4*proto.ChunkSize {
		t.Fatalf("receiver %+v %v", rs, err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mtime: true})
}

// TestResumeBadPrefix covers XFER-4 with resume: a .part whose prefix does
// not match the source fails the final hash, is deleted, and the file is
// resent from offset 0.
func TestResumeBadPrefix(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	p := filepath.Join(src, "f.bin")
	testutil.RandomFile(t, p, 3*proto.ChunkSize, 1)
	testutil.RandomFile(t, filepath.Join(dst, "f.bin.part"), 2*proto.ChunkSize, 2) // wrong content
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{p}, nil)
	if err != nil || sum.Transferred != 1 || len(sum.Integrity) != 0 {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestResumeOversizedPart: a .part longer than the file is stale and the
// transfer restarts at zero (RES-3).
func TestResumeOversizedPart(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	p := filepath.Join(src, "f.bin")
	testutil.RandomFile(t, p, proto.ChunkSize, 1)
	testutil.RandomFile(t, filepath.Join(dst, "f.bin.part"), 5*proto.ChunkSize, 2)
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{p}, nil)
	if err != nil || sum.Bytes != proto.ChunkSize {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestStrayPartsUntouched covers RES-4: .part files for paths not in the
// manifest are left alone and listed in the summary.
func TestStrayPartsUntouched(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"d/a": "a"})
	testutil.WriteTree(t, dst, map[string]string{"other.part": "keep me", "d/old.part": "keep me too"})
	h := startReceiver(t, dst, nil)
	if _, err := runSend(t, h.addr, []string{filepath.Join(src, "d")}, nil); err != nil {
		t.Fatal(err)
	}
	rs, err := h.wait(t)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rs.StrayParts, []string{"d/old.part", "other.part"}) {
		t.Fatalf("stray parts %v", rs.StrayParts)
	}
	for _, p := range []string{"other.part", "d/old.part"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err != nil {
			t.Fatalf("%s was removed", p)
		}
	}
}

// TestPipelining covers XFER-6 and REL-8: the sender has several files in
// flight without waiting for each ACK, and never more than the bounds.
func TestPipelining(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	files := map[string]string{}
	for i := range 200 {
		files[fmt.Sprintf("many/f%03d", i)] = fmt.Sprint(i)
	}
	files["many/big"] = string(make([]byte, 3*proto.MaxInFlightBytes/2))
	testutil.WriteTree(t, src, files)
	var mu sync.Mutex
	maxFiles, maxBytes := 0, uint64(0)
	testObserveInflight = func(f int, b uint64) {
		mu.Lock()
		maxFiles, maxBytes = max(maxFiles, f), max(maxBytes, b)
		mu.Unlock()
	}
	defer func() { testObserveInflight = nil }()
	// A single slow finalizer makes ACKs lag behind, so pipelining shows.
	h := startReceiver(t, dst, func(o *recv.Options) { o.Finalizers = 1 })
	if _, err := runSend(t, h.addr, []string{filepath.Join(src, "many")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
	mu.Lock()
	defer mu.Unlock()
	if maxFiles < 2 {
		t.Fatalf("no pipelining observed (max %d file in flight)", maxFiles)
	}
	if maxFiles > proto.MaxInFlightFiles {
		t.Fatalf("%d files in flight exceeds %d", maxFiles, proto.MaxInFlightFiles)
	}
	// The byte bound is checked before a file starts, so it can be
	// exceeded by at most one file.
	if maxBytes > proto.MaxInFlightBytes+uint64(len(files["many/big"])) {
		t.Fatalf("%d bytes in flight", maxBytes)
	}
}
