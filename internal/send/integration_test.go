// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package send

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/manifest"
	"github.com/nedmchugh/transporter/internal/pairing"
	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/recv"
	"github.com/nedmchugh/transporter/internal/testutil"
)

const testCode = "abandon-ability-able-about-above-absent-absorb-abstract-absurd"

// fastLink keeps fault tests quick while exercising the same code paths.
var fastLink = proto.LinkConfig{Heartbeat: 100 * time.Millisecond, DeadAfter: 2 * time.Second}

func testPairer(t testing.TB, s string) pairing.Pairer {
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

// rcv is a receiver running in-process on a loopback listener.
type rcv struct {
	r    *recv.Receiver
	addr string
	done chan struct{}
	sum  *recv.Summary
	err  error
	stop context.CancelFunc
}

func startReceiver(t *testing.T, dest string, mod func(*recv.Options)) *rcv {
	t.Helper()
	opts := recv.Options{
		Dest: dest, Pairer: testPairer(t, testCode), Link: fastLink,
		Linger: 200 * time.Millisecond, Logger: testLogger(t),
	}
	if mod != nil {
		mod(&opts)
	}
	r, err := recv.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &rcv{r: r, addr: ln.Addr().String(), done: make(chan struct{}), stop: cancel}
	go func() {
		defer close(h.done)
		h.sum, h.err = r.Run(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-h.done
		_ = r.Close()
	})
	return h
}

func (h *rcv) wait(t *testing.T) (*recv.Summary, error) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(30 * time.Second):
		t.Fatal("receiver did not finish")
	}
	return h.sum, h.err
}

func testLogger(t testing.TB) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t testing.TB }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func mustWalkB(t testing.TB, sources ...string) *manifest.List {
	t.Helper()
	l, err := manifest.Walk(sources)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func mustWalk(t *testing.T, sources ...string) *manifest.List {
	t.Helper()
	l, err := manifest.Walk(sources)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func runSend(t *testing.T, addr string, sources []string, mod func(*Options)) (*Summary, error) {
	t.Helper()
	list, err := manifest.Walk(sources)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		List: list, Addr: addr, Pairer: testPairer(t, testCode), Link: fastLink,
		RetryTimeout: 5 * time.Second, Logger: testLogger(t),
		Backoff: &Backoff{Base: 10 * time.Millisecond, Factor: 2, Cap: 100 * time.Millisecond},
	}
	if mod != nil {
		mod(&opts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return Run(ctx, opts)
}

// TestSingleFile covers XFER-1, XFER-3, XFER-5, TREE-7 and PROTO-7: a file
// arrives intact with its mode and mtime, and no .part file remains.
func TestSingleFile(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	p := filepath.Join(src, "data.bin")
	testutil.RandomFile(t, p, 3*proto.ChunkSize+123, 1)
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2020, 1, 2, 3, 4, 5, 600_000_000, time.UTC)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Transferred != 1 || sum.Kind() != fail.None || sum.Receiver == nil || sum.Receiver.Transferred != 1 {
		t.Fatalf("summary %+v", sum)
	}
	rs, rerr := h.wait(t)
	if rerr != nil || rs.Transferred != 1 || rs.Bytes != 3*proto.ChunkSize+123 {
		t.Fatalf("receiver: %+v %v", rs, rerr)
	}
	want := filepath.Join(t.TempDir(), "want")
	if err := os.Mkdir(want, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(want, "data.bin")); err != nil {
		t.Skip("hard links unsupported:", err)
	}
	testutil.CompareTrees(t, want, dst, testutil.CompareOptions{Mode: true, Mtime: true})
	fi, err := os.Stat(filepath.Join(dst, "data.bin"))
	if err != nil || !fi.ModTime().Equal(mt) {
		t.Fatalf("mtime %v, want %v (%v)", fi.ModTime(), mt, err)
	}
}

// TestEmptyFileAndDirs covers TREE-4 (empty directories) and zero-length
// files.
func TestEmptyFileAndDirs(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{
		"tree/empty.txt":       "",
		"tree/empty-dir/":      "",
		"tree/a/b/c/":          "",
		"tree/a/b/file":        "content",
		"tree/a/sibling":       strings.Repeat("x", proto.ChunkSize),
		"tree/ünïcode ñame.md": "unicode",
	})
	h := startReceiver(t, dst, nil)
	if _, err := runSend(t, h.addr, []string{filepath.Join(src, "tree")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mtime: true})
}

// TestMultipleSources covers SND-1 and SND-2 naming.
func TestMultipleSources(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"one.txt": "1", "dir/two.txt": "2"})
	h := startReceiver(t, dst, nil)
	if _, err := runSend(t, h.addr, []string{filepath.Join(src, "one.txt"), filepath.Join(src, "dir")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestHashMismatchRetransmitsOnce covers XFER-4: data corrupted after
// hashing is detected, the .part is deleted, and the file is resent once.
func TestHashMismatchRetransmitsOnce(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f.txt": "the quick brown fox"})
	corrupted := 0
	testCorruptChunk = func(_ uint32, _ uint64, data []byte) {
		if corrupted == 0 {
			data[0] ^= 1
		}
		corrupted++
	}
	defer func() { testCorruptChunk = nil }()
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{filepath.Join(src, "f.txt")}, nil)
	if err != nil || sum.Transferred != 1 || corrupted != 2 {
		t.Fatalf("sum %+v err %v corrupted %d", sum, err, corrupted)
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
}

// TestHashMismatchTwiceIsIntegrityFailure covers XFER-4 and CLI-7: a second
// mismatch is an integrity failure (exit 6) reported after other files
// finish, and the file never appears under its final name (XFER-3).
func TestHashMismatchTwiceIsIntegrityFailure(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"d/bad.txt": "always corrupted", "d/good.txt": "fine"})
	list, err := manifest.Walk([]string{filepath.Join(src, "d")})
	if err != nil {
		t.Fatal(err)
	}
	var badIdx uint32
	for i, it := range list.Items {
		if it.Path == "d/bad.txt" {
			badIdx = uint32(i)
		}
	}
	testCorruptChunk = func(idx uint32, _ uint64, data []byte) {
		if idx == badIdx {
			data[0] ^= 1
		}
	}
	defer func() { testCorruptChunk = nil }()
	h := startReceiver(t, dst, nil)
	sum, err := runSend(t, h.addr, []string{filepath.Join(src, "d")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Integrity) != 1 || sum.Integrity[0] != "d/bad.txt" || sum.Transferred != 1 || sum.Kind().ExitCode() != 6 {
		t.Fatalf("summary %+v", sum)
	}
	rs, rerr := h.wait(t)
	if rerr != nil || len(rs.Integrity) != 1 || rs.Kind().ExitCode() != 6 {
		t.Fatalf("receiver %+v %v", rs, rerr)
	}
	if _, err := os.Stat(filepath.Join(dst, "d", "bad.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupted file visible under its final name")
	}
	if b, err := os.ReadFile(filepath.Join(dst, "d", "good.txt")); err != nil || !bytes.Equal(b, []byte("fine")) {
		t.Fatal("good file missing")
	}
}

// TestWrongCode covers REL-5 and TEST-8 scenario 6 in-process: a wrong code
// fails at once with an authentication error (no retries) and writes
// nothing.
func TestWrongCode(t *testing.T) {
	testutil.CheckLeaks(t)
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f": "x"})
	h := startReceiver(t, dst, nil)
	start := time.Now()
	sum, err := runSend(t, h.addr, []string{filepath.Join(src, "f")}, func(o *Options) {
		o.Pairer = testPairer(t, "zoo-zone-zero-youth-young-yellow-year-wrong-write")
	})
	if fail.KindOf(err) != fail.Auth || sum.Retries != 0 {
		t.Fatalf("err %v, retries %d", err, sum.Retries)
	}
	if !strings.Contains(fail.HintOf(err), "code may be wrong") {
		t.Fatalf("hint %q", fail.HintOf(err))
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("wrong code did not fail fast")
	}
	entries, _ := os.ReadDir(dst)
	if len(entries) != 0 {
		t.Fatalf("destination not empty: %v", entries)
	}
}
