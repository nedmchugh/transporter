// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/pairing"
	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/secure"
	"github.com/nedmchugh/transporter/internal/testutil"
)

// TestE2ETree covers TEST-8 scenario 2: nested tree with empty directories,
// about 5000 small files, Unicode names and spaces (TREE-4, XFER-6, TEST-10).
func TestE2ETree(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	files := map[string]string{
		"proj/empty/":                       "",
		"proj/deep/a/b/c/d/e/":              "",
		"proj/with space/file name.txt":     "spaces",
		"proj/ünïcødé/日本語.txt":              "unicode",
		"proj/ünïcødé/emoji-\U0001F600.txt": "emoji",
	}
	n := 5000
	if testing.Short() {
		n = 1000
	}
	for i := range n {
		files[fmt.Sprintf("proj/many/d%02d/f%04d.txt", i%50, i)] = strings.Repeat("x", i%300)
	}
	testutil.WriteTree(t, src, files)
	r := startReceiver(t, dst)
	start := time.Now()
	res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "proj"))
	if res.exit != 0 {
		t.Fatalf("sender exit %d", res.exit)
	}
	if code := r.wait(t, 2*time.Minute); code != 0 {
		t.Fatalf("receiver exit %d", code)
	}
	t.Logf("%d files in %v", n, time.Since(start))
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mode: true, Mtime: true})
}

// TestE2EHostileManifest covers TEST-8 scenario 7: a test-only sender
// that knows the code sends a manifest with an escaping path; the real
// receiver rejects it, exits non-zero, and writes nothing.
func TestE2EHostileManifest(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	dst := filepath.Join(parent, "dest")
	r := startReceiver(t, dst)
	c, err := code.Parse(r.code)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pairing.NewCodePairer(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", r.addr())
	if err != nil {
		t.Fatal(err)
	}
	sc, err := secure.Client(context.Background(), raw, p)
	if err != nil {
		t.Fatal(err)
	}
	link := proto.NewLink(sc, proto.LinkConfig{})
	defer link.Close()
	_ = link.Send(proto.Hello{Version: proto.Version, SessionID: [16]byte{9}})
	if m, err := link.Recv(); err != nil || m.Type() != proto.TypeHello {
		t.Fatalf("hello: %v %v", m, err)
	}
	_ = link.Send(proto.Manifest{Entries: []proto.Entry{{Path: "../escaped.txt", Type: proto.EntryFile, Size: 4}}})
	_ = link.Send(proto.ManifestEnd{Count: 1, TotalBytes: 4})
	m, _ := link.Recv()
	if e, ok := m.(proto.Error); !ok || !e.Fatal {
		t.Fatalf("expected fatal ERROR, got %#v", m)
	}
	if code := r.wait(t, 30*time.Second); code != 1 {
		t.Fatalf("receiver exit %d, want 1", code)
	}
	ents, _ := os.ReadDir(parent)
	if len(ents) != 1 || ents[0].Name() != "dest" {
		t.Fatalf("something was written outside the destination: %v", ents)
	}
	if ents, _ := os.ReadDir(dst); len(ents) != 0 {
		t.Fatalf("destination not empty: %v", ents)
	}
}

// TestE2EOverwriteAndVerify covers TEST-8 scenario 8 (XFER-7, RES-2): a
// differing file is a conflict (exit 7 on both sides) and is kept; with
// --verify a same-size, same-mtime change is still detected; with
// --overwrite it is replaced.
func TestE2EOverwriteAndVerify(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	mt := time.Date(2023, 3, 3, 3, 3, 3, 0, time.UTC)
	write := func(p, s string) {
		testutil.WriteTree(t, filepath.Dir(p), map[string]string{filepath.Base(p): s})
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(src, "f.txt"), "new content")
	write(filepath.Join(dst, "f.txt"), "OLD CONTENT") // same size and mtime

	// Quick check passes (same size and mtime): skipped, exit 0.
	r := startReceiver(t, dst)
	if res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "f.txt")); res.exit != 0 {
		t.Fatalf("quick check run: exit %d", res.exit)
	}
	if r.wait(t, 30*time.Second) != 0 {
		t.Fatal("receiver failed")
	}
	// --verify on the sender detects the difference: conflict, exit 7.
	r = startReceiver(t, dst)
	res := runSender(t, nil, nil, "--verify", "--to", r.addr(), r.code, filepath.Join(src, "f.txt"))
	if res.exit != 7 || !strings.Contains(res.stderr, "Conflicts") {
		t.Fatalf("verify run: exit %d\n%s", res.exit, res.stderr)
	}
	if code := r.wait(t, 30*time.Second); code != 7 {
		t.Fatalf("receiver exit %d, want 7", code)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "f.txt")); string(b) != "OLD CONTENT" {
		t.Fatal("conflicting file was modified")
	}
	// --verify --overwrite on the receiver replaces it.
	r = startReceiver(t, "--verify", "--overwrite", dst)
	if res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "f.txt")); res.exit != 0 {
		t.Fatalf("overwrite run: exit %d", res.exit)
	}
	if r.wait(t, 30*time.Second) != 0 {
		t.Fatal("receiver failed")
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "f.txt")); string(b) != "new content" {
		t.Fatalf("not replaced: %q", b)
	}
}
