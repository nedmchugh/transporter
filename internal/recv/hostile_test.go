// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recv

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/transporter/internal/code"
	"github.com/OWNER/transporter/internal/fail"
	"github.com/OWNER/transporter/internal/pairing"
	"github.com/OWNER/transporter/internal/proto"
	"github.com/OWNER/transporter/internal/secure"
	"github.com/OWNER/transporter/internal/testutil"
)

const testCode = "abandon-ability-able-about-above-absent-absorb-abstract-absurd"

var fastLink = proto.LinkConfig{Heartbeat: 100 * time.Millisecond, DeadAfter: 2 * time.Second}

func testPairer(t testing.TB) pairing.Pairer {
	t.Helper()
	c, err := code.Parse(testCode)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pairing.NewCodePairer(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type logWriter struct{ t testing.TB }

func (w logWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// running is an in-process receiver on loopback.
type running struct {
	addr string
	done chan struct{}
	sum  *Summary
	err  error
}

func start(t *testing.T, dest string, mod func(*Options)) *running {
	t.Helper()
	opts := Options{
		Dest: dest, Pairer: testPairer(t), Link: fastLink, Linger: 100 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(logWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if mod != nil {
		mod(&opts)
	}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &running{addr: ln.Addr().String(), done: make(chan struct{})}
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

func (h *running) wait(t *testing.T) (*Summary, error) {
	t.Helper()
	select {
	case <-h.done:
		return h.sum, h.err
	case <-time.After(20 * time.Second):
		t.Fatal("receiver did not stop")
		return nil, nil
	}
}

// client is a hand-driven sender used to send crafted messages (TEST-5,
// TEST-8 scenario 7).
type client struct {
	t    *testing.T
	link *proto.Link
}

func dialClient(t *testing.T, addr string, sid byte) *client {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := secure.Client(context.Background(), raw, testPairer(t))
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, link: proto.NewLink(sc, fastLink)}
	t.Cleanup(func() { _ = c.link.Close() })
	c.send(proto.Hello{Version: proto.Version, SessionID: [16]byte{sid}})
	if m := c.recv(); m == nil || m.Type() != proto.TypeHello {
		t.Fatalf("expected HELLO, got %#v", m)
	}
	return c
}

func (c *client) send(m proto.Message) {
	c.t.Helper()
	if err := c.link.Send(m); err != nil {
		c.t.Logf("send %v: %v", m.Type(), err)
	}
}

// recv returns the next message, or nil if the connection ended.
func (c *client) recv() proto.Message {
	c.t.Helper()
	m, err := c.link.Recv()
	if err != nil {
		return nil
	}
	return m
}

// expectFatal reads until a fatal ERROR (or the end) and returns its code.
func (c *client) expectFatal() proto.Code {
	c.t.Helper()
	for {
		m := c.recv()
		if m == nil {
			return proto.CodeOK
		}
		if e, ok := m.(proto.Error); ok && e.Fatal {
			return e.Code
		}
	}
}

func manifestOf(entries ...proto.Entry) []proto.Message {
	var total uint64
	for _, e := range entries {
		total += e.Size
	}
	return []proto.Message{proto.Manifest{Entries: entries}, proto.ManifestEnd{Count: uint32(len(entries)), TotalBytes: total}}
}

func fileE(p string, size uint64) proto.Entry {
	return proto.Entry{Path: p, Type: proto.EntryFile, Mode: 0o644, Size: size, MtimeSec: 1_600_000_000}
}

func dirE(p string) proto.Entry { return proto.Entry{Path: p, Type: proto.EntryDir, Mode: 0o755} }

// assertNothingOutside checks that the directory containing dest holds
// nothing except dest itself and the given extra names (TEST-5: nothing is
// written outside the destination).
func assertNothingOutside(t *testing.T, parent string, allowed ...string) {
	t.Helper()
	ents, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]bool{"dest": true}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, e := range ents {
		if !ok[e.Name()] {
			t.Errorf("unexpected %q outside the destination", e.Name())
		}
	}
}

// TestHostileManifest covers TEST-5, TREE-2, TREE-9, TREE-11, SEC-9,
// SEC-12 and D-5.10: each hostile manifest is rejected as fatal, the sender
// gets a fatal ERROR, and nothing is written.
func TestHostileManifest(t *testing.T) {
	testutil.CheckLeaks(t)
	tests := []struct {
		name    string
		entries []proto.Entry
		end     *proto.ManifestEnd
	}{
		{name: "dotdot", entries: []proto.Entry{fileE("../escape", 1)}},
		{name: "nested dotdot", entries: []proto.Entry{dirE("a"), fileE("a/../../escape", 1)}},
		{name: "absolute", entries: []proto.Entry{fileE("/tmp/escape", 1)}},
		{name: "backslash", entries: []proto.Entry{fileE("..\\escape", 1)}},
		{name: "nul", entries: []proto.Entry{fileE("a\x00b", 1)}},
		{name: "invalid utf8", entries: []proto.Entry{fileE("a\xffb", 1)}},
		{name: "dot component", entries: []proto.Entry{dirE("a"), fileE("a/./b", 1)}},
		{name: "empty component", entries: []proto.Entry{dirE("a"), fileE("a//b", 1)}},
		{name: "overlong component", entries: []proto.Entry{fileE(strings.Repeat("x", 256), 1)}},
		{name: "duplicate", entries: []proto.Entry{fileE("a", 1), fileE("a", 1)}},
		{name: "case collision", entries: []proto.Entry{fileE("Read.me", 1), fileE("read.ME", 1)}},
		{name: "unicode collision", entries: []proto.Entry{fileE("café", 1), fileE("café", 1)}},
		{name: "missing parent", entries: []proto.Entry{fileE("no/parent", 1)}},
		{name: "file as parent", entries: []proto.Entry{fileE("f", 1), fileE("f/child", 1)}},
		{name: "too many entries", entries: []proto.Entry{fileE("a", 1), fileE("b", 1), fileE("c", 1), fileE("d", 1)}},
		{name: "wrong end count", entries: []proto.Entry{fileE("a", 1)}, end: &proto.ManifestEnd{Count: 2, TotalBytes: 1}},
		{name: "wrong end bytes", entries: []proto.Entry{fileE("a", 1)}, end: &proto.ManifestEnd{Count: 1, TotalBytes: 9}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			h := start(t, dest, func(o *Options) { o.MaxEntries = 3 })
			c := dialClient(t, h.addr, 1)
			msgs := manifestOf(tc.entries...)
			if tc.end != nil {
				msgs[1] = *tc.end
			}
			for _, m := range msgs {
				c.send(m)
			}
			got := c.expectFatal()
			if got != proto.CodeBadManifest && got != proto.CodeProtocol {
				t.Fatalf("fatal code %v", got)
			}
			_, err := h.wait(t)
			if fail.KindOf(err) != fail.Protocol {
				t.Fatalf("receiver error %v", err)
			}
			ents, _ := os.ReadDir(dest)
			if len(ents) != 0 {
				t.Fatalf("destination not empty: %v", ents)
			}
			assertNothingOutside(t, parent)
		})
	}
}

// TestOutOfStateMessages covers SEC-10, SEC-13, PROTO-4 and TEST-5: messages
// that do not fit the state machine, or offsets outside the declared size,
// end the session as protocol violations.
func TestOutOfStateMessages(t *testing.T) {
	testutil.CheckLeaks(t)
	var h [32]byte
	tests := []struct {
		name string
		msgs []proto.Message // sent after the manifest {d/, d/f (64 KiB)} and its NEED
	}{
		{"chunk before start", []proto.Message{proto.Chunk{Index: 1, Offset: 0, Data: []byte("x")}}},
		{"end before start", []proto.Message{proto.FileEnd{Index: 1}}},
		{"start wrong offset", []proto.Message{proto.FileStart{Index: 1, Offset: proto.ChunkSize}}},
		{"start for directory", []proto.Message{proto.FileStart{Index: 0}}},
		{"start out of range", []proto.Message{proto.FileStart{Index: 99}}},
		{"start twice", []proto.Message{proto.FileStart{Index: 1}, proto.FileStart{Index: 1}}},
		{"chunk gap", []proto.Message{proto.FileStart{Index: 1}, proto.Chunk{Index: 1, Offset: 10, Data: []byte("x")}}},
		{"chunk beyond size", []proto.Message{proto.FileStart{Index: 1}, proto.Chunk{Index: 1, Offset: 0, Data: make([]byte, proto.ChunkSize)},
			proto.Chunk{Index: 1, Offset: proto.ChunkSize, Data: make([]byte, proto.ChunkSize)},
			proto.Chunk{Index: 1, Offset: 2 * proto.ChunkSize, Data: []byte("over")}}},
		{"end early", []proto.Message{proto.FileStart{Index: 1}, proto.Chunk{Index: 1, Offset: 0, Data: []byte("x")}, proto.FileEnd{Index: 1, Hash: h}}},
		{"done early", []proto.Message{proto.Done{}}},
		{"hello again", []proto.Message{proto.Hello{Version: proto.Version}}},
		{"manifest again", []proto.Message{proto.Manifest{Entries: []proto.Entry{fileE("z", 1)}}}},
		{"verify result unexpected", []proto.Message{proto.VerifyResult{Index: 1, Same: true}}},
		{"abort for directory", []proto.Message{proto.FileAbort{Index: 0, Code: proto.CodeChanged}}},
		{"ack from sender", []proto.Message{proto.Ack{Index: 1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			hr := start(t, dest, nil)
			c := dialClient(t, hr.addr, 2)
			for _, m := range manifestOf(dirE("d"), fileE("d/f", 2*proto.ChunkSize)) {
				c.send(m)
			}
			// Wait for the NEED covering both entries.
			for seen := 0; seen < 2; {
				m := c.recv()
				n, ok := m.(proto.Need)
				if !ok {
					t.Fatalf("expected NEED, got %#v", m)
				}
				seen += len(n.Records)
			}
			for _, m := range tc.msgs {
				c.send(m)
			}
			if got := c.expectFatal(); got != proto.CodeProtocol {
				t.Fatalf("fatal code %v", got)
			}
			if _, err := hr.wait(t); fail.KindOf(err) != fail.Protocol {
				t.Fatalf("receiver error %v", err)
			}
			if _, err := os.Stat(filepath.Join(dest, "d", "f")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("file appeared under its final name")
			}
			assertNothingOutside(t, parent)
		})
	}
}

// TestNotHello and TestVersionMismatch cover PROTO-3 and SEC-13 before the
// session starts.
func TestVersionMismatch(t *testing.T) {
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), nil)
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := secure.Client(context.Background(), raw, testPairer(t))
	if err != nil {
		t.Fatal(err)
	}
	link := proto.NewLink(sc, fastLink)
	defer link.Close()
	_ = link.Send(proto.Hello{Version: 2})
	m, err := link.Recv()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m.(proto.Error)
	if !ok || e.Code != proto.CodeVersion || !e.Fatal || !strings.Contains(e.Message, "version 1") || !strings.Contains(e.Message, "version 2") {
		t.Fatalf("got %#v", m)
	}
	if _, err := h.wait(t); fail.KindOf(err) != fail.Protocol || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("receiver error %v", err)
	}
}

func TestNotHello(t *testing.T) {
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), nil)
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := secure.Client(context.Background(), raw, testPairer(t))
	if err != nil {
		t.Fatal(err)
	}
	link := proto.NewLink(sc, fastLink)
	defer link.Close()
	_ = link.Send(proto.Done{})
	if _, err := h.wait(t); fail.KindOf(err) != fail.Protocol {
		t.Fatalf("receiver error %v", err)
	}
}

// TestSymlinkEscape covers SEC-9, SEC-11 and TEST-5: symlinks in the
// destination, whether pointing outside or inside, are never followed;
// affected entries become per-file errors and nothing outside changes.
func TestSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	testutil.CheckLeaks(t)
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	outside := filepath.Join(parent, "outside")
	testutil.WriteTree(t, parent, map[string]string{"outside/target": "original", "dest/inner/": ""})
	for link, target := range map[string]string{
		"linkdir":   outside,                          // directory symlink out of the root
		"linkfile":  filepath.Join(outside, "target"), // file symlink out of the root
		"part.part": filepath.Join(outside, "target"), // .part symlink out of the root
		"innerlink": filepath.Join(dest, "inner"),     // symlink that stays inside
		"rel":       filepath.Join("..", "outside"),   // relative escape
	} {
		if err := os.Symlink(target, filepath.Join(dest, link)); err != nil {
			t.Fatal(err)
		}
	}
	h := start(t, dest, func(o *Options) { o.Overwrite = true })
	c := dialClient(t, h.addr, 3)
	entries := []proto.Entry{
		dirE("innerlink"), fileE("innerlink/x", 3),
		dirE("linkdir"), fileE("linkdir/target", 3),
		fileE("linkfile", 3),
		fileE("part", 3),
		dirE("rel"), fileE("rel/target", 3),
	}
	for _, m := range manifestOf(entries...) {
		c.send(m)
	}
	var recs []proto.NeedRecord
	for len(recs) < len(entries) {
		n, ok := c.recv().(proto.Need)
		if !ok {
			t.Fatal("expected NEED")
		}
		recs = append(recs, n.Records...)
	}
	want := []proto.Code{proto.CodeSymlink, proto.CodeParentFailed, proto.CodeSymlink, proto.CodeParentFailed,
		proto.CodeSymlink, proto.CodeSymlink, proto.CodeSymlink, proto.CodeParentFailed}
	for i, r := range recs {
		if r.Action != proto.NeedError || r.Code != want[i] {
			t.Errorf("entry %d (%s): action %d code %v, want error %v", i, entries[i].Path, r.Action, r.Code, want[i])
		}
	}
	c.send(proto.Done{})
	if d, ok := c.recv().(proto.Done); !ok || d.Errors != uint64(len(entries)) {
		t.Fatalf("DONE %+v", d)
	}
	sum, err := h.wait(t)
	if err != nil || sum.Kind() != fail.Partial {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "target")); string(b) != "original" {
		t.Fatal("file outside the destination was modified")
	}
	ents, _ := os.ReadDir(outside)
	if len(ents) != 1 {
		t.Fatalf("outside has %d entries", len(ents))
	}
	if ents, _ := os.ReadDir(filepath.Join(dest, "inner")); len(ents) != 0 {
		t.Fatal("symlink inside the destination was followed")
	}
	assertNothingOutside(t, parent, "outside")
}

// TestTypeConflicts covers RES-5 and D-5.11: clashes between files and
// directories, and NAME.part names in the manifest, are per-file errors.
func TestTypeConflicts(t *testing.T) {
	testutil.CheckLeaks(t)
	dest := filepath.Join(t.TempDir(), "dest")
	testutil.WriteTree(t, dest, map[string]string{
		"isdir/":        "",
		"isfile":        "x",
		"partdir.part/": "",
	})
	h := start(t, dest, func(o *Options) { o.Overwrite = true })
	c := dialClient(t, h.addr, 4)
	entries := []proto.Entry{
		fileE("isdir", 1),        // a directory exists where the file goes
		dirE("isfile"),           // a file exists where the directory goes
		fileE("isfile/child", 1), // child of the failed directory
		fileE("partdir", 1),      // its .part name is a directory
		fileE("t", 1),            // t.part is also in the manifest
		fileE("t.part", 1),
	}
	for _, m := range manifestOf(entries...) {
		c.send(m)
	}
	var recs []proto.NeedRecord
	for len(recs) < len(entries) {
		n, ok := c.recv().(proto.Need)
		if !ok {
			t.Fatal("expected NEED")
		}
		recs = append(recs, n.Records...)
	}
	want := []proto.Code{proto.CodeTypeConflict, proto.CodeTypeConflict, proto.CodeParentFailed, proto.CodeTypeConflict, proto.CodeTempName}
	for i, w := range want {
		if recs[i].Action != proto.NeedError || recs[i].Code != w {
			t.Errorf("entry %d (%s): %+v, want %v", i, entries[i].Path, recs[i], w)
		}
	}
	if recs[5].Action != proto.NeedSend {
		t.Errorf("t.part itself should be sendable: %+v", recs[5])
	}
	// Send t.part, then finish.
	c.send(proto.FileStart{Index: 5})
	c.send(proto.Chunk{Index: 5, Data: []byte("z")})
	c.send(proto.FileEnd{Index: 5, Hash: hashOf("z")})
	if a, ok := c.recv().(proto.Ack); !ok || a.Status != proto.AckOK {
		t.Fatalf("ack %+v", a)
	}
	c.send(proto.Done{})
	if _, ok := c.recv().(proto.Done); !ok {
		t.Fatal("no DONE")
	}
	sum, err := h.wait(t)
	if err != nil || sum.Transferred != 1 || len(sum.Errors) != 5 {
		t.Fatalf("summary %+v err %v", sum, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "isfile")); string(b) != "x" {
		t.Fatal("existing file was modified")
	}
}

func hashOf(s string) [32]byte {
	h := newHasher()
	_, _ = h.Write([]byte(s))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// TestWindowsInvalidNames covers TREE-10 on Windows receivers.
func TestWindowsInvalidNames(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only rule (TREE-10); ValidateWindowsPath is unit-tested on all platforms")
	}
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), nil)
	c := dialClient(t, h.addr, 5)
	entries := []proto.Entry{fileE("CON", 1), fileE("a:b", 1), fileE("trail.", 1), fileE("ok", 0)}
	for _, m := range manifestOf(entries...) {
		c.send(m)
	}
	var recs []proto.NeedRecord
	for len(recs) < len(entries) {
		n := c.recv().(proto.Need)
		recs = append(recs, n.Records...)
	}
	for i := range 3 {
		if recs[i].Code != proto.CodeInvalidName {
			t.Errorf("entry %d: %+v", i, recs[i])
		}
	}
}
