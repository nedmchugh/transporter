// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recv

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/OWNER/transporter/internal/fail"
	"github.com/OWNER/transporter/internal/proto"
	"github.com/OWNER/transporter/internal/testutil"
)

// TestResumeOffset covers RES-3 and TREE-5: rounding down to a chunk
// boundary, with 64-bit sizes beyond 4 GiB.
func TestResumeOffset(t *testing.T) {
	const c = proto.ChunkSize
	tests := []struct {
		part int64
		size uint64
		want uint64
	}{
		{0, 100, 0},
		{-1, 100, 0},
		{c - 1, 10 * c, 0},
		{c, 10 * c, c},
		{3*c + 5, 10 * c, 3 * c},
		{10 * c, 10 * c, 10 * c},
		{10*c + 1, 10 * c, 0}, // longer than the file: stale
		{5<<30 + 12345, 6 << 30, 5 << 30},
	}
	for _, tc := range tests {
		if got := resumeOffset(tc.part, tc.size); got != tc.want {
			t.Errorf("resumeOffset(%d, %d) = %d, want %d", tc.part, tc.size, got, tc.want)
		}
	}
}

type fakeInfo struct {
	fs.FileInfo
	size int64
	mt   time.Time
}

func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) ModTime() time.Time { return f.mt }

// TestQuickCheck covers RES-2: size equality and a 2-second mtime
// tolerance in both directions.
func TestQuickCheck(t *testing.T) {
	base := time.Unix(1_700_000_000, 500_000_000)
	e := proto.Entry{Size: 10, MtimeSec: base.Unix(), MtimeNsec: uint32(base.Nanosecond())}
	tests := []struct {
		size int64
		d    time.Duration
		want bool
	}{
		{10, 0, true},
		{10, 2 * time.Second, true},
		{10, -2 * time.Second, true},
		{10, 2*time.Second + time.Millisecond, false},
		{10, -2*time.Second - time.Millisecond, false},
		{11, 0, false},
		{-1, 0, false},
	}
	for _, tc := range tests {
		if got := quickCheck(fakeInfo{size: tc.size, mt: base.Add(tc.d)}, e); got != tc.want {
			t.Errorf("size %d, delta %v: got %v", tc.size, tc.d, got)
		}
	}
	if QuickCheckTolerance != 2*time.Second {
		t.Fatal("RES-2 tolerance changed")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteTree(t, dir, map[string]string{"f": "hello world", "d/": ""})
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	h, err := hashFile(context.Background(), root, "f", 5)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != fmt.Sprintf("%x", hashOf("hello")) {
		t.Fatal("prefix hash wrong")
	}
	if _, err := hashFile(context.Background(), root, "f", 50); err == nil {
		t.Fatal("short file accepted")
	}
	if _, err := hashFile(context.Background(), root, "d", -1); err == nil {
		t.Fatal("directory hashed")
	}
	if _, err := hashFile(context.Background(), root, "missing", -1); err == nil {
		t.Fatal("missing file hashed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashFile(ctx, root, "f", -1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	nospace := &fs.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}
	if !isNoSpace(nospace) || fail.KindOf(fsFatal(nospace)) != fail.FS || !errors.Is(fsFatal(nospace), errNoSpace) {
		t.Fatal("ENOSPC not fatal FS")
	}
	if !isNotWritable(fs.ErrPermission) || fail.KindOf(fsFatal(fs.ErrPermission)) != fail.FS {
		t.Fatal("permission not classified")
	}
	if fsFatal(errors.New("other")) != nil {
		t.Fatal("other error classified as fatal")
	}
	if freeSpace(t.TempDir()) == 0 {
		t.Fatal("free space reported as zero")
	}
}

// TestNoSpace covers RCV-9 and CLI-7 exit 5: when the destination clearly
// lacks space for what must be transferred, the receiver fails before any
// data is accepted and tells the sender.
func TestNoSpace(t *testing.T) {
	testutil.CheckLeaks(t)
	saved := diskFree
	diskFree = func(string) int64 { return 10 }
	defer func() { diskFree = saved }()
	h := start(t, filepath.Join(t.TempDir(), "dest"), nil)
	c := dialClient(t, h.addr, 6)
	for _, m := range manifestOf(fileE("big", 1000)) {
		c.send(m)
	}
	if got := c.expectFatal(); got != proto.CodeNoSpace {
		t.Fatalf("fatal code %v", got)
	}
	_, err := h.wait(t)
	if fail.KindOf(err) != fail.FS || fail.KindOf(err).ExitCode() != 5 {
		t.Fatalf("receiver error %v", err)
	}
}

// TestDestinationNotWritable covers CLI-7 exit 5 at startup (D-4.8).
func TestDestinationNotWritable(t *testing.T) {
	if os.Getuid() == 0 || isWindows() {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	_, err := New(Options{Dest: dir, Pairer: testPairer(t)})
	if fail.KindOf(err) != fail.FS {
		t.Fatalf("got %v", err)
	}
	if _, err := New(Options{Dest: filepath.Join(dir, "sub"), Pairer: testPairer(t)}); fail.KindOf(err) != fail.FS {
		t.Fatalf("uncreatable dest: %v", err)
	}
	if _, err := New(Options{Dest: dir}); err == nil {
		t.Fatal("missing pairer accepted")
	}
}

func isWindows() bool { return filepath.Separator == '\\' }

// TestIdleTimeout covers RCV-7 and CLI-7 exit 4: no sender within the
// idle timeout ends the receiver with a network failure.
func TestIdleTimeout(t *testing.T) {
	testutil.CheckLeaks(t)
	h := start(t, filepath.Join(t.TempDir(), "dest"), func(o *Options) { o.IdleTimeout = 200 * time.Millisecond })
	_, err := h.wait(t)
	if fail.KindOf(err) != fail.Network {
		t.Fatalf("got %v", err)
	}
}

// TestDirectoryCreatedEvenIfPresent covers TREE-4 with existing directories
// and that directories are created 0755-masked (D-5.8, TREE-7).
func TestExistingDirectories(t *testing.T) {
	testutil.CheckLeaks(t)
	dest := filepath.Join(t.TempDir(), "dest")
	testutil.WriteTree(t, dest, map[string]string{"d/": ""})
	h := start(t, dest, nil)
	c := dialClient(t, h.addr, 7)
	for _, m := range manifestOf(dirE("d"), proto.Entry{Path: "d/new", Type: proto.EntryDir, Mode: 0o777}) {
		c.send(m)
	}
	n, ok := c.recv().(proto.Need)
	if !ok || len(n.Records) != 2 || n.Records[0].Action != proto.NeedSkip || n.Records[1].Action != proto.NeedSkip {
		t.Fatalf("NEED %+v", n)
	}
	c.send(proto.Done{})
	if _, ok := c.recv().(proto.Done); !ok {
		t.Fatal("no DONE")
	}
	if _, err := h.wait(t); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dest, "d", "new"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&^0o755 != 0 {
		t.Fatalf("new dir: %v %v", fi.Mode(), err)
	}
}
