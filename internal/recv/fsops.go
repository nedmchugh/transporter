// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package recv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"lukechampine.com/blake3"

	"github.com/nedmchugh/transporter/internal/proto"
)

// All filesystem access to the destination goes through *os.Root (SEC-9).
// os.Root blocks ".." and symlinks that lead outside the destination, but it
// does follow symlinks that stay inside. SEC-11 forbids that, so every name
// is Lstat'ed first and symlinks are refused (docs/DECISIONS.md D-4.6).

// PartSuffix is appended to a file's name while it is being received
// (XFER-2).
const PartSuffix = ".part"

// QuickCheckTolerance is the mtime tolerance of the quick check (RES-2).
const QuickCheckTolerance = 2 * time.Second

// newHasher returns a BLAKE3-256 hasher (XFER-1).
func newHasher() *blake3.Hasher { return blake3.New(proto.HashSize, nil) }

// native converts a validated wire path to the platform's separator.
func native(wire string) string { return filepath.FromSlash(wire) }

// kind of an existing name, from Lstat.
type nameKind int

const (
	kMissing nameKind = iota
	kRegular
	kDir
	kSymlink
	kOther
)

// lstatKind classifies name without following a final symlink.
func lstatKind(root *os.Root, name string) (nameKind, fs.FileInfo, error) {
	fi, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return kMissing, nil, nil
	case err != nil:
		return kOther, nil, err
	}
	m := fi.Mode()
	switch {
	case m&fs.ModeSymlink != 0:
		return kSymlink, fi, nil
	case m.IsRegular():
		return kRegular, fi, nil
	case m.IsDir():
		return kDir, fi, nil
	}
	return kOther, fi, nil
}

// quickCheck reports whether an existing file matches the entry by size and
// mtime within QuickCheckTolerance (RES-2).
func quickCheck(fi fs.FileInfo, e proto.Entry) bool {
	if fi.Size() < 0 || uint64(fi.Size()) != e.Size {
		return false
	}
	d := fi.ModTime().Sub(mtime(e))
	return d <= QuickCheckTolerance && d >= -QuickCheckTolerance
}

func mtime(e proto.Entry) time.Time { return time.Unix(e.MtimeSec, int64(e.MtimeNsec)) }

// resumeOffset is the .part size rounded down to a chunk boundary (RES-3):
// a crash can leave a torn tail, and whole chunks are what the sender
// resends. A .part longer than the file is stale and restarts at zero.
func resumeOffset(partSize int64, fileSize uint64) uint64 {
	if partSize <= 0 || uint64(partSize) > fileSize {
		return 0
	}
	return uint64(partSize) / proto.ChunkSize * proto.ChunkSize
}

// hashFile hashes the first n bytes of a regular file (n < 0: all of it),
// checking ctx between reads so a large file does not delay shutdown.
func hashFile(ctx context.Context, root *os.Root, name string, n int64) (*blake3.Hasher, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	var r io.Reader = f
	if n >= 0 {
		r = io.LimitReader(f, n)
	}
	h := newHasher()
	buf := make([]byte, 256<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		k, err := r.Read(buf)
		_, _ = h.Write(buf[:k])
		total += int64(k)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if n >= 0 && total != n {
		return nil, fmt.Errorf("%s is shorter than expected", name)
	}
	return h, nil
}

// syncDir flushes a directory so a rename in it is durable (XFER-3).
// Windows cannot fsync a directory handle; there it is skipped.
func syncDir(root *os.Root, dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	// Some filesystems (for example some network mounts) do not support
	// syncing directories; that is not a reason to fail the file.
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}

// diskFree is freeSpace, replaceable by tests of the RCV-9 check.
var diskFree = freeSpace

// isNoSpace reports whether err means the filesystem is full; that is fatal
// for the whole transfer (REL-4).
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || isNoSpacePlatform(err)
}

// isNotWritable reports whether err is a permission or read-only error.
func isNotWritable(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS)
}
