// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// WriteTree creates files under root. Keys are slash-separated relative
// paths; a key ending in "/" is a directory. Parent directories are created
// as needed.
func WriteTree(t testing.TB, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(p, "/")))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// RandomFile writes size pseudo-random bytes (deterministic for seed) to
// path, streaming so large files do not need large buffers.
func RandomFile(t testing.TB, path string, size int64, seed uint64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	buf := make([]byte, 1<<20)
	for left := size; left > 0; {
		n := min(int64(len(buf)), left)
		for i := range buf[:n] {
			buf[i] = byte(r.Uint32())
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		left -= n
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// Node describes one entry of a tree snapshot.
type Node struct {
	Dir   bool
	Size  int64
	Hash  string
	Mode  fs.FileMode
	Mtime time.Time
}

// Snapshot describes every entry under root by slash-separated relative
// path (TEST-10). Symlinks are recorded with Hash "symlink".
func Snapshot(t testing.TB, root string) map[string]Node {
	t.Helper()
	out := map[string]Node{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		n := Node{Dir: d.IsDir(), Mode: info.Mode().Perm(), Mtime: info.ModTime()}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			n.Hash = "symlink"
		case d.Type().IsRegular():
			n.Size = info.Size()
			n.Hash = hashFile(t, p)
		}
		out[rel] = n
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func hashFile(t testing.TB, p string) string {
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CompareOptions selects what CompareTrees checks besides paths, sizes and
// content.
type CompareOptions struct {
	Mode  bool // file permission bits (skipped on Windows)
	Mtime bool // file modification times, to the second
}

// CompareTrees fails the test unless the trees under want and got have the
// same entries, sizes and content hashes (TEST-10).
func CompareTrees(t testing.TB, want, got string, opts CompareOptions) {
	t.Helper()
	w, g := Snapshot(t, want), Snapshot(t, got)
	var keys []string
	for k := range w {
		keys = append(keys, k)
	}
	for k := range g {
		if _, ok := w[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		a, aok := w[k]
		b, bok := g[k]
		switch {
		case !aok:
			t.Errorf("unexpected %s in destination", k)
		case !bok:
			t.Errorf("missing %s in destination", k)
		case a.Dir != b.Dir || a.Size != b.Size || a.Hash != b.Hash:
			t.Errorf("%s differs: want %+v, got %+v", k, a, b)
		case a.Dir:
		case opts.Mode && runtime.GOOS != "windows" && a.Mode != b.Mode:
			t.Errorf("%s mode: want %v, got %v", k, a.Mode, b.Mode)
		case opts.Mtime && a.Mtime.Unix() != b.Mtime.Unix():
			t.Errorf("%s mtime: want %v, got %v", k, a.Mtime, b.Mtime)
		}
	}
}
