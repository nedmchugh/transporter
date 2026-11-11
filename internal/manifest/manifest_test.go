// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/testutil"
)

// hostilePaths is the TEST-5 corpus of wire paths that must be rejected by
// ValidatePath (TREE-2, TREE-11).
var hostilePaths = []string{
	"",
	"/etc/passwd",
	"/",
	"../escape",
	"a/../../escape",
	"a/..",
	"..",
	".",
	"./a",
	"a/./b",
	"a//b",
	"a/",
	"a\\..\\b",
	"..\\escape",
	"C:\\Windows",
	"\\\\server\\share",
	"nul\x00byte",
	"bad\xffutf8",
	strings.Repeat("a", proto.MaxComponentLen+1),
	strings.Repeat("a/", proto.MaxPathLen/2) + "a",
}

// TestValidatePathHostile covers TREE-2, TREE-11 and TEST-5.
func TestValidatePathHostile(t *testing.T) {
	for _, p := range hostilePaths {
		if err := ValidatePath(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ValidatePath(%q) = %v, want rejection", p, err)
		}
	}
}

func TestValidatePathValid(t *testing.T) {
	for _, p := range []string{
		"a", "a/b/c", "file.txt", ".hidden", "a/.hidden/b", "...", "a/...b",
		"ünïcode/ñame", "with space", "CON", "a:b", "trailing.",
		strings.Repeat("a", proto.MaxComponentLen),
		strings.Repeat(strings.Repeat("a", 200)+"/", 21)[:proto.MaxPathLen-1] + "b",
	} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v", p, err)
		}
	}
}

// TestValidateWindowsPath covers TREE-10.
func TestValidateWindowsPath(t *testing.T) {
	bad := []string{
		"CON", "con", "con.txt", "dir/NUL", "aux.tar.gz", "COM1", "lpt9.log", "COM¹", "CONIN$",
		"trailing.", "trailing ", "dir./x", "a<b", "a>b", "a:b", "a\"b", "a|b", "a?b", "a*b",
		"ctl\x01x", "C:", "c:/x", "//server/share",
	}
	for _, p := range bad {
		if err := ValidateWindowsPath(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ValidateWindowsPath(%q) = %v, want rejection", p, err)
		}
	}
	for _, p := range []string{"console", "COM10", "con2", "a/b.c", "nul_file", "LPT"} {
		if err := ValidateWindowsPath(p); err != nil {
			t.Errorf("ValidateWindowsPath(%q) = %v", p, err)
		}
	}
}

func file(p string) proto.Entry {
	return proto.Entry{Path: p, Type: proto.EntryFile, Mode: 0o644, Size: 1}
}
func dir(p string) proto.Entry { return proto.Entry{Path: p, Type: proto.EntryDir, Mode: 0o755} }

// TestCheckerCollisions covers TREE-9: duplicates and paths that collide
// after case folding or NFC normalization are fatal.
func TestCheckerCollisions(t *testing.T) {
	tests := []struct {
		name    string
		entries []proto.Entry
	}{
		{"duplicate", []proto.Entry{file("a"), file("a")}},
		{"case", []proto.Entry{file("README"), file("readme")}},
		{"case dir", []proto.Entry{dir("Dir"), dir("dir")}},
		{"nfc vs nfd", []proto.Entry{file("caf\u00e9"), file("cafe\u0301")}},
		{"full fold", []proto.Entry{file("stra\u00dfe"), file("STRASSE")}},
		{"kelvin sign", []proto.Entry{file("\u212a"), file("k")}},
		{"file vs dir", []proto.Entry{file("x"), dir("x")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewChecker()
			var err error
			for _, e := range tc.entries {
				if err = c.Add(e); err != nil {
					break
				}
			}
			if !errors.Is(err, ErrCollision) {
				t.Fatalf("got %v", err)
			}
			var ee *EntryError
			if !errors.As(err, &ee) || ee.Index != len(tc.entries)-1 || !strings.Contains(ee.Error(), "manifest entry") {
				t.Fatalf("error %v", err)
			}
		})
	}
}

// TestCheckerStructure covers D-5.10, TREE-6, TREE-11 and TREE-12 (limits
// bound the checker's O(entries) memory).
func TestCheckerStructure(t *testing.T) {
	c := NewChecker()
	for _, e := range []proto.Entry{dir("d"), file("d/f"), dir("d/e"), file("d/e/g"), file("top")} {
		if err := c.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if c.Count() != 5 || c.TotalBytes() != 3 || !c.Contains("D/F") || c.Contains("nope") {
		t.Fatal("checker state wrong")
	}
	bad := map[string][]proto.Entry{
		"missing parent":   {file("x/y")},
		"parent is a file": {file("x"), file("x/y")},
		"bad path":         {file("../x")},
		"symlink type":     {{Path: "l", Type: 3}},
		"parent case":      {dir("P"), file("p/x")},
	}
	for name, entries := range bad {
		c := NewChecker()
		var err error
		for _, e := range entries {
			if err = c.Add(e); err != nil {
				break
			}
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Limits.
	c = NewChecker()
	c.MaxEntries = 2
	_ = c.Add(file("a"))
	_ = c.Add(file("b"))
	if err := c.Add(file("c")); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	c = NewChecker()
	_ = c.Add(proto.Entry{Path: "a", Type: proto.EntryFile, Size: 1 << 63})
	if err := c.Add(proto.Entry{Path: "b", Type: proto.EntryFile, Size: 1 << 63}); !errors.Is(err, ErrLimit) {
		t.Fatalf("overflow: %v", err)
	}
}

func FuzzValidatePath(f *testing.F) {
	for _, p := range hostilePaths {
		f.Add(p)
	}
	f.Add("a/b/c")
	f.Add("CON.txt")
	f.Fuzz(func(t *testing.T, p string) {
		err := ValidatePath(p)
		_ = ValidateWindowsPath(p)
		if err != nil {
			return
		}
		// Anything accepted is a clean relative path that cannot escape.
		if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "\x00") {
			t.Fatalf("accepted unsafe path %q", p)
		}
		for _, c := range strings.Split(p, "/") {
			if c == "" || c == "." || c == ".." {
				t.Fatalf("accepted %q", p)
			}
		}
		c := NewChecker()
		if err := c.Add(proto.Entry{Path: p, Type: proto.EntryFile}); err != nil && !strings.Contains(p, "/") {
			t.Fatalf("checker rejected valid top-level path %q: %v", p, err)
		}
	})
}

// TestWalk covers SND-2, SND-4, TREE-1, TREE-4, TREE-6 and TREE-7.
func TestWalk(t *testing.T) {
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{
		"proj/a.txt":         "aaa",
		"proj/sub/b.txt":     "bb",
		"proj/empty/":        "",
		"proj/sub/deep/c.go": "c",
		"single.txt":         "s",
	})
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(src, "proj", "a.txt"), 0o4755); err != nil {
			t.Fatal(err)
		}
		makeSpecialFiles(t, filepath.Join(src, "proj"))
	}
	l, err := Walk([]string{filepath.Join(src, "proj"), filepath.Join(src, "single.txt")})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, it := range l.Items {
		paths = append(paths, it.Path)
		if it.Mode&^0o777 != 0 {
			t.Errorf("%s: mode %o has special bits (TREE-7)", it.Path, it.Mode)
		}
	}
	want := "proj proj/a.txt proj/empty proj/sub proj/sub/b.txt proj/sub/deep proj/sub/deep/c.go single.txt"
	if got := strings.Join(paths, " "); got != want {
		t.Fatalf("paths:\n got %s\nwant %s", got, want)
	}
	if l.TotalBytes != 3+2+1+1 {
		t.Fatalf("total %d", l.TotalBytes)
	}
	if runtime.GOOS != "windows" {
		skipped := 0
		for _, p := range l.Problems {
			if p.Kind == Skipped {
				skipped++
			}
		}
		if skipped < 2 {
			t.Fatalf("symlink and fifo not skipped: %v", l.Problems)
		}
	}
}

// TestWalkErrors covers SND-2 (duplicate base names) and missing sources.
func TestWalkErrors(t *testing.T) {
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"a/x": "1", "b/x": "2", "C/f": "", "c/f": ""})
	var ue *UsageError
	if _, err := Walk([]string{filepath.Join(src, "a", "x"), filepath.Join(src, "b", "x")}); !errors.As(err, &ue) || !strings.Contains(ue.Msg, "both be stored") {
		t.Fatalf("duplicate base: %v", err)
	}
	if _, err := Walk([]string{filepath.Join(src, "missing")}); !errors.As(err, &ue) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := Walk([]string{"/"}); !errors.As(err, &ue) {
		t.Fatalf("root: %v", err)
	}
	if runtime.GOOS == "linux" {
		// Case collision detected before connecting (D-5.17).
		if _, err := Walk([]string{filepath.Join(src, "C"), filepath.Join(src, "c")}); !errors.As(err, &ue) {
			t.Fatalf("case collision: %v", err)
		}
	}
}

// TestWalkUnrepresentable covers TREE-3: names that cannot be sent are
// skipped with a warning.
func TestWalkUnrepresentable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs a filesystem that allows arbitrary bytes in names")
	}
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"d/ok": "1"})
	for _, n := range []string{"bad\xffname", "back\\slash"} {
		if err := os.WriteFile(filepath.Join(src, "d", n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(src, "d")+string(filepath.Separator)+"dir\xfe", 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := Walk([]string{filepath.Join(src, "d")})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 2 || len(l.Problems) != 3 {
		t.Fatalf("items %v problems %v", l.Items, l.Problems)
	}
	for _, p := range l.Problems {
		if p.Kind != Skipped || !strings.Contains(p.String(), "skipped") || strings.Contains(p.String(), "\xff") || strings.Contains(p.String(), "\xfe") {
			t.Errorf("problem %q", p.String())
		}
	}
}

// TestWalkUnreadable covers SND-5: an unreadable directory is a per-file
// error, and the walk continues.
func TestWalkUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	src := t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"d/locked/x": "1", "d/ok": "2"})
	locked := filepath.Join(src, "d", "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(locked, 0o755) }()
	l, err := Walk([]string{filepath.Join(src, "d")})
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, p := range l.Problems {
		if p.Kind == Failed {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("problems %v", l.Problems)
	}
}

func TestEncodedSizeMatches(t *testing.T) {
	e := proto.Entry{Path: "abc", Type: proto.EntryFile}
	b := proto.Append(nil, proto.Manifest{Entries: []proto.Entry{e}})
	if len(b) != proto.ManifestHeaderSize+e.EncodedSize() {
		t.Fatalf("EncodedSize %d, actual %d", e.EncodedSize(), len(b)-proto.ManifestHeaderSize)
	}
}
