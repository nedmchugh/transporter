// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package manifest

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/nedmchugh/transporter/internal/proto"
)

// ErrInvalidPath is wrapped by every path validation error.
var ErrInvalidPath = errors.New("invalid path")

func invalid(p, why string) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidPath, proto.Printable(p), why)
}

// ValidatePath checks a wire path against TREE-2 and the length limits of
// TREE-11: relative, UTF-8, forward-slash separated, no empty, "." or ".."
// components, no NUL bytes or backslashes, no leading slash.
//
// The receiver applies this to every manifest entry before any filesystem
// operation, in addition to os.Root confinement (SEC-9, defense in depth).
func ValidatePath(p string) error {
	switch {
	case p == "":
		return invalid(p, "empty")
	case len(p) > proto.MaxPathLen:
		return invalid(p[:64]+"...", fmt.Sprintf("longer than %d bytes", proto.MaxPathLen))
	case !utf8.ValidString(p):
		return invalid(p, "not valid UTF-8")
	case strings.ContainsRune(p, 0):
		return invalid(p, "contains a NUL byte")
	case strings.ContainsRune(p, '\\'):
		return invalid(p, "contains a backslash")
	case strings.HasPrefix(p, "/"):
		return invalid(p, "absolute")
	}
	for c := range strings.SplitSeq(p, "/") {
		switch {
		case c == "":
			return invalid(p, "empty component")
		case c == "." || c == "..":
			return invalid(p, "contains a . or .. component")
		case len(c) > proto.MaxComponentLen:
			return invalid(p, fmt.Sprintf("a component is longer than %d bytes", proto.MaxComponentLen))
		}
	}
	return nil
}

// windowsReserved are device names that Windows reserves in every
// directory, with or without an extension (TREE-10).
var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
	"COM0": true, "COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true, "COM¹": true, "COM²": true, "COM³": true,
	"LPT0": true, "LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true, "LPT¹": true, "LPT²": true, "LPT³": true,
}

// ValidateWindowsPath reports why a valid wire path cannot be created on
// Windows (TREE-10): reserved device names, trailing dots or spaces,
// characters <>:"|?* or control characters, and drive or UNC prefixes. The
// receiver calls it only when running on Windows; it is portable so it can
// be tested everywhere.
func ValidateWindowsPath(p string) error {
	if len(p) >= 2 && p[1] == ':' {
		return invalid(p, "has a drive prefix (not valid on Windows)")
	}
	if strings.HasPrefix(p, "//") {
		return invalid(p, "has a UNC prefix (not valid on Windows)")
	}
	for c := range strings.SplitSeq(p, "/") {
		if i := strings.IndexFunc(c, func(r rune) bool {
			return r < 32 || strings.ContainsRune(`<>:"|?*`, r)
		}); i >= 0 {
			return invalid(p, fmt.Sprintf("contains %q, which is not allowed on Windows", c[i:i+1]))
		}
		if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return invalid(p, "a component ends with a dot or space (not valid on Windows)")
		}
		base, _, _ := strings.Cut(c, ".")
		if windowsReserved[strings.ToUpper(strings.TrimRight(base, " "))] {
			return invalid(p, fmt.Sprintf("%q is a reserved device name on Windows", base))
		}
	}
	return nil
}

// Folder computes collision keys: Unicode NFC normalization followed by full
// case folding (TREE-9). Two paths with the same key would be the same file
// on a case-insensitive or normalizing filesystem. A Folder is not safe for
// concurrent use.
type Folder struct {
	caser cases.Caser
}

// NewFolder returns a Folder.
func NewFolder() *Folder {
	return &Folder{caser: cases.Fold()}
}

// Key returns the collision key of p.
func (f *Folder) Key(p string) string {
	// NFC first so precomposed and decomposed forms agree, then fold, then
	// NFC again because folding can produce decomposed sequences.
	return norm.NFC.String(f.caser.String(norm.NFC.String(p)))
}

// EntryError is a fatal problem with a received manifest (TREE-9,
// TREE-11, D-5.10).
type EntryError struct {
	Index int
	Err   error
}

func (e *EntryError) Error() string {
	return fmt.Sprintf("manifest entry %d: %v", e.Index, e.Err)
}

func (e *EntryError) Unwrap() error { return e.Err }

// ErrCollision is wrapped by duplicate and case/normalization collisions.
var ErrCollision = errors.New("paths collide")

// ErrLimit is wrapped when a manifest exceeds TREE-11 limits.
var ErrLimit = errors.New("manifest limit exceeded")

type seenEntry struct {
	path string
	dir  bool
}

// Checker validates a manifest entry by entry: path rules, limits,
// duplicates and fold collisions, and that every entry's parent is an
// earlier directory entry (docs/DECISIONS.md D-5.10). Memory is O(entries),
// bounded by proto.MaxEntries (TREE-12).
type Checker struct {
	folder *Folder
	seen   map[string]seenEntry // collision key -> entry
	count  int
	total  uint64
	// MaxEntries overrides proto.MaxEntries when positive (for tests).
	MaxEntries int
}

// NewChecker returns an empty Checker.
func NewChecker() *Checker {
	return &Checker{folder: NewFolder(), seen: make(map[string]seenEntry)}
}

// Add validates e as the next entry.
func (c *Checker) Add(e proto.Entry) error {
	idx := c.count
	fail := func(err error) error { return &EntryError{Index: idx, Err: err} }
	limit := proto.MaxEntries
	if c.MaxEntries > 0 {
		limit = c.MaxEntries
	}
	if c.count >= limit {
		return fail(fmt.Errorf("%w: more than %d entries", ErrLimit, limit))
	}
	if err := ValidatePath(e.Path); err != nil {
		return fail(err)
	}
	if e.Type != proto.EntryFile && e.Type != proto.EntryDir {
		return fail(fmt.Errorf("%w: entry %q has unsupported type %v", ErrInvalidPath, proto.Printable(e.Path), e.Type))
	}
	key := c.folder.Key(e.Path)
	if prev, ok := c.seen[key]; ok {
		if prev.path == e.Path {
			return fail(fmt.Errorf("%w: %q appears twice", ErrCollision, proto.Printable(e.Path)))
		}
		return fail(fmt.Errorf("%w: %q and %q differ only in case or Unicode normalization",
			ErrCollision, proto.Printable(prev.path), proto.Printable(e.Path)))
	}
	if parent := path.Dir(e.Path); parent != "." {
		p, ok := c.seen[c.folder.Key(parent)]
		if !ok || p.path != parent || !p.dir {
			return fail(fmt.Errorf("%w: parent of %q is not an earlier directory entry", ErrInvalidPath, proto.Printable(e.Path)))
		}
	}
	sum := c.total + e.Size
	if sum < c.total {
		return fail(fmt.Errorf("%w: total size overflows", ErrLimit))
	}
	c.total = sum
	c.seen[key] = seenEntry{path: e.Path, dir: e.Type == proto.EntryDir}
	c.count++
	return nil
}

// Count returns the number of entries accepted.
func (c *Checker) Count() int { return c.count }

// TotalBytes returns the sum of accepted file sizes.
func (c *Checker) TotalBytes() uint64 { return c.total }

// Contains reports whether a path with the same collision key as p was
// accepted. The receiver uses it to detect NAME.part names that are
// themselves in the manifest (docs/DECISIONS.md D-5.11).
func (c *Checker) Contains(p string) bool {
	_, ok := c.seen[c.folder.Key(p)]
	return ok
}
