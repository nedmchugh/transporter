// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package manifest builds the sender's list of entries from local paths and
// validates manifests on the receiver: wire path rules (TREE-2), Windows
// name rules (TREE-10), limits (TREE-11) and collisions (TREE-9).
package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/nedmchugh/transporter/internal/proto"
)

// Item is one manifest entry plus the local file it came from.
type Item struct {
	proto.Entry
	Local string // path on the sender's filesystem
}

// ProblemKind classifies a Problem.
type ProblemKind int

const (
	// Skipped is a warning: the item is not transferred by design (TREE-3,
	// TREE-6). It does not change the exit code (CLI-8).
	Skipped ProblemKind = iota
	// Failed is a per-file error: the item should have been transferred
	// but cannot be read (SND-5). It yields exit code 7.
	Failed
)

// Problem is a warning or per-file error found while walking.
type Problem struct {
	Kind  ProblemKind
	Local string // local path (may be unprintable; use proto.Printable)
	Msg   string
}

func (p Problem) String() string {
	return proto.Printable(p.Local) + ": " + p.Msg
}

// List is the result of Walk.
type List struct {
	Items      []Item
	TotalBytes uint64
	Problems   []Problem
}

// UsageError is a problem with the sender's arguments, found before
// connecting (SND-2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// Walk lists sources with `cp -r` naming (SND-2): a file is stored under its
// base name, a directory under its base name with its contents beneath it.
// Directory trees are walked in lexical order, so parents always precede
// their contents. Symlinks, devices, FIFOs and sockets are skipped with a
// warning and never opened (TREE-6); names that cannot be represented on
// the wire are skipped with a warning (TREE-3). File contents are not read
// (SND-4).
//
// Memory is O(entries); the entry limit (TREE-11) bounds it (TREE-12).
func Walk(sources []string) (*List, error) {
	l := &List{}
	bases := map[string]string{}
	for _, src := range sources {
		info, err := os.Lstat(src)
		if err != nil {
			return nil, &UsageError{Msg: fmt.Sprintf("cannot send %s: %v", proto.Printable(src), unwrapPathError(err))}
		}
		abs, err := filepath.Abs(src)
		if err != nil {
			return nil, &UsageError{Msg: fmt.Sprintf("cannot resolve %s: %v", proto.Printable(src), err)}
		}
		base := filepath.Base(abs)
		if base == string(filepath.Separator) || base == "." || base == "/" {
			return nil, &UsageError{Msg: fmt.Sprintf("cannot send %s: it has no name to store it under; send its contents instead", proto.Printable(src))}
		}
		if prev, ok := bases[base]; ok {
			return nil, &UsageError{Msg: fmt.Sprintf("%s and %s would both be stored as %q; rename one or send them separately",
				proto.Printable(prev), proto.Printable(src), proto.Printable(base))}
		}
		bases[base] = src
		if why := unrepresentable(base); why != "" {
			l.Problems = append(l.Problems, Problem{Skipped, src, why})
			continue
		}
		switch {
		case info.Mode().IsRegular():
			l.add(Item{Entry: fileEntry(base, info), Local: src})
		case info.IsDir():
			if err := l.walkDir(src, base); err != nil {
				return nil, err
			}
		default:
			l.Problems = append(l.Problems, Problem{Skipped, src, skipReason(info.Mode())})
		}
	}
	if len(l.Items) > proto.MaxEntries {
		return nil, &UsageError{Msg: fmt.Sprintf("too many files and directories: %d (limit %d); send the tree in parts", len(l.Items), proto.MaxEntries)}
	}
	// Run the receiver's checks now, so a manifest the receiver would
	// reject fails before connecting with a clear message (D-5.17).
	c := NewChecker()
	for _, it := range l.Items {
		if err := c.Add(it.Entry); err != nil {
			var me *EntryError
			if errors.As(err, &me) && errors.Is(err, ErrCollision) {
				return nil, &UsageError{Msg: fmt.Sprintf("cannot send: %v; such names cannot be stored on case-insensitive systems, so rename one", me.Err)}
			}
			return nil, &UsageError{Msg: fmt.Sprintf("cannot send: %v", err)}
		}
	}
	return l, nil
}

func (l *List) add(it Item) {
	l.Items = append(l.Items, it)
	l.TotalBytes += it.Size
}

func (l *List) walkDir(root, base string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		wire := base
		if rel != "." {
			wire = base + "/" + filepath.ToSlash(rel)
		}
		if err != nil {
			// Unreadable directory, or an entry removed during the walk
			// (SND-5). The directory itself was already added if it could
			// be stat'ed; its contents are reported as failed.
			l.Problems = append(l.Problems, Problem{Failed, p, "cannot read: " + unwrapPathError(err).Error()})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if rel != "." {
			if why := unrepresentable(d.Name()); why != "" {
				l.Problems = append(l.Problems, Problem{Skipped, p, why})
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if ValidatePath(wire) != nil {
			// Only the length limits can fail here, since every
			// component was checked above.
			l.Problems = append(l.Problems, Problem{Failed, p, fmt.Sprintf("path is longer than %d bytes or has a component longer than %d bytes", proto.MaxPathLen, proto.MaxComponentLen)})
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// d.Type() comes from the directory listing (lstat semantics), so
		// symlinks are seen as symlinks and never followed or opened.
		switch t := d.Type(); {
		case t.IsDir():
			info, err := d.Info()
			if err != nil {
				l.Problems = append(l.Problems, Problem{Failed, p, "cannot read: " + unwrapPathError(err).Error()})
				return filepath.SkipDir
			}
			l.add(Item{Entry: proto.Entry{Path: wire, Type: proto.EntryDir, Mode: uint32(info.Mode().Perm()), MtimeSec: info.ModTime().Unix(), MtimeNsec: uint32(info.ModTime().Nanosecond())}, Local: p})
		case t.IsRegular():
			info, err := d.Info()
			if err != nil {
				l.Problems = append(l.Problems, Problem{Failed, p, "cannot read: " + unwrapPathError(err).Error()})
				return nil
			}
			l.add(Item{Entry: fileEntry(wire, info), Local: p})
		default:
			l.Problems = append(l.Problems, Problem{Skipped, p, skipReason(t)})
		}
		return nil
	})
}

func fileEntry(wire string, info fs.FileInfo) proto.Entry {
	mt := info.ModTime()
	return proto.Entry{
		Path:      wire,
		Type:      proto.EntryFile,
		Mode:      uint32(info.Mode().Perm()), // never setuid/setgid/sticky (TREE-7)
		Size:      uint64(info.Size()),
		MtimeSec:  mt.Unix(),
		MtimeNsec: uint32(mt.Nanosecond()),
	}
}

// unrepresentable reports why a single name cannot be sent (TREE-3), or "".
func unrepresentable(name string) string {
	switch {
	case !utf8.ValidString(name):
		return "skipped: the name is not valid UTF-8"
	case strings.ContainsRune(name, '\\'):
		return "skipped: the name contains a backslash"
	case strings.ContainsRune(name, 0):
		return "skipped: the name contains a NUL byte"
	case len(name) > proto.MaxComponentLen:
		return fmt.Sprintf("skipped: the name is longer than %d bytes", proto.MaxComponentLen)
	}
	return ""
}

func skipReason(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "skipped: symbolic links are not transferred"
	case m&fs.ModeNamedPipe != 0:
		return "skipped: named pipes (FIFOs) are not transferred"
	case m&fs.ModeSocket != 0:
		return "skipped: sockets are not transferred"
	case m&fs.ModeDevice != 0:
		return "skipped: device files are not transferred"
	default:
		return "skipped: not a regular file or directory"
	}
}

// unwrapPathError drops the path from *fs.PathError, since messages already
// name the path.
func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
