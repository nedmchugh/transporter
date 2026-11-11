// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recv

import (
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/nedmchugh/transporter/internal/proto"
)

// outcome is the settled result for one entry within a session.
type outcome uint8

const (
	oNone outcome = iota
	oTransferred
	oSkipped
	oConflict
	oError
	oIntegrity
)

// session is the state that survives reconnects of the same session_id. It
// holds only results for the summary and XFER-4 retry counts; everything
// about the files themselves is rebuilt from the destination directory on
// each connection (REL-2, RES-1). It is used by one connection at a time
// (acquire serializes connections).
type session struct {
	id           [proto.SessionIDSize]byte
	manifestHash [32]byte
	haveManifest bool
	entries      []proto.Entry
	outcome      []outcome
	codes        map[uint32]proto.Code
	mismatches   map[uint32]uint8
	bytes        int64
}

func newSession(id [proto.SessionIDSize]byte) *session {
	return &session{id: id}
}

// prepare installs the manifest of a new connection. If it differs from the
// previous connection's manifest (a sender cannot legitimately do that, but
// the receiver must not trust it), earlier results are discarded.
func (s *session) prepare(hash [32]byte, entries []proto.Entry) {
	if !s.haveManifest || hash != s.manifestHash || len(entries) != len(s.outcome) {
		s.outcome = make([]outcome, len(entries))
		s.codes = map[uint32]proto.Code{}
		s.mismatches = map[uint32]uint8{}
		s.bytes = 0
	}
	s.manifestHash, s.haveManifest = hash, true
	s.entries = entries
}

func (s *session) set(i uint32, o outcome, code proto.Code) {
	s.outcome[i] = o
	if o == oError {
		s.codes[i] = code
	} else {
		delete(s.codes, i)
	}
}

// fill copies the session's results into sum.
func (s *session) fill(sum *Summary) {
	sum.Bytes = s.bytes
	for i, o := range s.outcome {
		e := s.entries[i]
		switch o {
		case oTransferred:
			sum.Transferred++
		case oSkipped:
			if e.Type == proto.EntryFile {
				sum.Skipped++
			}
		case oConflict:
			sum.Conflicts = append(sum.Conflicts, e.Path)
		case oError:
			sum.Errors = append(sum.Errors, FileIssue{Path: e.Path, Code: s.codes[uint32(i)]})
		case oIntegrity:
			sum.Integrity = append(sum.Integrity, e.Path)
		case oNone:
			if e.Type == proto.EntryFile {
				sum.NotTransferred = append(sum.NotTransferred, e.Path)
			}
		}
	}
}

// done returns totals for the DONE message.
func (s *session) done() proto.Done {
	var sum Summary
	s.fill(&sum)
	return proto.Done{
		Transferred: uint64(sum.Transferred),
		Bytes:       uint64(sum.Bytes),
		Skipped:     uint64(sum.Skipped),
		Conflicts:   uint64(len(sum.Conflicts)),
		Errors:      uint64(len(sum.Errors)),
		Integrity:   uint64(len(sum.Integrity)),
	}
}

// maxStray bounds the stray .part list in the summary.
const maxStray = 100

// strayParts lists .part files in the destination whose final names are not
// in the manifest (RES-4). It walks through the root's fs.FS, which never
// follows symlinks out of the destination, and only reads directory
// listings.
func strayParts(root *os.Root, entries []proto.Entry) []string {
	files := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Type == proto.EntryFile {
			files[e.Path] = true
		}
	}
	var out []string
	_ = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best effort: skip unreadable directories
		}
		if len(out) >= maxStray {
			return fs.SkipAll
		}
		if d.Type().IsRegular() && strings.HasSuffix(p, ".part") && path.Base(p) != ".part" {
			if !files[strings.TrimSuffix(p, ".part")] {
				out = append(out, p)
			}
		}
		return nil
	})
	sort.Strings(out)
	return out
}
