// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package fail classifies errors into the kinds that determine retry
// behavior (REL-4) and exit codes (CLI-7, CLI-9), and carries user-facing
// messages: what went wrong, the likely cause, and what to try (CLI-4).
package fail

import (
	"context"
	"errors"
	"strings"

	"github.com/nedmchugh/transporter/internal/meta"
)

// SameVersionHint is the hint for protocol and version errors.
var SameVersionHint = "use the same " + meta.Name + " version on both machines"

// Kind is the class of a failure.
type Kind int

// Failure kinds. Their exit codes are given by Kind.ExitCode.
const (
	None        Kind = iota // success
	Internal                // unexpected error (exit 1)
	Protocol                // protocol violation or version mismatch (exit 1)
	Usage                   // bad command line (exit 2)
	Auth                    // authentication failure (exit 3)
	Network                 // network failure or timeout (exit 4)
	FS                      // destination not writable or out of space (exit 5)
	Integrity               // hash mismatch after retransmission (exit 6)
	Partial                 // conflicts or per-file errors (exit 7)
	Interrupted             // stopped by a signal (exit 130)
)

// Exit codes (CLI-7).
const (
	ExitOK          = 0
	ExitInternal    = 1
	ExitUsage       = 2
	ExitAuth        = 3
	ExitNetwork     = 4
	ExitFS          = 5
	ExitIntegrity   = 6
	ExitPartial     = 7
	ExitInterrupted = 130
)

// ExitCode returns the process exit code for k. Protocol errors share code 1
// with internal errors because CLI-7 has no separate row
// (docs/DECISIONS.md D-5.5).
func (k Kind) ExitCode() int {
	switch k {
	case None:
		return ExitOK
	case Usage:
		return ExitUsage
	case Auth:
		return ExitAuth
	case Network:
		return ExitNetwork
	case FS:
		return ExitFS
	case Integrity:
		return ExitIntegrity
	case Partial:
		return ExitPartial
	case Interrupted:
		return ExitInterrupted
	default:
		return ExitInternal
	}
}

func (k Kind) String() string {
	return [...]string{"none", "internal", "protocol", "usage", "auth", "network", "fs", "integrity", "partial", "interrupted"}[k]
}

// rank orders kinds for Worst: higher wins. CLI-9 fixes 3 > 5 > 6 > 4 > 7 >
// 0; internal/protocol errors rank above all, and an interrupt above
// everything else (docs/DECISIONS.md D-5.6). Usage errors happen before any
// transfer, so their rank only matters for completeness.
var rank = map[Kind]int{
	None: 0, Partial: 1, Network: 2, Integrity: 3, FS: 4, Auth: 5,
	Usage: 6, Interrupted: 7, Protocol: 8, Internal: 9,
}

// Worst returns the kind with the highest precedence (CLI-9).
func Worst(kinds ...Kind) Kind {
	w := None
	for _, k := range kinds {
		if rank[k] > rank[w] {
			w = k
		}
	}
	return w
}

// Error is a classified, user-facing error.
type Error struct {
	Kind Kind
	// Msg says what went wrong, in terms an end user understands.
	Msg string
	// Hint says what to try. It may be empty.
	Hint string
	// Err is the underlying cause, if any.
	Err error
	// Final marks an error of a normally transient kind that must not be
	// retried, such as failed discovery (DISC-3).
	Final bool
}

// New returns an *Error.
func New(kind Kind, msg, hint string, err error) *Error {
	return &Error{Kind: kind, Msg: msg, Hint: hint, Err: err}
}

func (e *Error) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Msg)
	if e.Err != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Err.Error())
	}
	return sb.String()
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Err }

// KindOf classifies err. Unclassified errors are Internal, except context
// cancellation, which is Interrupted.
func KindOf(err error) Kind {
	if err == nil {
		return None
	}
	var fe *Error
	if errors.As(err, &fe) {
		return fe.Kind
	}
	if errors.Is(err, context.Canceled) {
		return Interrupted
	}
	return Internal
}

// HintOf returns the hint of the first *Error in err's chain, if any.
func HintOf(err error) string {
	var fe *Error
	if errors.As(err, &fe) {
		return fe.Hint
	}
	return ""
}

// Transient reports whether err should be retried by the sender (REL-4).
func Transient(err error) bool {
	var fe *Error
	if errors.As(err, &fe) && fe.Final {
		return false
	}
	return KindOf(err) == Network
}
