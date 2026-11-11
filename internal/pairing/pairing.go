// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package pairing abstracts how the handshake secret is obtained from user
// input (SEC-14).
//
// The secure channel (internal/secure) needs a 32-byte pre-shared key for
// Noise NNpsk0. A Pairer supplies it. Today the only implementation is
// CodePairer, which derives the key from a high-entropy code with HKDF and
// does not touch the network. A future short-code PAKE mode would implement
// Pairer by running its own exchange over the raw connection before the Noise
// handshake and returning the agreed key; nothing above internal/secure would
// change. See docs/architecture.md, "Pairing extension point".
package pairing

import (
	"context"
	"errors"
	"io"

	"github.com/OWNER/transporter/internal/code"
)

// Role says which side of the connection a Pairer is acting for.
type Role uint8

const (
	// Initiator is the sender, which dials the connection.
	Initiator Role = iota + 1
	// Responder is the receiver, which accepts the connection.
	Responder
)

func (r Role) String() string {
	switch r {
	case Initiator:
		return "initiator"
	case Responder:
		return "responder"
	default:
		return "unknown"
	}
}

// KeySize is the size of the handshake secret.
const KeySize = 32

// Pairer obtains the handshake secret for one connection.
type Pairer interface {
	// Mode names the pairing mode, for diagnostics. It never includes
	// secret material.
	Mode() string

	// HandshakeKey returns the pre-shared key for the Noise handshake on
	// one connection. Implementations may exchange messages over rw first
	// (a PAKE would); they must respect ctx and must not retain rw.
	HandshakeKey(ctx context.Context, rw io.ReadWriter, role Role) ([KeySize]byte, error)

	// DiscoveryTag returns the short public tag used to find the matching
	// receiver on the local network (DISC-1). It must not allow recovering
	// the secret.
	DiscoveryTag() [code.TagSize]byte
}

// CodePairer is the high-entropy-code pairing mode: the pre-shared key is
// HKDF-SHA-256 of the canonical code (SEC-2).
type CodePairer struct {
	psk [KeySize]byte
	tag [code.TagSize]byte
}

// ErrNoCode is returned by NewCodePairer for the zero Code.
var ErrNoCode = errors.New("pairing: no code")

// NewCodePairer derives the key and tag from c once, so the code itself is
// not retained.
func NewCodePairer(c code.Code) (*CodePairer, error) {
	if c.IsZero() {
		return nil, ErrNoCode
	}
	psk, err := c.PSK()
	if err != nil {
		return nil, err
	}
	tag, err := c.DiscoveryTag()
	if err != nil {
		return nil, err
	}
	return &CodePairer{psk: psk, tag: tag}, nil
}

// Mode implements Pairer.
func (p *CodePairer) Mode() string { return "code" }

// HandshakeKey implements Pairer. The code mode needs no exchange, so rw is
// unused; ctx is checked so callers see cancellation consistently.
func (p *CodePairer) HandshakeKey(ctx context.Context, _ io.ReadWriter, _ Role) ([KeySize]byte, error) {
	if err := ctx.Err(); err != nil {
		return [KeySize]byte{}, err
	}
	return p.psk, nil
}

// DiscoveryTag implements Pairer.
func (p *CodePairer) DiscoveryTag() [code.TagSize]byte { return p.tag }

// String keeps key material out of formatted output.
func (p *CodePairer) String() string { return "pairing.CodePairer{" + code.Redacted + "}" }

// GoString keeps key material out of %#v output.
func (p *CodePairer) GoString() string { return p.String() }
