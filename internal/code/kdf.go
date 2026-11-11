// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package code

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Key-derivation labels (SEC-2). These are wire-protocol constants: changing
// them breaks interoperability, so they are covered by golden-value tests.
const (
	// PSKInfo is the HKDF info label for the Noise pre-shared key.
	PSKInfo = "transporter v1 psk"
	// DiscoveryInfo is the HKDF info label for the mDNS discovery tag.
	DiscoveryInfo = "transporter v1 discovery"
)

// PSKSize and TagSize are the derived output lengths in bytes.
const (
	PSKSize = 32
	TagSize = 4
)

// ErrZeroCode is returned when deriving keys from the zero Code.
var ErrZeroCode = errors.New("code: no code set")

// derive runs HKDF-SHA-256 over the canonical code with an empty salt
// (docs/DECISIONS.md D-3.3).
func (c Code) derive(info string, n int) ([]byte, error) {
	if c.IsZero() {
		return nil, ErrZeroCode
	}
	k, err := hkdf.Key(sha256.New, []byte(c.get()), nil, info, n)
	if err != nil {
		return nil, fmt.Errorf("deriving %d-byte key: %w", n, err)
	}
	return k, nil
}

// PSK derives the 32-byte Noise pre-shared key (SEC-2).
func (c Code) PSK() ([PSKSize]byte, error) {
	var out [PSKSize]byte
	k, err := c.derive(PSKInfo, PSKSize)
	if err != nil {
		return out, err
	}
	copy(out[:], k)
	return out, nil
}

// DiscoveryTag derives the 4-byte mDNS discovery tag (SEC-2, DISC-1). The tag
// is a one-way function of the code; it lets a sender pick the right
// receiver without the code being advertised.
func (c Code) DiscoveryTag() ([TagSize]byte, error) {
	var out [TagSize]byte
	k, err := c.derive(DiscoveryInfo, TagSize)
	if err != nil {
		return out, err
	}
	copy(out[:], k)
	return out, nil
}
