// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pairing

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/nedmchugh/transporter/internal/code"
)

const sample = "abandon-ability-able-about-above-absent-absorb-abstract-absurd"

// TestCodePairer covers SEC-14 (interface) and SEC-2 (the key is the HKDF
// output of the canonical code).
func TestCodePairer(t *testing.T) {
	c, err := code.Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	var p Pairer
	cp, err := NewCodePairer(c)
	if err != nil {
		t.Fatal(err)
	}
	p = cp
	if p.Mode() != "code" {
		t.Fatalf("mode %q", p.Mode())
	}
	for _, role := range []Role{Initiator, Responder} {
		k, err := p.HandshakeKey(context.Background(), nil, role)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(k[:]) != "97ec51a315a13084adad2469a8609452633e36bfd06cc25ad62c7b7939326cc6" {
			t.Fatalf("%v: unexpected key", role)
		}
	}
	tag := p.DiscoveryTag()
	if hex.EncodeToString(tag[:]) != "cdee60db" {
		t.Fatalf("tag %x", tag)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.HandshakeKey(ctx, nil, Initiator); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: %v", err)
	}
	// Key material never appears in formatted output.
	for _, s := range []string{fmt.Sprint(cp), fmt.Sprintf("%#v", cp), fmt.Sprintf("%+v", p)} {
		if s != "pairing.CodePairer{[REDACTED]}" {
			t.Fatalf("formatted pairer = %q", s)
		}
	}
}

func TestNewCodePairerZero(t *testing.T) {
	if _, err := NewCodePairer(code.Code{}); !errors.Is(err, ErrNoCode) {
		t.Fatalf("got %v", err)
	}
}

func TestRoleString(t *testing.T) {
	for r, want := range map[Role]string{Initiator: "initiator", Responder: "responder", 0: "unknown"} {
		if r.String() != want {
			t.Errorf("%d: %q", r, r.String())
		}
	}
}
