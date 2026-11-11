// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package fail

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestExitCodes covers CLI-7: every kind maps to the documented code.
func TestExitCodes(t *testing.T) {
	want := map[Kind]int{
		None: 0, Internal: 1, Protocol: 1, Usage: 2, Auth: 3, Network: 4,
		FS: 5, Integrity: 6, Partial: 7, Interrupted: 130,
	}
	for k, code := range want {
		if k.ExitCode() != code {
			t.Errorf("%v: exit %d, want %d", k, k.ExitCode(), code)
		}
		if k.String() == "" {
			t.Errorf("%d has no name", k)
		}
	}
}

// TestWorst covers CLI-9 precedence: 3, 5, 6, 4, 7, then 0.
func TestWorst(t *testing.T) {
	order := []Kind{Auth, FS, Integrity, Network, Partial, None}
	for i := range order {
		for j := i; j < len(order); j++ {
			if got := Worst(order[j], order[i]); got != order[i] {
				t.Errorf("Worst(%v,%v) = %v", order[j], order[i], got)
			}
		}
	}
	if Worst() != None {
		t.Fatal("empty")
	}
	if Worst(Auth, Interrupted) != Interrupted || Worst(Interrupted, Internal) != Internal {
		t.Fatal("interrupt/internal precedence (D-5.6)")
	}
	if Worst(Partial, Integrity, Network).ExitCode() != 6 {
		t.Fatal("6 outranks 4 and 7")
	}
}

// TestClassification covers REL-4: transient vs fatal.
func TestClassification(t *testing.T) {
	base := errors.New("reset")
	tests := []struct {
		err       error
		kind      Kind
		transient bool
	}{
		{nil, None, false},
		{base, Internal, false},
		{context.Canceled, Interrupted, false},
		{fmt.Errorf("wrapped: %w", context.Canceled), Interrupted, false},
		{New(Network, "connection lost", "", base), Network, true},
		{fmt.Errorf("ctx: %w", New(Network, "x", "", nil)), Network, true},
		{New(Auth, "authentication failed", "check the code", nil), Auth, false},
		{New(Protocol, "violation", "", nil), Protocol, false},
		{New(FS, "out of space", "", nil), FS, false},
		{New(Usage, "bad flag", "", nil), Usage, false},
	}
	for _, tc := range tests {
		if got := KindOf(tc.err); got != tc.kind {
			t.Errorf("KindOf(%v) = %v, want %v", tc.err, got, tc.kind)
		}
		if got := Transient(tc.err); got != tc.transient {
			t.Errorf("Transient(%v) = %v", tc.err, got)
		}
	}
	final := New(Network, "discovery failed", "", nil)
	final.Final = true
	if Transient(final) || KindOf(final).ExitCode() != 4 {
		t.Fatal("final network error must not be retried but still exit 4")
	}
	e := New(Auth, "authentication failed", "check the code", base)
	if e.Error() != "authentication failed: reset" || !errors.Is(e, base) || HintOf(fmt.Errorf("x: %w", e)) != "check the code" {
		t.Fatal(e.Error())
	}
	if New(Auth, "m", "", nil).Error() != "m" || HintOf(base) != "" {
		t.Fatal("no cause")
	}
}
