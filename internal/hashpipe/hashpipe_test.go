// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package hashpipe

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"lukechampine.com/blake3"

	"github.com/nedmchugh/transporter/internal/testutil"
)

// TestEquivalent checks that pipelined hashing gives the same result as
// sequential Write calls, including with reused buffers.
func TestEquivalent(t *testing.T) {
	testutil.CheckLeaks(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), 10000)
	want := sha256.Sum256(data)
	p := New(sha256.New())
	buf := make([]byte, 1000)
	for off := 0; off < len(data); off += len(buf) {
		n := copy(buf, data[off:])
		p.Start(buf[:n])
		p.Wait() // buf is reused next iteration
	}
	got := p.Hash().Sum(nil)
	p.Close()
	if !bytes.Equal(got, want[:]) {
		t.Fatal("hash differs")
	}
	// Start without Wait waits for the previous chunk itself.
	b3 := New(blake3.New(32, nil))
	b3.Start([]byte("a"))
	b3.Start([]byte("b"))
	ref := blake3.New(32, nil)
	_, _ = ref.Write([]byte("ab"))
	if !bytes.Equal(b3.Hash().Sum(nil), ref.Sum(nil)) {
		t.Fatal("blake3 differs")
	}
	b3.Close()
}
