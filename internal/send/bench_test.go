// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package send

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/recv"
	"github.com/nedmchugh/transporter/internal/testutil"
)

// BenchmarkTransfer measures single-file throughput over loopback (NFR-3).
// Run with: go test -run '^$' -bench Transfer -benchtime 3x ./internal/send/
func BenchmarkTransfer(b *testing.B) {
	const size = 256 << 20
	src := b.TempDir()
	testutil.RandomFile(b, filepath.Join(src, "f.bin"), size, 1)
	list := mustWalkB(b, filepath.Join(src, "f.bin"))
	b.SetBytes(size)
	for b.Loop() {
		dst := b.TempDir()
		r, err := recv.New(recv.Options{Dest: dst, Pairer: testPairer(b, testCode), Linger: time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			b.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := r.Run(context.Background(), ln); done <- err }()
		if _, err := Run(context.Background(), Options{List: list, Addr: ln.Addr().String(), Pairer: testPairer(b, testCode)}); err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		_ = r.Close()
	}
}
