// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !windows

package manifest

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// makeSpecialFiles creates a symlink, a FIFO and (where possible) a Unix
// socket in dir, for TREE-6 tests.
func makeSpecialFiles(t *testing.T, dir string) {
	t.Helper()
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ln, err := net.Listen("unix", filepath.Join(dir, "sock")); err == nil {
		t.Cleanup(func() { _ = ln.Close() })
	}
}
