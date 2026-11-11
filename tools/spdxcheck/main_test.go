// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheck covers LIC-2 enforcement (LIC-4).
func TestCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good.go", Header+"\npackage x\n")
	write("crlf.go", "// SPDX-License-Identifier: MPL-2.0\r\n//\r\n// This Source Code Form is subject to the terms of the Mozilla Public\r\n// License, v. 2.0. If a copy of the MPL was not distributed with this\r\n// file, You can obtain one at https://mozilla.org/MPL/2.0/.\r\n\r\npackage x\r\n")
	write("bad.go", "package x\n")
	write("sub/incompat.go", Header+"// "+forbidden+"\npackage x\n")
	write("testdata/ignored.go", "package x\n")
	write("notes.txt", "no header needed")
	bad, err := check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 2 {
		t.Fatalf("got %v, want 2 failures", bad)
	}
	if _, err := check(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error for missing root")
	}
}

// TestRepository runs the check on this repository itself.
func TestRepository(t *testing.T) {
	bad, err := check(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("files without header: %v", bad)
	}
}
