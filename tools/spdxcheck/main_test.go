// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheck covers LIC-2 enforcement (LIC-4) and the copyright line
// (DECISIONS.md D-9.6).
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
	write("good.go", Header+Copyright+"\npackage x\n")
	write("crlf.go", strings.ReplaceAll(Header+Copyright+"\npackage x\n", "\n", "\r\n"))
	write("bad.go", "package x\n")
	write("nocopyright.go", Header+"\npackage x\n")
	write("sub/incompat.go", Header+Copyright+"// "+forbidden+"\npackage x\n")
	write("testdata/ignored.go", "package x\n")
	write("notes.txt", "no header needed")
	bad, err := check(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bad.go: missing or altered", "nocopyright.go: missing copyright", "incompat.go: contains"}
	if len(bad) != len(want) {
		t.Fatalf("got %v, want %d failures", bad, len(want))
	}
	for _, w := range want {
		if !strings.Contains(strings.Join(bad, "\n"), w) {
			t.Errorf("no failure matching %q in %v", w, bad)
		}
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
