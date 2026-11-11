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

// TestRepository enforces TEST-1 on this repository.
func TestRepository(t *testing.T) {
	problems, err := check(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestCheckDetectsGaps(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(dir, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o750)
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/requirements.md", "- AA-1 (MUST): x\n- AA-2 (MUST): y\n- AA-3 (SHOULD): z\n")
	write("docs/testing.md", "| AA-1 | `pkg` TestThere; `pkg` TestGone |\n")
	write("pkg/x_test.go", "package pkg\nfunc TestThere(t *testing.T) {}\n")
	problems, err := check(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 {
		t.Fatalf("problems: %v", problems)
	}
	if _, err := check(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing root accepted")
	}
}
