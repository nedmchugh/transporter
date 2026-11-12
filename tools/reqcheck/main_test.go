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
	// The same files with CRLF line endings (a Windows checkout) give the
	// same result.
	for _, p := range []string{"docs/requirements.md", "docs/testing.md"} {
		b, _ := os.ReadFile(filepath.Join(dir, p))
		write(p, strings.ReplaceAll(string(b), "\n", "\r\n"))
	}
	crlf, err := check(dir)
	if err != nil || strings.Join(crlf, "\n") != strings.Join(problems, "\n") {
		t.Fatalf("CRLF: problems %v, err %v; want %v", crlf, err, problems)
	}
	if _, err := check(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing root accepted")
	}
}
