// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

//go:build e2e

package e2e

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestVersion checks the binary builds and reports its version (CLI-1).
func TestVersion(t *testing.T) {
	out, err := exec.Command(binPath, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.HasPrefix(string(out), "transporter ") {
		t.Fatalf("unexpected output %q", out)
	}
}

// TestBinaryKeepsDeadcodeElimination guards the binary size (NFR-5,
// DECISIONS.md D-9.9): if reflect's MethodByName is reachable (cobra
// templates, text/template), the linker keeps every exported method and
// the binary grows by megabytes. Cobra avoids this only while no template
// is customized, so this fails if one is.
func TestBinaryKeepsDeadcodeElimination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("go tool nm does not read the Windows binary reliably")
	}
	out, err := exec.Command("go", "tool", "nm", binPath).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "MethodByName") {
		t.Fatal("the binary links reflect.Value.MethodByName; was a cobra template customized?")
	}
}
