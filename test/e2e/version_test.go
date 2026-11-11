// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build e2e

package e2e

import (
	"os/exec"
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
