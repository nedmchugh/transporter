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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/testutil"
)

// TestE2EConfigFile covers the config file with the real binary
// (DECISIONS.md D-9.9): the sender takes --to and --verify from the file
// given with --config, and a code in the file is refused (CODE-8).
func TestE2EConfigFile(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"from-config.txt": "configured"})
	r := startReceiver(t, dst)
	cfg := filepath.Join(t.TempDir(), "transporter.yaml")
	if err := os.WriteFile(cfg, []byte("send:\n  to: "+r.addr()+"\n  verify: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No --to on the command line: the address comes from the file.
	res := runSender(t, nil, nil, "--config", cfg, r.code, filepath.Join(src, "from-config.txt"))
	if res.exit != 0 {
		t.Fatalf("sender exit %d\n%s", res.exit, res.stderr)
	}
	if code := r.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("receiver exit %d", code)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("send:\n  code: "+r.code+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = runSender(t, nil, nil, "--config", bad, filepath.Join(src, "from-config.txt"))
	if res.exit != 2 || !strings.Contains(res.stderr, "the code cannot be set in a config file") {
		t.Fatalf("code in config: exit %d\n%s", res.exit, res.stderr)
	}
	if strings.Contains(res.stderr, r.code) {
		t.Fatal("the error message echoed the code (CODE-7)")
	}
}
