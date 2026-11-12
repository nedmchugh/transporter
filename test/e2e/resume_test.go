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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/testutil"
)

const resumeSize = 192 << 20

// waitForPart polls until path exists with at least n bytes.
func waitForPart(t *testing.T, path string, n int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && fi.Size() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s did not reach %d bytes", path, n)
}

// startSender starts `transporter send ARGS` without waiting.
func startSender(t *testing.T, args ...string) (*exec.Cmd, *syncBuffer) {
	t.Helper()
	var errb syncBuffer
	cmd := exec.Command(binPath, append([]string{"send"}, args...)...)
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd, &errb
}

var unitScale = map[string]float64{"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}

// receivedBytes parses "N file(s) received (X UNIT)" from a summary.
func receivedBytes(t *testing.T, stderr string) float64 {
	t.Helper()
	m := regexp.MustCompile(`received \(([0-9.]+) (B|KiB|MiB|GiB)\)`).FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("no summary in:\n%s", stderr)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v * unitScale[m[2]]
}

// TestE2EKillSenderAndRerun covers TEST-8 scenario 3 (REL-7, RES-1, RES-3,
// RCV-5/D-5.13): the sender is killed mid-transfer, the receiver keeps
// waiting, a rerun sender (a new session) is accepted, only the remainder
// is transferred, and the result is byte-identical.
func TestE2EKillSenderAndRerun(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.RandomFile(t, filepath.Join(src, "big.bin"), resumeSize, 3)
	r := startReceiver(t, dst)
	cmd, _ := startSender(t, "--to", r.addr(), r.code, filepath.Join(src, "big.bin"))
	waitForPart(t, filepath.Join(dst, "big.bin.part"), 24<<20, time.Minute)
	_ = cmd.Process.Kill() // SIGKILL / TerminateProcess: no clean shutdown
	_ = cmd.Wait()

	res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "big.bin"))
	if res.exit != 0 {
		t.Fatalf("rerun exit %d\n%s", res.exit, res.stderr)
	}
	if code := r.wait(t, time.Minute); code != 0 {
		t.Fatalf("receiver exit %d", code)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mode: true, Mtime: true})
	if got := receivedBytes(t, r.stderr.String()); got >= resumeSize-(16<<20) {
		t.Fatalf("receiver wrote %.0f bytes in the resumed session; expected only the remainder of %d", got, resumeSize)
	}
}

// TestE2EKillReceiverAndRestart covers TEST-8 scenario 4 (XFER-2, RES-3):
// the receiver is killed mid-transfer; a new receiver on the same
// destination (with a new code) reuses the .part file.
func TestE2EKillReceiverAndRestart(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.RandomFile(t, filepath.Join(src, "big.bin"), resumeSize, 4)
	r := startReceiver(t, dst)
	cmd, _ := startSender(t, "--to", r.addr(), r.code, filepath.Join(src, "big.bin"))
	waitForPart(t, filepath.Join(dst, "big.bin.part"), 24<<20, time.Minute)
	_ = r.cmd.Process.Kill()
	r.wait(t, 10*time.Second)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if fi, err := os.Stat(filepath.Join(dst, "big.bin.part")); err != nil || fi.Size() == 0 {
		t.Fatalf(".part not kept: %v", err)
	}

	r2 := startReceiver(t, dst)
	res := runSender(t, nil, nil, "--to", r2.addr(), r2.code, filepath.Join(src, "big.bin"))
	if res.exit != 0 {
		t.Fatalf("sender exit %d\n%s", res.exit, res.stderr)
	}
	if code := r2.wait(t, time.Minute); code != 0 {
		t.Fatalf("receiver exit %d", code)
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mode: true, Mtime: true})
	if got := receivedBytes(t, r2.stderr.String()); got >= resumeSize-(16<<20) {
		t.Fatalf("restarted receiver wrote %.0f bytes; .part was not reused", got)
	}
}
