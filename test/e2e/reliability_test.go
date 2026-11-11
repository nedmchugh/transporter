// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build e2e

package e2e

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/transporter/internal/testutil"
)

// TestE2EWrongCode covers TEST-8 scenario 6 (REL-5, CLI-4, CLI-7 exit 3): a wrong
// code fails fast with exit 3 and writes nothing.
func TestE2EWrongCode(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"f.txt": "x"})
	r := startReceiver(t, dst)
	wrong := "zoo-zone-zero-youth-young-yellow-year-wrong-write"
	if r.code == wrong {
		t.Skip("astronomically unlikely code collision")
	}
	start := time.Now()
	res := runSender(t, nil, nil, "--to", r.addr(), wrong, filepath.Join(src, "f.txt"))
	if res.exit != 3 {
		t.Fatalf("exit %d, want 3\n%s", res.exit, res.stderr)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("wrong code did not fail fast")
	}
	if !strings.Contains(res.stderr, "authentication failed") || !strings.Contains(res.stderr, "code may be wrong") {
		t.Fatalf("message:\n%s", res.stderr)
	}
	if ents, _ := os.ReadDir(dst); len(ents) != 0 {
		t.Fatalf("destination not empty: %v", ents)
	}
}

// TestE2ETimeouts covers TEST-8 scenario 9 (RCV-7, REL-1, CLI-4, CLI-7
// exit 4):
// idle timeout on the receiver and retry-budget expiry on the sender.
func TestE2ETimeouts(t *testing.T) {
	t.Parallel()
	t.Run("idle", func(t *testing.T) {
		t.Parallel()
		r := startReceiver(t, "--idle-timeout", "1s", t.TempDir())
		if code := r.wait(t, 30*time.Second); code != 4 {
			t.Fatalf("exit %d, want 4", code)
		}
		if !strings.Contains(r.stderr.String(), "--idle-timeout") {
			t.Fatalf("no hint:\n%s", r.stderr)
		}
	})
	t.Run("retry budget", func(t *testing.T) {
		t.Parallel()
		// A port that nothing listens on.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		src := t.TempDir()
		testutil.WriteTree(t, src, map[string]string{"f": "x"})
		code := "abandon-ability-able-about-above-absent-absorb-abstract-absurd"
		start := time.Now()
		res := runSender(t, nil, nil, "--retry-timeout", "2s", "--to", addr, code, filepath.Join(src, "f"))
		if res.exit != 4 || time.Since(start) < 2*time.Second {
			t.Fatalf("exit %d after %v\n%s", res.exit, time.Since(start), res.stderr)
		}
		if !strings.Contains(res.stderr, "retrying") || !strings.Contains(res.stderr, "gave up") {
			t.Fatalf("output:\n%s", res.stderr)
		}
		res = runSender(t, nil, nil, "--retry-timeout", "0", "--to", addr, code, filepath.Join(src, "f"))
		if res.exit != 4 || strings.Contains(res.stderr, "retrying in") {
			t.Fatalf("retry disabled: exit %d\n%s", res.exit, res.stderr)
		}
	})
}

// TestE2ECodeInputMethods covers TEST-8 scenario 10 (CODE-8, CLI-6):
// positional, --code-file PATH, --code-file - and $TRANSPORTER_CODE. The
// interactive prompt needs a terminal and is covered by unit tests.
func TestE2ECodeInputMethods(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"positional", "code-file", "stdin", "env", "lenient"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			src, dst := t.TempDir(), t.TempDir()
			testutil.WriteTree(t, src, map[string]string{"f.txt": method})
			r := startReceiver(t, dst)
			path := filepath.Join(src, "f.txt")
			var res result
			switch method {
			case "positional":
				res = runSender(t, nil, nil, "--to", r.addr(), r.code, path)
			case "lenient":
				res = runSender(t, nil, nil, "--to", r.addr(), strings.ToUpper(strings.ReplaceAll(r.code, "-", " ")), path)
			case "code-file":
				f := filepath.Join(t.TempDir(), "code")
				if err := os.WriteFile(f, []byte(r.code+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				res = runSender(t, nil, nil, "--to", r.addr(), "--code-file", f, path)
			case "stdin":
				res = runSender(t, nil, strings.NewReader(r.code+"\n"), "--to", r.addr(), "--code-file", "-", path)
			case "env":
				res = runSender(t, []string{"TRANSPORTER_CODE=" + r.code}, nil, "--to", r.addr(), path)
			}
			if res.exit != 0 {
				t.Fatalf("exit %d\n%s", res.exit, res.stderr)
			}
			if r.wait(t, 30*time.Second) != 0 {
				t.Fatal("receiver failed")
			}
			testutil.CompareTrees(t, src, dst, testutil.CompareOptions{})
		})
	}
}

// TestE2EModifiedDuringTransfer covers TEST-8 scenario 12 (SND-6): a file
// that changes while it is being sent is reported, not completed, and the
// exit code is 7 on both sides.
func TestE2EModifiedDuringTransfer(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	p := filepath.Join(src, "d", "growing.bin")
	testutil.RandomFile(t, p, resumeSize, 5)
	testutil.WriteTree(t, src, map[string]string{"d/stable.txt": "stable"})
	r := startReceiver(t, dst)
	cmd, errb := startSender(t, "--to", r.addr(), r.code, filepath.Join(src, "d"))
	waitForPart(t, filepath.Join(dst, "d", "growing.bin.part"), 8<<20, time.Minute)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("appended while sending")
	_ = f.Close()
	err = cmd.Wait()
	if code := exitCode(err); code != 7 {
		t.Fatalf("sender exit %d, want 7\n%s", code, errb)
	}
	if !strings.Contains(errb.String(), "changed during transfer") {
		t.Fatalf("sender output:\n%s", errb)
	}
	if code := r.wait(t, time.Minute); code != 7 {
		t.Fatalf("receiver exit %d, want 7", code)
	}
	if _, err := os.Stat(filepath.Join(dst, "d", "growing.bin")); !os.IsNotExist(err) {
		t.Fatal("changed file was completed")
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "d", "stable.txt")); string(b) != "stable" {
		t.Fatal("other file not transferred")
	}
}

// TestE2EBusy covers TEST-8 scenario 13 (RCV-5): while one sender is
// transferring, a second sender (another session) is told the receiver is
// busy, retries, and gives up at its retry budget; the first completes.
func TestE2EBusy(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.RandomFile(t, filepath.Join(src, "a", "big.bin"), resumeSize, 6)
	testutil.WriteTree(t, src, map[string]string{"b/other.txt": "other"})
	r := startReceiver(t, dst)
	first, firstErr := startSender(t, "--to", r.addr(), r.code, filepath.Join(src, "a"))
	waitForPart(t, filepath.Join(dst, "a", "big.bin.part"), 1<<20, time.Minute)
	res := runSender(t, nil, nil, "-v", "--retry-timeout", "1s", "--to", r.addr(), r.code, filepath.Join(src, "b"))
	if res.exit != 4 || !strings.Contains(res.stderr, "busy") {
		t.Fatalf("second sender: exit %d\n%s", res.exit, res.stderr)
	}
	if code := exitCode(first.Wait()); code != 0 {
		t.Fatalf("first sender exit %d\n%s", code, firstErr)
	}
	if r.wait(t, time.Minute) != 0 {
		t.Fatal("receiver failed")
	}
	if _, err := os.Stat(filepath.Join(dst, "b")); !os.IsNotExist(err) {
		t.Fatal("busy sender's files were written")
	}
}

// TestE2EFlakyProxy covers TEST-8 scenario 5 (REL-1, REL-2) and scenario 13
// supersession: repeated interruptions through a TCP proxy, the first of
// which leaves the receiver's side half-open so the reconnect must
// supersede it (RCV-5).
func TestE2EFlakyProxy(t *testing.T) {
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.RandomFile(t, filepath.Join(src, "p", "big.bin"), 32<<20, 8)
	files := map[string]string{}
	for i := range 100 {
		files["p/s/"+string(rune('a'+i%26))+strings.Repeat("x", i)] = strings.Repeat("y", i)
	}
	testutil.WriteTree(t, src, files)
	r := startReceiver(t, dst)
	proxy := testutil.NewProxy(t, r.addr(), func(n int) (int64, testutil.CutMode) {
		switch {
		case n == 0:
			return 3 << 20, testutil.HalfDead
		case n < 5:
			return 4 << 20, testutil.Reset
		}
		return 0, testutil.Reset
	})
	start := time.Now()
	res := runSender(t, nil, nil, "--to", proxy.Addr(), r.code, filepath.Join(src, "p"))
	if res.exit != 0 {
		t.Fatalf("exit %d\n%s", res.exit, res.stderr)
	}
	if r.wait(t, time.Minute) != 0 {
		t.Fatal("receiver failed")
	}
	// The receiver's dead-connection timeout is 45 s; finishing well
	// before it shows the half-open connection was superseded.
	if took := time.Since(start); took > 40*time.Second {
		t.Fatalf("took %v", took)
	}
	if proxy.Cuts() < 3 {
		t.Fatalf("only %d interruptions", proxy.Cuts())
	}
	testutil.CompareTrees(t, src, dst, testutil.CompareOptions{Mode: true, Mtime: true})
}

// TestE2ESignals covers REL-7 and CLI-7 exit 130: an interrupted sender or
// receiver stops cleanly, prints a summary, keeps .part files, and exits
// 130.
func TestE2ESignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt cannot be sent to a process on Windows (TEST-11; see docs/testing.md)")
	}
	t.Parallel()
	for _, who := range []string{"sender", "receiver"} {
		t.Run(who, func(t *testing.T) {
			t.Parallel()
			src, dst := t.TempDir(), t.TempDir()
			testutil.RandomFile(t, filepath.Join(src, "big.bin"), resumeSize, 9)
			r := startReceiver(t, dst)
			cmd, errb := startSender(t, "--to", r.addr(), r.code, filepath.Join(src, "big.bin"))
			waitForPart(t, filepath.Join(dst, "big.bin.part"), 8<<20, time.Minute)
			if who == "sender" {
				_ = cmd.Process.Signal(os.Interrupt)
				if code := exitCode(cmd.Wait()); code != 130 {
					t.Fatalf("sender exit %d\n%s", code, errb)
				}
				if !strings.Contains(errb.String(), "Summary:") || !strings.Contains(errb.String(), "interrupted") || !strings.Contains(errb.String(), "Not transferred yet") {
					t.Fatalf("sender output:\n%s", errb)
				}
				_ = r.cmd.Process.Signal(os.Interrupt)
			} else {
				_ = r.cmd.Process.Signal(os.Interrupt)
			}
			if code := r.wait(t, 30*time.Second); code != 130 {
				t.Fatalf("receiver exit %d", code)
			}
			if !strings.Contains(r.stderr.String(), "Summary:") {
				t.Fatalf("receiver output:\n%s", r.stderr)
			}
			if fi, err := os.Stat(filepath.Join(dst, "big.bin.part")); err != nil || fi.Size() == 0 {
				t.Fatalf(".part not kept: %v", err)
			}
			if who == "receiver" {
				// The sender learns the receiver stopped and gives up
				// after its budget instead of hanging.
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
	}
}

// TestE2EExitPrecedence covers TEST-8 scenario 14 (CLI-3, CLI-8, CLI-9): a
// run with a conflict, an unreadable file and a skipped symlink exits 7 and
// lists each in the summary; the symlink warning alone would not change the
// exit code.
func TestE2EExitPrecedence(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs POSIX permissions, symlinks and a non-root user")
	}
	t.Parallel()
	src, dst := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src, map[string]string{"d/ok.txt": "ok", "d/conflict.txt": "new", "d/locked.txt": "secret"})
	testutil.WriteTree(t, dst, map[string]string{"d/conflict.txt": "old!!"})
	if err := os.Chmod(filepath.Join(src, "d", "locked.txt"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ok.txt", filepath.Join(src, "d", "link")); err != nil {
		t.Fatal(err)
	}
	r := startReceiver(t, dst)
	res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src, "d"))
	if res.exit != 7 {
		t.Fatalf("exit %d\n%s", res.exit, res.stderr)
	}
	for _, want := range []string{"Summary:", "1 conflict(s)", "1 error(s)", "d/conflict.txt", "d/locked.txt", "Warnings", "symbolic links"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("summary lacks %q:\n%s", want, res.stderr)
		}
	}
	if code := r.wait(t, 30*time.Second); code != 7 {
		t.Fatalf("receiver exit %d", code)
	}

	// Only a skipped symlink: exit 0 (CLI-8).
	src2, dst2 := t.TempDir(), t.TempDir()
	testutil.WriteTree(t, src2, map[string]string{"e/ok.txt": "ok"})
	if err := os.Symlink("ok.txt", filepath.Join(src2, "e", "link")); err != nil {
		t.Fatal(err)
	}
	r = startReceiver(t, dst2)
	if res := runSender(t, nil, nil, "--to", r.addr(), r.code, filepath.Join(src2, "e")); res.exit != 0 || !strings.Contains(res.stderr, "Warnings") {
		t.Fatalf("warning-only run: exit %d\n%s", res.exit, res.stderr)
	}
	r.wait(t, 30*time.Second)
}
