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
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe bytes.Buffer for subprocess output.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// receiver is a running `transporter receive` subprocess.
type receiver struct {
	cmd    *exec.Cmd
	addrs  []string
	code   string
	stdout *syncBuffer
	stderr *syncBuffer
	done   chan struct{}
	exit   int
}

// startReceiver runs `transporter receive --bind 127.0.0.1 --no-mdns
// --no-sweep ARGS` and waits for its banner (RCV-2: "Listening on ADDR" lines, then
// "Code: CODE").
func startReceiver(t *testing.T, args ...string) *receiver {
	t.Helper()
	full := append([]string{"receive", "--bind", "127.0.0.1", "--no-mdns", "--no-sweep"}, args...)
	return startReceiverRaw(t, full...)
}

func startReceiverRaw(t *testing.T, args ...string) *receiver {
	t.Helper()
	r := &receiver{stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan struct{})}
	r.cmd = exec.Command(binPath, args...)
	r.cmd.Stderr = r.stderr
	pr, pw := io.Pipe()
	r.cmd.Stdout = io.MultiWriter(r.stdout, pw)
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := r.cmd.Wait()
		r.exit = exitCode(err)
		_ = pw.Close()
		close(r.done)
	}()
	t.Cleanup(func() {
		select {
		case <-r.done:
		default:
			_ = r.cmd.Process.Kill()
			<-r.done
		}
		if t.Failed() {
			t.Logf("receiver stdout:\n%s\nreceiver stderr:\n%s", r.stdout, r.stderr)
		}
	})
	banner := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			if a, ok := strings.CutPrefix(line, "Listening on "); ok {
				r.addrs = append(r.addrs, a)
			}
			if c, ok := strings.CutPrefix(line, "Code: "); ok {
				r.code = c
				banner <- nil
				_, _ = io.Copy(io.Discard, pr)
				return
			}
		}
		banner <- errors.New("receiver exited before printing its banner")
	}()
	select {
	case err := <-banner:
		if err != nil {
			<-r.done
			t.Fatalf("%v (exit %d): %s", err, r.exit, r.stderr)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for the receiver banner")
	}
	if len(r.addrs) == 0 {
		t.Fatal("receiver printed no address")
	}
	return r
}

// addr returns the receiver's first listening address.
func (r *receiver) addr() string { return r.addrs[0] }

// wait waits for the receiver to exit and returns its exit code.
func (r *receiver) wait(t *testing.T, timeout time.Duration) int {
	t.Helper()
	select {
	case <-r.done:
		return r.exit
	case <-time.After(timeout):
		t.Fatalf("receiver did not exit within %v\nstderr:\n%s", timeout, r.stderr)
		return -1
	}
}

// result is the outcome of a finished subprocess.
type result struct {
	exit   int
	stdout string
	stderr string
}

// runSender runs `transporter send ARGS` to completion.
func runSender(t *testing.T, env []string, stdin io.Reader, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, append([]string{"send"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = stdin
	var out, errb syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := result{exit: exitCode(err), stdout: out.String(), stderr: errb.String()}
	if t.Failed() {
		t.Logf("sender stderr:\n%s", res.stderr)
	}
	return res
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
