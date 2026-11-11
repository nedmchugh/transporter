// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package testutil provides test helpers: a fault-injecting connection, a
// TCP proxy that can interrupt traffic, tree builders and comparers, and a
// goroutine leak check. It is imported only by tests.
package testutil

import (
	"bytes"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// modulePrefix identifies goroutines created by this project's code.
const modulePrefix = "github.com/OWNER/transporter/"

// CheckLeaks records the goroutines running now and, when the test ends,
// fails it if goroutines created by this module's code (outside the test
// function itself) are still running after a grace period (TEST-6, REL-6).
//
// An in-repo helper is used instead of go.uber.org/goleak to avoid a test
// dependency (docs/DECISIONS.md section 6). Call it only from tests that do
// not use t.Parallel: Go runs a sequential test while no parallel tests run,
// so other tests' goroutines cannot be mistaken for leaks.
func CheckLeaks(t testing.TB) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			leaked := leakedSince(before)
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutine(s) leaked:\n\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

func leakedSince(before map[int]string) []string {
	var out []string
	for id, stack := range goroutines() {
		if _, ok := before[id]; ok {
			continue
		}
		if isProjectGoroutine(stack) {
			out = append(out, stack)
		}
	}
	return out
}

// isProjectGoroutine reports whether a goroutine was created by this
// module's code (including test helpers, which must clean up too).
// Goroutines created by the runtime or the testing framework are ignored.
func isProjectGoroutine(stack string) bool {
	i := strings.LastIndex(stack, "created by ")
	if i < 0 {
		return false
	}
	return strings.Contains(stack[i:], modulePrefix)
}

// goroutines returns the stacks of all goroutines keyed by goroutine ID.
func goroutines() map[int]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[int]string{}
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		s := string(g)
		rest, ok := strings.CutPrefix(s, "goroutine ")
		if !ok {
			continue
		}
		idStr, _, _ := strings.Cut(rest, " ")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		out[id] = s
	}
	return out
}
