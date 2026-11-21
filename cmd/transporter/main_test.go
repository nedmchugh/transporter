// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/progress"
)

const validCode = "abandon-ability-able-about-above-absent-absorb-abstract-absurd"

func testEnv(stdin string, vars map[string]string, tty bool) (*environment, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return &environment{
		stdin:        strings.NewReader(stdin),
		stdout:       &out,
		stderr:       &errb,
		getenv:       func(k string) string { return vars[k] },
		isTerminal:   func(any) bool { return tty },
		readPassword: func() (string, error) { return stdin, nil },
		// No user config directory, so the developer's own config file
		// never affects tests; config tests set one explicitly.
		userConfigDir: func() (string, error) { return "", errors.New("no config dir in tests") },
	}, &out, &errb
}

// captured holds the flags a subcommand would have run with.
type captured struct {
	send    *sendFlags
	receive *receiveFlags
	verbose int
}

// capture runs the CLI with args, replacing the subcommands so that the
// final flags (command line and config file merged) are recorded instead
// of starting a transfer.
func capture(t *testing.T, env *environment, args ...string) (captured, int) {
	t.Helper()
	var got captured
	oldS, oldR := sendMain, receiveMain
	t.Cleanup(func() { sendMain, receiveMain = oldS, oldR })
	sendMain = func(_ context.Context, f *sendFlags, v int, _ *environment) int {
		got.send, got.verbose = f, v
		return 0
	}
	receiveMain = func(_ context.Context, f *receiveFlags, v int, _ *environment) int {
		got.receive, got.verbose = f, v
		return 0
	}
	return got, run(context.Background(), args, env)
}

// TestInterspersedFlags covers SND-1 and RCV-1: flags may come before,
// between or after positional arguments, and "--" ends flag parsing.
func TestInterspersedFlags(t *testing.T) {
	tests := []struct {
		args    []string
		wantPos []string
		wantTo  string
	}{
		{[]string{"a", "b"}, []string{"a", "b"}, ""},
		{[]string{"--to", "h:1", "a"}, []string{"a"}, "h:1"},
		{[]string{"a", "--to", "h:1", "b"}, []string{"a", "b"}, "h:1"},
		{[]string{"a", "b", "--to=h:2"}, []string{"a", "b"}, "h:2"},
		{[]string{"a", "--", "--to", "b"}, []string{"a", "--to", "b"}, ""},
		{[]string{"-"}, []string{"-"}, ""},
	}
	for _, tc := range tests {
		env, _, errb := testEnv("", nil, false)
		got, exit := capture(t, env, append([]string{"send"}, tc.args...)...)
		if exit != 0 || got.send == nil || !slices.Equal(got.send.positionals, tc.wantPos) || got.send.to != tc.wantTo {
			t.Errorf("%v: exit %d, flags %+v\n%s", tc.args, exit, got.send, errb)
		}
	}
}

// TestSplitCodeAndPaths covers CLI-6.
func TestSplitCodeAndPaths(t *testing.T) {
	none := func(string) bool { return false }
	all := func(string) bool { return true }
	c, paths, err := splitCodeAndPaths([]string{validCode, "a", "b"}, none)
	if err != nil || c.IsZero() || !slices.Equal(paths, []string{"a", "b"}) {
		t.Fatalf("code first: %v %v", paths, err)
	}
	// A lenient form is still a complete valid code.
	c, paths, err = splitCodeAndPaths([]string{"ABANDON.abil.able.about.above.absent.absorb.abstract.absurd", "a"}, none)
	if err != nil || c.IsZero() || len(paths) != 1 {
		t.Fatalf("lenient code: %v %v", paths, err)
	}
	// Not a code: every positional is a path.
	c, paths, err = splitCodeAndPaths([]string{"./project", "b"}, all)
	if err != nil || !c.IsZero() || len(paths) != 2 {
		t.Fatalf("paths only: %v %v", paths, err)
	}
	// A mistyped code that is not a file is an error naming only the bad
	// word, never echoing the argument (D-3.4, CODE-7).
	typo := "abandon-abillity-able-about-above-absent-absorb-abstract-absurd"
	_, _, err = splitCodeAndPaths([]string{typo, "a"}, none)
	if err == nil || strings.Contains(err.Error(), typo) || strings.Contains(err.Error(), "absorb") || !strings.Contains(err.Error(), "abillity") {
		t.Fatalf("typo error: %v", err)
	}
	// ...but if such a file exists, it is a path.
	if _, paths, err = splitCodeAndPaths([]string{typo}, all); err != nil || len(paths) != 1 {
		t.Fatalf("existing typo file: %v %v", paths, err)
	}
	if c, paths, err = splitCodeAndPaths(nil, none); err != nil || !c.IsZero() || paths != nil {
		t.Fatal("empty")
	}
}

// TestReadCodePrecedence covers CODE-8: positional, --code-file, the
// environment, then an interactive prompt.
func TestReadCodePrecedence(t *testing.T) {
	other := "zoo-zone-zero-youth-young-yellow-year-wrong-write"
	pos, _ := code.Parse(validCode)
	file := filepath.Join(t.TempDir(), "code.txt")
	if err := os.WriteFile(file, []byte(other+"\nsecond line ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env, _, _ := testEnv("", map[string]string{CodeEnv: validCode}, true)
	if c, err := readCode(pos, file, env); err != nil || c.Reveal() != validCode {
		t.Fatalf("positional wins: %v", err)
	}
	if c, err := readCode(code.Code{}, file, env); err != nil || c.Reveal() != other {
		t.Fatalf("code file: %v", err)
	}
	env, _, _ = testEnv(validCode+"\n", nil, false)
	if c, err := readCode(code.Code{}, "-", env); err != nil || c.Reveal() != validCode {
		t.Fatalf("stdin: %v", err)
	}
	env, _, _ = testEnv("", map[string]string{CodeEnv: other}, true)
	if c, err := readCode(code.Code{}, "", env); err != nil || c.Reveal() != other {
		t.Fatalf("env: %v", err)
	}
	env, _, errb := testEnv(validCode, nil, true)
	if c, err := readCode(code.Code{}, "", env); err != nil || c.Reveal() != validCode || !strings.Contains(errb.String(), "Enter the code") {
		t.Fatalf("prompt: %v", err)
	}
	env, _, _ = testEnv("", nil, false)
	if _, err := readCode(code.Code{}, "", env); err == nil || !strings.Contains(err.Error(), "no code given") {
		t.Fatalf("none: %v", err)
	}
	if _, err := readCode(code.Code{}, filepath.Join(t.TempDir(), "missing"), env); err == nil {
		t.Fatal("missing code file accepted")
	}
	bad := "abandon-ability-able-about-above-absent-absorb-abstract-zzzzzz"
	env, _, _ = testEnv("", map[string]string{CodeEnv: bad}, false)
	if _, err := readCode(code.Code{}, "", env); err == nil || strings.Contains(err.Error(), "absorb") {
		t.Fatalf("invalid env code: %v", err)
	}
}

// TestRunUsage covers CLI-1, CLI-5 and the usage exit code (CLI-7).
func TestRunUsage(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		args []string
		exit int
		want string
	}{
		{[]string{"--version"}, 0, "transporter "},
		{[]string{"--help"}, 0, "Commands:"},
		{[]string{"help"}, 0, "Commands:"},
		{nil, 2, "Usage:"},
		{[]string{"frobnicate"}, 2, "unknown command"},
		{[]string{"--bogus"}, 2, "unknown flag: --bogus"},
		{[]string{"send", "--bogus", "x"}, 2, "unknown flag: --bogus"},
		{[]string{"recv", "--help"}, 0, "--idle-timeout DUR"},
		{[]string{"help", "send"}, 0, "--retry-timeout DUR"},
		{[]string{"--help"}, 0, "Config file:"},
		{[]string{"send", "--help"}, 0, "--retry-timeout DUR"},
		{[]string{"receive", "-h"}, 0, "--idle-timeout DUR"},
		{[]string{"send"}, 2, "nothing to send"},
		{[]string{"send", validCode}, 2, "nothing to send"},
		{[]string{"send", "--no-mdns", "--no-sweep", validCode, "x"}, 2, "--no-mdns and --no-sweep together require --to"},
		{[]string{"send", "--sweep-port", "0", "x"}, 2, "--sweep-port must be between 1 and 65535"},
		{[]string{"receive", "--sweep-port", "65536"}, 2, "--sweep-port must be between 1 and 65535"},
		{[]string{"send", "--help"}, 0, "--sweep-port N"},
		{[]string{"receive", "--help"}, 0, "(default 29873)"},
		{[]string{"send", "--retry-timeout", "-1s", "x"}, 2, "must not be negative"},
		{[]string{"send", "--to", "h:1", "x"}, 2, "no code given"},
		{[]string{"receive", "--port", "70000"}, 2, "--port"},
		{[]string{"receive", "--idle-timeout", "-1s"}, 2, "must not be negative"},
		{[]string{"receive", "a", "b"}, 2, "at most one"},
	}
	for _, tc := range tests {
		env, out, errb := testEnv("", nil, false)
		if got := run(ctx, tc.args, env); got != tc.exit {
			t.Errorf("%v: exit %d, want %d\n%s", tc.args, got, tc.exit, errb)
		}
		if !strings.Contains(out.String()+errb.String(), tc.want) {
			t.Errorf("%v: output lacks %q:\n%s%s", tc.args, tc.want, out, errb)
		}
	}
}

// TestHelpDocumentsEveryFlag covers CLI-5: each help text lists every
// flag the command actually defines, and states defaults.
func TestHelpDocumentsEveryFlag(t *testing.T) {
	for _, tc := range []struct {
		usage string
		add   func(*pflag.FlagSet)
		extra []string
	}{
		{receiveUsage, addReceiveFlags, []string{"--verbose"}},
		{sendUsage, addSendFlags, []string{"--verbose"}},
		{globalUsage, func(*pflag.FlagSet) {}, []string{"--verbose", "--config", "--version", "--help"}},
	} {
		fs := pflag.NewFlagSet("x", pflag.ContinueOnError)
		tc.add(fs)
		names := tc.extra
		fs.VisitAll(func(f *pflag.Flag) { names = append(names, "--"+f.Name) })
		for _, f := range names {
			if !strings.Contains(tc.usage, f) {
				t.Errorf("usage lacks %s", f)
			}
		}
		if tc.usage != globalUsage {
			if got := strings.Count(tc.usage, "(default"); got < len(names) {
				t.Errorf("usage states %d defaults for %d flags", got, len(names))
			}
		}
	}
	for _, d := range []string{"10m0s", "random free port", "all interfaces"} {
		if all := receiveUsage + sendUsage; !strings.Contains(all, d) {
			t.Errorf("default %q not documented", d)
		}
	}
}

// TestListenAddrs covers RCV-4: every non-loopback address, or only the
// explicitly bound one.
func TestListenAddrs(t *testing.T) {
	if got := listenAddrs("192.0.2.1", 4000); !slices.Equal(got, []string{"192.0.2.1:4000"}) {
		t.Fatalf("explicit bind: %v", got)
	}
	got := listenAddrs("", 4000)
	if len(got) == 0 {
		t.Fatal("no addresses")
	}
	for _, a := range got {
		if !strings.HasSuffix(a, ":4000") {
			t.Fatalf("address %q", a)
		}
	}
}

// TestParseReceiveFlags covers RCV-1 (DEST defaults to ".") and RCV-3
// (every flag and its default).
func TestParseReceiveFlags(t *testing.T) {
	env, _, _ := testEnv("", nil, false)
	got, exit := capture(t, env, "receive")
	f := got.receive
	if exit != 0 || f.dest != "." || f.port != 0 || f.bind != "" || f.overwrite || f.verify || f.noMDNS || f.noSweep || f.sweepPort != 29873 || f.idleTimeout != 10*time.Minute {
		t.Fatalf("defaults: %+v exit %d", f, exit)
	}
	got, exit = capture(t, env, "receive", "--port", "4000", "dest", "--bind", "127.0.0.1", "--overwrite", "--verify", "--idle-timeout", "0", "--no-mdns", "--no-sweep", "--sweep-port", "4001", "-v")
	f = got.receive
	if exit != 0 || f.dest != "dest" || f.port != 4000 || f.bind != "127.0.0.1" || !f.overwrite || !f.verify || !f.noMDNS || !f.noSweep || f.sweepPort != 4001 || f.idleTimeout != 0 || got.verbose != 1 {
		t.Fatalf("set: %+v exit %d", f, exit)
	}
}

// TestParseSendFlags covers SND-3: every flag and its default.
func TestParseSendFlags(t *testing.T) {
	if CodeEnv != "TRANSPORTER_CODE" {
		t.Fatalf("CODE-8 environment variable is %q", CodeEnv)
	}
	env, _, _ := testEnv("", nil, false)
	got, exit := capture(t, env, "send", "a")
	f := got.send
	if exit != 0 || f.to != "" || f.codeFile != "" || f.retryTimeout != 10*time.Minute || f.verify || f.noMDNS || f.noSweep || f.sweepPort != 29873 {
		t.Fatalf("defaults: %+v exit %d", f, exit)
	}
	got, exit = capture(t, env, "send", "a", "--to", "h:1", "--code-file", "-", "--retry-timeout", "0", "--verify", "--no-mdns", "--no-sweep", "--sweep-port", "4001", "b")
	f = got.send
	if exit != 0 || f.to != "h:1" || f.codeFile != "-" || f.retryTimeout != 0 || !f.verify || !f.noMDNS || !f.noSweep || f.sweepPort != 4001 || !slices.Equal(f.positionals, []string{"a", "b"}) {
		t.Fatalf("set: %+v exit %d", f, exit)
	}
}

// TestVerbosity covers CLI-1: -v/--verbose is global, repeatable, and may
// appear before or after the subcommand.
func TestVerbosity(t *testing.T) {
	env, _, _ := testEnv("", nil, false)
	for _, args := range [][]string{{"-v", "-v", "send", "a"}, {"-v", "send", "a", "--verbose"}, {"send", "-vv", "a"}} {
		if got, exit := capture(t, env, args...); exit != 0 || got.verbose != 2 {
			t.Errorf("%v: verbose %d exit %d", args, got.verbose, exit)
		}
	}
	for _, lvl := range []int{0, 1, 2} {
		if newLogger(&bytes.Buffer{}, lvl) == nil {
			t.Fatal("nil logger")
		}
	}
}

func TestPrintError(t *testing.T) {
	env, _, errb := testEnv("", nil, false)
	printError(env, fail.New(fail.Auth, "authentication failed", "check the code", errors.New("x")))
	if !strings.Contains(errb.String(), "error: authentication failed: x") || !strings.Contains(errb.String(), "hint: check the code") {
		t.Fatal(errb.String())
	}
}

// lockedBuffer is a bytes.Buffer safe to read while the tracker writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestStartProgressClearsLine covers CLI-2: when stop returns, the status
// line has been cleared, so the summary written next starts on a clean
// line instead of after the last progress line.
func TestStartProgressClearsLine(t *testing.T) {
	for range 20 { // the old race lost most of the time; repeat to be sure
		var buf lockedBuffer
		prog := progress.New(&buf, true)
		prog.SetTotals(5, 1000)
		stop := startProgress(context.Background(), prog)
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(buf.String(), "files") {
			if time.Now().After(deadline) {
				stop()
				t.Fatal("no status line rendered")
			}
			time.Sleep(10 * time.Millisecond)
		}
		stop()
		if out := buf.String(); !strings.HasSuffix(out, "\r\x1b[K") {
			t.Fatalf("status line not cleared when stop returned: %q", out)
		}
	}
}
