// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/OWNER/transporter/internal/code"
	"github.com/OWNER/transporter/internal/fail"
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
	}, &out, &errb
}

func TestParseInterspersed(t *testing.T) {
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
		fs := flag.NewFlagSet("x", flag.ContinueOnError)
		to := fs.String("to", "", "")
		pos, err := parseInterspersed(fs, tc.args)
		if err != nil || !slices.Equal(pos, tc.wantPos) || *to != tc.wantTo {
			t.Errorf("%v: pos %v to %q err %v", tc.args, pos, *to, err)
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
		{[]string{"--bogus"}, 2, "flag provided but not defined"},
		{[]string{"send", "--help"}, 0, "--retry-timeout DUR"},
		{[]string{"receive", "-h"}, 0, "--idle-timeout DUR"},
		{[]string{"send"}, 2, "nothing to send"},
		{[]string{"send", validCode}, 2, "nothing to send"},
		{[]string{"send", "--no-mdns", validCode, "x"}, 2, "--no-mdns requires --to"},
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

// TestHelpDocumentsEveryFlag covers CLI-5: each subcommand's help lists
// every flag it defines, and states defaults.
func TestHelpDocumentsEveryFlag(t *testing.T) {
	for _, tc := range []struct {
		usage string
		flags []string
	}{
		{receiveUsage, []string{"--port", "--bind", "--overwrite", "--verify", "--idle-timeout", "--no-mdns", "--verbose"}},
		{sendUsage, []string{"--to", "--code-file", "--retry-timeout", "--verify", "--no-mdns", "--verbose"}},
	} {
		for _, f := range tc.flags {
			if !strings.Contains(tc.usage, f) {
				t.Errorf("usage lacks %s", f)
			}
		}
		if got := strings.Count(tc.usage, "(default"); got < len(tc.flags) {
			t.Errorf("usage states %d defaults for %d flags", got, len(tc.flags))
		}
	}
	for _, d := range []string{"10m0s", "random free port", "all interfaces"} {
		if all := receiveUsage + sendUsage; !strings.Contains(all, d) {
			t.Errorf("default %q not documented", d)
		}
	}
}

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

func TestVerbosity(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	var v verbosity
	fs.Var(&v, "v", "")
	if err := fs.Parse([]string{"-v", "-v"}); err != nil || v != 2 || v.String() != "2" {
		t.Fatalf("v=%d err=%v", v, err)
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
