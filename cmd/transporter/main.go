// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command transporter copies files and directory trees between machines over
// an encrypted, resumable connection, paired with a one-time code.
//
//	receiver$ transporter receive ./dest
//	sender$   transporter send CODE ./project
//
// This package only wires flags and I/O to the internal packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/meta"
	"github.com/nedmchugh/transporter/internal/progress"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	// SIGINT and SIGTERM (os.Interrupt and the console close/Ctrl-Break
	// equivalents on Windows) cancel the context; the subcommands then stop
	// cleanly, keep .part files, print a summary and exit 130 (REL-7).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	env := &environment{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		getenv: os.Getenv,
		isTerminal: func(f any) bool {
			fd, ok := f.(interface{ Fd() uintptr })
			if !ok || !term.IsTerminal(int(fd.Fd())) {
				return false
			}
			// The status line uses ANSI escapes; where the console cannot
			// interpret them (old Windows consoles), use plain output.
			return enableVT(fd.Fd())
		},
		readPassword: func() (string, error) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			return string(b), err
		},
	}
	return run(ctx, os.Args[1:], env)
}

// environment abstracts process I/O so the CLI can be tested in-process.
type environment struct {
	stdin        io.Reader
	stdout       io.Writer
	stderr       io.Writer
	getenv       func(string) string
	isTerminal   func(f any) bool
	readPassword func() (string, error)
}

const globalUsage = `Usage:
  %[1]s receive [flags] [DEST]
  %[1]s send [flags] [CODE] PATH...

Copy files and directories between machines, encrypted, with automatic
resume. Start the receiver first; it prints a one-time code. Then run the
sender on the other machine with that code.

Commands:
  receive   wait for one transfer and write it into DEST (default: .)
  send      send files and directories to a waiting receiver

Global flags:
  -v, --verbose   more log output on stderr (repeat for debug: -v -v)
  --version       print the version and exit
  -h, --help      show help (also: %[1]s send --help, %[1]s receive --help)
`

// verbosity is a repeatable -v flag.
type verbosity int

func (v *verbosity) String() string   { return fmt.Sprint(int(*v)) }
func (v *verbosity) Set(string) error { *v++; return nil }
func (v *verbosity) IsBoolFlag() bool { return true }

func run(ctx context.Context, args []string, env *environment) int {
	fs := flag.NewFlagSet(meta.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var verbose verbosity
	var version bool
	fs.Var(&verbose, "v", "")
	fs.Var(&verbose, "verbose", "")
	fs.BoolVar(&version, "version", false, "")
	help := func() { fmt.Fprintf(env.stderr, globalUsage, meta.Name) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			help()
			return fail.ExitOK
		}
		return usageError(env, err.Error())
	}
	if version {
		fmt.Fprintln(env.stdout, meta.Name, meta.Version)
		return fail.ExitOK
	}
	rest := fs.Args()
	if len(rest) == 0 {
		help()
		return fail.ExitUsage
	}
	switch rest[0] {
	case "receive", "recv":
		return runReceive(ctx, rest[1:], int(verbose), env)
	case "send":
		return runSend(ctx, rest[1:], int(verbose), env)
	case "help":
		help()
		return fail.ExitOK
	}
	return usageError(env, fmt.Sprintf("unknown command %q", rest[0]))
}

func usageError(env *environment, msg string) int {
	fmt.Fprintf(env.stderr, "%s: %s\nRun '%s --help' for usage.\n", meta.Name, msg, meta.Name)
	return fail.ExitUsage
}

// parseInterspersed parses flags that may appear before, between or after
// positional arguments, returning the positionals. "--" ends flag parsing.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		// flag.FlagSet stops at the first non-flag or just after "--";
		// in the latter case everything left is positional.
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	return pos, nil
}

// newLogger returns a slog.Logger writing to w at the level implied by -v.
// Logs never include the code: it is a redacting type and is only revealed
// for the receiver banner (CODE-6, CODE-7, SEC-15).
func newLogger(w io.Writer, verbose int) *slog.Logger {
	level := slog.LevelWarn
	switch {
	case verbose >= 2:
		level = slog.LevelDebug
	case verbose == 1:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// newProgress returns a tracker for stderr, styled for a terminal or not
// (CLI-2).
func newProgress(env *environment) *progress.Tracker {
	return progress.New(env.stderr, env.isTerminal(env.stderr))
}

// printError prints a classified error for end users (CLI-4).
func printError(env *environment, err error) {
	msg := err.Error()
	fmt.Fprintf(env.stderr, "%s: error: %s\n", meta.Name, msg)
	if h := fail.HintOf(err); h != "" {
		fmt.Fprintf(env.stderr, "%s: hint: %s\n", meta.Name, h)
	}
}
