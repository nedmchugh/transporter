// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

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
		userConfigDir: os.UserConfigDir,
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
	// userConfigDir locates the default config file (os.UserConfigDir).
	userConfigDir func() (string, error)
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
                  (default: warnings and errors only)
  --config PATH   read default flag values from PATH (default: the file
                  below, if it exists)
  --version       print the version and exit
  -h, --help      show help (also: %[1]s send --help, %[1]s receive --help)

Config file:
  Default values for flags can be set in a YAML file, by default
  %[2]s. Flags on the command line win over the
  file, and the file wins over built-in defaults. Example:

    verbose: 1
    send:
      retry-timeout: 30m
      verify: true
    receive:
      port: 4000
      idle-timeout: 1h

  Keys are the flag names under "send:" or "receive:". The code cannot be
  set there. On Unix the file must not be writable by other users.
`

func usageError(env *environment, msg string) int {
	fmt.Fprintf(env.stderr, "%s: %s\nRun '%s --help' for usage.\n", meta.Name, msg, meta.Name)
	return fail.ExitUsage
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
