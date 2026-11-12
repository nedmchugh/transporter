// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/discover"
	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/manifest"
	"github.com/nedmchugh/transporter/internal/meta"
	"github.com/nedmchugh/transporter/internal/pairing"
	"github.com/nedmchugh/transporter/internal/progress"
	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/send"
)

const sendUsage = `Usage: %[1]s send [flags] [CODE] PATH...

Send files and directories to a waiting receiver. Each PATH is stored under
its base name, like 'cp -r'. Transfers resume automatically after network
problems.

The code can be given as the first argument, with --code-file, in the
%[2]s environment variable, or typed at a prompt (in that order of
precedence). A code on the command line is visible to other users of this
machine in process listings and shell history; prefer the other methods on
shared machines.

Flags:
  --to HOST:PORT       connect to this receiver (default "": find it on the
                       local network with mDNS)
  --code-file PATH     read the code from the first line of PATH, or stdin
                       for '-' (default "": not used)
  --retry-timeout DUR  keep retrying after network failures for this long
                       without progress (default 10m0s; 0 disables retries)
  --verify             compare file contents by hash instead of size and
                       modification time (default false)
  --no-mdns            do not use mDNS; requires --to (default false)
  -v, --verbose        more log output; repeat for debug (default: warnings
                       and errors only)
`

// CodeEnv is the environment variable holding the code (CODE-8):
// TRANSPORTER_CODE, derived from the project name (NFR-7).
var CodeEnv = strings.ToUpper(meta.Name) + "_CODE"

type sendFlags struct {
	to           string
	codeFile     string
	retryTimeout time.Duration
	verify       bool
	noMDNS       bool
	verbose      verbosity
	positionals  []string
}

func parseSend(args []string) (*sendFlags, error) {
	f := &sendFlags{retryTimeout: send.DefaultRetryTimeout}
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	fs.StringVar(&f.to, "to", "", "")
	fs.StringVar(&f.codeFile, "code-file", "", "")
	fs.DurationVar(&f.retryTimeout, "retry-timeout", send.DefaultRetryTimeout, "")
	fs.BoolVar(&f.verify, "verify", false, "")
	fs.BoolVar(&f.noMDNS, "no-mdns", false, "")
	fs.Var(&f.verbose, "v", "")
	fs.Var(&f.verbose, "verbose", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	if f.retryTimeout < 0 {
		return nil, errors.New("--retry-timeout must not be negative")
	}
	f.positionals = pos
	return f, nil
}

// splitCodeAndPaths applies CLI-6: the first positional is the code if and
// only if it parses as a complete, valid code; otherwise every positional
// is a path. A first positional that looks like a mistyped code and is not
// an existing path is reported by its parse error, without echoing it
// (docs/DECISIONS.md D-3.4).
func splitCodeAndPaths(pos []string, exists func(string) bool) (code.Code, []string, error) {
	if len(pos) == 0 {
		return code.Code{}, nil, nil
	}
	c, err := code.Parse(pos[0])
	if err == nil {
		return c, pos[1:], nil
	}
	if !exists(pos[0]) && code.LooksLikeCode(pos[0]) {
		return code.Code{}, nil, fmt.Errorf("the first argument looks like a code but is not valid: %w", err)
	}
	return code.Code{}, pos, nil
}

// readCode obtains the code from the CODE-8 sources in order of precedence:
// positional, --code-file, environment, interactive prompt.
func readCode(positional code.Code, codeFile string, env *environment) (code.Code, error) {
	if !positional.IsZero() {
		return positional, nil
	}
	parse := func(src, s string) (code.Code, error) {
		c, err := code.Parse(s)
		if err != nil {
			return code.Code{}, fmt.Errorf("the code from %s is not valid: %w", src, err)
		}
		return c, nil
	}
	if codeFile != "" {
		r := env.stdin
		src := "standard input"
		if codeFile != "-" {
			f, err := os.Open(codeFile) //nolint:gosec // path chosen by the user
			if err != nil {
				return code.Code{}, fmt.Errorf("cannot read --code-file: %w", unwrapPathErr(err))
			}
			defer func() { _ = f.Close() }()
			r, src = f, "--code-file"
		}
		line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return code.Code{}, fmt.Errorf("cannot read the code from %s: %w", src, err)
		}
		return parse(src, line)
	}
	if v := env.getenv(CodeEnv); v != "" {
		return parse("$"+CodeEnv, v)
	}
	if env.isTerminal(env.stdin) {
		fmt.Fprint(env.stderr, "Enter the code shown by the receiver: ")
		s, err := env.readPassword()
		fmt.Fprintln(env.stderr)
		if err != nil {
			return code.Code{}, fmt.Errorf("cannot read the code: %w", err)
		}
		return parse("the prompt", s)
	}
	return code.Code{}, errors.New("no code given: pass it as the first argument, with --code-file, or in $" + CodeEnv)
}

func unwrapPathErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func runSend(ctx context.Context, args []string, verbose int, env *environment) int {
	f, err := parseSend(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(env.stderr, sendUsage, meta.Name, CodeEnv)
			return fail.ExitOK
		}
		return usageError(env, err.Error())
	}
	verbose += int(f.verbose)
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	posCode, paths, err := splitCodeAndPaths(f.positionals, exists)
	if err != nil {
		return usageError(env, err.Error())
	}
	if len(paths) == 0 {
		return usageError(env, "nothing to send: give one or more files or directories")
	}
	if f.noMDNS && f.to == "" {
		return usageError(env, "--no-mdns requires --to HOST:PORT")
	}
	c, err := readCode(posCode, f.codeFile, env)
	if err != nil {
		return usageError(env, err.Error())
	}
	pairer, err := pairing.NewCodePairer(c)
	if err != nil {
		printError(env, fail.New(fail.Internal, "cannot derive keys", "", err))
		return fail.ExitInternal
	}

	list, err := manifest.Walk(paths)
	if err != nil {
		var ue *manifest.UsageError
		if errors.As(err, &ue) {
			return usageError(env, ue.Msg)
		}
		printError(env, err)
		return fail.ExitInternal
	}
	prog := newProgress(env)
	log := newLogger(prog.Writer(), verbose)
	for _, p := range list.Problems {
		if p.Kind == manifest.Skipped {
			log.Warn("skipping", "path", p.String())
		} else {
			log.Warn("cannot send", "path", p.String())
		}
	}

	opts := send.Options{
		List: list, Addr: f.to, Pairer: pairer, Verify: f.verify,
		RetryTimeout: f.retryTimeout, Logger: log, Progress: prog,
	}
	if f.to == "" {
		// DISC-4: --to always takes precedence; discovery is only the
		// fallback when no address was given.
		tag := pairer.DiscoveryTag()
		opts.Resolve = func(ctx context.Context) (string, error) {
			addr, err := browse(ctx, tag, log)
			if err != nil {
				// DISC-3: point at --to and at the usual cause.
				fe := fail.New(fail.Network, fmt.Sprintf("could not find the receiver on the local network within %v", discover.DefaultTimeout),
					"use --to HOST:PORT with an address the receiver printed; mDNS is often blocked on guest and corporate networks", err)
				fe.Final = true // DISC-3: fail, do not retry discovery
				return "", fe
			}
			log.Info("found receiver", "addr", addr)
			return addr, nil
		}
	}
	pctx, stopProg := context.WithCancel(ctx)
	go prog.Run(pctx, 0)
	sum, runErr := send.Run(ctx, opts)
	stopProg()
	printSendSummary(env, sum)
	if runErr != nil {
		printError(env, runErr)
	}
	kind := fail.KindOf(runErr)
	if sum != nil {
		kind = fail.Worst(kind, sum.Kind())
	}
	return kind.ExitCode()
}

func printSendSummary(env *environment, s *send.Summary) {
	if s == nil {
		return
	}
	w := env.stderr
	fmt.Fprintf(w, "Summary: %d file(s) sent (%s), %d already complete, %d conflict(s), %d error(s), %d integrity failure(s), %d retr%s, %s elapsed\n",
		s.Transferred, bytesText(s.Bytes), s.Skipped, len(s.Conflicts), len(s.Errors), len(s.Integrity),
		s.Retries, plural(s.Retries, "y", "ies"), durText(s.Elapsed))
	list(w, "Conflicts (the receiver has different files; rerun the receiver with --overwrite to replace)", s.Conflicts)
	var errs []string
	for _, e := range s.Errors {
		errs = append(errs, e.Path+": "+e.Msg)
	}
	list(w, "Errors", errs)
	list(w, "Integrity failures (hash mismatch after retransmission)", s.Integrity)
	list(w, "Warnings (not transferred, by design)", s.Warnings)
	list(w, "Not transferred yet (run the same command again to resume)", s.NotTransferred)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// maxListed bounds each list in the summary.
const maxListed = 20

func list(w io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", title)
	for i, it := range items {
		if i == maxListed {
			fmt.Fprintf(w, "  ... and %d more\n", len(items)-maxListed)
			break
		}
		// Items may contain peer-supplied names; never print control
		// characters from them (terminal escape injection).
		fmt.Fprintf(w, "  %s\n", proto.Printable(strings.TrimSpace(it)))
	}
}

func bytesText(n int64) string       { return progress.Bytes(n) }
func durText(d time.Duration) string { return progress.Duration(d) }
