// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/nedmchugh/transporter/internal/discover"
	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/meta"
)

// sendMain and receiveMain run the subcommands once flags are final. They
// are variables so tests can check the merged flags without a transfer.
var (
	sendMain    = runSend
	receiveMain = runReceive
)

// usageErr marks errors that are the user's invocation (exit 2, CLI-7).
type usageErr struct{ msg string }

func (e usageErr) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageErr{fmt.Sprintf(format, a...)} }

// run parses args and runs the chosen subcommand, returning the exit code.
// A fresh command tree is built per call, so tests can run it repeatedly.
func run(ctx context.Context, args []string, env *environment) int {
	exit := fail.ExitOK
	var configPath string

	var version bool
	root := &cobra.Command{
		Use: meta.Name,
		// Version is left unset and --version handled here: cobra's version
		// output, like any custom template, goes through text/template,
		// which disables most dead-code elimination in the linker and adds
		// megabytes to the binary (see cobra's TestDeadcodeElimination).
		// Errors and usage are printed by run, in the project's format
		// (CLI-4), not by cobra.
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if version {
				fmt.Fprintln(env.stdout, meta.Name, meta.Version)
				return nil
			}
			if len(args) > 0 {
				return usagef("unknown command %q", args[0])
			}
			printHelp(env, c)
			exit = fail.ExitUsage
			return nil
		},
	}
	root.SetArgs(args)
	root.SetContext(ctx)
	root.SetIn(env.stdin)
	root.SetOut(env.stdout)
	root.SetErr(env.stderr)
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpFunc(func(c *cobra.Command, _ []string) { printHelp(env, c) })
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr{err.Error()} })
	pf := root.PersistentFlags()
	pf.CountP("verbose", "v", "")
	pf.StringVar(&configPath, "config", "", "")
	root.Flags().BoolVar(&version, "version", false, "")

	root.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		if c.Name() == "help" || version {
			return nil // help and --version work even with a broken config file
		}
		return applyConfig(c, configPath, env)
	}

	send := &cobra.Command{
		Use:  "send",
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			f, err := sendFlagsFrom(c, args)
			if err != nil {
				return err
			}
			exit = sendMain(c.Context(), f, verboseOf(c), env)
			return nil
		},
	}
	addSendFlags(send.Flags())

	receive := &cobra.Command{
		Use:     "receive",
		Aliases: []string{"recv"},
		Args:    cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			f, err := receiveFlagsFrom(c, args)
			if err != nil {
				return err
			}
			exit = receiveMain(c.Context(), f, verboseOf(c), env)
			return nil
		},
	}
	addReceiveFlags(receive.Flags())

	root.AddCommand(send, receive)

	if err := root.Execute(); err != nil {
		msg := err.Error()
		// cobra's own message for an unknown subcommand names the root
		// command and suggests the closest match; keep only the first line.
		msg, _, _ = strings.Cut(msg, "\n")
		return usageError(env, msg)
	}
	return exit
}

func verboseOf(c *cobra.Command) int {
	n, _ := c.Flags().GetCount("verbose")
	return n
}

// printHelp writes the hand-written help for c (CLI-5) to stderr. The text
// is kept by hand, rather than generated, so that every flag states its
// default in words, which pflag's generated usage omits for zero values.
func printHelp(env *environment, c *cobra.Command) {
	switch c.Name() {
	case "send":
		fmt.Fprintf(env.stderr, sendUsage, meta.Name, CodeEnv, discover.SweepPort)
	case "receive":
		fmt.Fprintf(env.stderr, receiveUsage, meta.Name, discover.SweepPort)
	default:
		fmt.Fprintf(env.stderr, globalUsage, meta.Name, defaultConfigHint(env))
	}
}

// defaultConfigPath returns where the config file is looked for when
// --config is not given, or "" if the user has no config directory.
func defaultConfigPath(env *environment) string {
	dir, err := env.userConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, meta.Name, configFileName)
}

func defaultConfigHint(env *environment) string {
	if p := defaultConfigPath(env); p != "" {
		return p
	}
	return "(none: no user config directory)"
}

// addSweepFlags defines the UDP sweep flags shared by send and receive
// (DISC-9).
func addSweepFlags(fs *pflag.FlagSet) {
	fs.Bool("no-sweep", false, "")
	fs.Int("sweep-port", discover.SweepPort, "")
}

func sweepFlagsFrom(fl *pflag.FlagSet) (noSweep bool, port int, err error) {
	noSweep, _ = fl.GetBool("no-sweep")
	port, _ = fl.GetInt("sweep-port")
	if port < 1 || port > 65535 {
		return false, 0, usagef("--sweep-port must be between 1 and 65535")
	}
	return noSweep, port, nil
}
