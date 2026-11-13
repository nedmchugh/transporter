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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/meta"
)

// configKeys are the settings a config file may hold, as "section.flag"
// (or just "flag" for global flags), mapped to the flag they set. They
// mirror the flags exactly, so the file and the command line cannot
// disagree about names or value syntax (docs/DECISIONS.md D-9.9).
//
// The code and --code-file are deliberately absent: CODE-8 fixes where the
// code may come from, and a code stored in a file of defaults would be a
// long-lived secret on disk.
var configKeys = map[string][]string{
	"":        {"verbose"},
	"send":    {"to", "retry-timeout", "verify", "no-mdns"},
	"receive": {"port", "bind", "overwrite", "verify", "idle-timeout", "no-mdns"},
}

// configFileName is the default config file inside the user's config
// directory (os.UserConfigDir, then the project name).
const configFileName = "config.yaml"

// configFormats are the file types accepted for --config, by extension.
// Viper can parse more; the list is kept short so the parsers reachable
// from a config file stay few.
var configFormats = []string{".yaml", ".yml", ".toml", ".json"}

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

	root := &cobra.Command{
		Use:     meta.Name,
		Version: meta.Version,
		// Errors and usage are printed by run, in the project's format
		// (CLI-4), not by cobra.
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
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
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpFunc(func(c *cobra.Command, _ []string) { printHelp(env, c) })
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr{err.Error()} })
	pf := root.PersistentFlags()
	pf.CountP("verbose", "v", "")
	pf.StringVar(&configPath, "config", "", "")
	root.Flags().Bool("version", false, "")

	root.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		if c.Name() == "help" {
			return nil // help works even with a broken config file
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
		fmt.Fprintf(env.stderr, sendUsage, meta.Name, CodeEnv)
	case "receive":
		fmt.Fprintf(env.stderr, receiveUsage, meta.Name)
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

// applyConfig reads the config file, if any, and applies its values to the
// flags of command c that were not given on the command line, so the
// precedence is: command line, then config file, then built-in default.
// Values go through each flag's own parser, so a config value is checked
// exactly like the same value typed on the command line.
func applyConfig(c *cobra.Command, explicit string, env *environment) error {
	path := explicit
	if path == "" {
		path = defaultConfigPath(env)
		if path == "" {
			return nil
		}
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return nil // no config file is the normal case
		}
	}
	v, err := readConfig(path)
	if err != nil {
		return err
	}
	section := c.Name()
	if c == c.Root() {
		section = ""
	}
	for _, key := range sortedKeys(v) {
		sec, name := "", key
		if i := strings.LastIndexByte(key, '.'); i >= 0 {
			sec, name = key[:i], key[i+1:]
		}
		if sec != "" && sec != section {
			continue // a setting for the other subcommand
		}
		f := c.Flags().Lookup(name)
		if f == nil || f.Changed {
			continue
		}
		if err := setFromConfig(f, v.Get(key)); err != nil {
			return usagef("config file %s: %s: %v", path, key, err)
		}
	}
	return nil
}

// readConfig loads and validates the config file at path: a known format,
// not writable by other users (on Unix), and only known keys.
func readConfig(path string) (*viper.Viper, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if !slices.Contains(configFormats, ext) {
		return nil, usagef("config file %s: unsupported type %q (use %s)", path, ext, strings.Join(configFormats, ", "))
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, usagef("cannot read config file: %v", unwrapPathErr(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, usagef("config file %s is not a regular file", path)
	}
	// Defaults such as --overwrite and --to change what a transfer does,
	// so, like ssh with its config, refuse a file that other users could
	// have written. Windows has no such permission bits.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return nil, usagef("config file %s is writable by other users; run: chmod go-w %s", path, path)
	}
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, usagef("config file %s: %v", path, err)
	}
	for _, key := range v.AllKeys() {
		if err := checkConfigKey(key); err != nil {
			return nil, usagef("config file %s: %v", path, err)
		}
	}
	return v, nil
}

func checkConfigKey(key string) error {
	sec, name := "", key
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		sec, name = key[:i], key[i+1:]
	}
	if name == "code" || name == "code-file" {
		return fmt.Errorf("%s: the code cannot be set in a config file; pass it as an argument, with --code-file, in $%s, or at the prompt", key, CodeEnv)
	}
	if slices.Contains(configKeys[sec], name) {
		return nil
	}
	if _, isSection := configKeys[name]; sec == "" && isSection && name != "" {
		return nil // an empty "send:" or "receive:" section
	}
	return fmt.Errorf("unknown setting %q (known: %s)", key, strings.Join(knownConfigKeys(), ", "))
}

func knownConfigKeys() []string {
	var out []string
	for sec, names := range configKeys {
		for _, n := range names {
			if sec == "" {
				out = append(out, n)
			} else {
				out = append(out, sec+"."+n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(v *viper.Viper) []string {
	keys := v.AllKeys()
	sort.Strings(keys)
	return keys
}

// setFromConfig sets flag f from a parsed config value. Lists and maps are
// never valid for these flags; scalars are formatted and parsed by the
// flag, as if typed on the command line.
func setFromConfig(f *pflag.Flag, val any) error {
	switch val.(type) {
	case map[string]any, []any:
		return errors.New("must be a single value")
	}
	s := fmt.Sprint(val)
	if err := f.Value.Set(s); err != nil {
		return fmt.Errorf("invalid value %q: %w", s, err)
	}
	f.Changed = true
	return nil
}
