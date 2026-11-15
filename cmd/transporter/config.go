// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// The config file holds the user's own defaults for flags (docs/DECISIONS.md
// D-9.9). It is YAML:
//
//	verbose: 1
//	send:
//	  retry-timeout: 30m
//	receive:
//	  port: 4000
//
// Precedence is: command line, then config file, then built-in default.

// configKeys are the settings a config file may hold: the flag names, per
// section ("" is the top level, for global flags). They mirror the flags
// exactly, so the file and the command line cannot disagree about names.
//
// The code and --code-file are deliberately absent: CODE-8 fixes where the
// code may come from, and a code stored in a file of defaults would be a
// long-lived secret on disk.
var configKeys = map[string][]string{
	"":        {"verbose"},
	"send":    {"to", "retry-timeout", "verify", "no-mdns", "no-sweep", "sweep-port"},
	"receive": {"port", "bind", "overwrite", "verify", "idle-timeout", "no-mdns", "no-sweep", "sweep-port"},
}

// configFileName is the default config file inside the user's config
// directory (os.UserConfigDir, then the project name).
const configFileName = "config.yaml"

// configFormats are the accepted file extensions. Only YAML is parsed.
var configFormats = []string{".yaml", ".yml"}

// maxConfigSize bounds how much of a config file is read; a real one is a
// few hundred bytes.
const maxConfigSize = 64 << 10

// setting is one value from the config file: its raw text, exactly as it
// would be typed after the flag, and where it was, for error messages.
type setting struct {
	value string
	line  int
}

// applyConfig reads the config file, if any, and applies its values to the
// flags of command c that were not given on the command line. Each value
// goes through the flag's own parser (and later the same range checks), so
// the file accepts exactly what the command line accepts.
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
	settings, err := readConfig(path)
	if err != nil {
		return err
	}
	section := c.Name()
	if c == c.Root() {
		section = ""
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sec, name := splitKey(key)
		if sec != "" && sec != section {
			continue // a setting for the other subcommand
		}
		f := c.Flags().Lookup(name)
		if f == nil || f.Changed {
			continue
		}
		s := settings[key]
		if err := f.Value.Set(s.value); err != nil {
			return usagef("config file %s, line %d: %s: invalid value %q: %v", path, s.line, key, s.value, err)
		}
		f.Changed = true
	}
	return nil
}

func splitKey(key string) (section, name string) {
	if i := strings.IndexByte(key, '.'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "", key
}

// readConfig loads and validates the config file at path: a YAML file, not
// writable by other users (on Unix), holding only known keys with single
// values. It returns the settings by key ("verbose", "send.to", ...).
func readConfig(path string) (map[string]setting, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if !slices.Contains(configFormats, ext) {
		return nil, usagef("config file %s: unsupported type %q (the config file is YAML: use %s)", path, ext, strings.Join(configFormats, " or "))
	}
	f, err := os.Open(path) //nolint:gosec // path chosen by the user or the user's config directory
	if err != nil {
		return nil, usagef("cannot read config file: %v", unwrapPathErr(err))
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, usagef("cannot read config file: %v", unwrapPathErr(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, usagef("config file %s is not a regular file", path)
	}
	// Defaults such as overwrite and to change what a transfer does, so,
	// like ssh with its config, refuse a file that other users could have
	// written. Windows has no such permission bits.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return nil, usagef("config file %s is writable by other users; run: chmod go-w %s", path, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, usagef("cannot read config file: %v", err)
	}
	if len(data) > maxConfigSize {
		return nil, usagef("config file %s is larger than %d KiB", path, maxConfigSize>>10)
	}
	settings, err := parseConfig(data)
	if err != nil {
		return nil, usagef("config file %s: %v", path, err)
	}
	return settings, nil
}

// parseConfig parses YAML into settings. It walks the node tree rather than
// decoding into Go values, so each value keeps its exact text (no type
// conversion between the file and the flag parser) and its line number.
// Duplicate keys and repeated sections are errors: decoding into a node
// tree does not reject them, and silently keeping one would hide a mistake.
func parseConfig(data []byte) (map[string]setting, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := map[string]setting{}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return out, nil // an empty file
	}
	root := doc.Content[0]
	if isNull(root) {
		return out, nil // a file holding only comments or "~"
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: expected settings like \"send:\" or \"verbose: 1\"", root.Line)
	}
	sections := map[string]bool{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		name := k.Value
		if _, isSection := configKeys[name]; isSection && name != "" {
			if sections[name] {
				return nil, fmt.Errorf("line %d: %q appears more than once", k.Line, name)
			}
			sections[name] = true
			if isNull(v) {
				continue // an empty "send:" or "receive:" section
			}
			if v.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("line %d: %q must hold settings, like \"%s:\\n  verify: true\"", v.Line, name, name)
			}
			for j := 0; j+1 < len(v.Content); j += 2 {
				if err := addSetting(out, name, v.Content[j], v.Content[j+1]); err != nil {
					return nil, err
				}
			}
			continue
		}
		if err := addSetting(out, "", k, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func addSetting(out map[string]setting, section string, k, v *yaml.Node) error {
	key := k.Value
	if section != "" {
		key = section + "." + key
	}
	if err := checkConfigKey(section, k.Value, key); err != nil {
		return fmt.Errorf("line %d: %w", k.Line, err)
	}
	if prev, dup := out[key]; dup {
		return fmt.Errorf("line %d: %s is already set on line %d", k.Line, key, prev.line)
	}
	// Only plain values: no lists, maps, aliases or nulls.
	if v.Kind != yaml.ScalarNode || isNull(v) {
		return fmt.Errorf("line %d: %s must be a single value", v.Line, key)
	}
	out[key] = setting{value: v.Value, line: v.Line}
	return nil
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// checkConfigKey reports whether name is a known setting in section; key
// is the full name, for messages. The error never includes the value, so a
// code put in the file is not echoed (CODE-7).
func checkConfigKey(section, name, key string) error {
	if name == "code" || name == "code-file" {
		return fmt.Errorf("%s: the code cannot be set in a config file; pass it as an argument, with --code-file, in $%s, or at the prompt", key, CodeEnv)
	}
	if slices.Contains(configKeys[section], name) {
		return nil
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
