// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// configEnv returns a test environment whose user config directory is a
// fresh temporary directory, and the path of the default config file in it.
func configEnv(t *testing.T) (*environment, string, *strings.Builder) {
	t.Helper()
	env, _, _ := testEnv("", nil, false)
	dir := t.TempDir()
	env.userConfigDir = func() (string, error) { return dir, nil }
	var sb strings.Builder
	env.stderr = &sb
	return env, filepath.Join(dir, "transporter", configFileName), &sb
}

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConfigDefaults covers the config file (DECISIONS.md D-9.9): values
// from the default file apply to the matching subcommand, and a flag on
// the command line wins over the file.
func TestConfigDefaults(t *testing.T) {
	env, path, errb := configEnv(t)
	writeConfig(t, path, `
verbose: 1
send:
  to: 192.0.2.1:4000
  retry-timeout: 30m
  verify: true
receive:
  port: 4000
  bind: 127.0.0.1
  overwrite: true
  idle-timeout: 1h
  no-mdns: true
  no-sweep: true
  sweep-port: 4001
`)
	got, exit := capture(t, env, "send", "a")
	if exit != 0 {
		t.Fatalf("exit %d\n%s", exit, errb)
	}
	if f := got.send; f.to != "192.0.2.1:4000" || f.retryTimeout != 30*time.Minute || !f.verify || f.noMDNS || f.noSweep || f.sweepPort != 29873 || got.verbose != 1 {
		t.Fatalf("send from config: %+v verbose %d", f, got.verbose)
	}
	got, _ = capture(t, env, "receive", "dest")
	if f := got.receive; f.port != 4000 || f.bind != "127.0.0.1" || !f.overwrite || f.verify || f.idleTimeout != time.Hour || !f.noMDNS || !f.noSweep || f.sweepPort != 4001 || f.dest != "dest" {
		t.Fatalf("receive from config: %+v", f)
	}
	// The command line wins, including setting a boolean back to false.
	got, _ = capture(t, env, "-v", "-v", "send", "--to", "h:1", "--verify=false", "--retry-timeout", "0", "a")
	if f := got.send; f.to != "h:1" || f.verify || f.retryTimeout != 0 || got.verbose != 2 {
		t.Fatalf("flags over config: %+v verbose %d", f, got.verbose)
	}
	// No file: built-in defaults.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, exit := capture(t, env, "send", "a"); exit != 0 || got.send.to != "" || got.send.retryTimeout != 10*time.Minute {
		t.Fatalf("no config: %+v exit %d", got.send, exit)
	}
}

// TestConfigExplicitPath covers --config with each accepted extension,
// and that an explicitly named file must exist.
func TestConfigExplicitPath(t *testing.T) {
	env, _, errb := configEnv(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"c.yaml": "receive:\n  port: 4001\n",
		"c.YML":  "receive:\n  port: \"4001\"\n",
	} {
		p := filepath.Join(dir, name)
		writeConfig(t, p, content)
		got, exit := capture(t, env, "--config", p, "receive")
		if exit != 0 || got.receive == nil || got.receive.port != 4001 {
			t.Errorf("%s: %+v exit %d\n%s", name, got.receive, exit, errb)
		}
	}
	if _, exit := capture(t, env, "--config", filepath.Join(dir, "missing.yaml"), "send", "a"); exit != 2 {
		t.Fatalf("missing explicit config: exit %d", exit)
	}
}

// TestConfigRejects covers the config checks (DECISIONS.md D-9.9, CODE-8,
// CLI-4): each bad file is a usage error (exit 2) with a clear message,
// and nothing runs.
func TestConfigRejects(t *testing.T) {
	tests := []struct {
		name, sub, content, want string
	}{
		{"code", "send", "send:\n  code: abandon-ability\n", "the code cannot be set in a config file"},
		{"code-file", "send", "send:\n  code-file: /tmp/x\n", "the code cannot be set"},
		{"top-level code", "send", "code: abandon-ability\n", "the code cannot be set"},
		{"unknown key", "send", "sned:\n  to: h:1\n", `unknown setting "sned"`},
		{"unknown key in section", "send", "send:\n  tto: h:1\n", `unknown setting "send.tto"`},
		{"global flag in section", "send", "send:\n  verbose: 1\n", `unknown setting "send.verbose"`},
		{"receive flag under send", "send", "send:\n  port: 1\n", `unknown setting "send.port"`},
		{"bad duration", "receive", "receive:\n  idle-timeout: 600\n", "missing unit"},
		{"bad bool", "receive", "receive:\n  verify: maybe\n", "receive.verify"},
		{"list", "receive", "receive:\n  port: [1, 2]\n", "must be a single value"},
		{"range checked like a flag", "receive", "receive:\n  port: 70000\n", "--port must be between"},
		{"syntax", "send", "send: [\n", "config file"},
		{"duplicate key", "send", "send:\n  to: a:1\n  to: b:2\n", "send.to is already set on line 2"},
		{"repeated section", "send", "send:\n  to: a:1\nsend:\n  verify: true\n", `"send" appears more than once`},
		{"duplicate top-level", "send", "verbose: 1\nverbose: 2\n", "verbose is already set"},
		{"alias", "send", "x: &a h:1\nsend:\n  to: *a\n", `unknown setting "x"`},
		{"alias value", "send", "send:\n  to: &a h:1\n  verify: *a\n", "must be a single value"},
		{"not a mapping", "send", "- verbose\n", "expected settings"},
		{"section not a mapping", "send", "send: true\n", `"send" must hold settings`},
		{"null value", "send", "send:\n  to:\n", "must be a single value"},
		{"line number", "receive", "verbose: 1\nreceive:\n  port: 70000\n", "--port must be between"},
		{"line number in error", "receive", "verbose: 1\nreceive:\n\n  idle-timeout: 5\n", "line 4: receive.idle-timeout"},
		{"case matters", "send", "Send:\n  to: h:1\n", `unknown setting "Send"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, path, errb := configEnv(t)
			writeConfig(t, path, tc.content)
			got, exit := capture(t, env, tc.sub, "a")
			if exit != 2 || got.send != nil || got.receive != nil {
				t.Fatalf("exit %d, ran %+v %+v", exit, got.send, got.receive)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("message lacks %q:\n%s", tc.want, errb)
			}
		})
	}
}

// TestConfigUnsupportedType checks that only YAML files are read, and
// that a file far larger than any real config is refused.
func TestConfigUnsupportedType(t *testing.T) {
	for _, name := range []string{"c.toml", "c.json", "c.ini", "c"} {
		env, _, errb := configEnv(t)
		p := filepath.Join(t.TempDir(), name)
		writeConfig(t, p, "{}\n")
		if _, exit := capture(t, env, "--config", p, "send", "a"); exit != 2 || !strings.Contains(errb.String(), "unsupported type") {
			t.Errorf("%s: exit %d\n%s", name, exit, errb)
		}
	}
	env, path, errb := configEnv(t)
	writeConfig(t, path, "# "+strings.Repeat("x", maxConfigSize)+"\n")
	if _, exit := capture(t, env, "send", "a"); exit != 2 || !strings.Contains(errb.String(), "larger than") {
		t.Fatalf("large file: exit %d\n%s", exit, errb)
	}
}

// TestConfigPermissions checks that, on Unix, a config file other users
// can write is refused: it could, for example, turn on --overwrite.
func TestConfigPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX permission bits")
	}
	env, path, errb := configEnv(t)
	writeConfig(t, path, "receive:\n  overwrite: true\n")
	for _, mode := range []os.FileMode{0o620, 0o602} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		got, exit := capture(t, env, "receive")
		if exit != 2 || got.receive != nil || !strings.Contains(errb.String(), "writable by other users") {
			t.Fatalf("mode %o: exit %d\n%s", mode, exit, errb)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, exit := capture(t, env, "receive"); exit != 0 || !got.receive.overwrite {
		t.Fatalf("0644 file: exit %d\n%s", exit, errb)
	}
}

// TestConfigEmptyAndHelp checks that empty sections are fine and that help
// still works when the config file is broken.
func TestConfigEmptyAndHelp(t *testing.T) {
	env, path, errb := configEnv(t)
	for _, content := range []string{"send:\nreceive:\n", "", "# only a comment\n", "~\n"} {
		writeConfig(t, path, content)
		if _, exit := capture(t, env, "send", "a"); exit != 0 {
			t.Fatalf("%q: exit %d\n%s", content, exit, errb)
		}
	}
	writeConfig(t, path, "bogus: 1\n")
	for _, args := range [][]string{{"help"}, {"--help"}, {"send", "--help"}, {"--version"}} {
		if _, exit := capture(t, env, args...); exit != 0 {
			t.Errorf("%v with a broken config: exit %d\n%s", args, exit, errb)
		}
	}
}

// TestConfigKeysMatchFlags keeps configKeys in step with the flags the
// commands define, so every flag except the code ones can be configured.
func TestConfigKeysMatchFlags(t *testing.T) {
	for _, k := range knownConfigKeys() {
		sec, name := splitKey(k)
		if err := checkConfigKey(sec, name, k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	want := map[string]bool{}
	for _, k := range []string{"send.to", "send.retry-timeout", "send.verify", "send.no-mdns", "send.no-sweep", "send.sweep-port",
		"receive.port", "receive.bind", "receive.overwrite", "receive.verify", "receive.idle-timeout", "receive.no-mdns", "receive.no-sweep", "receive.sweep-port", "verbose"} {
		want[k] = true
	}
	for _, k := range knownConfigKeys() {
		if !want[k] {
			t.Errorf("unexpected key %s", k)
		}
		delete(want, k)
	}
	for k := range want {
		t.Errorf("missing key %s", k)
	}
}

// FuzzParseConfig checks that any file content either parses into known
// keys with single values or is rejected, without panicking.
func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		"verbose: 1\nsend:\n  to: h:1\n  verify: true\nreceive:\n  port: 4000\n",
		"send:\nreceive:\n", "~", "", "- a\n", "send: [\n", "x: &a 1\ny: *a\n",
		"send:\n  code: abandon\n", "send:\n  to: a\n  to: b\n",
	} {
		f.Add([]byte(s))
	}
	known := map[string]bool{}
	for _, k := range knownConfigKeys() {
		known[k] = true
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		settings, err := parseConfig(data)
		if err != nil {
			return
		}
		for k, s := range settings {
			if !known[k] {
				t.Fatalf("accepted unknown key %q", k)
			}
			if s.line < 1 {
				t.Fatalf("%s: line %d", k, s.line)
			}
		}
	})
}
