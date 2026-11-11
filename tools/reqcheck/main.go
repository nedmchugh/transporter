// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command reqcheck verifies that every MUST requirement in
// docs/requirements.md has a row in the requirements-to-tests table of
// docs/testing.md (TEST-1), and that every test the table names exists.
//
// Usage: go run ./tools/reqcheck [ROOT]
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	mustRe = regexp.MustCompile(`(?m)^- ([A-Z]+-\d+) \(MUST\)`)
	rowRe  = regexp.MustCompile(`(?m)^\| ([A-Z]+-\d+) \| (.*) \|$`)
	testRe = regexp.MustCompile("`([a-z0-9/]+)` ((?:Test|Fuzz|Example)\\w+)")
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	problems, err := check(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reqcheck:", err)
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
}

func check(root string) ([]string, error) {
	req, err := os.ReadFile(filepath.Join(root, "docs", "requirements.md")) //nolint:gosec // repository files
	if err != nil {
		return nil, err
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "testing.md")) //nolint:gosec // repository files
	if err != nil {
		return nil, err
	}
	rows := map[string]string{}
	for _, m := range rowRe.FindAllStringSubmatch(string(doc), -1) {
		rows[m[1]] = m[2]
	}
	var problems []string
	for _, m := range mustRe.FindAllStringSubmatch(string(req), -1) {
		id := m[1]
		cell, ok := rows[id]
		if !ok || strings.TrimSpace(cell) == "" {
			problems = append(problems, "docs/testing.md: no row for "+id)
			continue
		}
		for _, t := range testRe.FindAllStringSubmatch(cell, -1) {
			if !testExists(filepath.Join(root, filepath.FromSlash(t[1])), t[2]) {
				problems = append(problems, fmt.Sprintf("docs/testing.md: %s names %s in %s, which does not exist", id, t[2], t[1]))
			}
		}
	}
	return problems, nil
}

func testExists(dir, name string) bool {
	files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
	files2, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, f := range append(files, files2...) {
		b, err := os.ReadFile(f) //nolint:gosec // repository files
		if err == nil && strings.Contains(string(b), "func "+name+"(") {
			return true
		}
	}
	return false
}
