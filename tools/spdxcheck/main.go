// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command spdxcheck verifies that every .go file in the repository begins
// with the MPL-2.0 SPDX header required by LIC-2, and that none carries the
// MPL Exhibit B notice (which LIC-2 forbids).
//
// Usage: go run ./tools/spdxcheck [ROOT]
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Header is the exact text every Go file must start with (LIC-2).
const Header = `// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
`

// forbidden must not appear in source files (LIC-2). It is split so this
// file does not match its own check.
const forbidden = "Incompatible With " + "Secondary Licenses"

// skipDirs are not part of the project's source.
var skipDirs = map[string]bool{".git": true, "obsolete": true, "dist": true, "bin": true, "testdata": true, "vendor": true}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	bad, err := check(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spdxcheck:", err)
		os.Exit(1)
	}
	for _, b := range bad {
		fmt.Fprintln(os.Stderr, b)
	}
	if len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "spdxcheck: %d file(s) lack the MPL-2.0 header (see docs/requirements.md LIC-2)\n", len(bad))
		os.Exit(1)
	}
}

// check returns one message per non-conforming file under root.
func check(root string) ([]string, error) {
	var bad []string
	// root is the repository path given by the developer running the check.
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { //nolint:gosec // G703: walking the developer-supplied repository root is the purpose
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
		if err != nil {
			return err
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		switch {
		case !bytes.HasPrefix(b, []byte(Header)):
			bad = append(bad, path+": missing or altered SPDX/MPL-2.0 header")
		case bytes.Contains(b, []byte(forbidden)):
			bad = append(bad, path+": contains the \""+forbidden+"\" notice")
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipDir) {
		return nil, err
	}
	return bad, nil
}
