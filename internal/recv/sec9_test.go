// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package recv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyRootFilesystemAccess enforces SEC-9 by inspecting this package's
// source: path-based os functions may not be used, except os.MkdirAll for
// creating the destination itself (the root cannot exist before it is
// created) in receiver.go. Everything else must go through *os.Root.
func TestOnlyRootFilesystemAccess(t *testing.T) {
	banned := map[string]bool{
		"Open": true, "OpenFile": true, "Create": true, "Mkdir": true, "MkdirAll": true,
		"Remove": true, "RemoveAll": true, "Rename": true, "Chmod": true, "Chtimes": true,
		"Chown": true, "Lchown": true, "Stat": true, "Lstat": true, "ReadFile": true,
		"WriteFile": true, "ReadDir": true, "Truncate": true, "Link": true, "Symlink": true,
		"Readlink": true, "DirFS": true, "CopyFS": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && banned[sel.Sel.Name] {
				if name == "receiver.go" && sel.Sel.Name == "MkdirAll" {
					return true
				}
				t.Errorf("%s: os.%s bypasses os.Root (SEC-9)", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}
