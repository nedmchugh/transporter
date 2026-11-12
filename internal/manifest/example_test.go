// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package manifest_test

import (
	"fmt"

	"github.com/nedmchugh/transporter/internal/manifest"
)

// ValidatePath is applied by the receiver to every manifest path before any
// filesystem operation.
func ExampleValidatePath() {
	for _, p := range []string{"photos/2024/beach.jpg", "../etc/passwd", "a\\b"} {
		fmt.Println(p, "->", manifest.ValidatePath(p) == nil)
	}
	// Output:
	// photos/2024/beach.jpg -> true
	// ../etc/passwd -> false
	// a\b -> false
}
