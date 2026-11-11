// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command transporter copies files and directory trees between machines over
// an encrypted, resumable connection, paired with a one-time code.
package main

import (
	"fmt"
	"os"

	"github.com/OWNER/transporter/internal/meta"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println(meta.Name, meta.Version)
		return
	}
	fmt.Fprintf(os.Stderr, "usage: %s send|receive ...\n", meta.Name)
	os.Exit(2)
}
