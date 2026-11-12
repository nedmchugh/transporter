// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

//go:build windows

package manifest

import "testing"

// makeSpecialFiles is a no-op on Windows; the TREE-6 assertions that use it
// are skipped there.
func makeSpecialFiles(*testing.T, string) {}
