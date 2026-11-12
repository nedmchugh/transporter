// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

//go:build !windows

package main

// enableVT reports whether the terminal interprets ANSI escapes; Unix
// terminals do.
func enableVT(uintptr) bool { return true }
