// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

//go:build !linux && !darwin && !freebsd && !windows

package recv

// freeSpace is unknown on this platform; the RCV-9 check is skipped.
func freeSpace(string) int64 { return -1 }

func isNoSpacePlatform(error) bool { return false }
