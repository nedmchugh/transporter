// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

//go:build linux || darwin || freebsd

package recv

import "golang.org/x/sys/unix"

// freeSpace returns the bytes available to unprivileged users on the
// filesystem holding dir, or -1 if unknown (RCV-9).
func freeSpace(dir string) int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return -1
	}
	// Field types differ between platforms; the conversions are safe for
	// any real filesystem size.
	return int64(uint64(st.Bavail) * uint64(st.Bsize)) //nolint:unconvert // types differ by GOOS
}

func isNoSpacePlatform(error) bool { return false }
