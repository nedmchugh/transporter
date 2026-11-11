// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package recv

import (
	"errors"

	"golang.org/x/sys/windows"
)

// freeSpace returns the bytes available to the caller on the volume holding
// dir, or -1 if unknown (RCV-9).
func freeSpace(dir string) int64 {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree); err != nil {
		return -1
	}
	return int64(avail)
}

// isNoSpacePlatform recognizes the Windows "disk full" errors.
func isNoSpacePlatform(err error) bool {
	return errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL)
}
