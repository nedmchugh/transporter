// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build e2e && race

package e2e

// raceEnabled builds the binary under test with the race detector when the
// tests themselves run with -race.
const raceEnabled = true
