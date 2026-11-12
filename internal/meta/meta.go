// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package meta holds the project name and build metadata. The project name
// appears only here (NFR-7), so renaming the tool is a one-line change.
//
// Wire-protocol constants that contain the same word (the Noise prologue,
// HKDF labels and mDNS service type) deliberately do not use Name: renaming
// the project must not change the protocol (see docs/DECISIONS.md D-2.2).
package meta

// Name is the project and binary name.
const Name = "transporter"

// Version is the release version. It is set at build time with
// -ldflags "-X github.com/nedmchugh/transporter/internal/meta.Version=v1.2.3".
var Version = "dev"
