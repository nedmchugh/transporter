// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package proto_test

import (
	"fmt"

	"github.com/nedmchugh/transporter/internal/proto"
)

// Messages are encoded with Append and parsed with Decode; one message
// travels in one secure frame.
func ExampleDecode() {
	b := proto.Append(nil, proto.FileStart{Index: 3, Offset: 2 * proto.ChunkSize})
	fmt.Printf("% x\n", b)
	m, err := proto.Decode(b)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%v %+v\n", m.Type(), m)
	// Output:
	// 05 00 00 00 03 00 00 00 00 00 01 00 00
	// FILE_START {Index:3 Offset:65536}
}
