// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package hashpipe runs a hash on a helper goroutine so that hashing a chunk
// overlaps with encrypting and writing it (NFR-3). The caller hands over a
// slice with Start, may read (never modify) it concurrently, and calls Wait
// before reusing the slice. Hash state and order are exactly those of
// calling Write sequentially.
package hashpipe

import "hash"

// Pipe owns a hash and its helper goroutine.
type Pipe struct {
	h    hash.Hash
	in   chan []byte
	done chan struct{}
	busy bool
}

// New starts a helper goroutine for h. Close must be called to stop it.
func New(h hash.Hash) *Pipe {
	p := &Pipe{h: h, in: make(chan []byte), done: make(chan struct{})}
	go func() {
		for b := range p.in {
			_, _ = p.h.Write(b) // hash.Hash.Write never returns an error
			p.done <- struct{}{}
		}
		close(p.done)
	}()
	return p
}

// Start begins hashing b. b must not be modified until Wait returns.
func (p *Pipe) Start(b []byte) {
	p.Wait()
	p.busy = true
	p.in <- b
}

// Wait blocks until the hashing started by the last Start is done.
func (p *Pipe) Wait() {
	if p.busy {
		<-p.done
		p.busy = false
	}
}

// Hash waits for pending work and returns the underlying hash.
func (p *Pipe) Hash() hash.Hash {
	p.Wait()
	return p.h
}

// Close waits for pending work and stops the helper goroutine.
func (p *Pipe) Close() {
	p.Wait()
	close(p.in)
	<-p.done
}
