// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

// Package secure implements the encrypted channel: a Noise NNpsk0 handshake
// (X25519, ChaCha20-Poly1305, BLAKE2s) keyed by the pairing secret, followed
// by length-prefixed Noise transport frames (SEC-1 to SEC-8).
//
// Wire format of every frame, including the two handshake messages:
//
//	uint16 big-endian length N | N bytes of Noise message
//
// Nonces are managed entirely by the Noise library's per-direction counters
// (SEC-6); this package never sets or reuses them. Each connection performs
// a fresh handshake with fresh ephemeral keys (SEC-5).
package secure

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/nedmchugh/transporter/internal/pairing"
)

const (
	// Prologue is mixed into the handshake hash, so peers speaking another
	// protocol (or version) fail the handshake cleanly (SEC-3).
	Prologue = "transporter/1"

	// HandshakeTimeout bounds the whole handshake (SEC-4).
	HandshakeTimeout = 10 * time.Second

	// MaxPlaintext is the largest plaintext carried in one frame (SEC-7).
	MaxPlaintext = 48 * 1024

	// TagSize is the AEAD authentication tag appended to each frame.
	TagSize = 16

	// MaxFrame is the largest valid frame length on the wire: comfortably
	// below the Noise limit of 65535 bytes.
	MaxFrame = MaxPlaintext + TagSize

	// maxHandshakeFrame bounds handshake messages. NNpsk0 messages with
	// empty payloads are 48 bytes; anything much larger is not ours
	// (docs/DECISIONS.md D-4.4).
	maxHandshakeFrame = 256

	lenSize = 2
)

// Compile-time check that MaxFrame fits the Noise limit and the length field.
var _ [noise.MaxMsgLen - MaxFrame]struct{}

var (
	// ErrAuthFailed means the handshake did not authenticate: the peer has
	// a different code or is not a Transporter of this version (REL-5).
	// It is deliberately generic (SEC-4).
	ErrAuthFailed = errors.New("authentication failed")

	// ErrFrameSize means a frame header declared a length of zero, below
	// the minimum, or above MaxFrame. The connection is closed.
	ErrFrameSize = errors.New("secure: invalid frame length")

	// ErrFrameAuth means a frame failed authentication (tampered, replayed,
	// reordered or corrupted). The connection is closed (SEC-7).
	ErrFrameAuth = errors.New("secure: frame failed authentication")

	// ErrPlaintextSize is returned by WriteFrame for an empty or oversized
	// plaintext. The connection stays usable.
	ErrPlaintextSize = errors.New("secure: plaintext must be 1 to MaxPlaintext bytes")
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// Conn is an authenticated, encrypted frame connection. ReadFrame must be
// called from one goroutine at a time; WriteFrame is safe for concurrent use
// and may run concurrently with ReadFrame (the two directions use separate
// cipher states and locks).
type Conn struct {
	raw net.Conn

	rmu  sync.Mutex
	br   *bufio.Reader // buffers raw reads: one syscall serves many frames
	rhdr [lenSize]byte
	rbuf []byte // MaxFrame bytes, allocated once
	dec  *noise.CipherState
	rerr error // sticky: the stream position is lost after any error

	wmu  sync.Mutex
	wbuf []byte // lenSize+MaxFrame bytes, allocated once
	enc  *noise.CipherState
	werr error // sticky: a failed write may have advanced the nonce
}

// Client performs the initiator (sender) side of the handshake over raw and
// returns the secure connection. It takes ownership of raw: on error raw is
// closed.
func Client(ctx context.Context, raw net.Conn, p pairing.Pairer) (*Conn, error) {
	return handshake(ctx, raw, p, pairing.Initiator)
}

// Server performs the responder (receiver) side of the handshake. It takes
// ownership of raw: on error raw is closed. On authentication failure it
// sends nothing; the peer only sees the connection close (SEC-4).
func Server(ctx context.Context, raw net.Conn, p pairing.Pairer) (*Conn, error) {
	return handshake(ctx, raw, p, pairing.Responder)
}

func handshake(ctx context.Context, raw net.Conn, p pairing.Pairer, role pairing.Role) (_ *Conn, err error) {
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()

	deadline := time.Now().Add(HandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("setting handshake deadline: %w", err)
	}
	// Cancelling ctx unblocks any read or write in progress by moving the
	// deadline into the past.
	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	key, err := p.HandshakeKey(ctx, raw, role)
	if err != nil {
		return nil, fmt.Errorf("obtaining handshake key: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeNN,
		Initiator:             role == pairing.Initiator,
		Prologue:              []byte(Prologue),
		PresharedKey:          key[:],
		PresharedKeyPlacement: 0, // NNpsk0
	})
	if err != nil {
		return nil, fmt.Errorf("initializing handshake: %w", err)
	}

	c := &Conn{raw: raw}
	if role == pairing.Initiator {
		err = c.clientHandshake(hs)
	} else {
		err = c.serverHandshake(hs)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("handshake: %w", ctxErr)
		}
		return nil, err
	}
	if !stop() {
		// ctx was cancelled after the last message; the deadline has been
		// forced into the past, so the connection is not usable.
		return nil, fmt.Errorf("handshake: %w", context.Cause(ctx))
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clearing handshake deadline: %w", err)
	}
	c.rbuf = make([]byte, MaxFrame)
	c.wbuf = make([]byte, lenSize+MaxFrame)
	// Read deadlines still apply: bufio only reads from raw when its
	// buffer is empty. The handshake used raw directly, so no data has
	// been read ahead of this buffer.
	c.br = bufio.NewReaderSize(raw, 64<<10)
	return c, nil
}

// clientHandshake sends "-> psk, e" and processes "<- e, ee".
func (c *Conn) clientHandshake(hs *noise.HandshakeState) error {
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if err := writeRaw(c.raw, msg); err != nil {
		return fmt.Errorf("handshake: sending: %w", err)
	}
	reply, err := readRaw(c.raw, maxHandshakeFrame)
	if err != nil {
		// A receiver that cannot authenticate message 1 closes the
		// connection without replying (SEC-4). A clean EOF exactly where
		// message 2 should start is therefore the rejection signal.
		// Timeouts, resets and partial frames stay network errors so they
		// are retried (docs/DECISIONS.md D-4.1).
		if errors.Is(err, io.EOF) {
			return ErrAuthFailed
		}
		return fmt.Errorf("handshake: receiving: %w", err)
	}
	payload, cs1, cs2, err := hs.ReadMessage(nil, reply)
	if err != nil || len(payload) != 0 || cs1 == nil || cs2 == nil {
		return ErrAuthFailed
	}
	// Noise returns (initiator->responder, responder->initiator).
	c.enc, c.dec = cs1, cs2
	return nil
}

// serverHandshake processes "-> psk, e" and sends "<- e, ee".
func (c *Conn) serverHandshake(hs *noise.HandshakeState) error {
	msg, err := readRaw(c.raw, maxHandshakeFrame)
	if err != nil {
		if errors.Is(err, ErrFrameSize) {
			return ErrAuthFailed
		}
		return fmt.Errorf("handshake: receiving: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, msg)
	if err != nil || len(payload) != 0 {
		// Wrong PSK or prologue: message 1's tag does not verify.
		return ErrAuthFailed
	}
	reply, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil || cs1 == nil || cs2 == nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if err := writeRaw(c.raw, reply); err != nil {
		return fmt.Errorf("handshake: sending: %w", err)
	}
	c.enc, c.dec = cs2, cs1
	return nil
}

// writeRaw writes one length-prefixed handshake message.
func writeRaw(w io.Writer, msg []byte) error {
	buf := make([]byte, lenSize+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[lenSize:], msg)
	_, err := w.Write(buf)
	return err
}

// readRaw reads one length-prefixed handshake message of at most limit
// bytes. The length is checked before the buffer is allocated.
func readRaw(r io.Reader, limit int) ([]byte, error) {
	var hdr [lenSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > limit {
		return nil, ErrFrameSize
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, noEOF(err)
	}
	return buf, nil
}

// noEOF converts io.EOF in the middle of a frame into io.ErrUnexpectedEOF,
// so a clean EOF is only ever reported at a frame boundary.
func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// ReadFrame reads and decrypts the next frame. The returned slice aliases an
// internal buffer and is valid only until the next ReadFrame call.
//
// Any error is permanent for the connection. Length violations and
// authentication failures also close it (SEC-7).
func (c *Conn) ReadFrame() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.rerr != nil {
		return nil, c.rerr
	}
	if _, err := io.ReadFull(c.br, c.rhdr[:]); err != nil {
		return nil, c.failRead(err, false)
	}
	n := int(binary.BigEndian.Uint16(c.rhdr[:]))
	// Reject before reading the body: the buffer is fixed-size, so no
	// allocation is ever sized from the peer-supplied length. A frame must
	// hold at least one plaintext byte plus the tag.
	if n < TagSize+1 || n > MaxFrame {
		return nil, c.failRead(ErrFrameSize, true)
	}
	if _, err := io.ReadFull(c.br, c.rbuf[:n]); err != nil {
		return nil, c.failRead(noEOF(err), false)
	}
	// Decrypt in place; ChaCha20-Poly1305 permits exact overlap.
	pt, err := c.dec.Decrypt(c.rbuf[:0], nil, c.rbuf[:n])
	if err != nil {
		return nil, c.failRead(fmt.Errorf("%w: %w", ErrFrameAuth, err), true)
	}
	return pt, nil
}

func (c *Conn) failRead(err error, closeConn bool) error {
	c.rerr = err
	if closeConn {
		_ = c.raw.Close()
	}
	return err
}

// WriteFrame encrypts p into one frame and writes it. len(p) must be between
// 1 and MaxPlaintext. After a write error the connection is unusable.
func (c *Conn) WriteFrame(p []byte) error {
	if len(p) == 0 || len(p) > MaxPlaintext {
		return ErrPlaintextSize
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return c.werr
	}
	ct, err := c.enc.Encrypt(c.wbuf[lenSize:lenSize], nil, p)
	if err != nil {
		// Only ErrMaxNonce is possible; a new handshake is required
		// (docs/DECISIONS.md D-4.5).
		c.werr = fmt.Errorf("secure: encrypting frame: %w", err)
		_ = c.raw.Close()
		return c.werr
	}
	binary.BigEndian.PutUint16(c.wbuf, uint16(len(ct)))
	if _, err := c.raw.Write(c.wbuf[:lenSize+len(ct)]); err != nil {
		c.werr = err
		return err
	}
	return nil
}

// SetReadDeadline sets the deadline for ReadFrame.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline for WriteFrame.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// Close closes the underlying connection. It unblocks pending reads and
// writes.
func (c *Conn) Close() error { return c.raw.Close() }

// CloseGracefully is Close for after a final message, such as a fatal
// ERROR. Closing a TCP socket while received data is still unread makes the
// OS send a reset instead of a normal close, and on Windows a reset makes
// the peer discard data it has received but not read yet: the final
// message would be lost. So the write side is shut down first (the peer
// sees the message, then end of stream), and whatever the peer still sends
// is discarded until it closes or timeout passes. The raw reads bypass the
// frame reader's buffer, so a ReadFrame blocked in another goroutine is
// not disturbed beyond seeing the deadline or the close. Connections
// without a write half-close (net.Pipe, test wrappers) are just closed.
func (c *Conn) CloseGracefully(timeout time.Duration) error {
	if cw, ok := c.raw.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
		if c.raw.SetReadDeadline(time.Now().Add(timeout)) == nil {
			_, _ = io.Copy(io.Discard, c.raw)
		}
	}
	return c.raw.Close()
}

// RemoteAddr returns the peer's network address.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }
