// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nedmchugh/transporter/internal/secure"
	"github.com/nedmchugh/transporter/internal/testutil"
)

func sampleMessages() []Message {
	var sid [SessionIDSize]byte
	copy(sid[:], "0123456789abcdef")
	var h [HashSize]byte
	for i := range h {
		h[i] = byte(i)
	}
	return []Message{
		Hello{Version: Version, SessionID: sid, Flags: FlagVerify},
		Hello{},
		Manifest{Entries: []Entry{
			{Path: "dir", Type: EntryDir, Mode: 0o755, MtimeSec: 1700000000},
			{Path: "dir/file.txt", Type: EntryFile, Mode: 0o644, Size: 5 << 32, MtimeSec: -5, MtimeNsec: 999_999_999},
			{Path: "ünïcode name", Type: EntryFile, Mode: 0, Size: 0},
		}},
		ManifestEnd{Count: 3, TotalBytes: 5 << 32},
		Need{Records: []NeedRecord{
			{Index: 0, Action: NeedSkip},
			{Index: 1, Action: NeedSend, Offset: 3 * ChunkSize},
			{Index: 2, Action: NeedError, Code: CodeSymlink},
			{Index: 3, Action: NeedVerifySend, Hash: h},
			{Index: 4, Action: NeedVerifyConflict, Hash: h},
			{Index: 5, Action: NeedConflict},
		}},
		FileStart{Index: 7, Offset: 1 << 40},
		Chunk{Index: 7, Offset: 1 << 40, Data: []byte("data")},
		Chunk{Index: 1, Offset: 0, Data: bytes.Repeat([]byte{1}, ChunkSize)},
		FileEnd{Index: 7, Hash: h},
		FileAbort{Index: 9, Code: CodeChanged},
		VerifyResult{Index: 2, Same: true},
		VerifyResult{Index: 3},
		Ack{Index: 4, Status: AckMismatch},
		Ack{Index: 5, Status: AckError, Code: CodeIO},
		Heartbeat{},
		Done{Transferred: 1, Bytes: 2, Skipped: 3, Conflicts: 4, Errors: 5, Integrity: 6},
		Error{Code: CodeVersion, Fatal: true, Message: "protocol version mismatch: receiver speaks 1, sender speaks 2"},
		Error{Code: CodeIO},
		Busy{},
	}
}

// TestRoundTrip covers PROTO-1, PROTO-2 and TEST-2: every message type
// encodes and decodes to itself, and the encoding is canonical.
func TestRoundTrip(t *testing.T) {
	seen := map[Type]bool{}
	for _, m := range sampleMessages() {
		b := Append(nil, m)
		if Type(b[0]) != m.Type() {
			t.Fatalf("%v: type byte %d", m.Type(), b[0])
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatalf("%v: %v", m.Type(), err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("%v: got %#v, want %#v", m.Type(), got, m)
		}
		if again := Append(nil, got); !bytes.Equal(again, b) {
			t.Fatalf("%v: not canonical", m.Type())
		}
		seen[m.Type()] = true
	}
	for typ := range typeNames {
		if !seen[typ] {
			t.Errorf("message type %v has no round-trip case", typ)
		}
	}
}

// TestTruncation covers PROTO-1 strict bounds checks: every proper prefix of
// a valid message, and every message with a trailing byte, is rejected.
func TestTruncation(t *testing.T) {
	for _, m := range sampleMessages() {
		b := Append(nil, m)
		for n := 1; n < len(b); n++ {
			if _, ok := m.(Chunk); ok && n > ChunkHeaderSize {
				continue // a shorter chunk is still a valid chunk
			}
			if _, err := Decode(b[:n]); !errors.Is(err, ErrMalformed) {
				t.Fatalf("%v prefix %d/%d accepted (%v)", m.Type(), n, len(b), err)
			}
		}
		if _, ok := m.(Chunk); ok {
			continue // trailing bytes are more data
		}
		if _, err := Decode(append(b, 0)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%v with trailing byte accepted", m.Type())
		}
	}
}

func entryBytes(typ EntryType, mode uint32, size uint64, nsec uint32, path string) []byte {
	b := []byte{byte(TypeManifest), 0, 1}
	return Manifest{Entries: []Entry{{Path: path, Type: typ, Mode: mode, Size: size, MtimeNsec: nsec}}}.appendBody(b[:1])
}

// TestDecodeInvalid covers PROTO-1, SEC-10 and TREE-6: out-of-range values
// are rejected by the decoder.
func TestDecodeInvalid(t *testing.T) {
	bigChunk := AppendChunkHeader(nil, 1, 0)
	bigChunk = append(bigChunk, make([]byte, ChunkSize+1)...)
	longErr := []byte{byte(TypeError), 0, 1, 0}
	longErr = binary.BigEndian.AppendUint16(longErr, MaxErrorMessage+1)
	longErr = append(longErr, make([]byte, MaxErrorMessage+1)...)
	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"unknown type", []byte{0}},
		{"unknown type 255", []byte{255}},
		{"oversized", append([]byte{byte(TypeChunk)}, make([]byte, MaxMessage)...)},
		{"symlink entry", entryBytes(3, 0o644, 0, 0, "x")},
		{"zero entry type", entryBytes(0, 0o644, 0, 0, "x")},
		{"setuid mode", entryBytes(EntryFile, 0o4755, 0, 0, "x")},
		{"sticky dir", entryBytes(EntryDir, 0o1777, 0, 0, "x")},
		{"nsec overflow", entryBytes(EntryFile, 0o644, 0, 1e9, "x")},
		{"dir with size", entryBytes(EntryDir, 0o755, 1, 0, "x")},
		{"empty path", entryBytes(EntryFile, 0o644, 0, 0, "")},
		{"long path", entryBytes(EntryFile, 0o644, 0, 0, strings.Repeat("a", MaxPathLen+1))},
		{"empty manifest", []byte{byte(TypeManifest), 0, 0}},
		{"manifest count lies", []byte{byte(TypeManifest), 0xFF, 0xFF, 1, 2, 3}},
		{"empty need", []byte{byte(TypeNeed), 0, 0}},
		{"need bad action", Append(nil, Need{Records: []NeedRecord{{Action: maxNeedAction + 1}}})},
		{"need count lies", []byte{byte(TypeNeed), 0, 2, 1}},
		{"empty chunk", AppendChunkHeader(nil, 1, 0)},
		{"oversized chunk", bigChunk},
		{"bad ack status", Append(nil, Ack{Status: maxAck + 1})},
		{"bad bool", []byte{byte(TypeVerifyResult), 0, 0, 0, 1, 2}},
		{"bad fatal flag", []byte{byte(TypeError), 0, 1, 7, 0, 0}},
		{"error not utf8", []byte{byte(TypeError), 0, 1, 1, 0, 1, 0xFF}},
		{"error too long", longErr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if m, err := Decode(tc.b); !errors.Is(err, ErrMalformed) {
				t.Fatalf("accepted: %#v, %v", m, err)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	if MaxMessage != secure.MaxPlaintext {
		t.Fatal("MaxMessage must equal the secure frame plaintext limit")
	}
	if ChunkHeaderSize+ChunkSize > MaxMessage {
		t.Fatal("a full chunk does not fit in a frame")
	}
	if 3+MaxNeedRecords*needRecordSize > MaxMessage {
		t.Fatal("NEED batch too large")
	}
	if ManifestHeaderSize+entryFixed+MaxPathLen > MaxMessage {
		t.Fatal("a maximal entry does not fit in a frame")
	}
	if MaxEntries != 1_000_000 || MaxPathLen != 4096 || MaxComponentLen != 255 {
		t.Fatal("TREE-11 defaults changed")
	}
	if MaxInFlightFiles != 8 || MaxInFlightBytes != 4<<20 {
		t.Fatal("XFER-6 defaults changed")
	}
}

func TestStrings(t *testing.T) {
	if TypeHello.String() != "HELLO" || Type(99).String() != "TYPE(99)" {
		t.Fatal("Type.String")
	}
	if CodeIO.String() == "" || Code(999).String() != "error code 999" {
		t.Fatal("Code.String")
	}
	for c := range codeText {
		if strings.Contains(c.String(), "error code") {
			t.Fatalf("code %d lacks text", c)
		}
	}
	if EntryFile.String() != "file" || EntryDir.String() != "directory" || EntryType(9).String() != "type(9)" {
		t.Fatal("EntryType.String")
	}
}

func TestTruncateMessage(t *testing.T) {
	long := strings.Repeat("é", MaxErrorMessage) // 2 bytes each
	got := TruncateMessage(long)
	if len(got) > MaxErrorMessage || !strings.HasPrefix(long, got) {
		t.Fatalf("len %d", len(got))
	}
	if TruncateMessage("a\xffb") != "a�b" {
		t.Fatal("invalid UTF-8 not replaced")
	}
	m, err := Decode(Append(nil, Error{Message: long}))
	if err != nil || len(m.(Error).Message) > MaxErrorMessage {
		t.Fatal(err)
	}
}

// TestPrintable checks that peer-supplied text cannot inject terminal
// control sequences.
func TestPrintable(t *testing.T) {
	tests := map[string]string{
		"plain name.txt":  "plain name.txt",
		"ünïcødé":         "ünïcødé",
		"evil\x1b[2Jname": `evil\x1b[2Jname`,
		"cr\rlf\n":        `cr\x0dlf\x0a`,
		"bidi\u202ename":  `bidi\u202ename`,
		"bad\xffutf8":     `bad\xffutf8`,
		"literal � ok":    "literal � ok",
		"line\u2028sep":   `line\u2028sep`,
	}
	for in, want := range tests {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzDecode covers TEST-4 for every message decoder: no panics, bounded
// allocation, and canonical re-encoding of anything accepted.
func FuzzDecode(f *testing.F) {
	for _, m := range sampleMessages() {
		f.Add(Append(nil, m))
	}
	f.Add([]byte{byte(TypeManifest), 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if again := Append(nil, m); !bytes.Equal(again, b) {
			t.Fatalf("non-canonical: %x -> %x", b, again)
		}
	})
}

// pipeFrames is a FrameConn over a net.Conn with plain length-prefixed
// frames, so Link can be tested without encryption.
type pipeFrames struct {
	net.Conn
	rmu sync.Mutex
	buf []byte
}

func (p *pipeFrames) ReadFrame() ([]byte, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(p.Conn, hdr[:]); err != nil {
		return nil, err
	}
	p.buf = make([]byte, binary.BigEndian.Uint16(hdr[:]))
	_, err := io.ReadFull(p.Conn, p.buf)
	return p.buf, err
}

func (p *pipeFrames) WriteFrame(b []byte) error {
	_, err := p.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
	return err
}

func linkPair(t *testing.T, cfgA, cfgB LinkConfig) (*Link, *Link) {
	t.Helper()
	a, b := net.Pipe()
	la := NewLink(&pipeFrames{Conn: a}, cfgA)
	lb := NewLink(&pipeFrames{Conn: b}, cfgB)
	t.Cleanup(func() {
		_ = la.Close()
		_ = lb.Close()
	})
	return la, lb
}

// TestLinkSendRecv covers SEC-8 (all messages are frames) and REL-3
// (heartbeats on an idle connection, invisible to Recv).
func TestLinkSendRecv(t *testing.T) {
	testutil.CheckLeaks(t)
	var received sync.WaitGroup
	received.Add(1)
	var once sync.Once
	cfg := LinkConfig{Heartbeat: 20 * time.Millisecond, DeadAfter: time.Second}
	recvCfg := cfg
	recvCfg.OnReceive = func() { once.Do(received.Done) }
	la, lb := linkPair(t, cfg, recvCfg)
	go func() {
		// Stay idle long enough for several heartbeats, then send.
		time.Sleep(120 * time.Millisecond)
		_ = la.Send(Ack{Index: 3})
		chunk := append(AppendChunkHeader(nil, 1, 0), "xyz"...)
		_ = la.SendEncoded(chunk)
	}()
	// lb's own heartbeats must be drained by la, so run a reader there.
	go func() {
		for {
			if _, err := la.Recv(); err != nil {
				return
			}
		}
	}()
	m, err := lb.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if m != (Ack{Index: 3}) {
		t.Fatalf("got %#v (heartbeat leaked to Recv?)", m)
	}
	received.Wait()
	m, err = lb.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := m.(Chunk); !ok || string(c.Data) != "xyz" {
		t.Fatalf("got %#v", m)
	}
	if err := la.SendEncoded(make([]byte, MaxMessage+1)); err == nil {
		t.Fatal("oversized message accepted")
	}
}

// TestLinkDeadPeer covers REL-3 and TEST-7 "stalled connection with no
// close": a peer that stops reading and writing is detected within
// DeadAfter, by both Recv and Send.
func TestLinkDeadPeer(t *testing.T) {
	testutil.CheckLeaks(t)
	a, b := net.Pipe()
	defer b.Close() // b never reads or writes: a stalled peer
	l := NewLink(&pipeFrames{Conn: a}, LinkConfig{Heartbeat: time.Hour, DeadAfter: 100 * time.Millisecond})
	defer l.Close()
	start := time.Now()
	if _, err := l.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Recv: %v", err)
	}
	if err := l.Send(Heartbeat{}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Send: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("dead peer not detected promptly")
	}
}

// TestLinkHeartbeatFailureCloses: when a heartbeat cannot be written, the
// connection is closed so a blocked Recv returns.
func TestLinkHeartbeatFailureCloses(t *testing.T) {
	testutil.CheckLeaks(t)
	a, b := net.Pipe()
	defer b.Close()
	l := NewLink(&pipeFrames{Conn: a}, LinkConfig{Heartbeat: 10 * time.Millisecond, DeadAfter: 50 * time.Millisecond})
	defer l.Close()
	start := time.Now()
	if _, err := l.Recv(); err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("too slow")
	}
}

func TestLinkClosed(t *testing.T) {
	testutil.CheckLeaks(t)
	la, lb := linkPair(t, LinkConfig{}, LinkConfig{})
	errc := make(chan error, 1)
	go func() {
		_, err := lb.Recv()
		errc <- err
	}()
	_ = lb.Close()
	if err := <-errc; !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("Recv after Close: %v", err)
	}
	if err := lb.Send(Busy{}); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
	_ = lb.Close() // idempotent
	// The peer sees the connection end (net.Pipe reports io.EOF or
	// io.ErrClosedPipe depending on timing), not ErrLinkClosed.
	if _, err := la.Recv(); err == nil || errors.Is(err, ErrLinkClosed) {
		t.Fatalf("peer: %v", err)
	}
}

func TestLinkMalformed(t *testing.T) {
	testutil.CheckLeaks(t)
	a, b := net.Pipe()
	l := NewLink(&pipeFrames{Conn: a}, LinkConfig{})
	defer l.Close()
	go func() {
		_ = (&pipeFrames{Conn: b}).WriteFrame([]byte{0xEE})
	}()
	if _, err := l.Recv(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	_ = b.Close()
}
