// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package proto defines the application messages exchanged inside secure
// frames, their compact binary encoding, protocol limits, and the Link that
// adds heartbeats and deadlines to a frame connection.
//
// Each frame carries exactly one message: a one-byte type followed by a
// fixed layout of big-endian fields (PROTO-1). Decoders are strict: every
// length is checked against the remaining input before use, values are range
// checked, and trailing bytes are rejected, so the encoding is canonical
// (Append(Decode(b)) == b for every accepted b). docs/protocol.md is the
// normative description.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Version is the protocol version carried in HELLO (PROTO-3).
const Version uint16 = 1

// Limits (TREE-11, SEC-12, XFER-6). They are protocol constants: a receiver
// rejects input that exceeds them.
const (
	// MaxMessage is the largest encoded message; it equals the secure
	// frame plaintext limit (secure.MaxPlaintext, checked by a test).
	MaxMessage = 48 * 1024
	// ChunkSize is the size of CHUNK data and the resume granularity
	// (RES-3).
	ChunkSize = 32 * 1024
	// MaxEntries is the maximum number of manifest entries.
	MaxEntries = 1_000_000
	// MaxPathLen is the maximum length of a wire path in bytes.
	MaxPathLen = 4096
	// MaxComponentLen is the maximum length of one path component.
	MaxComponentLen = 255
	// MaxErrorMessage is the maximum length of an ERROR message text.
	MaxErrorMessage = 1024
	// MaxInFlightFiles and MaxInFlightBytes bound the data the sender has
	// sent but the receiver has not yet acknowledged (XFER-6).
	MaxInFlightFiles = 8
	MaxInFlightBytes = 4 << 20
	// SessionIDSize is the size of the random session identifier.
	SessionIDSize = 16
	// HashSize is the size of a BLAKE3-256 file hash (XFER-1).
	HashSize = 32
)

// Type identifies a message.
type Type uint8

// Message types (PROTO-2).
const (
	TypeHello        Type = 1
	TypeManifest     Type = 2
	TypeManifestEnd  Type = 3
	TypeNeed         Type = 4
	TypeFileStart    Type = 5
	TypeChunk        Type = 6
	TypeFileEnd      Type = 7
	TypeFileAbort    Type = 8
	TypeVerifyResult Type = 9
	TypeAck          Type = 10
	TypeHeartbeat    Type = 11
	TypeDone         Type = 12
	TypeError        Type = 13
	TypeBusy         Type = 14
)

var typeNames = map[Type]string{
	TypeHello: "HELLO", TypeManifest: "MANIFEST", TypeManifestEnd: "MANIFEST_END",
	TypeNeed: "NEED", TypeFileStart: "FILE_START", TypeChunk: "CHUNK",
	TypeFileEnd: "FILE_END", TypeFileAbort: "FILE_ABORT", TypeVerifyResult: "VERIFY_RESULT",
	TypeAck: "ACK", TypeHeartbeat: "HEARTBEAT", TypeDone: "DONE", TypeError: "ERROR",
	TypeBusy: "BUSY",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE(%d)", uint8(t))
}

// Code is an error code carried in NEED, FILE_ABORT, ACK and ERROR.
type Code uint16

// Error codes. Codes up to CodeNoSpace describe conditions that are fatal
// when sent in ERROR; the others are per-file.
const (
	CodeOK           Code = 0
	CodeInternal     Code = 1  // unexpected internal error
	CodeProtocol     Code = 2  // protocol violation
	CodeVersion      Code = 3  // protocol version mismatch
	CodeBadManifest  Code = 4  // invalid path, collision or limit in the manifest
	CodeNotWritable  Code = 5  // destination cannot be written
	CodeNoSpace      Code = 6  // destination out of space
	CodeIntegrity    Code = 7  // hash mismatch after retransmission
	CodeIO           Code = 8  // per-file I/O error on the receiver
	CodeUnreadable   Code = 9  // sender cannot read the file
	CodeChanged      Code = 10 // file changed on the sender during transfer
	CodeTypeConflict Code = 11 // destination has a directory where a file goes, or the reverse
	CodeSymlink      Code = 12 // destination path is a symlink; not followed
	CodeTempName     Code = 13 // NAME.part is itself in the manifest
	CodeInvalidName  Code = 14 // name not valid on the receiver's platform
	CodeParentFailed Code = 15 // the parent directory could not be created
	CodeInterrupted  Code = 16 // the peer is shutting down
	CodeUnusable     Code = 17 // the destination path exists but is not a regular file
	CodeExists       Code = 18 // the destination file appeared during the transfer; not overwritten
)

var codeText = map[Code]string{
	CodeOK:           "ok",
	CodeInternal:     "internal error",
	CodeProtocol:     "protocol violation",
	CodeVersion:      "protocol version mismatch",
	CodeBadManifest:  "invalid manifest",
	CodeNotWritable:  "destination not writable",
	CodeNoSpace:      "destination out of space",
	CodeIntegrity:    "integrity check failed after retransmission",
	CodeIO:           "I/O error on the receiver",
	CodeUnreadable:   "cannot read the file on the sender",
	CodeChanged:      "file changed on the sender during transfer",
	CodeTypeConflict: "a directory exists where a file should go, or the reverse",
	CodeSymlink:      "the destination path is a symbolic link (not followed)",
	CodeTempName:     "the temporary name NAME.part is itself part of the transfer",
	CodeInvalidName:  "the name is not valid on the receiving system",
	CodeParentFailed: "the parent directory could not be created",
	CodeInterrupted:  "the transfer was interrupted",
	CodeUnusable:     "the destination path exists and is not a regular file",
	CodeExists:       "the destination file appeared during the transfer and was not overwritten",
}

func (c Code) String() string {
	if s, ok := codeText[c]; ok {
		return s
	}
	return fmt.Sprintf("error code %d", uint16(c))
}

// Message is implemented by every message type.
type Message interface {
	Type() Type
	appendBody(dst []byte) []byte
}

// Append appends the encoding of m (type byte and body) to dst.
func Append(dst []byte, m Message) []byte {
	return m.appendBody(append(dst, byte(m.Type())))
}

// Flags in HELLO.
const (
	// FlagVerify asks for content-hash comparison instead of the quick
	// check (RES-2). Either side setting it enables it.
	FlagVerify uint32 = 1 << 0
)

// Hello opens a session (PROTO-2, PROTO-3). The sender sends it first; the
// receiver replies with its own.
type Hello struct {
	Version   uint16
	SessionID [SessionIDSize]byte
	Flags     uint32
}

// EntryType is the type of a manifest entry.
type EntryType uint8

// Entry types. Other file types are never sent (TREE-6).
const (
	EntryFile EntryType = 1
	EntryDir  EntryType = 2
)

func (t EntryType) String() string {
	switch t {
	case EntryFile:
		return "file"
	case EntryDir:
		return "directory"
	}
	return fmt.Sprintf("type(%d)", uint8(t))
}

// Entry is one manifest entry (TREE-1).
type Entry struct {
	Path      string
	Type      EntryType
	Mode      uint32 // permission bits, at most 0777 (TREE-7)
	Size      uint64 // zero for directories
	MtimeSec  int64
	MtimeNsec uint32 // < 1e9
}

// entryFixed is the encoded size of an entry excluding its path bytes:
// type(1) mode(4) size(8) mtime_sec(8) mtime_nsec(4) path_len(2).
const entryFixed = 1 + 4 + 8 + 8 + 4 + 2

// EncodedSize returns the number of bytes e occupies in a MANIFEST message.
func (e Entry) EncodedSize() int { return entryFixed + len(e.Path) }

// Manifest carries a batch of entries. Entry indexes are implicit: entries
// are numbered from zero in the order they arrive across all MANIFEST
// messages of a connection. The encoder does not split batches: callers keep
// ManifestHeaderSize plus the entries' EncodedSize within MaxMessage.
type Manifest struct {
	Entries []Entry
}

// ManifestHeaderSize is the size of a MANIFEST message before its entries.
const ManifestHeaderSize = 1 + 2

// ManifestEnd ends the manifest and lets the receiver cross-check it.
type ManifestEnd struct {
	Count      uint32 // total entries
	TotalBytes uint64 // sum of file sizes
}

// NeedAction tells the sender what to do with one entry.
type NeedAction uint8

// NEED actions (PROTO-2, XFER-7, RES-2).
const (
	NeedSkip           NeedAction = 0 // already complete (or directory created)
	NeedSend           NeedAction = 1 // send from Offset
	NeedConflict       NeedAction = 2 // destination differs; not overwritten
	NeedError          NeedAction = 3 // per-file error Code
	NeedVerifySend     NeedAction = 4 // compare with Hash; send from 0 if different
	NeedVerifyConflict NeedAction = 5 // compare with Hash; conflict if different
	maxNeedAction                 = NeedVerifyConflict
)

// NeedRecord is the receiver's decision for one entry.
type NeedRecord struct {
	Index  uint32
	Action NeedAction
	Code   Code   // for NeedError
	Offset uint64 // for NeedSend
	Hash   [HashSize]byte
}

// needRecordSize: index(4) action(1) code(2) offset(8) hash(32).
const needRecordSize = 4 + 1 + 2 + 8 + HashSize

// MaxNeedRecords is the most NEED records that fit in one message.
const MaxNeedRecords = (MaxMessage - 3) / needRecordSize

// Need carries NEED records in increasing index order.
type Need struct {
	Records []NeedRecord
}

// FileStart announces that data for a file follows from Offset.
type FileStart struct {
	Index  uint32
	Offset uint64
}

// Chunk carries file data (PROTO-6). After Decode, Data aliases the input.
type Chunk struct {
	Index  uint32
	Offset uint64
	Data   []byte
}

// ChunkHeaderSize is the size of a CHUNK message before its data.
const ChunkHeaderSize = 1 + 4 + 8

// FileEnd carries the BLAKE3 hash of the whole file (XFER-1).
type FileEnd struct {
	Index uint32
	Hash  [HashSize]byte
}

// FileAbort tells the receiver the sender will not complete a file.
type FileAbort struct {
	Index uint32
	Code  Code
}

// VerifyResult answers a NeedVerify* record.
type VerifyResult struct {
	Index uint32
	Same  bool
}

// AckStatus is the outcome reported in ACK.
type AckStatus uint8

// ACK statuses.
const (
	AckOK       AckStatus = 0
	AckMismatch AckStatus = 1 // hash mismatch; the sender may retransmit once
	AckError    AckStatus = 2 // per-file failure with Code
	maxAck                = AckError
)

// Ack reports the outcome of one file.
type Ack struct {
	Index  uint32
	Status AckStatus
	Code   Code
}

// Heartbeat keeps an idle connection alive (REL-3).
type Heartbeat struct{}

// Done ends a session. The sender sends it with zero counts once every file
// is settled; the receiver replies with its totals (PROTO-7).
type Done struct {
	Transferred uint64 // files written
	Bytes       uint64 // file bytes written
	Skipped     uint64 // already complete
	Conflicts   uint64
	Errors      uint64 // per-file errors
	Integrity   uint64 // integrity failures
}

// Error reports an error. Fatal errors end the session.
type Error struct {
	Code    Code
	Fatal   bool
	Message string
}

// Busy tells a sender the receiver is serving another session (RCV-5).
type Busy struct{}

// Type implements Message.
func (Hello) Type() Type { return TypeHello }

// Type implements Message.
func (Manifest) Type() Type { return TypeManifest }

// Type implements Message.
func (ManifestEnd) Type() Type { return TypeManifestEnd }

// Type implements Message.
func (Need) Type() Type { return TypeNeed }

// Type implements Message.
func (FileStart) Type() Type { return TypeFileStart }

// Type implements Message.
func (Chunk) Type() Type { return TypeChunk }

// Type implements Message.
func (FileEnd) Type() Type { return TypeFileEnd }

// Type implements Message.
func (FileAbort) Type() Type { return TypeFileAbort }

// Type implements Message.
func (VerifyResult) Type() Type { return TypeVerifyResult }

// Type implements Message.
func (Ack) Type() Type { return TypeAck }

// Type implements Message.
func (Heartbeat) Type() Type { return TypeHeartbeat }

// Type implements Message.
func (Done) Type() Type { return TypeDone }

// Type implements Message.
func (Error) Type() Type { return TypeError }

// Type implements Message.
func (Busy) Type() Type { return TypeBusy }

var be = binary.BigEndian

func (m Hello) appendBody(b []byte) []byte {
	b = be.AppendUint16(b, m.Version)
	b = append(b, m.SessionID[:]...)
	return be.AppendUint32(b, m.Flags)
}

func (m Manifest) appendBody(b []byte) []byte {
	b = be.AppendUint16(b, uint16(len(m.Entries)))
	for _, e := range m.Entries {
		b = append(b, byte(e.Type))
		b = be.AppendUint32(b, e.Mode)
		b = be.AppendUint64(b, e.Size)
		b = be.AppendUint64(b, uint64(e.MtimeSec))
		b = be.AppendUint32(b, e.MtimeNsec)
		b = be.AppendUint16(b, uint16(len(e.Path)))
		b = append(b, e.Path...)
	}
	return b
}

func (m ManifestEnd) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Count)
	return be.AppendUint64(b, m.TotalBytes)
}

func (m Need) appendBody(b []byte) []byte {
	b = be.AppendUint16(b, uint16(len(m.Records)))
	for _, r := range m.Records {
		b = be.AppendUint32(b, r.Index)
		b = append(b, byte(r.Action))
		b = be.AppendUint16(b, uint16(r.Code))
		b = be.AppendUint64(b, r.Offset)
		b = append(b, r.Hash[:]...)
	}
	return b
}

func (m FileStart) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Index)
	return be.AppendUint64(b, m.Offset)
}

func (m Chunk) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Index)
	b = be.AppendUint64(b, m.Offset)
	return append(b, m.Data...)
}

// AppendChunkHeader appends a CHUNK type byte and header; the caller appends
// the data. The sender uses it to read file data directly into the frame
// buffer, avoiding a copy (NFR-3).
func AppendChunkHeader(b []byte, index uint32, offset uint64) []byte {
	b = append(b, byte(TypeChunk))
	b = be.AppendUint32(b, index)
	return be.AppendUint64(b, offset)
}

func (m FileEnd) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Index)
	return append(b, m.Hash[:]...)
}

func (m FileAbort) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Index)
	return be.AppendUint16(b, uint16(m.Code))
}

func (m VerifyResult) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Index)
	return append(b, boolByte(m.Same))
}

func (m Ack) appendBody(b []byte) []byte {
	b = be.AppendUint32(b, m.Index)
	b = append(b, byte(m.Status))
	return be.AppendUint16(b, uint16(m.Code))
}

func (Heartbeat) appendBody(b []byte) []byte { return b }

func (m Done) appendBody(b []byte) []byte {
	for _, v := range []uint64{m.Transferred, m.Bytes, m.Skipped, m.Conflicts, m.Errors, m.Integrity} {
		b = be.AppendUint64(b, v)
	}
	return b
}

func (m Error) appendBody(b []byte) []byte {
	b = be.AppendUint16(b, uint16(m.Code))
	b = append(b, boolByte(m.Fatal))
	msg := TruncateMessage(m.Message)
	b = be.AppendUint16(b, uint16(len(msg)))
	return append(b, msg...)
}

func (Busy) appendBody(b []byte) []byte { return b }

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// TruncateMessage shortens s to at most MaxErrorMessage bytes without
// splitting a UTF-8 sequence, and replaces invalid UTF-8.
func TruncateMessage(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= MaxErrorMessage {
		return s
	}
	cut := MaxErrorMessage
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ErrMalformed is wrapped by every decoding error.
var ErrMalformed = errors.New("malformed message")

// decoder reads big-endian fields with bounds checks. After the first short
// read every accessor returns zero and err is set.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) fail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
	}
}

func (d *decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.fail("truncated (need %d bytes, have %d)", n, len(d.b))
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *decoder) u8() uint8 {
	if v := d.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (d *decoder) u16() uint16 {
	if v := d.take(2); v != nil {
		return be.Uint16(v)
	}
	return 0
}

func (d *decoder) u32() uint32 {
	if v := d.take(4); v != nil {
		return be.Uint32(v)
	}
	return 0
}

func (d *decoder) u64() uint64 {
	if v := d.take(8); v != nil {
		return be.Uint64(v)
	}
	return 0
}

func (d *decoder) boolean(field string) bool {
	switch v := d.u8(); v {
	case 0:
		return false
	case 1:
		return true
	default:
		d.fail("%s: invalid boolean %d", field, v)
		return false
	}
}

func (d *decoder) end() {
	if d.err == nil && len(d.b) != 0 {
		d.fail("%d trailing bytes", len(d.b))
	}
}

// Decode parses one message. Byte slices in the result (CHUNK data) alias b;
// strings are copied. Decode never allocates more than a small multiple of
// len(b).
func Decode(b []byte) (Message, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrMalformed)
	}
	if len(b) > MaxMessage {
		return nil, fmt.Errorf("%w: %d bytes exceeds limit", ErrMalformed, len(b))
	}
	t := Type(b[0])
	d := &decoder{b: b[1:]}
	var m Message
	switch t {
	case TypeHello:
		var h Hello
		h.Version = d.u16()
		copy(h.SessionID[:], d.take(SessionIDSize))
		h.Flags = d.u32()
		m = h
	case TypeManifest:
		m = decodeManifest(d)
	case TypeManifestEnd:
		m = ManifestEnd{Count: d.u32(), TotalBytes: d.u64()}
	case TypeNeed:
		m = decodeNeed(d)
	case TypeFileStart:
		m = FileStart{Index: d.u32(), Offset: d.u64()}
	case TypeChunk:
		c := Chunk{Index: d.u32(), Offset: d.u64()}
		c.Data = d.take(len(d.b))
		if d.err == nil && (len(c.Data) == 0 || len(c.Data) > ChunkSize) {
			d.fail("chunk data length %d not in 1..%d", len(c.Data), ChunkSize)
		}
		m = c
	case TypeFileEnd:
		fe := FileEnd{Index: d.u32()}
		copy(fe.Hash[:], d.take(HashSize))
		m = fe
	case TypeFileAbort:
		m = FileAbort{Index: d.u32(), Code: Code(d.u16())}
	case TypeVerifyResult:
		m = VerifyResult{Index: d.u32(), Same: d.boolean("same")}
	case TypeAck:
		a := Ack{Index: d.u32(), Status: AckStatus(d.u8()), Code: Code(d.u16())}
		if d.err == nil && a.Status > maxAck {
			d.fail("ack status %d", a.Status)
		}
		m = a
	case TypeHeartbeat:
		m = Heartbeat{}
	case TypeDone:
		m = Done{Transferred: d.u64(), Bytes: d.u64(), Skipped: d.u64(), Conflicts: d.u64(), Errors: d.u64(), Integrity: d.u64()}
	case TypeError:
		e := Error{Code: Code(d.u16()), Fatal: d.boolean("fatal")}
		n := int(d.u16())
		if d.err == nil && n > MaxErrorMessage {
			d.fail("error message length %d exceeds %d", n, MaxErrorMessage)
		}
		msg := d.take(n)
		if d.err == nil && !utf8.Valid(msg) {
			d.fail("error message is not UTF-8")
		}
		e.Message = string(msg)
		m = e
	case TypeBusy:
		m = Busy{}
	default:
		return nil, fmt.Errorf("%w: unknown type %d", ErrMalformed, uint8(t))
	}
	d.end()
	if d.err != nil {
		return nil, fmt.Errorf("decoding %v: %w", t, d.err)
	}
	return m, nil
}

func decodeManifest(d *decoder) Manifest {
	n := int(d.u16())
	if d.err != nil {
		return Manifest{}
	}
	if n == 0 {
		d.fail("empty manifest batch")
		return Manifest{}
	}
	// Bound the allocation by the input actually present: each entry needs
	// at least entryFixed bytes.
	if n*entryFixed > len(d.b) {
		d.fail("%d entries cannot fit in %d bytes", n, len(d.b))
		return Manifest{}
	}
	m := Manifest{Entries: make([]Entry, 0, n)}
	for range n {
		var e Entry
		e.Type = EntryType(d.u8())
		e.Mode = d.u32()
		e.Size = d.u64()
		e.MtimeSec = int64(d.u64())
		e.MtimeNsec = d.u32()
		pl := int(d.u16())
		p := d.take(pl)
		if d.err != nil {
			return Manifest{}
		}
		switch {
		case e.Type != EntryFile && e.Type != EntryDir:
			// TREE-6: symlinks, devices, FIFOs and sockets are never
			// valid manifest entries.
			d.fail("entry type %d is not file or directory", e.Type)
		case e.Mode&^0o777 != 0:
			d.fail("mode %#o has bits outside 0777", e.Mode)
		case e.MtimeNsec >= 1e9:
			d.fail("mtime nanoseconds %d out of range", e.MtimeNsec)
		case e.Type == EntryDir && e.Size != 0:
			d.fail("directory with non-zero size")
		case pl == 0 || pl > MaxPathLen:
			d.fail("path length %d not in 1..%d", pl, MaxPathLen)
		}
		if d.err != nil {
			return Manifest{}
		}
		e.Path = string(p)
		m.Entries = append(m.Entries, e)
	}
	return m
}

func decodeNeed(d *decoder) Need {
	n := int(d.u16())
	if d.err != nil {
		return Need{}
	}
	if n == 0 || n*needRecordSize != len(d.b) {
		d.fail("%d records do not match %d bytes", n, len(d.b))
		return Need{}
	}
	m := Need{Records: make([]NeedRecord, n)}
	for i := range m.Records {
		r := &m.Records[i]
		r.Index = d.u32()
		r.Action = NeedAction(d.u8())
		r.Code = Code(d.u16())
		r.Offset = d.u64()
		copy(r.Hash[:], d.take(HashSize))
		if r.Action > maxNeedAction {
			d.fail("need action %d", r.Action)
			return Need{}
		}
	}
	return m
}

// Printable makes peer-supplied text (file names, error messages) safe to
// print on a terminal: control and format characters, which could move the
// cursor or rewrite earlier output, are replaced by escapes.
func Printable(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) && utf8.ValidString(s) {
		return s
	}
	var sb strings.Builder
	for i, r := range s {
		switch {
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "�"):
			fmt.Fprintf(&sb, `\x%02x`, s[i])
		case unsafeRune(r):
			if r < 0x100 {
				fmt.Fprintf(&sb, `\x%02x`, r)
			} else {
				fmt.Fprintf(&sb, `\u%04x`, r)
			}
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' '
}
