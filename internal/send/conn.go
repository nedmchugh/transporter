// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package send

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"lukechampine.com/blake3"

	"github.com/OWNER/transporter/internal/fail"
	"github.com/OWNER/transporter/internal/proto"
)

// sconn is the state of one connection. A reader goroutine records NEED,
// ACK, DONE and ERROR messages under mu and signals the main goroutine
// through notify; it never blocks on the main goroutine, so a full pipeline
// cannot deadlock against unread ACKs.
type sconn struct {
	s    *sender
	link *proto.Link

	mu            sync.Mutex
	need          []proto.NeedRecord
	haveNeed      int               // NEED records received so far (prefix of need)
	awaiting      map[uint32]uint64 // files sent, awaiting ACK -> bytes in flight
	open          bool              // a file between FILE_START and FILE_END
	inflightBytes uint64
	retry         []uint32
	acked         bool
	sentBytes     uint64
	peerDone      *proto.Done
	readerErr     error
	readerExited  bool

	notify chan struct{}
	verify bool
}

func (c *sconn) signal() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *sconn) progressed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acked || c.peerDone != nil || c.sentBytes >= ProgressBytes
}

// waitFor blocks until cond (evaluated under mu) is true, the reader fails,
// or ctx ends.
func (c *sconn) waitFor(ctx context.Context, cond func() bool) error {
	for {
		c.mu.Lock()
		ok, err, exited := cond(), c.readerErr, c.readerExited
		c.mu.Unlock()
		if ok {
			return nil
		}
		if err != nil {
			return err
		}
		if exited {
			return violation(c.link, "the receiver ended the session early")
		}
		select {
		case <-c.notify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func violation(link *proto.Link, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	link.Abort(proto.Error{Code: proto.CodeProtocol, Fatal: true, Message: "protocol violation: " + msg}, abortTimeout)
	return fail.New(fail.Protocol, "protocol violation by the receiver: "+msg, "use the same Transporter version on both machines", nil)
}

// abortTimeout bounds how long a final ERROR message may take to send.
const abortTimeout = time.Second

func (c *sconn) run(ctx context.Context) (*proto.Done, error) {
	s := c.s
	var flags uint32
	if s.opts.Verify {
		flags |= proto.FlagVerify
	}
	if err := c.link.Send(proto.Hello{Version: proto.Version, SessionID: s.sessionID, Flags: flags}); err != nil {
		return nil, netErr("connection lost", err)
	}
	m, err := c.link.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, netErr("the receiver closed the connection", err)
		}
		return nil, netErr("connection lost", err)
	}
	switch m := m.(type) {
	case proto.Hello:
		if m.Version != proto.Version {
			msg := fmt.Sprintf("protocol version mismatch: this sender speaks version %d, the receiver speaks version %d", proto.Version, m.Version)
			c.link.Abort(proto.Error{Code: proto.CodeVersion, Fatal: true, Message: msg}, abortTimeout)
			return nil, fail.New(fail.Protocol, msg, "use the same Transporter version on both machines", nil)
		}
		if m.SessionID != s.sessionID {
			return nil, violation(c.link, "HELLO with a different session id")
		}
		c.verify = s.opts.Verify || m.Flags&proto.FlagVerify != 0
	case proto.Busy:
		return nil, fail.New(fail.Network, "the receiver is busy with another transfer", "", nil)
	case proto.Error:
		return nil, peerError(m)
	default:
		return nil, violation(c.link, "expected HELLO, got %v", m.Type())
	}

	if err := c.sendManifest(); err != nil {
		return nil, err
	}
	c.need = make([]proto.NeedRecord, len(s.items))
	c.awaiting = map[uint32]uint64{}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.reader()
	}()
	defer func() {
		_ = c.link.Close() // unblocks the reader
		wg.Wait()
	}()

	if err := c.transfer(ctx); err != nil {
		return nil, err
	}
	if err := c.link.Send(proto.Done{}); err != nil {
		return nil, netErr("connection lost", err)
	}
	if err := c.waitFor(ctx, func() bool { return c.peerDone != nil }); err != nil {
		return nil, err
	}
	c.mu.Lock()
	done := c.peerDone
	c.mu.Unlock()
	return done, nil
}

// sendManifest sends the manifest in batches that fit one frame each.
func (c *sconn) sendManifest() error {
	var batch []proto.Entry
	size := proto.ManifestHeaderSize
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := c.link.Send(proto.Manifest{Entries: batch})
		batch, size = batch[:0], proto.ManifestHeaderSize
		if err != nil {
			return netErr("connection lost", err)
		}
		return nil
	}
	var total uint64
	for _, it := range c.s.items {
		if size+it.EncodedSize() > proto.MaxMessage || len(batch) == 0xFFFF {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, it.Entry)
		size += it.EncodedSize()
		total += it.Size
	}
	if err := flush(); err != nil {
		return err
	}
	if err := c.link.Send(proto.ManifestEnd{Count: uint32(len(c.s.items)), TotalBytes: total}); err != nil {
		return netErr("connection lost", err)
	}
	return nil
}

// reader handles messages from the receiver during the data phase.
func (c *sconn) reader() {
	defer func() {
		c.mu.Lock()
		c.readerExited = true
		c.mu.Unlock()
		c.signal()
	}()
	for {
		m, err := c.link.Recv()
		if err != nil {
			c.setErr(netErr("connection lost", err))
			return
		}
		switch m := m.(type) {
		case proto.Need:
			err = c.onNeed(m)
		case proto.Ack:
			err = c.onAck(m)
		case proto.Done:
			c.mu.Lock()
			c.peerDone = &m
			c.mu.Unlock()
			c.signal()
			return
		case proto.Error:
			err = peerError(m)
		default:
			err = violation(c.link, "unexpected %v", m.Type())
		}
		if err != nil {
			c.setErr(err)
			return
		}
		c.signal()
	}
}

func (c *sconn) setErr(err error) {
	c.mu.Lock()
	if c.readerErr == nil {
		c.readerErr = err
	}
	c.mu.Unlock()
}

// onNeed validates NEED records: one per entry, in index order (D-5.3), with
// actions and offsets that make sense for the entry.
func (c *sconn) onNeed(m proto.Need) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range m.Records {
		if int(r.Index) != c.haveNeed || c.haveNeed >= len(c.need) {
			return violation(c.link, "NEED for entry %d, expected %d", r.Index, c.haveNeed)
		}
		it := c.s.items[r.Index]
		if it.Type == proto.EntryDir && r.Action != proto.NeedSkip && r.Action != proto.NeedError {
			return violation(c.link, "NEED action %d for directory %d", r.Action, r.Index)
		}
		if r.Action == proto.NeedSend && (r.Offset > it.Size || r.Offset%proto.ChunkSize != 0) {
			return violation(c.link, "NEED offset %d for file %d of %d bytes", r.Offset, r.Index, it.Size)
		}
		c.need[r.Index] = r
		c.haveNeed++
	}
	return nil
}

func (c *sconn) onAck(m proto.Ack) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.awaiting[m.Index]
	if !ok {
		return violation(c.link, "ACK for file %d, which is not awaiting one", m.Index)
	}
	delete(c.awaiting, m.Index)
	c.inflightBytes -= n
	c.acked = true
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &s.files[m.Index]
	path := proto.Printable(s.items[m.Index].Path)
	switch m.Status {
	case proto.AckOK:
		s.setOutcome(m.Index, oTransferred, "")
		s.bytes += int64(n)
	case proto.AckMismatch:
		f.attempts++
		if f.attempts < 2 {
			s.log.Warn("hash mismatch; resending the file once", "path", path)
			c.retry = append(c.retry, m.Index)
		} else {
			s.setOutcome(m.Index, oIntegrity, "")
		}
	case proto.AckError:
		switch m.Code {
		case proto.CodeIntegrity:
			s.setOutcome(m.Index, oIntegrity, "")
		case proto.CodeExists:
			s.setOutcome(m.Index, oConflict, "")
		default:
			s.setOutcome(m.Index, oError, "receiver: "+m.Code.String())
		}
	}
	return nil
}

// peerError converts an ERROR from the receiver into a classified error.
func peerError(m proto.Error) error {
	msg := "the receiver reported: " + proto.Printable(m.Message)
	switch m.Code {
	case proto.CodeNoSpace:
		return fail.New(fail.FS, msg, "free space on the receiver and run the same commands again to resume", nil)
	case proto.CodeNotWritable:
		return fail.New(fail.FS, msg, "fix the destination's permissions on the receiver", nil)
	case proto.CodeIntegrity:
		return fail.New(fail.Integrity, msg, "", nil)
	case proto.CodeInterrupted:
		return fail.New(fail.Network, msg, "start the receiver again and rerun with its new code to resume", nil)
	case proto.CodeVersion, proto.CodeProtocol, proto.CodeBadManifest:
		return fail.New(fail.Protocol, msg, "use the same Transporter version on both machines", nil)
	}
	return fail.New(fail.Internal, msg, "", nil)
}

// transfer handles every entry in NEED order, then any retransmissions,
// then waits for all ACKs.
func (c *sconn) transfer(ctx context.Context) error {
	buf := make([]byte, proto.ChunkHeaderSize+proto.ChunkSize)
	for i := range c.s.items {
		idx := uint32(i)
		if err := c.waitFor(ctx, func() bool { return c.haveNeed > i }); err != nil {
			return err
		}
		if err := c.drainRetries(ctx, buf); err != nil {
			return err
		}
		c.mu.Lock()
		rec := c.need[i]
		c.mu.Unlock()
		if err := c.handle(ctx, idx, rec, buf); err != nil {
			return err
		}
	}
	for {
		if err := c.drainRetries(ctx, buf); err != nil {
			return err
		}
		if err := c.waitFor(ctx, func() bool { return len(c.awaiting) == 0 || len(c.retry) > 0 }); err != nil {
			return err
		}
		c.mu.Lock()
		finished := len(c.awaiting) == 0 && len(c.retry) == 0
		c.mu.Unlock()
		if finished {
			return nil
		}
	}
}

func (c *sconn) drainRetries(ctx context.Context, buf []byte) error {
	for {
		c.mu.Lock()
		if len(c.retry) == 0 {
			c.mu.Unlock()
			return nil
		}
		idx := c.retry[0]
		c.retry = c.retry[1:]
		c.mu.Unlock()
		if err := c.sendFile(ctx, idx, 0, buf); err != nil {
			return err
		}
	}
}

func (c *sconn) handle(ctx context.Context, idx uint32, rec proto.NeedRecord, buf []byte) error {
	s := c.s
	it := s.items[idx]
	set := func(o outcome, msg string) {
		s.mu.Lock()
		if o != oSkipped || s.files[idx].outcome != oTransferred {
			s.setOutcome(idx, o, msg)
		}
		s.mu.Unlock()
	}
	switch rec.Action {
	case proto.NeedSkip:
		set(oSkipped, "")
		if it.Type == proto.EntryFile {
			s.opts.Progress.AddBytes(int64(it.Size))
			s.opts.Progress.FileDone()
		}
	case proto.NeedConflict:
		set(oConflict, "")
	case proto.NeedError:
		set(oError, "receiver: "+rec.Code.String())
	case proto.NeedSend:
		return c.sendFile(ctx, idx, rec.Offset, buf)
	case proto.NeedVerifySend, proto.NeedVerifyConflict:
		same, err := hashEquals(it.Local, it.Entry, rec.Hash)
		if err != nil {
			set(oError, err.Error())
			return c.abort(idx, proto.CodeUnreadable, false)
		}
		if same || rec.Action == proto.NeedVerifyConflict {
			if err := c.link.Send(proto.VerifyResult{Index: idx, Same: same}); err != nil {
				return netErr("connection lost", err)
			}
			if same {
				set(oSkipped, "")
				s.opts.Progress.AddBytes(int64(it.Size))
				s.opts.Progress.FileDone()
			} else {
				set(oConflict, "")
			}
			return nil
		}
		return c.sendFile(ctx, idx, 0, buf)
	}
	return nil
}

// hashEquals compares the local file's BLAKE3 hash with want (--verify).
func hashEquals(local string, e proto.Entry, want [proto.HashSize]byte) (bool, error) {
	f, err := os.Open(local) //nolint:gosec // the user chose to send this path
	if err != nil {
		return false, readErr(err)
	}
	defer func() { _ = f.Close() }()
	h := blake3.New(proto.HashSize, nil)
	if err := readPrefix(h, f, e.Size); err != nil {
		return false, errChanged
	}
	var got [proto.HashSize]byte
	copy(got[:], h.Sum(nil))
	return got == want, nil
}

var errChanged = errors.New("changed during transfer")

// testCorruptChunk, when set by tests, may modify chunk data after it has
// been hashed, simulating corruption that the end-to-end hash must catch
// (XFER-4). It is always nil in production.
var testCorruptChunk func(index uint32, offset uint64, data []byte)

func readErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("cannot read: %w", err)
}

// abort tells the receiver a file will not be completed.
func (c *sconn) abort(idx uint32, code proto.Code, started bool) error {
	if started {
		c.mu.Lock()
		c.open = false
		c.mu.Unlock()
	}
	if err := c.link.Send(proto.FileAbort{Index: idx, Code: code}); err != nil {
		return netErr("connection lost", err)
	}
	return nil
}

// sendFile streams one file from offset (XFER-1, XFER-6, SND-4, SND-6).
func (c *sconn) sendFile(ctx context.Context, idx uint32, offset uint64, buf []byte) error {
	s := c.s
	it := s.items[idx]
	perFile := func(msg string, code proto.Code, started bool) error {
		s.mu.Lock()
		s.setOutcome(idx, oError, msg)
		s.mu.Unlock()
		s.log.Warn("file not sent", "path", proto.Printable(it.Path), "reason", msg)
		return c.abort(idx, code, started)
	}
	// Bounded pipelining (XFER-6): never more than MaxInFlightFiles files
	// or MaxInFlightBytes of completed-but-unacknowledged data. The file
	// being streamed is bounded by TCP flow control.
	if err := c.waitFor(ctx, func() bool {
		return len(c.awaiting) < proto.MaxInFlightFiles && c.inflightBytes < proto.MaxInFlightBytes
	}); err != nil {
		return err
	}
	f, err := os.Open(it.Local) //nolint:gosec // the user chose to send this path
	if err != nil {
		return perFile(readErr(err).Error(), proto.CodeUnreadable, false)
	}
	defer func() { _ = f.Close() }()
	if !sameFile(f, it.Entry) {
		return perFile(errChanged.Error(), proto.CodeChanged, false)
	}
	h := blake3.New(proto.HashSize, nil)
	if offset > 0 {
		if err := readPrefix(h, f, offset); err != nil {
			return perFile(errChanged.Error(), proto.CodeChanged, false)
		}
	}
	if err := c.link.Send(proto.FileStart{Index: idx, Offset: offset}); err != nil {
		return netErr("connection lost", err)
	}
	c.mu.Lock()
	c.open = true
	c.mu.Unlock()
	s.opts.Progress.SetCurrent(it.Path)
	s.opts.Progress.AddBytes(int64(offset))
	// Reading exactly the declared size guarantees no more than that is
	// ever sent (SND-6); memory use is one chunk buffer (SND-4).
	for pos := offset; pos < it.Size; {
		n := min(uint64(proto.ChunkSize), it.Size-pos)
		hdr := proto.AppendChunkHeader(buf[:0], idx, pos)
		data := buf[len(hdr) : len(hdr)+int(n)]
		if _, err := io.ReadFull(f, data); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return perFile(errChanged.Error(), proto.CodeChanged, true)
			}
			return perFile(readErr(err).Error(), proto.CodeUnreadable, true)
		}
		_, _ = h.Write(data)
		if testCorruptChunk != nil {
			testCorruptChunk(idx, pos, data)
		}
		if err := c.link.SendEncoded(buf[:len(hdr)+int(n)]); err != nil {
			return netErr("connection lost", err)
		}
		pos += n
		c.mu.Lock()
		c.sentBytes += n
		c.mu.Unlock()
		s.opts.Progress.AddBytes(int64(n))
	}
	// Size and mtime must be unchanged after reading (SND-6).
	if !sameFile(f, it.Entry) {
		return perFile(errChanged.Error(), proto.CodeChanged, true)
	}
	var sum [proto.HashSize]byte
	copy(sum[:], h.Sum(nil))
	c.mu.Lock()
	c.open = false
	c.awaiting[idx] = it.Size - offset
	c.inflightBytes += it.Size - offset
	c.mu.Unlock()
	if err := c.link.Send(proto.FileEnd{Index: idx, Hash: sum}); err != nil {
		return netErr("connection lost", err)
	}
	s.opts.Progress.FileDone()
	return nil
}

// sameFile reports whether the open file still has the manifest's size and
// mtime.
func sameFile(f *os.File, e proto.Entry) bool {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() < 0 || uint64(fi.Size()) != e.Size {
		return false
	}
	mt := fi.ModTime()
	return mt.Unix() == e.MtimeSec && uint32(mt.Nanosecond()) == e.MtimeNsec
}
