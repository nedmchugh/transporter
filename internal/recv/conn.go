// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"lukechampine.com/blake3"

	"github.com/OWNER/transporter/internal/fail"
	"github.com/OWNER/transporter/internal/manifest"
	"github.com/OWNER/transporter/internal/progress"
	"github.com/OWNER/transporter/internal/proto"
)

// Per-file connection state (PROTO-4). Transitions:
//
//	unplanned -> awaitStart   (NEED send)       -> receiving (FILE_START)
//	unplanned -> awaitVerify  (NEED verify-*)   -> receiving (FILE_START, verify-send only)
//	                                            -> settled   (VERIFY_RESULT)
//	unplanned -> settled      (NEED skip, conflict, error)
//	receiving -> finalizing   (FILE_END)        -> settled | retry (hash mismatch, once)
//	retry     -> receiving    (FILE_START at offset 0)
//	awaitStart, awaitVerify, receiving, retry -> settled (FILE_ABORT)
//
// Any message that does not fit the current state is a protocol violation
// that ends the connection (SEC-13).
type fstate uint8

const (
	stUnplanned fstate = iota
	stAwaitStart
	stAwaitVerify
	stReceiving
	stFinalizing
	stRetry
	stSettled
)

// plan is the receiver's decision for one entry.
type plan struct {
	action proto.NeedAction
	code   proto.Code
	offset uint64
}

// fileInfo is the per-connection state of one entry.
type fileInfo struct {
	st     fstate
	action proto.NeedAction
	offset uint64         // expected FILE_START offset
	prefix *blake3.Hasher // hash of the .part prefix when offset > 0
}

// openFile is a file being received or finalized.
type openFile struct {
	index  uint32
	entry  proto.Entry
	f      *os.File // nil when writes failed and data is being discarded
	h      *blake3.Hasher
	next   uint64 // next expected offset
	start  uint64
	err    proto.Code // per-file error while receiving, or CodeOK
	want   [proto.HashSize]byte
	create bool // the final name was absent at planning time
}

// conn serves one authenticated connection.
type conn struct {
	r       *Receiver
	link    *proto.Link
	sess    *session
	verify  bool
	root    *os.Root
	prog    *progress.Tracker
	entries []proto.Entry
	checker *manifest.Checker

	mu        sync.Mutex // guards files, open, receiving, sess outcomes
	files     []fileInfo
	open      map[uint32]*openFile
	receiving int

	jobs    chan *openFile
	errOnce sync.Once
	errc    chan error // first fatal error from the planner or finalizers
	wg      sync.WaitGroup
}

func newConn(r *Receiver, link *proto.Link, sess *session, verify bool) *conn {
	return &conn{
		r: r, link: link, sess: sess, verify: verify,
		root: r.root, prog: r.opts.Progress,
		checker: manifest.NewChecker(),
		open:    map[uint32]*openFile{},
		errc:    make(chan error, 1),
	}
}

// fail records the first fatal error from a helper goroutine and closes the
// link, which unblocks the main loop.
func (c *conn) fail(err error) {
	c.errOnce.Do(func() {
		c.errc <- err
		var fe *fail.Error
		code := proto.CodeInternal
		if errors.As(err, &fe) {
			switch fe.Kind {
			case fail.FS:
				code = proto.CodeNotWritable
				if errors.Is(err, errNoSpace) {
					code = proto.CodeNoSpace
				}
			case fail.Protocol:
				code = proto.CodeProtocol
			case fail.Network:
				_ = c.link.Close()
				return
			}
		}
		c.link.Abort(proto.Error{Code: code, Fatal: true, Message: err.Error()}, abortTimeout)
	})
}

var errNoSpace = errors.New("no space left on the destination")

// fsFatal classifies a destination write error: out of space and not
// writable are fatal for the transfer (REL-4); other errors are per-file.
func fsFatal(err error) error {
	switch {
	case isNoSpace(err):
		return fail.New(fail.FS, "the destination is out of space", "free some space and run the same commands again to resume", fmt.Errorf("%w: %w", errNoSpace, err))
	case isNotWritable(err):
		return fail.New(fail.FS, "the destination is not writable", "fix the destination's permissions and run again", err)
	}
	return nil
}

func (c *conn) run(ctx context.Context) (err error) {
	if err := c.readManifest(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	c.jobs = make(chan *openFile, proto.MaxInFlightFiles)
	defer func() {
		cancel()
		close(c.jobs)
		c.wg.Wait()
		c.closeOpen()
		// A fatal error from a helper outranks the network error the main
		// loop saw when the link was closed underneath it.
		select {
		case ferr := <-c.errc:
			err = ferr
		default:
		}
	}()
	c.wg.Add(1 + c.r.opts.Finalizers)
	go func() {
		defer c.wg.Done()
		if err := c.plan(ctx); err != nil && ctx.Err() == nil {
			c.fail(err)
		}
	}()
	for range c.r.opts.Finalizers {
		go c.finalizer(ctx)
	}
	return c.loop(ctx)
}

// readManifest receives MANIFEST batches until MANIFEST_END, validating each
// entry (TREE-2, TREE-9, TREE-11, SEC-12).
func (c *conn) readManifest() error {
	h := blake3.New(32, nil)
	var buf []byte
	for {
		m, err := c.link.Recv()
		if err != nil {
			return netErr(err)
		}
		switch m := m.(type) {
		case proto.Manifest:
			for _, e := range m.Entries {
				if err := c.checker.Add(e); err != nil {
					msg := "invalid manifest: " + err.Error()
					c.link.Abort(proto.Error{Code: proto.CodeBadManifest, Fatal: true, Message: msg}, abortTimeout)
					return fail.New(fail.Protocol, "rejected the sender's file list", "", err)
				}
			}
			c.entries = append(c.entries, m.Entries...)
			buf = proto.Append(buf[:0], m)
			_, _ = h.Write(buf)
		case proto.ManifestEnd:
			if int(m.Count) != len(c.entries) || m.TotalBytes != c.checker.TotalBytes() {
				return violation(c.link, "MANIFEST_END says %d entries and %d bytes, but %d entries and %d bytes were sent",
					m.Count, m.TotalBytes, len(c.entries), c.checker.TotalBytes())
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			c.files = make([]fileInfo, len(c.entries))
			c.sess.prepare(sum, c.entries)
			c.r.log.Info("manifest received", "entries", len(c.entries), "bytes", m.TotalBytes)
			return nil
		default:
			return violation(c.link, "expected MANIFEST, got %v", m.Type())
		}
	}
}

// plan decides what each entry needs and streams NEED records in index
// order (D-5.3). Pass 1 is cheap (lstat, mkdir) and gives the byte total for
// the free-space check (RCV-9); pass 2 does the expensive hashing of resume
// prefixes and --verify candidates, so the sender can start on early files
// while later ones are still being hashed.
func (c *conn) plan(ctx context.Context) error {
	plans := make([]plan, len(c.entries))
	failedDirs := map[string]bool{}
	var needBytes, sendFiles uint64
	for i, e := range c.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, err := c.decide(uint32(i), e, failedDirs)
		if err != nil {
			return err
		}
		plans[i] = p
		switch p.action {
		case proto.NeedSend:
			needBytes += e.Size - p.offset
			sendFiles++
		case proto.NeedVerifySend:
			needBytes += e.Size
			sendFiles++
		}
	}
	if avail := freeSpace(c.r.opts.Dest); avail >= 0 && needBytes > uint64(avail) {
		return fail.New(fail.FS,
			fmt.Sprintf("the destination has %s free, but the transfer needs about %s", progress.Bytes(avail), progress.Bytes(int64(needBytes))),
			"free some space or choose another destination", errNoSpace)
	}
	c.prog.SetTotals(int64(sendFiles), int64(needBytes))

	batch := make([]proto.NeedRecord, 0, proto.MaxNeedRecords)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := c.link.Send(proto.Need{Records: batch})
		batch = batch[:0]
		if err != nil {
			return netErr(err)
		}
		return nil
	}
	for i, e := range c.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		idx := uint32(i)
		p := plans[i]
		rec := proto.NeedRecord{Index: idx, Action: p.action, Code: p.code, Offset: p.offset}
		var prefix *blake3.Hasher
		hashed := false
		switch p.action {
		case proto.NeedSend:
			if p.offset > 0 {
				hashed = true
				h, err := hashFile(ctx, c.root, native(e.Path)+PartSuffix, int64(p.offset))
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					c.r.log.Info("cannot reuse partial file; starting over", "path", proto.Printable(e.Path), "err", err)
					rec.Offset = 0
				} else {
					prefix = h
				}
			}
		case proto.NeedVerifySend, proto.NeedVerifyConflict:
			hashed = true
			h, err := hashFile(ctx, c.root, native(e.Path), -1)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				rec = proto.NeedRecord{Index: idx, Action: proto.NeedError, Code: proto.CodeIO}
			} else {
				copy(rec.Hash[:], h.Sum(nil))
			}
		}
		c.mu.Lock()
		fi := &c.files[i]
		fi.action, fi.offset, fi.prefix = rec.Action, rec.Offset, prefix
		switch rec.Action {
		case proto.NeedSend:
			fi.st = stAwaitStart
		case proto.NeedVerifySend, proto.NeedVerifyConflict:
			fi.st = stAwaitVerify
		case proto.NeedSkip:
			fi.st = stSettled
			if c.sess.outcome[i] != oTransferred {
				c.sess.set(idx, oSkipped, 0)
			}
		case proto.NeedConflict:
			fi.st = stSettled
			c.sess.set(idx, oConflict, 0)
		case proto.NeedError:
			fi.st = stSettled
			c.sess.set(idx, oError, rec.Code)
		}
		c.mu.Unlock()
		batch = append(batch, rec)
		// Flush full batches, and after slow hashing so the sender is not
		// kept waiting for records that are already decided.
		if len(batch) == cap(batch) || hashed || len(batch) >= 256 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// decide makes the pass-1 decision for one entry. Directories are created
// here, so files planned later always have their parent (D-5.10).
func (c *conn) decide(i uint32, e proto.Entry, failedDirs map[string]bool) (plan, error) {
	perEntry := func(code proto.Code) (plan, error) {
		if e.Type == proto.EntryDir {
			failedDirs[e.Path] = true
		}
		return plan{action: proto.NeedError, code: code}, nil
	}
	if parent := path.Dir(e.Path); parent != "." && failedDirs[parent] {
		return perEntry(proto.CodeParentFailed)
	}
	if runtime.GOOS == "windows" && manifest.ValidateWindowsPath(e.Path) != nil {
		return perEntry(proto.CodeInvalidName) // TREE-10
	}
	name := native(e.Path)
	kind, fi, err := lstatKind(c.root, name)
	if err != nil {
		c.r.log.Info("cannot inspect destination path", "path", proto.Printable(e.Path), "err", err)
		return perEntry(proto.CodeIO)
	}
	if e.Type == proto.EntryDir {
		switch kind {
		case kDir:
			return plan{action: proto.NeedSkip}, nil
		case kSymlink:
			return perEntry(proto.CodeSymlink)
		case kMissing:
			// Directory modes are not copied (D-5.8); 0755 is subject to
			// the umask. os.Root.Mkdir never creates setuid/setgid/sticky.
			if err := c.root.Mkdir(name, 0o755); err != nil {
				if isNoSpace(err) {
					fe := fsFatal(err)
					return plan{}, fe
				}
				c.r.log.Info("cannot create directory", "path", proto.Printable(e.Path), "err", err)
				return perEntry(proto.CodeIO)
			}
			return plan{action: proto.NeedSkip}, nil
		default:
			return perEntry(proto.CodeTypeConflict) // RES-5
		}
	}
	// A file whose temporary name is itself in the manifest (D-5.11).
	if c.checker.Contains(e.Path + PartSuffix) {
		return perEntry(proto.CodeTempName)
	}
	switch kind {
	case kSymlink:
		return perEntry(proto.CodeSymlink) // SEC-11
	case kDir:
		return perEntry(proto.CodeTypeConflict) // RES-5
	case kOther:
		return perEntry(proto.CodeUnusable)
	case kRegular:
		if c.sess.outcome[i] == oTransferred && quickCheck(fi, e) {
			return plan{action: proto.NeedSkip}, nil // written earlier in this session
		}
		sameSize := fi.Size() >= 0 && uint64(fi.Size()) == e.Size
		switch {
		case c.verify && sameSize && c.r.opts.Overwrite:
			return plan{action: proto.NeedVerifySend}, nil
		case c.verify && sameSize:
			return plan{action: proto.NeedVerifyConflict}, nil
		case !c.verify && quickCheck(fi, e):
			return plan{action: proto.NeedSkip}, nil // XFER-7 "already complete"
		case !c.r.opts.Overwrite:
			return plan{action: proto.NeedConflict}, nil // XFER-7
		}
	}
	// Send, resuming from a .part file if there is a usable one.
	pk, pfi, err := lstatKind(c.root, name+PartSuffix)
	switch {
	case err != nil:
		return perEntry(proto.CodeIO)
	case pk == kSymlink:
		return perEntry(proto.CodeSymlink)
	case pk == kDir:
		return perEntry(proto.CodeTypeConflict) // RES-5
	case pk == kOther:
		return perEntry(proto.CodeUnusable)
	case pk == kRegular:
		return plan{action: proto.NeedSend, offset: resumeOffset(pfi.Size(), e.Size)}, nil
	}
	return plan{action: proto.NeedSend}, nil
}

// loop is the main message loop for the data phase.
func (c *conn) loop(ctx context.Context) error {
	for {
		m, err := c.link.Recv()
		if err != nil {
			return netErr(err)
		}
		switch m := m.(type) {
		case proto.FileStart:
			err = c.onFileStart(m)
		case proto.Chunk:
			err = c.onChunk(m)
		case proto.FileEnd:
			err = c.onFileEnd(ctx, m)
		case proto.FileAbort:
			err = c.onFileAbort(m)
		case proto.VerifyResult:
			err = c.onVerifyResult(m)
		case proto.Done:
			return c.onDone()
		case proto.Error:
			return c.onPeerError(m)
		default:
			err = violation(c.link, "unexpected %v", m.Type())
		}
		if err != nil {
			return err
		}
	}
}

func (c *conn) fileIndex(i uint32, what string) (proto.Entry, error) {
	if int(i) >= len(c.entries) || c.entries[i].Type != proto.EntryFile {
		return proto.Entry{}, violation(c.link, "%s for index %d, which is not a file in the manifest", what, i)
	}
	return c.entries[i], nil
}

func (c *conn) onFileStart(m proto.FileStart) error {
	e, err := c.fileIndex(m.Index, "FILE_START")
	if err != nil {
		return err
	}
	c.mu.Lock()
	fi := &c.files[m.Index]
	var ok bool
	switch fi.st {
	case stAwaitStart:
		ok = m.Offset == fi.offset
	case stAwaitVerify:
		ok = fi.action == proto.NeedVerifySend && m.Offset == 0
	case stRetry:
		ok = m.Offset == 0
	}
	if !ok || c.receiving >= proto.MaxInFlightFiles {
		st, want := fi.st, fi.offset
		c.mu.Unlock()
		return violation(c.link, "FILE_START for file %d at offset %d in state %d (expected offset %d)", m.Index, m.Offset, st, want)
	}
	prefix := fi.prefix
	fi.prefix = nil
	fi.st = stReceiving
	c.receiving++
	c.mu.Unlock()

	of := &openFile{index: m.Index, entry: e, next: m.Offset, start: m.Offset}
	name := native(e.Path)
	kind, _, err := lstatKind(c.root, name)
	of.create = err == nil && kind == kMissing
	of.f, of.err, err = c.openPart(name+PartSuffix, m.Offset)
	if err != nil {
		return err
	}
	if m.Offset > 0 && prefix != nil {
		of.h = prefix
	} else {
		of.h = newHasher()
	}
	c.mu.Lock()
	c.open[m.Index] = of
	c.mu.Unlock()
	c.prog.SetCurrent(e.Path)
	c.prog.AddBytes(int64(m.Offset))
	return nil
}

// openPart opens NAME.part for writing at offset. A per-file failure returns
// a nil file and an error code (data is then discarded, RES-5); only fatal
// conditions return an error.
func (c *conn) openPart(part string, offset uint64) (*os.File, proto.Code, error) {
	kind, _, err := lstatKind(c.root, part)
	switch {
	case err != nil:
		return nil, proto.CodeIO, nil //nolint:nilerr // per-file failure, reported through the code (RES-5)
	case kind == kSymlink:
		return nil, proto.CodeSymlink, nil
	case kind != kMissing && kind != kRegular:
		return nil, proto.CodeTypeConflict, nil
	}
	flags := os.O_WRONLY | os.O_CREATE
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := c.root.OpenFile(part, flags, 0o600)
	if err != nil {
		if isNoSpace(err) {
			fe := fsFatal(err)
			return nil, 0, fe
		}
		c.r.log.Info("cannot create partial file", "path", proto.Printable(part), "err", err)
		return nil, proto.CodeIO, nil
	}
	if offset > 0 {
		// Drop any torn tail beyond the chunk boundary (RES-3), then
		// append from there.
		if err := f.Truncate(int64(offset)); err != nil {
			_ = f.Close()
			return nil, proto.CodeIO, nil //nolint:nilerr // per-file failure (RES-5)
		}
		if _, err := f.Seek(int64(offset), io.SeekStart); err != nil {
			_ = f.Close()
			return nil, proto.CodeIO, nil //nolint:nilerr // per-file failure (RES-5)
		}
	}
	return f, proto.CodeOK, nil
}

func (c *conn) onChunk(m proto.Chunk) error {
	c.mu.Lock()
	of := c.open[m.Index]
	c.mu.Unlock()
	if of == nil {
		return violation(c.link, "CHUNK for file %d, which is not being received", m.Index)
	}
	// SEC-10: offsets must continue exactly where the last chunk ended and
	// never pass the declared size.
	n := uint64(len(m.Data))
	if m.Offset != of.next || n > of.entry.Size-of.next {
		return violation(c.link, "CHUNK for file %d at offset %d (+%d), expected offset %d of %d bytes", m.Index, m.Offset, n, of.next, of.entry.Size)
	}
	of.next += n
	c.prog.AddBytes(int64(n))
	if of.f == nil {
		return nil // per-file failure: discard
	}
	_, _ = of.h.Write(m.Data)
	if _, err := of.f.Write(m.Data); err != nil {
		if isNoSpace(err) {
			fe := fsFatal(err)
			c.fail(fe)
			return fe
		}
		c.r.log.Info("write failed", "path", proto.Printable(of.entry.Path), "err", err)
		_ = of.f.Close()
		of.f, of.err = nil, proto.CodeIO
	}
	return nil
}

func (c *conn) onFileEnd(ctx context.Context, m proto.FileEnd) error {
	c.mu.Lock()
	of := c.open[m.Index]
	if of != nil && of.next == of.entry.Size {
		delete(c.open, m.Index)
		c.files[m.Index].st = stFinalizing
	}
	c.mu.Unlock()
	if of == nil {
		return violation(c.link, "FILE_END for file %d, which is not being received", m.Index)
	}
	if of.next != of.entry.Size {
		return violation(c.link, "FILE_END for file %d after %d of %d bytes", m.Index, of.next, of.entry.Size)
	}
	of.want = m.Hash
	select {
	case c.jobs <- of:
		return nil
	case <-ctx.Done():
		if of.f != nil {
			_ = of.f.Close()
		}
		return netErr(ctx.Err())
	}
}

func (c *conn) onFileAbort(m proto.FileAbort) error {
	if _, err := c.fileIndex(m.Index, "FILE_ABORT"); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fi := &c.files[m.Index]
	switch fi.st {
	case stAwaitStart, stAwaitVerify, stRetry:
	case stReceiving:
		// Keep the .part file: a later run may resume it, and the final
		// hash check catches stale content (XFER-1).
		if of := c.open[m.Index]; of != nil && of.f != nil {
			_ = of.f.Close()
		}
		delete(c.open, m.Index)
		c.receiving--
	default:
		return violation(c.link, "FILE_ABORT for file %d in state %d", m.Index, fi.st)
	}
	code := m.Code
	if code == proto.CodeOK {
		code = proto.CodeInternal
	}
	fi.st = stSettled
	fi.prefix = nil
	c.sess.set(m.Index, oError, code)
	return nil
}

func (c *conn) onVerifyResult(m proto.VerifyResult) error {
	if _, err := c.fileIndex(m.Index, "VERIFY_RESULT"); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fi := &c.files[m.Index]
	if fi.st != stAwaitVerify || (!m.Same && fi.action != proto.NeedVerifyConflict) {
		return violation(c.link, "VERIFY_RESULT for file %d in state %d", m.Index, fi.st)
	}
	fi.st = stSettled
	if m.Same {
		if c.sess.outcome[m.Index] != oTransferred {
			c.sess.set(m.Index, oSkipped, 0)
		}
	} else {
		c.sess.set(m.Index, oConflict, 0)
	}
	return nil
}

// finalizer verifies completed files and moves them into place (XFER-3,
// XFER-4). Several run concurrently so fsync latency overlaps receiving.
func (c *conn) finalizer(ctx context.Context) {
	defer c.wg.Done()
	for of := range c.jobs {
		if ctx.Err() != nil {
			if of.f != nil {
				_ = of.f.Close()
			}
			continue
		}
		ack, err := c.finalize(of)
		if err != nil {
			c.fail(err)
			continue
		}
		if err := c.link.Send(ack); err != nil {
			c.fail(netErr(err))
		}
	}
}

func (c *conn) finalize(of *openFile) (proto.Ack, error) {
	idx, e := of.index, of.entry
	name := native(e.Path)
	part := name + PartSuffix
	settle := func(o outcome, code proto.Code) {
		c.mu.Lock()
		c.files[idx].st = stSettled
		c.receiving--
		c.sess.set(idx, o, code)
		c.mu.Unlock()
	}
	if of.f == nil {
		settle(oError, of.err)
		return proto.Ack{Index: idx, Status: proto.AckError, Code: of.err}, nil
	}
	var sum [proto.HashSize]byte
	copy(sum[:], of.h.Sum(nil))
	if !bytes.Equal(sum[:], of.want[:]) {
		// XFER-4: delete the .part and allow one retransmission from 0.
		_ = of.f.Close()
		_ = c.root.Remove(part)
		c.mu.Lock()
		c.sess.mismatches[idx]++
		first := c.sess.mismatches[idx] == 1
		c.receiving--
		if first {
			c.files[idx].st = stRetry
		} else {
			c.files[idx].st = stSettled
			c.sess.set(idx, oIntegrity, proto.CodeIntegrity)
		}
		c.mu.Unlock()
		if first {
			c.r.log.Warn("hash mismatch; asking the sender to resend", "path", proto.Printable(e.Path))
			return proto.Ack{Index: idx, Status: proto.AckMismatch}, nil
		}
		c.r.log.Error("hash mismatch after retransmission", "path", proto.Printable(e.Path))
		return proto.Ack{Index: idx, Status: proto.AckError, Code: proto.CodeIntegrity}, nil
	}
	perFile := func(step string, err error) (proto.Ack, error) {
		if isNoSpace(err) {
			fe := fsFatal(err)
			return proto.Ack{}, fe
		}
		c.r.log.Info("cannot finalize file", "path", proto.Printable(e.Path), "step", step, "err", err)
		settle(oError, proto.CodeIO)
		return proto.Ack{Index: idx, Status: proto.AckError, Code: proto.CodeIO}, nil
	}
	// Mode is applied through the open descriptor, never by path, and is
	// masked to 0777 so setuid/setgid/sticky never appear (TREE-7, SEC-11).
	if err := of.f.Chmod(os.FileMode(e.Mode & 0o777)); err != nil {
		_ = of.f.Close()
		return perFile("chmod", err)
	}
	if err := of.f.Sync(); err != nil {
		_ = of.f.Close()
		return perFile("sync", err)
	}
	if err := of.f.Close(); err != nil {
		return perFile("close", err)
	}
	// Set the mtime before the rename, so a crash after the rename never
	// leaves a complete file with a fresh mtime that a later quick check
	// would call a conflict (D-5.7).
	mt := mtime(e)
	if err := c.root.Chtimes(part, mt, mt); err != nil {
		return perFile("chtimes", err)
	}
	// Re-check the final name: if something appeared there since planning
	// and overwriting is off, do not replace it (XFER-7).
	kind, _, err := lstatKind(c.root, name)
	if err != nil {
		return perFile("lstat", err)
	}
	switch {
	case kind == kSymlink:
		settle(oError, proto.CodeSymlink)
		return proto.Ack{Index: idx, Status: proto.AckError, Code: proto.CodeSymlink}, nil
	case kind == kDir:
		settle(oError, proto.CodeTypeConflict)
		return proto.Ack{Index: idx, Status: proto.AckError, Code: proto.CodeTypeConflict}, nil
	case kind != kMissing && of.create && !c.r.opts.Overwrite:
		settle(oConflict, 0)
		return proto.Ack{Index: idx, Status: proto.AckError, Code: proto.CodeExists}, nil
	}
	if err := c.root.Rename(part, name); err != nil {
		return perFile("rename", err)
	}
	if err := syncDir(c.root, path.Dir(native(e.Path))); err != nil {
		c.r.log.Debug("cannot sync directory", "path", proto.Printable(path.Dir(e.Path)), "err", err)
	}
	c.mu.Lock()
	c.sess.bytes += int64(e.Size - of.start)
	c.mu.Unlock()
	settle(oTransferred, 0)
	c.prog.FileDone()
	return proto.Ack{Index: idx, Status: proto.AckOK}, nil
}

// onDone completes the session (PROTO-7).
func (c *conn) onDone() error {
	c.mu.Lock()
	for i := range c.files {
		if c.files[i].st != stSettled {
			st := c.files[i].st
			c.mu.Unlock()
			return violation(c.link, "DONE while file %d is unsettled (state %d)", i, st)
		}
	}
	totals := c.sess.done()
	c.mu.Unlock()
	if err := c.link.Send(totals); err != nil {
		return netErr(err)
	}
	c.r.log.Info("transfer complete", "files", totals.Transferred, "bytes", totals.Bytes)
	c.r.complete()
	// Give the sender a moment to read DONE and close first, so the reply
	// is not lost to an early close (D-5.15).
	t := time.AfterFunc(c.r.opts.Linger, func() { _ = c.link.Close() })
	defer t.Stop()
	for {
		if _, err := c.link.Recv(); err != nil {
			return nil
		}
	}
}

func (c *conn) onPeerError(m proto.Error) error {
	msg := proto.Printable(m.Message)
	if m.Code == proto.CodeInterrupted {
		return fail.New(fail.Network, "the sender stopped: "+msg, "", nil)
	}
	return fail.New(fail.Protocol, "the sender reported an error: "+msg, "", nil)
}

// closeOpen closes files left open when a connection ends. The .part files
// stay on disk for resume (REL-7).
func (c *conn) closeOpen() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, of := range c.open {
		if of.f != nil {
			_ = of.f.Close()
		}
		delete(c.open, i)
	}
}
