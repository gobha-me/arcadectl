// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// ConfirmDurableComparing retains ConfirmDurable's three fresh full-file reads,
// identity checks and file/directory fsyncs. Every fresh byte is compared with
// an owned operand, whose SHA-256 is computed once per call and bound to the
// supplied identity. Exact byte equality establishes fresh digest equality;
// neither a digest nor a successful observation is cached between calls.
// Small operands use a separate fixed 32KiB Store workspace, wiped before mu
// is released. Larger bounded operands use a scrubbed call-local allocation.
// Callers must still establish their independent match and protocol guards.
func (s *Store) ConfirmDurableComparing(name string, identity FileIdentity, expected []byte) error {
	return s.confirmDurableComparingBounded(name, identity, expected, MaxFileBytes)
}

// ConfirmEvidenceDurableComparing preserves the separate evidence-file bound.
func (s *Store) ConfirmEvidenceDurableComparing(name string, identity FileIdentity, expected []byte) error {
	return s.confirmDurableComparingBounded(name, identity, expected, MaxEvidenceFileBytes)
}

func (s *Store) confirmDurableComparingBounded(name string, expected FileIdentity, body []byte, limit int64) error {
	if s == nil {
		return ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { clear(s.comparisonScratch) }()
	if !s.valid() || !safeName(name) || !validFileLimit(limit) {
		return ErrUnsafe
	}
	if s.confirmScratch == nil {
		s.confirmScratch = make([]byte, 32*1024)
	}

	// Never allocate an unbounded operand. An oversized operand still reaches
	// the old first physical read/stat error point before returning ErrChanged.
	bounded := int64(len(body)) <= limit
	var owned []byte
	if bounded {
		if len(body) > 0 && len(body) <= 32*1024 {
			if s.comparisonScratch == nil {
				s.comparisonScratch = make([]byte, 32*1024)
			}
			owned = s.comparisonScratch[:len(body)]
			copy(owned, body)
		} else {
			owned = append([]byte(nil), body...)
			defer clear(owned)
		}
	}
	operand := confirmationOperand{body: owned, digest: sha256.Sum256(owned), bounded: bounded}

	id, equal, err := readComparingIdentityAtBounded(s.fd, name, limit, s.confirmScratch, &operand)
	if err != nil {
		return err
	}
	if !equal || id != expected {
		return ErrChanged
	}
	fd, err := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || !privateStat(&stat) || uint64(stat.Dev) != expected.device || stat.Ino != expected.inode || stat.Ctim != expected.changeTime {
		return ErrChanged
	}
	if stat.Size < 0 || stat.Size > limit {
		return ErrChanged
	}

	digest, equal, err := compareConfirmationBounded(file, limit, s.confirmScratch, &operand)
	var after unix.Stat_t
	if err != nil || unix.Fstat(fd, &after) != nil {
		return ErrUnsafe
	}
	stat.Atim = after.Atim
	if stat != after || !equal || digest != expected.digest {
		return ErrChanged
	}
	if s.syncFile(file) != nil || s.syncDir(s.fd) != nil {
		return ErrDurability
	}
	if !s.valid() {
		return ErrUnsafe
	}
	id, equal, err = readComparingIdentityAtBounded(s.fd, name, limit, s.confirmScratch, &operand)
	if err != nil {
		return err
	}
	if !equal || id != expected {
		return ErrChanged
	}
	return nil
}

// Private, call-local storage only. No authority or borrowing API is exposed.
type confirmationOperand struct {
	body    []byte
	digest  [32]byte
	bounded bool
}

type confirmationWriter struct {
	operand *confirmationOperand
	n       int
	equal   bool
}

func (w *confirmationWriter) Write(chunk []byte) (int, error) {
	end := w.n + len(chunk)
	if !w.operand.bounded || end > len(w.operand.body) {
		w.equal = false
	} else {
		chunkEqual := bytes.Equal(w.operand.body[w.n:end], chunk)
		w.equal = chunkEqual && w.equal
	}
	w.n = end
	return len(chunk), nil
}

// Preserve digestBounded's LimitReader(max+1), io.CopyBuffer and underlying
// EOF/error behavior exactly. Even a known mismatch consumes the complete
// physical pass; a late read error still precedes ErrChanged. The digest is
// meaningful only alongside equal=true and never leaves these private helpers.
func compareConfirmationBounded(reader io.Reader, max int64, scratch []byte, operand *confirmationOperand) ([32]byte, bool, error) {
	defer clear(scratch)
	if reader == nil || max < 1 || max > MaxEvidenceFileBytes || len(scratch) == 0 {
		return [32]byte{}, false, ErrUnsafe
	}
	writer := confirmationWriter{operand: operand, equal: operand.bounded}
	n, err := io.CopyBuffer(&writer, io.LimitReader(reader, max+1), scratch)
	if err != nil || n > max {
		return [32]byte{}, false, ErrUnsafe
	}
	return operand.digest, writer.equal && n == int64(len(operand.body)), nil
}

// Same descriptor, before/after stats, protection and atime normalization as
// readIdentityAtBounded. Defer the comparison result until after all read/stat
// errors; an unequal operand must not mask an unsafe file or late reader error.
func readComparingIdentityAtBounded(dir int, name string, limit int64, scratch []byte, operand *confirmationOperand) (FileIdentity, bool, error) {
	defer clear(scratch)
	if !validFileLimit(limit) || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return FileIdentity{}, false, ErrUnsafe
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return FileIdentity{}, false, ErrNotFound
		}
		return FileIdentity{}, false, ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !privateStat(&before) || before.Size < 0 || before.Size > limit {
		return FileIdentity{}, false, ErrUnsafe
	}

	digest, equal, err := compareConfirmationBounded(file, limit, scratch, operand)
	if err != nil || unix.Fstat(fd, &after) != nil {
		return FileIdentity{}, false, ErrUnsafe
	}
	before.Atim = after.Atim
	if before != after {
		return FileIdentity{}, false, ErrUnsafe
	}
	id := FileIdentity{device: uint64(before.Dev), inode: before.Ino, digest: digest, changeTime: before.Ctim}
	return id, equal, nil
}
