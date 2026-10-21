// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"crypto/sha256"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Every call reads fresh physical bytes, with the same one-byte overflow probe
// as body-bearing reads. Bounded scratch replaces only discarded full-body
// allocations; it is wiped on both success and refusal, never evidence.
func digestBounded(reader io.Reader, max int64, scratch []byte) ([32]byte, error) {
	defer clear(scratch)
	if reader == nil || max < 1 || max > MaxEvidenceFileBytes || len(scratch) == 0 {
		return [32]byte{}, ErrUnsafe
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(reader, max+1), scratch)
	if err != nil || n > max {
		return [32]byte{}, ErrUnsafe
	}
	var digest [32]byte
	hash.Sum(digest[:0])
	return digest, nil
}

// Identity-only equivalent of a private readAtBounded. Both before/after stats,
// ownership/protection, exact full-byte digest and atime-only normalization are
// unchanged. Return no descriptor or body that could substitute read authority.
func readIdentityAtBounded(dir int, name string, limit int64, scratch []byte) (FileIdentity, error) {
	defer clear(scratch)
	if !validFileLimit(limit) || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return FileIdentity{}, ErrUnsafe
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return FileIdentity{}, ErrNotFound
		}
		return FileIdentity{}, ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !privateStat(&before) || before.Size < 0 || before.Size > limit {
		return FileIdentity{}, ErrUnsafe
	}
	digest, err := digestBounded(file, limit, scratch)
	if err != nil || unix.Fstat(fd, &after) != nil {
		return FileIdentity{}, ErrUnsafe
	}
	before.Atim = after.Atim
	if before != after {
		return FileIdentity{}, ErrUnsafe
	}
	id := FileIdentity{device: uint64(before.Dev), inode: before.Ino, digest: digest, changeTime: before.Ctim}
	return id, nil
}
