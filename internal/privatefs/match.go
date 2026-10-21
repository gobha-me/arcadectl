// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// MatchOriginal checks fresh ordinary-file bytes and identity without returning
// a discarded full-body copy. It is not a durability confirmation or authority
// to perform an effect. Read/Pin and their independently owned bodies are
// unchanged. The existing bounded scratch is serialized and scrubbed under mu;
// neither accepted bytes nor a successful comparison are cached.
// expected remains caller-owned and must not be mutated during this call.
func (s *Store) MatchOriginal(name string, max int64, expected []byte, identity FileIdentity) error {
	return s.matchOriginalBounded(name, max, MaxFileBytes, expected, identity)
}

// MatchEvidenceOriginal is the evidence-file counterpart of MatchOriginal.
// It still consumes fresh complete bytes and checks original identity; callers
// must separately confirm durability. The ordinary-file bound is unchanged.
func (s *Store) MatchEvidenceOriginal(name string, max int64, expected []byte, identity FileIdentity) error {
	return s.matchOriginalBounded(name, max, MaxEvidenceFileBytes, expected, identity)
}

func (s *Store) matchOriginalBounded(name string, max, limit int64, expected []byte, identity FileIdentity) error {
	if s == nil {
		return ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { clear(s.confirmScratch) }()
	if !s.valid() || !safeName(name) || !validFileLimit(limit) || max < 1 || max > limit {
		return ErrUnsafe
	}
	if s.confirmScratch == nil {
		s.confirmScratch = make([]byte, 32*1024)
	}
	fd, err := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return ErrNotFound
		}
		return ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), "private-file")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !privateStat(&before) || before.Size < 0 || before.Size > max {
		return ErrUnsafe
	}
	digest, equal, err := matchObservedSizeBounded(file, before.Size, max, limit, expected, s.confirmScratch)
	if err != nil || unix.Fstat(fd, &after) != nil {
		return ErrUnsafe
	}
	before.Atim = after.Atim
	if before != after {
		return ErrUnsafe
	}
	actual := FileIdentity{device: uint64(before.Dev), inode: before.Ino, digest: digest, changeTime: before.Ctim}
	if !equal || actual != identity {
		return ErrChanged
	}
	return nil
}

// Like readObservedSize, only literal underlying EOF at exactly the opening
// size succeeds. Read the same extra-byte growth probe, even on mismatches;
// partial-data and late errors cannot supply accepted bytes or an identity.
func matchObservedSize(reader io.Reader, size, max int64, expected, scratch []byte) ([32]byte, bool, error) {
	return matchObservedSizeBounded(reader, size, max, MaxFileBytes, expected, scratch)
}

func matchObservedSizeBounded(reader io.Reader, size, max, limit int64, expected, scratch []byte) ([32]byte, bool, error) {
	defer clear(scratch)
	if reader == nil || size < 0 || !validFileLimit(limit) || max < 1 || max > limit || size > max || len(scratch) == 0 || len(scratch) > 32*1024 {
		return [32]byte{}, false, ErrUnsafe
	}
	hash := sha256.New()
	equal := int64(len(expected)) == size
	for n := int64(0); n <= size; {
		want := min(int64(len(scratch)), size+1-n)
		count, err := reader.Read(scratch[:want])
		if count < 0 || int64(count) > want {
			return [32]byte{}, false, ErrUnsafe
		}
		end := n + int64(count)
		if end > size || err != nil && err != io.EOF {
			return [32]byte{}, false, ErrUnsafe
		}
		if int64(len(expected)) == size {
			chunkEqual := bytes.Equal(expected[n:end], scratch[:count])
			equal = chunkEqual && equal
		}
		_, _ = hash.Write(scratch[:count])
		n = end
		if err == io.EOF {
			if n != size {
				return [32]byte{}, false, ErrUnsafe
			}
			var digest [32]byte
			hash.Sum(digest[:0])
			return digest, equal, nil
		}
	}
	return [32]byte{}, false, ErrUnsafe
}
