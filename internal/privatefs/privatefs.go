// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package privatefs provides Linux descriptor-anchored private storage.
package privatefs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrUnsafe     = errors.New("private storage is unavailable or unsafe")
	ErrNotFound   = errors.New("private file not found")
	ErrExists     = errors.New("private file already exists")
	ErrChanged    = errors.New("private file changed")
	ErrDurability = errors.New("private storage durability is unconfirmed")
)

const MaxFileBytes int64 = 1024 * 1024

type Protection uint8

const (
	Private Protection = iota
	TrustedPublic
)

// FileIdentity is opaque, comparable and not serializable.
type FileIdentity struct {
	device, inode uint64
	digest        [32]byte
}
type Store struct {
	fd       int
	mu       sync.Mutex
	syncFile func(*os.File) error
	syncDir  func(int) error
}
type Lock struct {
	fd   int
	once sync.Once
	err  error
}

var fileName = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

func safeName(n string) bool { return fileName.MatchString(n) && n != "." && n != ".." }
func privateStat(s *unix.Stat_t) bool {
	return s.Uid == uint32(os.Geteuid()) && s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&0o777 == 0o600 && s.Nlink == 1
}
func safeAncestor(s *unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFDIR && (s.Uid == 0 || s.Uid == uint32(os.Geteuid())) && (s.Mode&0o022 == 0 || s.Uid == 0 && s.Mode&unix.S_ISVTX != 0)
}

// Symlinks in all components are refused. Root-owned sticky shared ancestors
// may precede, but may never be, the exact-0700 euid-owned private base.
func openDirectory(path string, create, private bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 {
		return -1, ErrUnsafe
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnsafe
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e == unix.ENOENT && create {
			if e = unix.Mkdirat(fd, part, 0o700); e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return -1, ErrUnsafe
			}
			if unix.Fsync(fd) != nil {
				unix.Close(fd)
				return -1, ErrDurability
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		unix.Close(fd)
		if e != nil {
			if e == unix.ENOENT {
				return -1, ErrNotFound
			}
			return -1, ErrUnsafe
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !safeAncestor(&st) {
			unix.Close(fd)
			return -1, ErrUnsafe
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || private && (st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700) {
		unix.Close(fd)
		return -1, ErrUnsafe
	}
	return fd, nil
}
func Open(base string, create bool) (*Store, error) {
	fd, e := openDirectory(base, create, true)
	if e != nil {
		return nil, e
	}
	return &Store{fd: fd, syncFile: func(file *os.File) error { return file.Sync() }, syncDir: unix.Fsync}, nil
}
func (s *Store) valid() bool {
	if s == nil || s.fd < 0 {
		return false
	}
	var st unix.Stat_t
	return unix.Fstat(s.fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == uint32(os.Geteuid()) && st.Mode&0o777 == 0o700 && st.Nlink != 0
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	e := unix.Close(s.fd)
	s.fd = -1
	if e != nil {
		return ErrUnsafe
	}
	return nil
}
func ReadAbsolute(path string, max int64, p Protection) ([]byte, FileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || (p != Private && p != TrustedPublic) {
		return nil, FileIdentity{}, ErrUnsafe
	}
	fd, e := openDirectory(filepath.Dir(path), false, p == Private)
	if e != nil {
		return nil, FileIdentity{}, e
	}
	defer unix.Close(fd)
	return readAt(fd, filepath.Base(path), max, p)
}
func readAt(dir int, name string, max int64, p Protection) ([]byte, FileIdentity, error) {
	if max < 1 || max > MaxFileBytes || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, FileIdentity{}, ErrUnsafe
	}
	fd, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		if e == unix.ENOENT {
			return nil, FileIdentity{}, ErrNotFound
		}
		return nil, FileIdentity{}, ErrUnsafe
	}
	f := os.NewFile(uintptr(fd), "private-file")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil {
		return nil, FileIdentity{}, ErrUnsafe
	}
	safe := privateStat(&before)
	if p == TrustedPublic {
		safe = before.Mode&unix.S_IFMT == unix.S_IFREG && (before.Uid == 0 || before.Uid == uint32(os.Geteuid())) && before.Mode&0o022 == 0 && before.Nlink == 1
	}
	if !safe || before.Size < 0 || before.Size > max {
		return nil, FileIdentity{}, ErrUnsafe
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max || unix.Fstat(fd, &after) != nil {
		return nil, FileIdentity{}, ErrUnsafe
	}
	before.Atim = after.Atim
	if before != after {
		return nil, FileIdentity{}, ErrUnsafe
	}
	return b, FileIdentity{uint64(before.Dev), before.Ino, sha256.Sum256(b)}, nil
}
func (s *Store) Read(name string, max int64) ([]byte, FileIdentity, error) {
	if s == nil {
		return nil, FileIdentity{}, ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.valid() || !safeName(name) {
		return nil, FileIdentity{}, ErrUnsafe
	}
	return readAt(s.fd, name, max, Private)
}
func (s *Store) CreateExclusive(name string, b []byte) (FileIdentity, error) {
	return s.AtomicWrite(name, b, nil)
}

// Hold a cooperative Lock for read/modify/write sequences. nil means create-
// only; replacement requires observed identity. Post-rename failure is
// durability-unconfirmed, never proof that nothing changed.
func (s *Store) AtomicWrite(name string, b []byte, expected *FileIdentity) (FileIdentity, error) {
	if s == nil {
		return FileIdentity{}, ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.valid() || !safeName(name) || int64(len(b)) > MaxFileBytes {
		return FileIdentity{}, ErrUnsafe
	}
	_, current, e := readAt(s.fd, name, MaxFileBytes, Private)
	if expected == nil {
		if e == nil {
			return FileIdentity{}, ErrExists
		}
		if !errors.Is(e, ErrNotFound) {
			return FileIdentity{}, e
		}
	} else if e != nil || current != *expected {
		return FileIdentity{}, ErrChanged
	}
	random := make([]byte, 16)
	if _, e := rand.Read(random); e != nil {
		return FileIdentity{}, ErrUnsafe
	}
	tmp := ".tmp-" + hex.EncodeToString(random)
	fd, e := unix.Openat(s.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if e != nil {
		return FileIdentity{}, ErrUnsafe
	}
	f := os.NewFile(uintptr(fd), "private-file")
	renamed := false
	defer func() {
		f.Close()
		if !renamed {
			_ = unix.Unlinkat(s.fd, tmp, 0)
		}
	}()
	var st unix.Stat_t
	if unix.Fchmod(fd, 0o600) != nil || unix.Fstat(fd, &st) != nil || !privateStat(&st) {
		return FileIdentity{}, ErrUnsafe
	}
	if n, e := f.Write(b); e != nil || n != len(b) || s.syncFile(f) != nil || f.Close() != nil {
		return FileIdentity{}, ErrUnsafe
	}
	flags := uint(0)
	if expected == nil {
		flags = unix.RENAME_NOREPLACE
	}
	if e := unix.Renameat2(s.fd, tmp, s.fd, name, flags); e != nil {
		if e == unix.EEXIST {
			return FileIdentity{}, ErrExists
		}
		return FileIdentity{}, ErrUnsafe
	}
	renamed = true
	if s.syncDir(s.fd) != nil {
		return FileIdentity{}, ErrDurability
	}
	_, id, e := readAt(s.fd, name, MaxFileBytes, Private)
	return id, e
}
func (s *Store) Remove(name string, expected FileIdentity) error {
	if s == nil {
		return ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.valid() || !safeName(name) {
		return ErrUnsafe
	}
	_, id, e := readAt(s.fd, name, MaxFileBytes, Private)
	if e != nil {
		return e
	}
	if id != expected {
		return ErrChanged
	}
	if unix.Unlinkat(s.fd, name, 0) != nil {
		return ErrUnsafe
	}
	if s.syncDir(s.fd) != nil {
		return ErrDurability
	}
	return nil
}
func (s *Store) Lock(ctx context.Context, name string) (*Lock, error) {
	if s == nil || ctx == nil || !safeName(name) {
		return nil, ErrUnsafe
	}
	s.mu.Lock()
	if !s.valid() {
		s.mu.Unlock()
		return nil, ErrUnsafe
	}
	hash := sha256.Sum256([]byte(name))
	n := ".lock-" + hex.EncodeToString(hash[:16])
	fd, e := unix.Openat(s.fd, n, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	s.mu.Unlock()
	if e != nil {
		return nil, ErrUnsafe
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !privateStat(&st) {
		unix.Close(fd)
		return nil, ErrUnsafe
	}
	for {
		if ctx.Err() != nil {
			unix.Close(fd)
			return nil, ErrUnsafe
		}
		e := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			return &Lock{fd: fd}, nil
		}
		if e != unix.EWOULDBLOCK && e != unix.EAGAIN {
			unix.Close(fd)
			return nil, ErrUnsafe
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			return nil, ErrUnsafe
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if unix.Flock(l.fd, unix.LOCK_UN) != nil {
			l.err = ErrUnsafe
		}
		if unix.Close(l.fd) != nil {
			l.err = ErrUnsafe
		}
	})
	return l.err
}
