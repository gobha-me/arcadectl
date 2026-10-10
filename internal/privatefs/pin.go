// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// FilePin retains the descriptor that supplied its original bounded read.
// Holding that inode prevents successive same-byte replacements from recycling
// it and reviving its identity. This is a local temporal witness, not a lock on
// the pathname or permission to perform an external mutation. Callers own Close
// on every path; confirmation does not release or renew the original witness.
type FilePin struct {
	state *filePinState
}

// Copies of the opaque handle share release state and descriptor ownership.
type filePinState struct {
	mu       sync.Mutex
	file     *os.File
	store    *Store
	name     string
	path     string
	identity FileIdentity
	max      int64
	limit    int64
	protect  Protection
}

func (s *Store) Pin(name string, max int64) ([]byte, FileIdentity, *FilePin, error) {
	return s.pinBounded(name, max, MaxFileBytes)
}

// PinEvidence holds an original descriptor for larger private evidence only.
// Credential/trust-input Pin and PinAbsolute retain their smaller limits.
// Evidence is neither a mutation permit nor authority to reconstruct a lost
// original inventory; callers must independently bind its canonical seal.
func (s *Store) PinEvidence(name string, max int64) ([]byte, FileIdentity, *FilePin, error) {
	return s.pinBounded(name, max, MaxEvidenceFileBytes)
}

func (s *Store) pinBounded(name string, max, limit int64) ([]byte, FileIdentity, *FilePin, error) {
	if s == nil {
		return nil, FileIdentity{}, nil, ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.valid() || !safeName(name) {
		return nil, FileIdentity{}, nil, ErrUnsafe
	}
	file, body, identity, err := openReadAtBounded(s.fd, name, max, Private, limit)
	if err != nil {
		return nil, FileIdentity{}, nil, err
	}
	return body, identity, &FilePin{&filePinState{file: file, store: s, name: name, identity: identity, max: max, limit: limit, protect: Private}}, nil
}

// PinAbsolute applies the same original-descriptor lifetime to a bounded trust
// input. Confirm rewalks the absolute pathname; it never accepts the old file
// merely because a replaced directory still has an open descriptor.
func PinAbsolute(path string, max int64, protection Protection) ([]byte, FileIdentity, *FilePin, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || protection != Private && protection != TrustedPublic {
		return nil, FileIdentity{}, nil, ErrUnsafe
	}
	dir, err := openDirectory(filepath.Dir(path), false, protection == Private)
	if err != nil {
		return nil, FileIdentity{}, nil, err
	}
	defer unix.Close(dir)
	file, body, identity, err := openReadAtBounded(dir, filepath.Base(path), max, protection, MaxFileBytes)
	if err != nil {
		return nil, FileIdentity{}, nil, err
	}
	return body, identity, &FilePin{&filePinState{file: file, path: path, identity: identity, max: max, protect: protection}}, nil
}

// Confirm uses only the sealed opening identity/address. Store-backed pins
// additionally confirm file and directory durability while the original inode
// remains held. Released pins and closed stores cannot supply evidence.
func (witness *FilePin) Confirm() error {
	if witness == nil || witness.state == nil {
		return ErrUnsafe
	}
	p := witness.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return ErrUnsafe
	}
	if p.store != nil {
		return p.store.confirmDurableBounded(p.name, p.identity, p.limit)
	}
	_, identity, err := ReadAbsolute(p.path, p.max, p.protect)
	if err != nil {
		return err
	}
	if identity != p.identity {
		return ErrChanged
	}
	return nil
}

func (witness *FilePin) Close() error {
	if witness == nil || witness.state == nil {
		return nil
	}
	p := witness.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	if err != nil {
		return ErrUnsafe
	}
	return nil
}
