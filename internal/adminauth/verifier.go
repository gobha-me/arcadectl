// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var ErrInvalidVerifier = errors.New("invalid credential verifier")

type verifierState struct {
	bundle VerifierBundle
}

// FileVerifier reloads the one projected verifier bundle without retaining an
// old digest. Invalid or regressed input immediately makes authentication
// unavailable; the last high watermark remains so stale input cannot revive.
type FileVerifier struct {
	path  string
	clock func() time.Time

	reloadMu        sync.Mutex
	highSerial      uint64
	highFingerprint [sha256.Size]byte
	highState       *verifierState
	current         atomic.Pointer[verifierState]
}

func NewFileVerifier(path string, clock func() time.Time) *FileVerifier {
	if clock == nil {
		clock = time.Now
	}
	return &FileVerifier{path: path, clock: clock}
}

// Reload reads one bounded file and atomically replaces the sole verifier.
func (verifier *FileVerifier) Reload() error {
	verifier.reloadMu.Lock()
	defer verifier.reloadMu.Unlock()

	contents, err := readBoundedFile(verifier.path, MaxVerifierBundleBytes)
	if err != nil {
		verifier.current.Store(nil)
		return ErrInvalidVerifier
	}
	bundle, err := ParseVerifierBundle(contents)
	if err != nil {
		verifier.current.Store(nil)
		return ErrInvalidVerifier
	}
	fingerprint := sha256.Sum256(contents)
	if verifier.highSerial != 0 {
		switch {
		case bundle.Serial < verifier.highSerial:
			verifier.current.Store(nil)
			return ErrInvalidVerifier
		case bundle.Serial == verifier.highSerial && fingerprint != verifier.highFingerprint:
			verifier.current.Store(nil)
			return ErrInvalidVerifier
		case bundle.Serial == verifier.highSerial:
			verifier.current.Store(verifier.highState)
			return nil
		}
	}
	state := &verifierState{bundle: bundle}
	verifier.highSerial = bundle.Serial
	verifier.highFingerprint = fingerprint
	verifier.highState = state
	verifier.current.Store(state)
	return nil
}

// Run performs an initial load and periodic polling. Reload failures are
// reflected through Ready and Authenticate rather than emitted to logs.
func (verifier *FileVerifier) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("credential reload interval must be positive")
	}
	_ = verifier.Reload()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = verifier.Reload()
		}
	}
}

func (verifier *FileVerifier) Ready() bool {
	state := verifier.current.Load()
	return state != nil && verifier.clock().Before(state.bundle.ExpiresAt)
}

func (verifier *FileVerifier) Authenticate(_ context.Context, token string) (Principal, error) {
	state := verifier.current.Load()
	if state == nil {
		return Principal{}, ErrUnavailable
	}
	if !verifier.clock().Before(state.bundle.ExpiresAt) {
		return Principal{}, ErrUnauthorized
	}
	if !TokenMatchesBundle(token, state.bundle) {
		return Principal{}, ErrUnauthorized
	}
	return Principal{
		ID: AdminPrincipalID, CredentialID: state.bundle.CredentialID,
		Roles: []Role{RoleAdministrator}, ExpiresAt: state.bundle.ExpiresAt,
	}, nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, ErrInvalidVerifier
	}
	return contents, nil
}
