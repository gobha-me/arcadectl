// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Observe a real same-tick history rather than mocking stat, changing the
// clock, or waiting for a distinct ctime. A high-resolution host may not supply
// this counterexample; the observed-current-mode and byte-refusal tests still run.
func sameTickProtectionHistory(t *testing.T) (*Store, FileIdentity, []byte) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "private"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	})
	body := []byte("non-secret protection-history fixture")
	if _, err := s.CreateExclusive("record", body); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 1024; attempt++ {
		// Refresh ctime before the snapshot; do not rely on the earlier create
		// and its file/directory fsync fitting within this timestamp tick.
		if err := unix.Fchmodat(s.fd, "record", 0o600, 0); err != nil {
			t.Fatal(err)
		}
		before, id, err := s.Read("record", MaxFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, body) {
			t.Fatal("original fixture bytes changed")
		}
		if err := unix.Fchmodat(s.fd, "record", 0o644, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Fchmodat(s.fd, "record", 0o600, 0); err != nil {
			t.Fatal(err)
		}
		after, restored, err := s.Read("record", MaxFileBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, body) {
			t.Fatal("mode transition changed fixture bytes")
		}
		// Keep the old four identity signals equal, even if a future fix adds
		// another signal. Such a fix must exercise the probe, not skip it.
		if restored.changeTime == id.changeTime && restored.device == id.device && restored.inode == id.inode && restored.digest == id.digest {
			t.Logf("same-tick counterexample observed after %d immediate attempts", attempt+1)
			return s, id, body
		}
	}
	t.Skip("no same-tick restored-protection identity observed in 1024 attempts; #174 history limitation not reproduced on this host")
	return nil, FileIdentity{}, nil
}

func TestSameTickProtectionRestorationBoundary(t *testing.T) {
	s, id, body := sameTickProtectionHistory(t)
	if err := s.ConfirmDurable("record", id); err != nil {
		t.Fatalf("state observation refused an identical restored identity: %v", err)
	}
	if err := s.ConfirmDurableComparing("record", id, body); err != nil {
		t.Fatalf("comparing observation refused identical restored state: %v", err)
	}
}

func TestProtectionHistoryStillRefusesObservedUnsafeModeAndChangedBytes(t *testing.T) {
	for _, comparing := range []bool{false, true} {
		s, err := Open(filepath.Join(t.TempDir(), "private"), true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Errorf("close fixture: %v", err)
			}
		})
		body := []byte("non-secret original fixture")
		id, err := s.CreateExclusive("record", body)
		if err != nil {
			t.Fatal(err)
		}
		confirm := func() error { return s.ConfirmDurable("record", id) }
		if comparing {
			confirm = func() error { return s.ConfirmDurableComparing("record", id, body) }
		}
		if err := unix.Fchmodat(s.fd, "record", 0o644, 0); err != nil {
			t.Fatal(err)
		}
		if err := confirm(); err != ErrUnsafe {
			t.Fatalf("currently unsafe file accepted or misclassified: %v", err)
		}
		if err := unix.Fchmodat(s.fd, "record", 0o600, 0); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Openat(s.fd, "record", unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := unix.Write(fd, []byte("non-secret changed fixture!"))
		closeErr := unix.Close(fd)
		if writeErr != nil || closeErr != nil || n != len("non-secret changed fixture!") {
			t.Fatalf("rewrite fixture: bytes=%d write=%v close=%v", n, writeErr, closeErr)
		}
		if err := confirm(); err != ErrChanged {
			t.Fatalf("changed content accepted or misclassified: %v", err)
		}
	}
}
