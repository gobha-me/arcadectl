// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImmutableEvidenceLargeBoundDoesNotExpandOrdinaryFiles(t *testing.T) {
	store, err := Open(privateTemp(t), false)
	if err != nil {
		t.Fatal("protected store unavailable")
	}
	defer store.Close()
	body := bytes.Repeat([]byte("x"), int(MaxFileBytes)+1)
	if _, err := store.CreateExclusive("ordinary.json", body); err != ErrUnsafe {
		t.Fatal("ordinary credential limit expanded")
	}
	identity, err := store.CreateEvidenceExclusive("worlds.json", body)
	if err != nil {
		t.Fatal("bounded original evidence publication failed")
	}
	if _, err := store.CreateEvidenceExclusive("worlds.json", []byte("replacement")); err != ErrExists {
		t.Fatal("evidence publication overwrote original")
	}
	for _, limit := range []int64{0, MaxEvidenceFileBytes + 1} {
		if _, _, err := store.ReadEvidence("worlds.json", limit); err != ErrUnsafe {
			t.Fatal("invalid evidence read bound accepted")
		}
	}
	for _, limit := range []int64{MaxFileBytes, MaxEvidenceFileBytes} {
		if _, _, err := store.Read("worlds.json", limit); err != ErrUnsafe {
			t.Fatal("ordinary reader inherited evidence capacity")
		}
	}
	if err := store.ConfirmDurable("worlds.json", identity); err != ErrUnsafe {
		t.Fatal("ordinary durability inherited evidence capacity")
	}
	if err := store.Remove("worlds.json", identity); err != ErrUnsafe {
		t.Fatal("ordinary removal inherited evidence capacity")
	}
	observed, id, err := store.ReadEvidence("worlds.json", MaxEvidenceFileBytes)
	if err != nil || id != identity || !bytes.Equal(observed, body) || store.ConfirmEvidenceDurable("worlds.json", id) != nil {
		t.Fatal("exact protected evidence read/durability refused")
	}
	if err := store.RemoveEvidence("worlds.json", identity); err != nil {
		t.Fatal("exact original evidence removal failed")
	}
	if _, _, err := store.ReadEvidence("worlds.json", MaxEvidenceFileBytes); err != ErrNotFound {
		t.Fatal("removed original evidence remained")
	}
}

func TestImmutableEvidenceRefusesReplacementUnsafeFileAndDurabilityUncertainty(t *testing.T) {
	for _, fault := range []string{"replacement", "symlink", "hardlink", "mode", "dir-fsync"} {
		t.Run(fault, func(t *testing.T) {
			dir := privateTemp(t)
			store, err := Open(dir, false)
			if err != nil {
				t.Fatal("protected store unavailable")
			}
			defer store.Close()
			body := []byte("original")
			if fault == "dir-fsync" {
				originalSync := store.syncDir
				store.syncDir = func(int) error { return errors.New("private injected failure") }
				if _, err := store.CreateEvidenceExclusive("worlds.json", body); err != ErrDurability {
					t.Fatal("uncertain publication reported success")
				}
				store.syncDir = originalSync
				observed, id, err := store.ReadEvidence("worlds.json", MaxEvidenceFileBytes)
				if err != nil || !bytes.Equal(observed, body) || store.ConfirmEvidenceDurable("worlds.json", id) != nil {
					t.Fatal("visible exact uncertain evidence could not be confirmed durable")
				}
				if _, err := store.CreateEvidenceExclusive("worlds.json", body); err != ErrExists {
					t.Fatal("uncertain evidence publication replayed")
				}
				return
			}
			id, err := store.CreateEvidenceExclusive("worlds.json", body)
			if err != nil {
				t.Fatal("original publication failed")
			}
			switch fault {
			case "replacement":
				if _, err := store.AtomicWrite("worlds.json", body, &id); err != nil {
					t.Fatal("replacement injection failed")
				}
				if store.ConfirmEvidenceDurable("worlds.json", id) != ErrChanged || store.RemoveEvidence("worlds.json", id) != ErrChanged {
					t.Fatal("same-byte replacement supplied original identity")
				}
				return
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "worlds.json"), filepath.Join(dir, "link.json")); err != nil {
					t.Fatal("symlink injection failed")
				}
				if _, _, err := store.ReadEvidence("link.json", MaxEvidenceFileBytes); err != ErrUnsafe {
					t.Fatal("evidence followed symlink")
				}
				return
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "worlds.json"), filepath.Join(dir, "link.json")); err != nil {
					t.Fatal("hardlink injection failed")
				}
			case "mode":
				if err := os.Chmod(filepath.Join(dir, "worlds.json"), 0644); err != nil {
					t.Fatal("mode injection failed")
				}
			}
			if _, _, err := store.ReadEvidence("worlds.json", MaxEvidenceFileBytes); err != ErrUnsafe || store.ConfirmEvidenceDurable("worlds.json", id) != ErrUnsafe || store.RemoveEvidence("worlds.json", id) != ErrUnsafe {
				t.Fatal("unsafe evidence admitted")
			}
		})
	}
}

func TestImmutableEvidenceExactHardLimitAndOrdinaryAbsoluteWriteLimits(t *testing.T) {
	dir := privateTemp(t)
	store, err := Open(dir, false)
	if err != nil {
		t.Fatal("protected store unavailable")
	}
	defer store.Close()
	body := bytes.Repeat([]byte("x"), int(MaxEvidenceFileBytes)+1)
	if _, err := store.CreateEvidenceExclusive("oversized.json", body); err != ErrUnsafe {
		t.Fatal("oversized evidence accepted")
	}
	identity, err := store.CreateEvidenceExclusive("exact.json", body[:MaxEvidenceFileBytes])
	if err != nil {
		t.Fatal("exact evidence hard limit refused")
	}
	read, id, err := store.ReadEvidence("exact.json", MaxEvidenceFileBytes)
	if err != nil || id != identity || !bytes.Equal(read, body[:MaxEvidenceFileBytes]) {
		t.Fatal("exact hard-limit evidence unavailable")
	}
	if _, err := store.AtomicWrite("ordinary.json", body[:MaxFileBytes+1], nil); err != ErrUnsafe {
		t.Fatal("ordinary mutable write limit expanded")
	}
	if _, _, err := ReadAbsolute(filepath.Join(dir, "exact.json"), MaxEvidenceFileBytes, Private); err != ErrUnsafe {
		t.Fatal("absolute credential read limit expanded")
	}
}

func TestImmutableEvidenceFileSyncFailureAndRemovalUncertainty(t *testing.T) {
	store, err := Open(privateTemp(t), false)
	if err != nil {
		t.Fatal("protected store unavailable")
	}
	defer store.Close()
	originalFileSync := store.syncFile
	store.syncFile = func(*os.File) error { return errors.New("private injected failure") }
	if _, err := store.CreateEvidenceExclusive("worlds.json", []byte("original")); err != ErrUnsafe {
		t.Fatal("file fsync failure reported durable publication")
	}
	store.syncFile = originalFileSync
	if _, _, err := store.ReadEvidence("worlds.json", MaxEvidenceFileBytes); err != ErrNotFound {
		t.Fatal("failed file sync published evidence")
	}
	id, err := store.CreateEvidenceExclusive("worlds.json", []byte("original"))
	if err != nil {
		t.Fatal("original evidence unavailable")
	}
	store.syncDir = func(int) error { return errors.New("private injected failure") }
	if err := store.RemoveEvidence("worlds.json", id); err != ErrDurability {
		t.Fatal("uncertain removal reported durable success")
	}
	if _, _, err := store.ReadEvidence("worlds.json", MaxEvidenceFileBytes); err != ErrNotFound {
		t.Fatal("uncertain removal did not preserve actual absence observation")
	}
}
