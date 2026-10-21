// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestEvidencePinKeepsOrdinaryLimitsAndOriginalDescriptor(t *testing.T) {
	dir := privateTemp(t)
	store, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	body := bytes.Repeat([]byte("x"), int(MaxFileBytes)+1)
	identity, err := store.CreateEvidenceExclusive("worlds.json", body)
	if err != nil {
		t.Fatal("protected evidence publication failed", err)
	}
	if _, _, _, err := store.Pin("worlds.json", int64(len(body))); err != ErrUnsafe {
		t.Fatal("evidence pin widened ordinary credential limit")
	}
	if _, _, _, err := PinAbsolute(filepath.Join(dir, "worlds.json"), int64(len(body)), Private); err != ErrUnsafe {
		t.Fatal("evidence pin widened absolute trust-input limit")
	}
	for _, max := range []int64{0, MaxEvidenceFileBytes + 1, int64(len(body)) - 1} {
		if _, _, pin, err := store.PinEvidence("worlds.json", max); err != ErrUnsafe || pin != nil {
			t.Fatal("invalid evidence pin bound returned an owner")
		}
	}
	got, observed, pin, err := store.PinEvidence("worlds.json", MaxEvidenceFileBytes)
	if err != nil || pin == nil || observed != identity || !bytes.Equal(got, body) || pin.Confirm() != nil {
		t.Fatal("large original evidence pin or durable confirmation unavailable")
	}
	t.Cleanup(func() { _ = pin.Close() })
	got[0] ^= 1
	if pin.Confirm() != nil {
		t.Fatal("caller-owned bytes changed the sealed evidence identity")
	}
	for range 2 {
		if os.WriteFile(filepath.Join(dir, "replacement.json"), body, 0600) != nil || os.Rename(filepath.Join(dir, "replacement.json"), filepath.Join(dir, "worlds.json")) != nil {
			t.Fatal("identical evidence replacement unavailable")
		}
		if pin.Confirm() != ErrChanged {
			t.Fatal("replacement revived the original held evidence inode")
		}
	}
	copy := *pin
	if pin.Close() != nil || copy.Confirm() != ErrUnsafe || copy.Close() != nil {
		t.Fatal("copied evidence owner outlived original release")
	}
}

func TestEvidencePinReleaseRaceAndClosedStore(t *testing.T) {
	store, _, _ := pinFixture(t)
	_, _, pin, err := store.PinEvidence("record", MaxEvidenceFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for range 8 {
			if err := pin.Confirm(); err != nil && err != ErrUnsafe {
				t.Error("unexpected evidence release race outcome", err)
			}
		}
	}()
	go func() { defer group.Done(); _ = pin.Close() }()
	group.Wait()
	if pin.Confirm() != ErrUnsafe {
		t.Fatal("released evidence owner supplied confirmation")
	}
	_, _, pin, err = store.PinEvidence("record", MaxEvidenceFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pin.Close() })
	if store.Close() != nil || pin.Confirm() != ErrUnsafe {
		t.Fatal("closed evidence store supplied confirmation")
	}
}
