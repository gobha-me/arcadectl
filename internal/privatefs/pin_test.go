// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func pinFixture(t *testing.T) (*Store, string, []byte) {
	t.Helper()
	dir := privateTemp(t)
	store, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	body := []byte("original protected receipt")
	if _, err := store.CreateExclusive("record", body); err != nil {
		t.Fatal(err)
	}
	return store, dir, body
}

func TestFilePinOriginalDescriptorAndRepeatedReplacement(t *testing.T) {
	store, _, body := pinFixture(t)
	got, identity, pin, err := store.Pin("record", 128)
	if err != nil || pin == nil || !bytes.Equal(got, body) {
		t.Fatal("original opening pin unavailable")
	}
	t.Cleanup(func() { _ = pin.Close() })
	for range 3 {
		if err := pin.Confirm(); err != nil {
			t.Fatal("healthy repeated confirmation refused", err)
		}
	}
	got[0] ^= 1 // Caller bytes cannot change the sealed confirmation identity.
	if pin.Confirm() != nil {
		t.Fatal("caller-owned body changed the sealed witness")
	}
	current := identity
	for range 64 {
		next, err := store.AtomicWrite("record", body, &current)
		if err != nil {
			t.Fatal(err)
		}
		var held unix.Stat_t
		if unix.Fstat(int(pin.state.file.Fd()), &held) != nil || held.Nlink != 0 || uint64(held.Dev) != identity.device || held.Ino != identity.inode {
			t.Fatal("opening descriptor was substituted or released")
		}
		if next.device == identity.device && next.inode == identity.inode || pin.Confirm() != ErrChanged {
			t.Fatal("a replacement revived the held original inode")
		}
		current = next
	}
}

func TestFilePinReleaseAndStoreClose(t *testing.T) {
	store, _, _ := pinFixture(t)
	_, _, pin, err := store.Pin("record", 128)
	if err != nil {
		t.Fatal(err)
	}
	copy := *pin
	if store.Close() != nil || pin.Confirm() != ErrUnsafe || pin.Close() != nil || pin.Close() != nil || copy.Confirm() != ErrUnsafe || copy.Close() != nil {
		t.Fatal("closed store/released or copied witness supplied authority")
	}
	var empty FilePin
	if empty.Confirm() != ErrUnsafe || empty.Close() != nil || (*FilePin)(nil).Confirm() != ErrUnsafe || (*FilePin)(nil).Close() != nil {
		t.Fatal("zero witness was usable")
	}
}

func TestFilePinConfirmationAndReleaseRace(t *testing.T) {
	store, _, _ := pinFixture(t)
	for range 32 {
		_, _, pin, err := store.Pin("record", 128)
		if err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			for range 8 {
				if err := pin.Confirm(); err != nil && err != ErrUnsafe {
					t.Error("unexpected confirmation outcome", err)
				}
			}
		}()
		go func() { defer group.Done(); _ = pin.Close() }()
		group.Wait()
		if pin.Confirm() != ErrUnsafe {
			t.Fatal("released witness remained usable")
		}
	}
}

func TestFilePinRefusesUnsafeAndChangedFiles(t *testing.T) {
	for _, mode := range []string{"missing", "symlink", "hardlink", "wide", "fifo", "oversize", "content", "unlink"} {
		t.Run(mode, func(t *testing.T) {
			store, dir, body := pinFixture(t)
			_, _, pin, err := store.Pin("record", 128)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pin.Close() })
			path := filepath.Join(dir, "record")
			switch mode {
			case "missing", "symlink", "fifo", "unlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "symlink" {
					err = os.Symlink("absent", path)
				} else if mode == "fifo" {
					err = unix.Mkfifo(path, 0o600)
				} else if mode == "unlink" {
					err = os.WriteFile(path, body, 0o600)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(dir, "alias"))
			case "wide":
				err = os.Chmod(path, 0o644)
			case "oversize":
				err = os.WriteFile(path, bytes.Repeat([]byte("x"), 129), 0o600)
			case "content":
				err = os.WriteFile(path, []byte("modified receipt"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if pin.Confirm() == nil {
				t.Fatal("unsafe or changed file confirmed")
			}
			if mode != "content" && mode != "unlink" {
				_, _, rejected, err := store.Pin("record", 128)
				if err == nil || rejected != nil {
					_ = rejected.Close()
					t.Fatal("unsafe acquisition produced a witness")
				}
			}
		})
	}
}

func TestFilePinNoDescriptorLeak(t *testing.T) {
	store, _, _ := pinFixture(t)
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := count()
	for range 64 {
		for _, request := range []struct {
			name string
			max  int64
		}{{"record", 128}, {"record", 1}, {"absent", 128}, {"../record", 128}, {"record", 0}, {"record", MaxFileBytes + 1}} {
			_, _, pin, err := store.Pin(request.name, request.max)
			if request.name == "record" && request.max == 128 {
				if err != nil || pin == nil || pin.Confirm() != nil {
					t.Fatal("healthy repeated acquisition failed")
				}
			} else if err == nil || pin != nil {
				t.Fatal("invalid acquisition produced witness")
			}
			if pin.Close() != nil {
				t.Fatal("release failed")
			}
		}
	}
	if after := count(); after != before {
		t.Fatalf("descriptor leak: before=%d after=%d", before, after)
	}
}

func TestFilePinSyncWindowReplacement(t *testing.T) {
	for _, checkpoint := range []string{"file", "directory"} {
		t.Run(checkpoint, func(t *testing.T) { testFilePinSyncWindowReplacement(t, checkpoint) })
	}
}

func testFilePinSyncWindowReplacement(t *testing.T, checkpoint string) {
	store, dir, body := pinFixture(t)
	_, _, pin, err := store.Pin("record", 128)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	// The sync hook cannot reenter Store.mu. Inject an actual same-byte rename
	// through the task-owned directory and independent filesystem operations.
	replace := func() error {
		if err := os.WriteFile(filepath.Join(dir, "replacement"), body, 0o600); err != nil {
			return err
		}
		return os.Rename(filepath.Join(dir, "replacement"), filepath.Join(dir, "record"))
	}
	if checkpoint == "file" {
		store.syncFile = func(*os.File) error { return replace() }
	} else {
		store.syncDir = func(int) error { return replace() }
	}
	if !errors.Is(pin.Confirm(), ErrChanged) {
		t.Fatal("sync-window replacement accepted")
	}
}

func TestFilePinDurabilityFailureDoesNotReleaseWitness(t *testing.T) {
	store, _, _ := pinFixture(t)
	_, _, pin, err := store.Pin("record", 128)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	fileSync, dirSync := store.syncFile, store.syncDir
	store.syncFile = func(*os.File) error { return unix.EIO }
	if pin.Confirm() != ErrDurability {
		t.Fatal("file sync failure supplied durability")
	}
	store.syncFile = fileSync
	store.syncDir = func(int) error { return unix.EIO }
	if pin.Confirm() != ErrDurability {
		t.Fatal("directory sync failure supplied durability")
	}
	store.syncDir = dirSync
	if pin.Confirm() != nil {
		t.Fatal("failed confirmation consumed the original witness")
	}
	copy := *pin
	if copy.Close() != nil || pin.Confirm() != ErrUnsafe {
		t.Fatal("copied handle did not share release ownership")
	}
}

func TestFilePinConcurrentStoreClose(t *testing.T) {
	for range 16 {
		store, _, _ := pinFixture(t)
		_, _, pin, err := store.Pin("record", 128)
		if err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		group.Add(3)
		go func() {
			defer group.Done()
			if err := pin.Confirm(); err != nil && err != ErrUnsafe {
				t.Error("unexpected concurrent outcome", err)
			}
		}()
		go func() { defer group.Done(); _ = pin.Close() }()
		go func() { defer group.Done(); _ = store.Close() }()
		group.Wait()
		if pin.Confirm() != ErrUnsafe || pin.Close() != nil {
			t.Fatal("closed witness remained usable")
		}
	}
}

func TestAbsoluteFilePinClosesOriginalPath(t *testing.T) {
	store, dir, body := pinFixture(t)
	path := filepath.Join(dir, "record")
	_, _, pin, err := PinAbsolute(path, 128, TrustedPublic)
	if err != nil || pin.Confirm() != nil {
		t.Fatal("healthy trust input pin unavailable")
	}
	defer pin.Close()
	_, current, err := store.Read("record", 128)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		current, err = store.AtomicWrite("record", body, &current)
		if err != nil || pin.Confirm() != ErrChanged {
			t.Fatal("trust input replacement revived opening witness")
		}
	}
}

func TestAbsoluteFilePinRewalksReplacedAncestor(t *testing.T) {
	_, dir, body := pinFixture(t)
	parent := filepath.Join(dir, "trust")
	if os.Mkdir(parent, 0o700) != nil || os.WriteFile(filepath.Join(parent, "ca"), body, 0o600) != nil {
		t.Fatal("task-owned trust directory unavailable")
	}
	path := filepath.Join(parent, "ca")
	_, _, pin, err := PinAbsolute(path, 128, TrustedPublic)
	if err != nil || pin.Confirm() != nil {
		t.Fatal("original trust input unavailable")
	}
	defer pin.Close()
	if os.Rename(parent, filepath.Join(dir, "old-trust")) != nil || os.Mkdir(parent, 0o700) != nil || os.WriteFile(path, body, 0o600) != nil {
		t.Fatal("task-owned ancestor replacement failed")
	}
	if pin.Confirm() != ErrChanged {
		t.Fatal("old directory descriptor concealed a replaced absolute pathname")
	}
	_, _, fresh, err := PinAbsolute(path, 128, TrustedPublic)
	if err != nil || fresh.Confirm() != nil {
		t.Fatal("independently opened new trust input unavailable")
	}
	defer fresh.Close()
	if os.Chmod(parent, 0o777) != nil || fresh.Confirm() != ErrUnsafe {
		t.Fatal("unsafe absolute ancestor was accepted")
	}
}
