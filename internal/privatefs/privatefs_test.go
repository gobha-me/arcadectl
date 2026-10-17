// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package privatefs

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func privateTemp(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0o700) != nil {
		t.Fatal("private fixture directory")
	}
	return directory
}

func TestExclusiveCASAndExactRemoval(t *testing.T) {
	base := privateTemp(t)
	store, e := Open(base, false)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	id, e := store.CreateExclusive("record.json", []byte("original"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := store.CreateExclusive("record.json", []byte("overwrite")); !errors.Is(e, ErrExists) {
		t.Fatal("exclusive create overwrote")
	}
	contents, readID, e := store.Read("record.json", 64)
	if e != nil || string(contents) != "original" || readID != id {
		t.Fatal("private read identity failed")
	}
	replacement, e := store.AtomicWrite("record.json", []byte("replacement"), &id)
	if e != nil || replacement == id {
		t.Fatal("atomic replacement failed")
	}
	if e := store.Remove("record.json", id); !errors.Is(e, ErrChanged) {
		t.Fatal("stale identity deleted replacement")
	}
	if e := store.Remove("record.json", replacement); e != nil {
		t.Fatal(e)
	}
	if _, _, e := store.Read("record.json", 64); !errors.Is(e, ErrNotFound) {
		t.Fatal("absence not reported")
	}
}
func TestRefusesSymlinksHardlinksFIFOModesAndTraversal(t *testing.T) {
	base := privateTemp(t)
	store, e := Open(base, false)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if _, e := store.CreateExclusive("safe", []byte("CANARY")); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"../outside", "/absolute", ".", "..", "slash/name", strings.Repeat("x", 129)} {
		if _, _, e := store.Read(name, 32); e == nil {
			t.Fatal("unsafe name accepted")
		}
	}
	if e := os.Symlink(filepath.Join(base, "safe"), filepath.Join(base, "link")); e != nil {
		t.Fatal(e)
	}
	if _, _, e := store.Read("link", 32); !errors.Is(e, ErrUnsafe) {
		t.Fatal("symlink read")
	}
	if e := os.Link(filepath.Join(base, "safe"), filepath.Join(base, "hard")); e != nil {
		t.Fatal(e)
	}
	if _, _, e := store.Read("safe", 32); !errors.Is(e, ErrUnsafe) {
		t.Fatal("hardlinked private file accepted")
	}
	if e := unix.Mkfifo(filepath.Join(base, "fifo"), 0o600); e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	if _, _, e := store.Read("fifo", 32); !errors.Is(e, ErrUnsafe) || time.Since(started) > time.Second {
		t.Fatal("FIFO read did not fail promptly")
	}
	file := filepath.Join(base, "wide")
	if e := os.WriteFile(file, []byte("CANARY"), 0o644); e != nil {
		t.Fatal(e)
	}
	// Establish the deliberate unsafe fixture independent of the process
	// umask; a private validation runner may correctly start with umask 077.
	if e := os.Chmod(file, 0o644); e != nil {
		t.Fatal(e)
	}
	if _, _, e := store.Read("wide", 32); !errors.Is(e, ErrUnsafe) {
		t.Fatal("world-readable file accepted")
	}
	if _, _, e := ReadAbsolute(file, 32, TrustedPublic); e != nil {
		t.Fatal("trusted nonsecret CA mode refused")
	}
	if e := os.Chmod(file, 0o666); e != nil {
		t.Fatal(e)
	}
	if _, _, e := ReadAbsolute(file, 32, TrustedPublic); e == nil {
		t.Fatal("writable public trust accepted")
	}
	linkParent := filepath.Join(privateTemp(t), "ancestor")
	if e := os.Symlink(base, linkParent); e != nil {
		t.Fatal(e)
	}
	if _, _, e := ReadAbsolute(filepath.Join(linkParent, "wide"), 32, TrustedPublic); e == nil {
		t.Fatal("ancestor symlink accepted")
	}
	if e := os.Chmod(base, 0o755); e != nil {
		t.Fatal(e)
	}
	if _, _, e := store.Read("wide", 32); e == nil {
		t.Fatal("private base permissions drift accepted")
	}
}
func TestDescriptorAnchoringAndOwnerValidation(t *testing.T) {
	parent := privateTemp(t)
	base := filepath.Join(parent, "private")
	if os.Mkdir(base, 0o700) != nil {
		t.Fatal("mkdir")
	}
	store, e := Open(base, false)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	retained := filepath.Join(parent, "original")
	if os.Rename(base, retained) != nil || os.Mkdir(base, 0o700) != nil {
		t.Fatal("replacement setup")
	}
	if _, e := store.CreateExclusive("record", []byte("anchor")); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(base, "record")); !os.IsNotExist(e) {
		t.Fatal("directory replacement redirected write")
	}
	if _, e := os.Stat(filepath.Join(retained, "record")); e != nil {
		t.Fatal("original anchor not used")
	}
	st := unix.Stat_t{Uid: uint32(os.Geteuid() + 1), Mode: unix.S_IFREG | 0o600, Nlink: 1}
	if privateStat(&st) {
		t.Fatal("wrong owner accepted")
	}
}
func TestLockCancellationAndConcurrentExclusiveWinners(t *testing.T) {
	base := privateTemp(t)
	first, e := Open(base, false)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := Open(base, false)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	lock, e := first.Lock(context.Background(), "record")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if held, e := second.Lock(ctx, "record"); e == nil {
		held.Close()
		t.Fatal("parallel lock admitted")
	}
	if lock.Close() != nil {
		t.Fatal("unlock")
	}
	held, e := second.Lock(context.Background(), "record")
	if e != nil {
		t.Fatal(e)
	}
	held.Close()
	var group sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			s := first
			if i%2 == 1 {
				s = second
			}
			_, e := s.CreateExclusive("winner", []byte("single"))
			if e == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(e, ErrExists) {
				t.Error("unexpected create error")
			}
		}(i)
	}
	group.Wait()
	if wins != 1 {
		t.Fatal("exclusive create did not produce one winner")
	}
}
func TestDurabilityFailuresPreserveHonestState(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "file-sync", true: "directory-sync"}[afterRename], func(t *testing.T) {
			s, e := Open(privateTemp(t), false)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if afterRename {
				s.syncDir = func(int) error { return unix.EIO }
			} else {
				s.syncFile = func(*os.File) error { return unix.EIO }
			}
			_, e = s.CreateExclusive("record", []byte("published"))
			if afterRename {
				if !errors.Is(e, ErrDurability) {
					t.Fatal("ambiguous durability reported as rollback")
				}
				b, _, e := s.Read("record", 32)
				if e != nil || string(b) != "published" {
					t.Fatal("published file lost")
				}
			} else {
				if !errors.Is(e, ErrUnsafe) {
					t.Fatal("sync failure lost")
				}
				if _, _, e := s.Read("record", 32); !errors.Is(e, ErrNotFound) {
					t.Fatal("pre-rename failure published file")
				}
			}
		})
	}
}

func TestConfirmDurablePinsIdentityAndRechecksAfterSync(t *testing.T) {
	for _, scenario := range []string{"success", "uncertain-publication", "file-sync", "directory-sync", "replacement", "replacement-during-sync", "content-drift", "content-drift-during-sync", "directory-mode-during-sync"} {
		t.Run(scenario, func(t *testing.T) {
			s, err := Open(privateTemp(t), false)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if scenario == "uncertain-publication" {
				s.syncDir = func(int) error { return unix.EIO }
			}
			id, err := s.CreateExclusive("record", []byte("private bytes"))
			if scenario == "uncertain-publication" {
				if !errors.Is(err, ErrDurability) {
					t.Fatal("fixture publication was not uncertain")
				}
				_, id, err = s.Read("record", 64)
				if err != nil {
					t.Fatal(err)
				}
				s.syncDir = unix.Fsync
			} else if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "file-sync":
				s.syncFile = func(*os.File) error { return unix.EIO }
			case "directory-sync":
				s.syncDir = func(int) error { return unix.EIO }
			case "replacement":
				if _, err := s.AtomicWrite("record", []byte("same name new inode"), &id); err != nil {
					t.Fatal(err)
				}
			case "content-drift", "content-drift-during-sync":
				change := func(fd int) error {
					fileFD, err := unix.Openat(fd, "record", unix.O_WRONLY|unix.O_NOFOLLOW, 0)
					if err != nil {
						return err
					}
					defer unix.Close(fileFD)
					_, err = unix.Pwrite(fileFD, []byte("foreign bytes"), 0)
					return err
				}
				if scenario == "content-drift" {
					if err := change(s.fd); err != nil {
						t.Fatal(err)
					}
				} else {
					s.syncDir = change
				}
			case "directory-mode-during-sync":
				s.syncDir = func(fd int) error { return unix.Fchmod(fd, 0755) }
				defer unix.Fchmod(s.fd, 0700)
			case "replacement-during-sync":
				s.syncDir = func(fd int) error {
					err := unix.Renameat(fd, "record", fd, "foreign-replacement")
					if err != nil {
						return err
					}
					fileFD, err := unix.Openat(fd, "record", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
					if err != nil {
						return err
					}
					defer unix.Close(fileFD)
					_, err = unix.Write(fileFD, []byte("private bytes"))
					return err
				}
			}
			err = s.ConfirmDurable("record", id)
			switch scenario {
			case "success", "uncertain-publication":
				if err != nil {
					t.Fatal(err)
				}
				_, after, readErr := s.Read("record", 64)
				if readErr != nil || after != id {
					t.Fatal("confirmation rewrote original inode")
				}
			case "file-sync", "directory-sync":
				if !errors.Is(err, ErrDurability) {
					t.Fatal("sync failure accepted")
				}
			case "directory-mode-during-sync":
				if !errors.Is(err, ErrUnsafe) {
					t.Fatal("changed directory protection accepted")
				}
			default:
				if !errors.Is(err, ErrChanged) {
					t.Fatal("replaced identity accepted")
				}
			}
		})
	}
}
