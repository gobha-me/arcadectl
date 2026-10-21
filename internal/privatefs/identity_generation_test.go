// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIdentitySeparatesRecycledInodeGenerationButIgnoresReadAtime(t *testing.T) {
	stat := unix.Stat_t{Dev: 7, Ino: 11, Ctim: unix.Timespec{Sec: 100, Nsec: 1}, Atim: unix.Timespec{Sec: 99}}
	body := []byte("identical protected evidence")
	opening := fileIdentity(stat, body)
	recycled := stat
	recycled.Ctim.Nsec++
	if fileIdentity(recycled, body) == opening {
		t.Fatal("same device/inode/content in a new observed generation reused original identity")
	}
	readAgain := stat
	readAgain.Atim = unix.Timespec{Sec: 101, Nsec: 99}
	if fileIdentity(readAgain, body) != opening {
		t.Fatal("read access time invalidated unchanged original evidence")
	}
	if fileIdentity(stat, []byte("different evidence")) == opening {
		t.Fatal("unchanged metadata concealed different evidence bytes")
	}
}

func TestRepeatedIdenticalAtomicReplacementNeverRevivesOpeningObservation(t *testing.T) {
	store, err := Open(privateTemp(t), false)
	if err != nil {
		t.Fatal("private replacement fixture unavailable")
	}
	t.Cleanup(func() { _ = store.Close() })
	body := []byte("identical protected receipt")
	opening, err := store.CreateExclusive("record", body)
	if err != nil || store.ConfirmDurable("record", opening) != nil {
		t.Fatal("original durable publication unavailable")
	}
	current := opening
	for range 64 {
		next, err := store.AtomicWrite("record", body, &current)
		if err != nil || next == current || next == opening {
			t.Fatal("replacement revived an earlier protected-file observation")
		}
		observed, fresh, err := store.Read("record", 128)
		if err != nil || !bytes.Equal(observed, body) || fresh != next || store.ConfirmDurable("record", fresh) != nil {
			t.Fatal("new generation's exact durable observation was not usable")
		}
		if store.ConfirmDurable("record", opening) != ErrChanged {
			t.Fatal("stale opening observation survived successive identical replacements")
		}
		if _, err := store.AtomicWrite("record", body, &opening); err != ErrChanged {
			t.Fatal("stale opening generation authorized a replacement CAS")
		}
		current = fresh
	}
}
