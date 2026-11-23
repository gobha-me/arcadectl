// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobha-me/arcadectl/internal/privatefs"
	"golang.org/x/sys/unix"
)

func TestRestoredProtectionWithinSameCTimeTickInvalidatesIdentity(t *testing.T) {
	t.Skip("bug #174: a restored protection change within one ctime tick retains the original identity")

	// This regression needs a real filesystem that can give both chmod calls
	// the same ctime as the opening observation. There is no portable way to
	// set ctime. Removing the bug skip on a finer-grained filesystem must fail
	// the fixture assertion below; that is not evidence of reproducing #174.
	// In particular, do not wait for a later tick or retry until this is green.
	for _, test := range []struct {
		name    string
		confirm func(*privatefs.Store, string, privatefs.FileIdentity, []byte) error
	}{
		{"ordinary", func(s *privatefs.Store, name string, id privatefs.FileIdentity, _ []byte) error {
			return s.ConfirmDurable(name, id)
		}},
		{"evidence", func(s *privatefs.Store, name string, id privatefs.FileIdentity, _ []byte) error {
			return s.ConfirmEvidenceDurable(name, id)
		}},
		{"ordinary-comparing", (*privatefs.Store).ConfirmDurableComparing},
		{"evidence-comparing", (*privatefs.Store).ConfirmEvidenceDurableComparing},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := privatefs.Open(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})

			const name = "record"
			body := []byte("unchanged private evidence")
			opening, err := store.CreateExclusive(name, body)
			if err != nil {
				t.Fatal(err)
			}
			observed, identity, err := store.Read(name, int64(len(body)))
			if err != nil || identity != opening || !bytes.Equal(observed, body) {
				t.Fatalf("opening observation = %q, %v; want unchanged bytes and identity", observed, err)
			}

			path := filepath.Join(dir, name)
			var before, exposed, after unix.Stat_t
			if err := unix.Stat(path, &before); err != nil {
				t.Fatal(err)
			}
			if before.Mode&0o777 != 0o600 {
				t.Fatalf("opening mode = %#o; want 0600", before.Mode&0o777)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := unix.Stat(path, &exposed); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unix.Stat(path, &after); err != nil {
				t.Fatal(err)
			}
			if exposed.Mode&0o777 != 0o644 || after.Mode&0o777 != 0o600 {
				t.Fatal("fixture did not expose and restore the file's protection")
			}
			if before.Ctim != exposed.Ctim || before.Ctim != after.Ctim {
				t.Fatalf("same-tick fixture unavailable: ctime changed from %+v to %+v to %+v", before.Ctim, exposed.Ctim, after.Ctim)
			}
			if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || after.Nlink != 1 {
				t.Fatal("fixture replaced, resized or linked the original file")
			}
			fresh, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(fresh, body) {
				t.Fatalf("restored file bytes = %q, %v; want original bytes", fresh, err)
			}

			if err := test.confirm(store, name, opening, body); !errors.Is(err, privatefs.ErrChanged) {
				t.Fatalf("bug #174: restored same-tick protection change accepted: error = %v; want ErrChanged", err)
			}
		})
	}
}
