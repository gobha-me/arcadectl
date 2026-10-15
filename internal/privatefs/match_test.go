// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMatchObservedSizeIndependentBodyReadOracle(t *testing.T) {
	for _, tc := range []struct {
		size int64
		body string
	}{
		{0, ""}, {3, "abc"}, {8, "abcdefgh"}, {0, "a"}, {3, "abcd"}, {4, "abc"}, {4, ""},
	} {
		for _, expected := range []string{tc.body, "different", tc.body + "x"} {
			for _, chunk := range []int{1, 2, 4, 32 * 1024} {
				original, originalErr := readObservedSize(strings.NewReader(tc.body), tc.size, 8)
				scratch := bytes.Repeat([]byte{42}, chunk)
				digest, equal, err := matchObservedSize(strings.NewReader(tc.body), tc.size, 8, []byte(expected), scratch)
				if err != originalErr || err == nil && (equal != bytes.Equal(original, []byte(expected)) || digest != sha256.Sum256(original)) || err != nil && (equal || digest != ([32]byte{})) || !bytes.Equal(scratch, make([]byte, chunk)) {
					t.Fatal("stream comparison differs from independent owned-body reader or retained scratch bytes")
				}
			}
		}
	}
	for _, final := range []error{nil, io.EOF, io.ErrUnexpectedEOF, errors.Join(io.EOF), errors.New("injected read refusal")} {
		for _, chunk := range []int{1, 3} {
			reader := func() io.Reader {
				remaining := []byte("abc")
				return observedSizeReader(func(p []byte) (int, error) {
					if len(remaining) == 0 {
						if final != nil {
							return 0, final
						}
						return 0, io.EOF
					}
					n := copy(p, remaining[:min(chunk, len(remaining))])
					remaining = remaining[n:]
					if len(remaining) == 0 {
						return n, final
					}
					return n, nil
				})
			}
			original, originalErr := readObservedSize(reader(), 3, 8)
			scratch := bytes.Repeat([]byte{42}, 4)
			digest, equal, err := matchObservedSize(reader(), 3, 8, []byte("abc"), scratch)
			if err != originalErr || err == nil && (!equal || digest != sha256.Sum256(original)) || err != nil && (equal || digest != ([32]byte{})) || !bytes.Equal(scratch, make([]byte, 4)) {
				t.Fatal("fragmented, final or late read error changed literal-EOF semantics")
			}
		}
	}
}

func TestMatchObservedSizeSeparateEOFProbeErrorsCannotBeHiddenByMismatch(t *testing.T) {
	for _, final := range []error{io.EOF, io.ErrUnexpectedEOF, errors.Join(io.EOF), errors.New("late read refusal")} {
		for _, expected := range []string{"abc", "xbc", "short"} {
			reader := func() io.Reader {
				remaining := []byte("abc")
				return observedSizeReader(func(p []byte) (int, error) {
					if len(remaining) == 0 {
						return 0, final
					}
					n := copy(p, remaining)
					remaining = remaining[n:]
					return n, nil // the error arrives only on the later EOF probe
				})
			}
			original, originalErr := readObservedSize(reader(), 3, 8)
			scratch := bytes.Repeat([]byte{42}, 2)
			digest, equal, err := matchObservedSize(reader(), 3, 8, []byte(expected), scratch)
			if err != originalErr || err == nil && (equal != bytes.Equal(original, []byte(expected)) || digest != sha256.Sum256(original)) || err != nil && (equal || digest != ([32]byte{})) || !bytes.Equal(scratch, []byte{0, 0}) {
				t.Fatal("late EOF-probe failure supplied a match or escaped scrubbing")
			}
		}
	}
}

func TestMatchObservedSizeBoundsBeforeReadsAndMismatchConsumesFreshBytes(t *testing.T) {
	for _, tc := range []struct {
		size, max int64
		scratch   int
	}{
		{-1, 8, 4}, {0, 0, 4}, {0, -1, 4}, {9, 8, 4}, {0, MaxFileBytes + 1, 4}, {0, 8, 0}, {0, 8, 32*1024 + 1},
	} {
		scratch := bytes.Repeat([]byte{42}, tc.scratch)
		_, _, err := matchObservedSize(observedSizeReader(func([]byte) (int, error) {
			t.Fatal("invalid bounds reached reader")
			return 0, nil
		}), tc.size, tc.max, nil, scratch)
		if err != ErrUnsafe || !bytes.Equal(scratch, make([]byte, tc.scratch)) {
			t.Fatal("invalid bounds accepted or left scratch")
		}
	}
	for _, expected := range []string{"xbcdef", "short", "abcdef-long"} {
		remaining, reads, consumed := []byte("abcdef"), 0, 0
		_, equal, err := matchObservedSize(observedSizeReader(func(p []byte) (int, error) {
			reads++
			if len(remaining) == 0 {
				return 0, io.EOF
			}
			n := copy(p, remaining)
			remaining = remaining[n:]
			consumed += n
			return n, nil
		}), 6, 8, []byte(expected), make([]byte, 2))
		if err != nil || equal || consumed != 6 || reads != 4 {
			t.Fatal("mismatch bypassed complete fresh read and EOF probe")
		}
	}
	for _, invalidCount := range []int{-1, 2} {
		if _, equal, err := matchObservedSize(observedSizeReader(func([]byte) (int, error) { return invalidCount, nil }), 0, 8, nil, make([]byte, 1)); err != ErrUnsafe || equal {
			t.Fatal("invalid reader count accepted")
		}
	}
}

func TestMatchOriginalPreservesPrivateReadIdentityAndBodyOracle(t *testing.T) {
	for _, fault := range []string{"healthy", "empty", "wal-limit", "file-limit", "different-expected", "wrong-identity", "growth", "shrink", "same-size-change", "replacement", "mode", "symlink", "hardlink", "fifo", "directory", "missing", "name", "bound", "closed"} {
		t.Run(fault, func(t *testing.T) {
			base := privateTemp(t)
			store, err := Open(base, false)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			body := []byte("original")
			if fault == "empty" {
				body = nil
			} else if fault == "wal-limit" {
				body = bytes.Repeat([]byte{42}, 81920)
			} else if fault == "file-limit" {
				body = bytes.Repeat([]byte{42}, int(MaxFileBytes))
			}
			identity, err := store.CreateExclusive("record", body)
			if err != nil {
				t.Fatal(err)
			}
			pinned, _, pin, err := store.Pin("record", MaxFileBytes)
			if err != nil {
				t.Fatal(err)
			}
			defer pin.Close()
			name, max, expected := "record", MaxFileBytes, bytes.Clone(body)
			path := filepath.Join(base, name)
			switch fault {
			case "different-expected":
				expected[0] = 'x'
			case "wrong-identity":
				identity = FileIdentity{}
			case "growth", "shrink", "same-size-change":
				replacement := []byte("changed!")
				if fault == "growth" {
					replacement = append(bytes.Clone(body), 'x')
				} else if fault == "shrink" {
					replacement = body[:len(body)-1]
				}
				if os.WriteFile(path, replacement, 0600) != nil {
					t.Fatal("injected write")
				}
			case "replacement":
				if _, err := store.AtomicWrite(name, body, &identity); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("injected mode")
				}
			case "symlink", "fifo", "directory", "missing":
				if os.Rename(path, filepath.Join(base, "original")) != nil {
					t.Fatal("injected rename")
				}
				if fault == "symlink" {
					err = os.Symlink("original", path)
				} else if fault == "fifo" {
					err = unix.Mkfifo(path, 0600)
				} else if fault == "directory" {
					err = os.Mkdir(path, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if os.Link(path, filepath.Join(base, "alias")) != nil {
					t.Fatal("injected hardlink")
				}
			case "name":
				name = "../record"
			case "bound":
				max = 2
			case "closed":
				if store.Close() != nil {
					t.Fatal("injected close")
				}
			}
			fresh, observed, oracle := store.Read(name, max)
			if oracle == nil && (observed != identity || !bytes.Equal(fresh, expected)) {
				oracle = ErrChanged
			}
			if got := store.MatchOriginal(name, max, expected, identity); got != oracle {
				t.Fatal("check-only result differs from independent protected body read")
			}
			if !bytes.Equal(pinned, body) || len(store.confirmScratch) > 32*1024 || !bytes.Equal(store.confirmScratch, make([]byte, len(store.confirmScratch))) {
				t.Fatal("scratch retained bytes or changed original descriptor body")
			}
		})
	}
}

func TestMatchOriginalDoesNotReplaceDurabilityAndSerializesScratch(t *testing.T) {
	store, err := Open(privateTemp(t), false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body := bytes.Repeat([]byte{42}, 81920)
	identity, err := store.CreateExclusive("record", body)
	if err != nil {
		t.Fatal(err)
	}
	originalSync, syncs := store.syncFile, 0
	store.syncFile = func(*os.File) error { syncs++; return errors.New("injected durability refusal") }
	if store.MatchOriginal("record", MaxFileBytes, body, identity) != nil || syncs != 0 || store.ConfirmDurable("record", identity) != ErrDurability || syncs != 1 {
		t.Fatal("matching bytes substituted for required durability confirmation")
	}
	store.syncFile = originalSync
	var joined sync.WaitGroup
	for range 4 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for range 8 {
				if store.MatchOriginal("record", MaxFileBytes, body, identity) != nil || store.ConfirmDurable("record", identity) != nil {
					t.Error("serialized scratch reused stale bytes or lost original evidence")
				}
			}
		}()
	}
	joined.Wait()
}
