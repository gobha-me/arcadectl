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
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestConfirmComparingFreshReaderOracle(t *testing.T) {
	for _, text := range []string{"", "abc", strings.Repeat("x", 65537)} {
		for _, expected := range []string{text, text + "x", "different"} {
			for _, max := range []int64{1, 3, 65537} {
				body := []byte(expected)
				op := confirmationOperand{body: body, digest: sha256.Sum256(body), bounded: true}
				scratch := bytes.Repeat([]byte{42}, 32768)
				want, wantErr := digestBounded(strings.NewReader(text), max, make([]byte, 32768))
				got, equal, err := compareConfirmationBounded(strings.NewReader(text), max, scratch, &op)
				if err != wantErr || err == nil && (equal != (text == expected) || equal && got != want) || !bytes.Equal(scratch, make([]byte, len(scratch))) {
					t.Fatal("fresh full-reader oracle or scratch erasure changed")
				}
			}
		}
	}
	for _, final := range []error{io.EOF, io.ErrUnexpectedEOF, errors.Join(io.EOF), errors.New("late refusal")} {
		for _, expected := range []string{"abc", "xbc", "short"} {
			reader := func() io.Reader {
				remaining := []byte("abc")
				return observedSizeReader(func(p []byte) (int, error) {
					if len(remaining) == 0 {
						return 0, final
					}
					n := copy(p, remaining[:min(1, len(remaining))])
					remaining = remaining[n:]
					return n, nil
				})
			}
			body := []byte(expected)
			op := confirmationOperand{body: body, digest: sha256.Sum256(body), bounded: true}
			want, wantErr := digestBounded(reader(), 8, make([]byte, 2))
			got, equal, err := compareConfirmationBounded(reader(), 8, make([]byte, 2), &op)
			if err != wantErr || err == nil && (equal != (expected == "abc") || equal && got != want) {
				t.Fatal("mismatch masked late error or skipped literal EOF")
			}
		}
	}
	for _, expected := range []string{"abc", "xbc", "short"} {
		remaining, calls, consumed := []byte("abc"), 0, 0
		reader := observedSizeReader(func(p []byte) (int, error) {
			calls++
			if len(remaining) == 0 {
				return 0, io.EOF
			}
			n := copy(p, remaining[:1])
			remaining = remaining[n:]
			consumed += n
			return n, nil
		})
		op := confirmationOperand{body: []byte(expected), digest: sha256.Sum256([]byte(expected)), bounded: true}
		_, _, err := compareConfirmationBounded(reader, 8, make([]byte, 2), &op)
		if err != nil || calls != 4 || consumed != 3 {
			t.Fatal("mismatch skipped fresh bytes or EOF probe")
		}
	}
}

func TestConfirmComparingOriginalRefusalOracle(t *testing.T) {
	for _, evidence := range []bool{false, true} {
		for _, scenario := range []string{"stable", "empty", "wrong-operand", "oversize-operand", "wrong-identity", "missing", "replacement", "content", "growth", "shrink", "mode", "link", "file-sync", "dir-sync", "file-sync-drift", "dir-sync-drift", "file-sync-replacement", "dir-sync-replacement", "dir-mode"} {
			t.Run(strings.Join([]string{map[bool]string{false: "ordinary", true: "evidence"}[evidence], scenario}, "/"), func(t *testing.T) {
				run := func(candidate bool) error {
					dir := filepath.Join(privateTemp(t), "private")
					s, err := Open(dir, true)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					body := []byte("private bytes")
					if scenario == "empty" {
						body = nil
					}
					id, err := s.CreateExclusive("record", body)
					if err != nil {
						t.Fatal(err)
					}
					expected := bytes.Clone(body)
					path := filepath.Join(dir, "record")
					change := func() error { return os.WriteFile(path, []byte("changed bytes"), 0600) }
					replace := func() error {
						if err := os.Rename(path, filepath.Join(dir, "old-record")); err != nil {
							return err
						}
						return os.WriteFile(path, body, 0600)
					}
					switch scenario {
					case "wrong-operand":
						expected = []byte("foreign bytes")
					case "oversize-operand":
						limit := MaxFileBytes
						if evidence {
							limit = MaxEvidenceFileBytes
						}
						expected = make([]byte, limit+1)
					case "wrong-identity":
						id = FileIdentity{}
					case "missing":
						err = os.Remove(path)
					case "replacement":
						err = replace()
					case "content":
						err = change()
					case "growth":
						err = os.WriteFile(path, append(bytes.Clone(body), 'x'), 0600)
					case "shrink":
						err = os.WriteFile(path, body[:len(body)-1], 0600)
					case "mode":
						err = os.Chmod(path, 0644)
					case "link":
						err = os.Link(path, filepath.Join(dir, "alias"))
					case "file-sync":
						s.syncFile = func(*os.File) error { return unix.EIO }
					case "dir-sync":
						s.syncDir = func(int) error { return unix.EIO }
					case "file-sync-drift":
						s.syncFile = func(*os.File) error { return change() }
					case "dir-sync-drift":
						s.syncDir = func(int) error { return change() }
					case "file-sync-replacement":
						s.syncFile = func(*os.File) error { return replace() }
					case "dir-sync-replacement":
						s.syncDir = func(int) error { return replace() }
					case "dir-mode":
						s.syncDir = func(fd int) error { return unix.Fchmod(fd, 0755) }
						defer unix.Fchmod(s.fd, 0700)
					}
					if err != nil {
						t.Fatal("fault setup refused")
					}
					// The independent baseline includes the unchanged initial match.
					match, confirm := s.MatchOriginal, s.ConfirmDurable
					limit := MaxFileBytes
					if evidence {
						match, confirm, limit = s.MatchEvidenceOriginal, s.ConfirmEvidenceDurable, MaxEvidenceFileBytes
					}
					if err := match("record", limit, expected, id); err != nil {
						return err
					}
					if candidate {
						if evidence {
							return s.ConfirmEvidenceDurableComparing("record", id, expected)
						}
						return s.ConfirmDurableComparing("record", id, expected)
					}
					return confirm("record", id)
				}
				want, got := run(false), run(true)
				if got != want || (scenario == "stable" || scenario == "empty") && got != nil || scenario != "stable" && scenario != "empty" && got == nil {
					t.Fatal("candidate changed match/confirmation refusal or accepted injected drift")
				}
			})
		}
	}
}

func TestConfirmComparingOwnedOperandAndExceptionalCleanup(t *testing.T) {
	for _, mode := range []string{"mutate-input", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			s, err := Open(filepath.Join(privateTemp(t), "private"), true)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			body := []byte("original bytes")
			id, err := s.CreateExclusive("record", body)
			if err != nil {
				t.Fatal(err)
			}
			original := s.syncFile
			hit, panicked := false, false
			s.syncFile = func(f *os.File) error {
				hit = true
				if mode == "panic" {
					panic("injected sync panic")
				}
				if mode == "goexit" {
					runtime.Goexit()
				}
				body[0] = '!'
				return original(f)
			}
			done := make(chan struct{})
			var result error
			go func() {
				defer close(done)
				defer func() { panicked = recover() != nil }()
				result = s.ConfirmDurableComparing("record", id, body)
			}()
			<-done
			if !hit || panicked != (mode == "panic") {
				t.Fatal("injected sync boundary was not exercised")
			}
			if !bytes.Equal(s.comparisonScratch, make([]byte, len(s.comparisonScratch))) {
				t.Fatal("exception retained comparison bytes")
			}
			if mode == "mutate-input" && result != nil {
				t.Fatal("sync callback altered owned comparison operand")
			}
			s.syncFile = original
			if s.ConfirmDurable("record", id) != nil || !bytes.Equal(s.confirmScratch, make([]byte, len(s.confirmScratch))) {
				t.Fatal("exception retained lock, dirty scratch or changed original")
			}
		})
	}
}

func TestConfirmComparingScratchBoundariesIsolationAndClose(t *testing.T) {
	open := func() *Store {
		s, err := Open(filepath.Join(privateTemp(t), "private"), true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	s, other := open(), open()
	for index, size := range []int{0, 32767, 32768, 32769, 2, 0, 32768, 1} {
		name := string(rune('a' + index))
		body := bytes.Repeat([]byte{byte(index + 1)}, size)
		id, err := s.CreateExclusive(name, body)
		if err != nil {
			t.Fatal(err)
		}
		if s.comparisonScratch != nil {
			for i := range s.comparisonScratch {
				s.comparisonScratch[i] = 42
			}
		}
		if s.ConfirmDurableComparing(name, id, body) != nil || !bytes.Equal(s.comparisonScratch, make([]byte, len(s.comparisonScratch))) {
			t.Fatal("threshold transition or poisoned workspace supplied authority or retained bytes")
		}
		if len(s.comparisonScratch) > 32768 || cap(s.comparisonScratch) > 32768 {
			t.Fatal("comparison capacity grew beyond fixed bound")
		}
		if len(s.comparisonScratch) > 0 && &s.comparisonScratch[0] == &s.confirmScratch[0] {
			t.Fatal("comparison aliases fresh-read scratch")
		}
	}
	body := []byte("isolation bytes")
	id, err := other.CreateExclusive("record", body)
	if err != nil || other.ConfirmDurableComparing("record", id, body) != nil {
		t.Fatal("second store fixture unavailable")
	}
	if &s.comparisonScratch[0] == &other.comparisonScratch[0] {
		t.Fatal("stores share comparison backing")
	}
	s.comparisonScratch[0] = 42
	if other.ConfirmDurableComparing("record", id, body) != nil || !bytes.Equal(other.comparisonScratch, make([]byte, len(other.comparisonScratch))) || s.comparisonScratch[0] != 42 {
		t.Fatal("another store accessed or retained comparison bytes")
	}
	retained := s.comparisonScratch
	if s.Close() != nil || s.comparisonScratch != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("close retained private comparison data or capacity")
	}
	// Already-closed cleanup must also scrub and release private capacity.
	s.comparisonScratch = bytes.Repeat([]byte{42}, 32768)
	retained = s.comparisonScratch
	if s.Close() != nil || s.comparisonScratch != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("already-closed cleanup retained comparison bytes")
	}
	// Close-error handling still releases the workspace before returning.
	broken := open()
	broken.comparisonScratch = bytes.Repeat([]byte{42}, 32768)
	retained = broken.comparisonScratch
	ownedFD := broken.fd
	defer unix.Close(ownedFD)
	broken.fd = 1 << 30 // Intentionally invalid; keep the real owned fd open.
	if broken.Close() != ErrUnsafe || broken.comparisonScratch != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("close-error path retained comparison data")
	}
}

func TestConfirmComparingScratchConcurrentSerializationAndClose(t *testing.T) {
	s, err := Open(filepath.Join(privateTemp(t), "private"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	body := []byte("serialized original")
	id, err := s.CreateExclusive("record", body)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		workers.Go(func() {
			for range 16 {
				if err := s.ConfirmDurableComparing("record", id, body); err != nil {
					failures <- err
					return
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	for range failures {
		t.Fatal("concurrent comparison corrupted a fresh observation")
	}
	entered, release, compared, closeStarted, closed := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{}), make(chan error, 1)
	original := s.syncFile
	s.syncFile = func(f *os.File) error { close(entered); <-release; return original(f) }
	go func() { compared <- s.ConfirmDurableComparing("record", id, body) }()
	select {
	case <-entered:
	case <-compared:
		t.Fatal("confirmation did not reach its sync boundary")
	}
	go func() { close(closeStarted); closed <- s.Close() }()
	<-closeStarted
	var closeErr error
	earlyClose := false
	select {
	case closeErr = <-closed:
		earlyClose = true
	default:
	}
	close(release)
	compareErr := <-compared
	if !earlyClose {
		closeErr = <-closed
	}
	if earlyClose || compareErr != nil || closeErr != nil || s.comparisonScratch != nil {
		t.Fatal("joined comparison/Close changed original evidence or retained capacity")
	}
	if s.ConfirmDurableComparing("record", id, body) != ErrUnsafe {
		t.Fatal("closed store accepted comparison")
	}
}

func TestConfirmComparingOperandBoundsAndFirstReadPrecedence(t *testing.T) {
	var absent *Store
	if absent.ConfirmDurableComparing("record", FileIdentity{}, nil) != ErrUnsafe || absent.ConfirmEvidenceDurableComparing("record", FileIdentity{}, nil) != ErrUnsafe {
		t.Fatal("nil store accepted")
	}
	for _, evidence := range []bool{false, true} {
		s, err := Open(filepath.Join(privateTemp(t), "private"), true)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		body := []byte("original bytes")
		id, err := s.CreateExclusive("record", body)
		if err != nil {
			t.Fatal(err)
		}
		confirm, limit := s.ConfirmDurableComparing, MaxFileBytes
		if evidence {
			confirm, limit = s.ConfirmEvidenceDurableComparing, MaxEvidenceFileBytes
		}
		for _, operand := range [][]byte{nil, []byte("foreign bytes"), make([]byte, limit+1)} {
			if confirm("missing", id, operand) != ErrNotFound || confirm("record", id, operand) != ErrChanged {
				t.Fatal("bad operand masked first path error or became accepted")
			}
			if unix.Fchmodat(s.fd, "record", 0644, 0) != nil {
				t.Fatal("mode injection failed")
			}
			if confirm("record", id, operand) != ErrUnsafe {
				t.Fatal("bad operand masked first protection error")
			}
			if unix.Fchmodat(s.fd, "record", 0600, 0) != nil {
				t.Fatal("mode restoration failed")
			}
		}
		if confirm("../record", id, body) != ErrUnsafe || s.confirmDurableComparingBounded("record", id, body, MaxFileBytes+1) != ErrUnsafe {
			t.Fatal("invalid path or open-ended limit accepted")
		}
		// Protection injection changed ctime; even original bytes cannot bind
		// the old identity after restoration.
		if confirm("record", id, body) != ErrChanged {
			t.Fatal("ctime drift accepted after restoring mode")
		}
	}
}
