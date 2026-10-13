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
	"testing"
)

type digestFaultReader struct {
	body []byte
	err  error
	n    int
}

type digestCombinedErrorReader struct{}

func (digestCombinedErrorReader) Read(p []byte) (int, error) {
	return copy(p, "partial bytes"), io.ErrUnexpectedEOF
}

func (r *digestFaultReader) Read(p []byte) (int, error) {
	if len(r.body) == 0 {
		return 0, r.err
	}
	n := copy(p, r.body[:min(7, len(r.body))]) // Deliberate short physical reads.
	r.body = r.body[n:]
	r.n += n
	return n, nil
}

func TestStreamingDigestExactLimitsErrorsAndScratchErasure(t *testing.T) {
	for _, size := range []int{0, 1, 32767, 32768, 32769, int(MaxFileBytes), int(MaxFileBytes) + 1, int(MaxEvidenceFileBytes)} {
		body := bytes.Repeat([]byte{'x'}, size)
		for _, limit := range []int64{MaxFileBytes, MaxEvidenceFileBytes} {
			scratch := bytes.Repeat([]byte{'s'}, 32*1024)
			got, err := digestBounded(bytes.NewReader(body), limit, scratch)
			if int64(size) <= limit {
				if err != nil || got != sha256.Sum256(body) {
					t.Fatal("stream changed complete byte digest or inclusive bound")
				}
			} else if err != ErrUnsafe || got != [32]byte{} {
				t.Fatal("oversized read yielded usable identity")
			}
			if !bytes.Equal(scratch, make([]byte, len(scratch))) {
				t.Fatal("discarded physical bytes retained in idle scratch")
			}
		}
	}
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF, errors.New("PRIVATE-CANARY")} {
		r := &digestFaultReader{body: []byte("short reads are fresh reads"), err: terminal}
		scratch := make([]byte, 32)
		got, err := digestBounded(r, 64, scratch)
		if terminal == io.EOF {
			if err != nil || got != sha256.Sum256([]byte("short reads are fresh reads")) {
				t.Fatal("short reads changed complete digest")
			}
		} else if err != ErrUnsafe || got != [32]byte{} {
			t.Fatal("partial/error bytes became authority or leaked provider error")
		}
		if r.n != 27 || !bytes.Equal(scratch, make([]byte, len(scratch))) {
			t.Fatal("physical read or erasure changed")
		}
	}
	r := &digestFaultReader{body: bytes.Repeat([]byte{'x'}, 100), err: io.EOF}
	if _, err := digestBounded(r, 10, make([]byte, 4)); err != ErrUnsafe || r.n != 11 {
		t.Fatal("overflow probe consumed beyond max+one physical bytes")
	}
	for _, limit := range []int64{0, -1, MaxEvidenceFileBytes + 1} {
		if _, err := digestBounded(bytes.NewReader(nil), limit, make([]byte, 8)); err != ErrUnsafe {
			t.Fatal("invalid digest bound accepted")
		}
	}
	if _, err := digestBounded(nil, 1, make([]byte, 8)); err != ErrUnsafe {
		t.Fatal("nil reader accepted")
	}
	if _, err := digestBounded(bytes.NewReader(nil), 1, nil); err != ErrUnsafe {
		t.Fatal("empty scratch accepted")
	}
	scratch := bytes.Repeat([]byte{'s'}, 32)
	if got, err := digestBounded(digestCombinedErrorReader{}, 64, scratch); err != ErrUnsafe || got != [32]byte{} || !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("same-call partial bytes/error accepted or retained")
	}
}

func TestStreamingIdentityMatchesOriginalProtectedReadAndFreshRefusals(t *testing.T) {
	dir := privateTemp(t)
	s, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, size := range []int{0, 1, 32769, int(MaxFileBytes), int(MaxFileBytes) + 1, int(MaxEvidenceFileBytes)} {
		body := bytes.Repeat([]byte{'x'}, size)
		name := "record"
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int64{MaxFileBytes, MaxEvidenceFileBytes} {
			_, original, originalErr := readAtBounded(s.fd, name, limit, Private, limit)
			scratch := bytes.Repeat([]byte{'s'}, 32*1024)
			got, err := readIdentityAtBounded(s.fd, name, limit, scratch)
			if err != originalErr || got != original || !bytes.Equal(scratch, make([]byte, len(scratch))) {
				t.Fatal("identity-only fresh read differs from body-bearing read")
			}
		}
	}
	for _, name := range []string{"missing", ".", "..", "../record", "bad\x00name"} {
		_, _, originalErr := readAtBounded(s.fd, name, MaxFileBytes, Private, MaxFileBytes)
		if _, err := readIdentityAtBounded(s.fd, name, MaxFileBytes, make([]byte, 32)); err != originalErr {
			t.Fatal("identity-only name refusal differs from original")
		}
	}
	if os.Chmod(filepath.Join(dir, "record"), 0644) != nil {
		t.Fatal("unsafe fixture unavailable")
	}
	if _, err := readIdentityAtBounded(s.fd, "record", MaxEvidenceFileBytes, make([]byte, 32)); err != ErrUnsafe {
		t.Fatal("fresh unsafe protection accepted")
	}
}

func TestConfirmDurableStreamingScratchIsBoundedErasedAndNeverAuthority(t *testing.T) {
	dir := privateTemp(t)
	s, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	body := bytes.Repeat([]byte("PRIVATE-CANARY"), 10000)
	id, err := s.CreateExclusive("record", body)
	if err != nil || s.confirmScratch != nil {
		t.Fatal("confirmation scratch allocated before identity-only use")
	}
	if s.ConfirmDurable("record", id) != nil || len(s.confirmScratch) != 32*1024 || !bytes.Equal(s.confirmScratch, make([]byte, len(s.confirmScratch))) {
		t.Fatal("confirmation retained physical bytes or unbounded scratch")
	}
	// Different byte contents must still be physically observed with reused
	// scratch. No remembered digest or body can make an old identity current.
	changed := bytes.Repeat([]byte{'y'}, len(body))
	if os.WriteFile(filepath.Join(dir, "record"), changed, 0600) != nil {
		t.Fatal("physical drift fixture unavailable")
	}
	if s.ConfirmDurable("record", id) != ErrChanged || !bytes.Equal(s.confirmScratch, make([]byte, len(s.confirmScratch))) {
		t.Fatal("reused scratch became identity authority or retained refused bytes")
	}
}
