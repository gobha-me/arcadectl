// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Synthetic encodings exercise byte comparison, not journal acceptance.
func TestSnapshotSameJournalBytesIsOnlyExactByteComparison(t *testing.T) {
	t.Run("caller-owned-bytes", func(t *testing.T) {
		var absent *Snapshot
		if absent.MatchesJournalBytes(nil) {
			t.Fatal("nil observation matched bytes")
		}
		for _, original := range [][]byte{nil, {}, []byte("sealed"), []byte(`{"revision":1}`)} {
			s := &Snapshot{body: bytes.Clone(original)}
			for _, input := range [][]byte{nil, {}, bytes.Clone(original), []byte("foreign"), append(bytes.Clone(original), ' ')} {
				if s.MatchesJournalBytes(input) != bytes.Equal(s.Bytes(), input) {
					t.Fatal("caller-owned comparison changed exact byte semantics")
				}
			}
			input := s.Bytes()
			if !s.MatchesJournalBytes(input) {
				t.Fatal("sealed bytes do not match defensive encoding")
			}
			if len(input) > 0 {
				input[0] ^= 1
				if s.MatchesJournalBytes(input) || !bytes.Equal(s.Bytes(), original) {
					t.Fatal("comparison retained mutable input or exposed sealed bytes")
				}
			}
		}
	})
	body := []byte(`{"revision":1,"stage":"applying"}`)
	s := &Snapshot{body: bytes.Clone(body), namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1"}}}
	var absent *Snapshot
	for _, test := range []struct {
		name        string
		left, right *Snapshot
		want        bool
	}{
		{"nil-both", absent, absent, false},
		{"nil-left", absent, s, false},
		{"nil-right", s, absent, false},
		{"self", s, s, true},
		{"independent", s, &Snapshot{body: bytes.Clone(body)}, true},
		{"changed-byte", s, &Snapshot{body: []byte(`{"revision":2,"stage":"applying"}`)}, false},
		{"shorter", s, &Snapshot{body: body[:len(body)-1]}, false},
		{"trailing-whitespace", s, &Snapshot{body: append(bytes.Clone(body), '\n')}, false},
		{"different-encoding", s, &Snapshot{body: []byte(`{"stage":"applying","revision":1}`)}, false},
		{"different-rv-not-compared", s, &Snapshot{body: bytes.Clone(body), namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "2"}}}, true},
		{"different-identity-not-compared", s, &Snapshot{body: bytes.Clone(body), store: &Store{}, document: Document{Namespace: "different", InstallationID: "different"}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.left.SameJournalBytes(test.right) != test.want {
				t.Fatal("journal-byte comparison changed exact-byte or nil semantics")
			}
		})
	}
}

func TestSnapshotSameJournalBytesKeepsDefensiveCopiesAndConcurrency(t *testing.T) {
	s := &Snapshot{body: []byte("sealed-journal")}
	other := &Snapshot{body: bytes.Clone(s.body)}
	for range 8 {
		t.Run("independent", func(t *testing.T) {
			t.Parallel()
			for range 100 {
				copy := s.Bytes()
				copy[0] ^= 1
				if !s.SameJournalBytes(other) || !other.SameJournalBytes(s) || !s.MatchesJournalBytes(other.Bytes()) || s.MatchesJournalBytes(copy) || string(s.Bytes()) != "sealed-journal" {
					t.Fatal("comparison exposed or changed immutable backing bytes")
				}
			}
		})
	}
}

var snapshotBytesComparisonResult bool

func TestSnapshotSameJournalBytesDoesNotAllocate(t *testing.T) {
	s := &Snapshot{body: bytes.Repeat([]byte("j"), 64*1024)}
	other := &Snapshot{body: bytes.Clone(s.body)}
	got := testing.AllocsPerRun(100, func() { snapshotBytesComparisonResult = s.SameJournalBytes(other) })
	// Assertion edit (#99, A2): preserve the candidate result before the
	// defensive-copy control overwrites the shared sink with its own result.
	candidateResult := snapshotBytesComparisonResult
	old := testing.AllocsPerRun(100, func() { snapshotBytesComparisonResult = bytes.Equal(s.Bytes(), other.Bytes()) })
	if err := checkSnapshotByteComparison(got, old, candidateResult); err != nil {
		t.Fatalf("byte comparison: %v", err)
	}
	input := bytes.Clone(s.body)
	got = testing.AllocsPerRun(100, func() { snapshotBytesComparisonResult = s.MatchesJournalBytes(input) })
	// Assertion edit (#99, A2): the caller-owned-byte candidate needs the same
	// protection against a successful control masking a false candidate result.
	candidateResult = snapshotBytesComparisonResult
	old = testing.AllocsPerRun(100, func() { snapshotBytesComparisonResult = bytes.Equal(s.Bytes(), input) })
	if err := checkSnapshotByteComparison(got, old, candidateResult); err != nil {
		t.Fatalf("owned-byte comparison: %v", err)
	}

	different := &Snapshot{body: bytes.Clone(s.body)}
	different.body[0] ^= 1
	for _, tc := range []struct {
		name    string
		compare func() bool
	}{
		{"same-journal-bytes", func() bool { return s.SameJournalBytes(different) }},
		{"matches-journal-bytes", func() bool { return s.MatchesJournalBytes(different.body) }},
	} {
		t.Run("rejects-false-"+tc.name, func(t *testing.T) {
			// Real unequal inputs yield the false, nonallocating result that
			// the old assertion would lose when the equal-byte control runs.
			got := testing.AllocsPerRun(100, func() { snapshotBytesComparisonResult = tc.compare() })
			candidateResult := snapshotBytesComparisonResult
			old := testing.AllocsPerRun(100, func() { snapshotBytesComparisonResult = bytes.Equal(s.Bytes(), other.Bytes()) })
			if got != 0 || old <= got || !snapshotBytesComparisonResult {
				t.Fatalf("expected nonallocating candidate and successful allocating control: new=%g control=%g result=%t", got, old, snapshotBytesComparisonResult)
			}
			if err := checkSnapshotByteComparison(got, old, candidateResult); err == nil {
				t.Fatal("comparison assertion accepted a false candidate masked by a true control")
			}
		})
	}
}

func checkSnapshotByteComparison(candidate, control float64, candidateResult bool) error {
	if candidate != 0 || control <= candidate || !candidateResult {
		return fmt.Errorf("allocations new=%g defensive-copy control=%g candidate result=%t", candidate, control, candidateResult)
	}
	return nil
}
