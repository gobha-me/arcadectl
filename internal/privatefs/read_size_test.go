// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package privatefs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type observedSizeReader func([]byte) (int, error)

func (read observedSizeReader) Read(body []byte) (int, error) { return read(body) }

func TestObservedSizeReadRequiresCompleteExactBytesAndEOF(t *testing.T) {
	for _, scenario := range []struct {
		name string
		size int64
		body string
	}{
		{"empty", 0, ""},
		{"small", 3, "abc"},
		{"exact-limit", 8, "abcdefgh"},
		{"growth-from-empty", 0, "a"},
		{"growth", 3, "abcd"},
		{"growth-over-limit", 8, "abcdefghi"},
		{"truncation", 4, "abc"},
		{"truncation-to-empty", 4, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			reader := bytes.NewBufferString(scenario.body)
			got, err := readObservedSize(reader, scenario.size, 8)
			if int64(len(scenario.body)) != scenario.size {
				if err != ErrUnsafe || got != nil {
					t.Fatal("changed file size returned data")
				}
			} else if err != nil || string(got) != scenario.body || cap(got) != len(got) {
				t.Fatal("exact complete fresh read failed")
			}
		})
	}
	for _, final := range []error{nil, io.EOF, io.ErrUnexpectedEOF, errors.Join(io.EOF), errors.New("injected read failure")} {
		for _, chunk := range []int{1, 3} {
			remaining := []byte("abc")
			reader := observedSizeReader(func(p []byte) (int, error) {
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
			got, err := readObservedSize(reader, 3, 8)
			if final == nil || final == io.EOF {
				if err != nil || string(got) != "abc" {
					t.Fatal("short or data-plus-EOF read failed")
				}
			} else if err != ErrUnsafe || got != nil {
				t.Fatal("partial-data error supplied complete bytes")
			}
		}
	}
	for _, prefix := range []string{"", "a", "abc"} {
		remaining := []byte(prefix)
		reader := observedSizeReader(func(p []byte) (int, error) {
			if len(remaining) != 0 {
				n := copy(p, remaining)
				remaining = remaining[n:]
				return n, nil
			}
			return 0, errors.New("injected late read failure")
		})
		if got, err := readObservedSize(reader, 3, 8); err != ErrUnsafe || got != nil {
			t.Fatal("error before the EOF probe supplied bytes")
		}
	}
}

func TestObservedSizeReadBoundsAndOwnedBuffers(t *testing.T) {
	for _, bounds := range [][2]int64{{-1, 8}, {0, 0}, {9, 8}, {0, MaxEvidenceFileBytes + 1}, {1 << 62, 1 << 62}} {
		called := false
		reader := observedSizeReader(func([]byte) (int, error) { called = true; return 0, io.EOF })
		if got, err := readObservedSize(reader, bounds[0], bounds[1]); err != ErrUnsafe || got != nil || called {
			t.Fatal("invalid bound allocated or read")
		}
	}
	source := []byte("original")
	first, err := readObservedSize(bytes.NewReader(source), int64(len(source)), MaxFileBytes)
	if err != nil {
		t.Fatal("first complete read failed")
	}
	second, err := readObservedSize(bytes.NewReader(source), int64(len(source)), MaxFileBytes)
	if err != nil {
		t.Fatal("second complete read failed")
	}
	first[0] ^= 1
	if string(source) != "original" || string(second) != "original" {
		t.Fatal("fresh returned bodies alias another read or input")
	}
}

func TestObservedSizeReadRealFileSizeChangesAndSparseBytes(t *testing.T) {
	for _, scenario := range []string{"empty", "regular", "sparse", "grown", "shrunk"} {
		t.Run(scenario, func(t *testing.T) {
			file, err := os.OpenFile(filepath.Join(privateTemp(t), "file"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal("private fixture file unavailable")
			}
			defer file.Close()
			expected := []byte{}
			if scenario == "sparse" {
				expected = make([]byte, 32768)
				expected[len(expected)-1] = 'x'
				if _, err := file.WriteAt([]byte{'x'}, int64(len(expected)-1)); err != nil {
					t.Fatal("sparse fixture failed")
				}
			} else if scenario != "empty" {
				expected = []byte("original")
				if _, err := file.Write(expected); err != nil {
					t.Fatal("fixture write failed")
				}
			}
			opening, err := file.Stat()
			if err != nil {
				t.Fatal("opening stat failed")
			}
			if scenario == "grown" || scenario == "shrunk" {
				size := opening.Size() + 1
				if scenario == "shrunk" {
					size = opening.Size() - 1
				}
				if file.Truncate(size) != nil {
					t.Fatal("size change injection failed")
				}
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatal("fixture rewind failed")
			}
			got, err := readObservedSize(file, opening.Size(), MaxFileBytes)
			if scenario == "grown" || scenario == "shrunk" {
				if got != nil || err != ErrUnsafe {
					t.Fatal("changed descriptor size accepted")
				}
			} else if err != nil || !bytes.Equal(got, expected) {
				t.Fatal("complete descriptor bytes differ")
			}
		})
	}
}
