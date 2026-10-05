// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package receiptid

import (
	"strings"
	"testing"
)

func TestVersionOneFixedVector(t *testing.T) {
	digest, err := KeyDigest("games", "admin", "retry-key")
	if err != nil || digest != "sha256:c03b29d5c8e77b02a813c9bdd1ccb7ca0866f2d9fb24abf28a37ea253695042c" {
		t.Fatal("receipt digest contract changed")
	}
	name, err := ReceiptName("games", "admin", "retry-key")
	fromDigest, e := NameForKeyDigest(digest)
	if err != nil || e != nil || name != fromDigest || len(name) != 55 || !strings.HasPrefix(name, "ao-") {
		t.Fatal("receipt name contract changed")
	}
	for _, input := range [][3]string{{"other", "admin", "retry-key"}, {"games", "other", "retry-key"}, {"games", "admin", "other"}} {
		got, err := ReceiptName(input[0], input[1], input[2])
		if err != nil || got == name {
			t.Fatal("receipt scope collision")
		}
	}
}

func TestRejectInvalidIdentity(t *testing.T) {
	for _, input := range [][3]string{{"Games", "admin", "key"}, {"games.example", "admin", "key"}, {strings.Repeat("a", 64), "admin", "key"}, {"games", "", "key"}, {"games", "admin", ""}, {"games", "admin", "key\ncanary"}, {"games", "admin", strings.Repeat("a", 129)}} {
		if _, err := KeyDigest(input[0], input[1], input[2]); err != ErrInvalid {
			t.Fatal("unsafe identity accepted")
		}
	}
}
