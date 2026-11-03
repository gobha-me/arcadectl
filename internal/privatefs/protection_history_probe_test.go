// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build privatefs_history_probe

package privatefs

import "testing"

// This opt-in counterexample deliberately fails the stronger protection-history
// contract on affected hosts. It must not be reported as a passing security fix.
func TestSameTickProtectionHistoryStrongerContractProbe(t *testing.T) {
	s, id, body := sameTickProtectionHistory(t)
	if err := s.ConfirmDurable("record", id); err != ErrChanged {
		t.Errorf("stronger contract missing: ConfirmDurable returned %v, want ErrChanged after a restored same-tick protection change", err)
	}
	if err := s.ConfirmDurableComparing("record", id, body); err != ErrChanged {
		t.Errorf("stronger contract missing: ConfirmDurableComparing returned %v, want ErrChanged after a restored same-tick protection change", err)
	}
}
