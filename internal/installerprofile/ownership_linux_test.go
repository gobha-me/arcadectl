// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestInheritedAttemptCannotReAdoptOwnedDescriptors(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var attempt atomic.Bool
		var begins, adopted atomic.Int32
		first := &Session{}
		begin := func() *Session {
			begins.Add(1) // Represents recognition/start/flags/owned cleanup path.
			if enabled {
				return first
			}
			return nil
		}
		var callers sync.WaitGroup
		for range 32 {
			callers.Go(func() {
				if got := startInheritedOnce(&attempt, begin); got != nil {
					if got != first {
						t.Error("ownership guard returned an unrelated session")
					}
					adopted.Add(1)
				}
			})
		}
		callers.Wait()
		if startInheritedOnce(&attempt, begin) != nil || begins.Load() != 1 || adopted.Load() != map[bool]int32{false: 0, true: 1}[enabled] {
			t.Fatal("repeat/concurrent start reached recognition or re-adopted descriptors")
		}
	}
}
