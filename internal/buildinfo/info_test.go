// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSourceClaimsAreBoundedAndFailClosed(t *testing.T) {
	oldSHA, oldEpoch := SourceSHA, SourceEpoch
	t.Cleanup(func() { SourceSHA, SourceEpoch = oldSHA, oldEpoch })
	for _, test := range []struct{ sha, epoch string }{
		{"unknown", "0"}, {"SECRET-CANARY", "1"},
		{strings.Repeat("A", 40), "1"}, {strings.Repeat("a", 40), "SECRET-CANARY"},
		{strings.Repeat("a", 40), "-1"}, {strings.Repeat("a", 40), "253402300800"},
	} {
		SourceSHA, SourceEpoch = test.sha, test.epoch
		got := Current()
		encoded, _ := json.Marshal(got)
		if got.SourceSHA != "unknown" || got.SourceEpoch != 0 || strings.Contains(string(encoded), "SECRET-CANARY") {
			t.Fatal("unbounded build claim escaped")
		}
	}
	SourceSHA, SourceEpoch = strings.Repeat("a", 40), "1793300400"
	if got := Current(); got.SourceSHA != SourceSHA || got.SourceEpoch != 1793300400 || got.GoVersion == "" || got.OS == "" || got.Arch == "" {
		t.Fatal("valid source/toolchain/platform identity lost")
	}
}
