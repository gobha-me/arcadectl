// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminclient

import (
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

func TestComponentVersionResponseRejectsUnboundedBuildClaims(t *testing.T) {
	base := adminv1.ComponentVersion{Version: "v1", SourceSHA: "unknown", GoVersion: "go1.26.10", OS: "linux", Arch: "amd64"}
	if !destinationMatches("ComponentVersion", &base) || validateResponse(&base) != nil {
		t.Fatal("bounded development version rejected")
	}
	known := base
	known.SourceSHA, known.SourceEpoch = strings.Repeat("a", 40), 1793300400
	if validateResponse(&known) != nil {
		t.Fatal("exact source build claim rejected")
	}
	for _, corrupt := range []func(*adminv1.ComponentVersion){
		func(v *adminv1.ComponentVersion) { v.SourceSHA = "SECRET-CANARY" },
		func(v *adminv1.ComponentVersion) { v.SourceEpoch = 1 },
		func(v *adminv1.ComponentVersion) { v.GoVersion = "SECRET-CANARY" },
		func(v *adminv1.ComponentVersion) { v.OS = "linux\nSECRET-CANARY" },
		func(v *adminv1.ComponentVersion) { v.Arch = strings.Repeat("a", 17) },
	} {
		value := base
		corrupt(&value)
		if validateResponse(&value) == nil {
			t.Fatal("unbounded component version crossed client validation")
		}
	}
	if decodeResponse([]byte(`{"version":"v1","sourceSha":"unknown","sourceEpoch":0,"goVersion":"go1.26.10","os":"linux","arch":"amd64","secret":"SECRET-CANARY"}`), &base) == nil {
		t.Fatal("unknown component data crossed strict decoding")
	}
}
