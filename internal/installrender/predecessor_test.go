// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"slices"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
)

// Frozen caller-side comparison uses defensive manifests as before #100.
func predecessorManifestOracle(next, previous *Plan) bool {
	m := previous.Manifest()
	for _, candidate := range next.Manifest().Predecessors {
		if candidate.PackageSHA256 == previous.Digest() && candidate.SourceSHA == m.SourceSHA && candidate.Images == m.Images && candidate.Namespace == previous.Namespace() && slices.Contains(candidate.ProfileIDs, previous.Profile().ID) {
			return true
		}
	}
	return false
}

func TestDeclaresPredecessorMatchesManifestComparison(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	metadata, payloads := fixture(t, false)
	metadata.Predecessors = []installpackage.Predecessor{{ID: "old", PackageSHA256: previous.Digest(), SourceSHA: previous.Manifest().SourceSHA, Images: previous.Images(), Namespace: previous.Namespace(), ProfileIDs: []string{previous.Profile().ID}}}
	next, err := Compile(authenticated(t, metadata, payloads), DefaultNamespace, Profile137)
	if err != nil || !next.DeclaresPredecessor(previous) {
		t.Fatal("signed predecessor positive control unavailable")
	}
	for _, fault := range []string{"original", "digest", "source", "controller-image", "api-image", "namespace", "profile", "missing", "later-match"} {
		t.Run(fault, func(t *testing.T) {
			// Private mutations are pure comparison inputs, not trusted plans.
			trial := *next
			trial.manifest = next.Manifest()
			candidate := &trial.manifest.Predecessors[0]
			switch fault {
			case "digest":
				candidate.PackageSHA256 = "foreign"
			case "source":
				candidate.SourceSHA = "foreign"
			case "controller-image":
				candidate.Images.Controller = "foreign"
			case "api-image":
				candidate.Images.API = "foreign"
			case "namespace":
				candidate.Namespace = "foreign"
			case "profile":
				candidate.ProfileIDs = []string{Profile135}
			case "missing":
				trial.manifest.Predecessors = nil
			case "later-match":
				trial.manifest.Predecessors = append([]installpackage.Predecessor{{PackageSHA256: "foreign"}}, *candidate)
			}
			want := fault == "original" || fault == "later-match"
			if trial.DeclaresPredecessor(previous) != want || predecessorManifestOracle(&trial, previous) != want {
				t.Fatal("immutable comparison changed an exact predecessor constraint")
			}
		})
	}
	if previous.DeclaresPredecessor(next) || next.DeclaresPredecessor(next) || next.DeclaresPredecessor(nil) || (*Plan)(nil).DeclaresPredecessor(previous) {
		t.Fatal("reverse, self or absent predecessor accepted")
	}
	returned := next.Manifest()
	returned.Predecessors[0].ProfileIDs[0] = "foreign"
	returned.Predecessors[0].Images.Controller = "foreign"
	if !next.DeclaresPredecessor(previous) {
		t.Fatal("detached manifest changed the sealed comparison")
	}
	old := testing.AllocsPerRun(10, func() {
		if !predecessorManifestOracle(next, previous) {
			t.Fatal("manifest control refused")
		}
	})
	current := testing.AllocsPerRun(10, func() {
		if !next.DeclaresPredecessor(previous) {
			t.Fatal("immutable control refused")
		}
	})
	if current != 0 || old <= current {
		t.Fatal("immutable predecessor comparison allocated")
	}
	t.Logf("predecessor comparison allocations: JSON=%.0f immutable=%.0f", old, current)
}
