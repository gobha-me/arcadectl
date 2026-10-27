// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
)

func independentPredecessorImages(digit string) installpackage.Images {
	return installpackage.Images{
		Controller: "registry.example/controller@sha256:" + strings.Repeat(digit, 64),
		API:        "registry.example/api@sha256:" + strings.Repeat(digit, 64),
	}
}

func independentCompileSignedPredecessorPlan(t *testing.T, predecessors []installpackage.Predecessor) (*Plan, error) {
	t.Helper()
	metadata, payloads := fixture(t, false)
	metadata.Predecessors = predecessors
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	body, err := installpackage.Build(metadata, payloads)
	if err != nil {
		return nil, err
	}
	signature, err := installpackage.Sign(body, key)
	if err != nil {
		return nil, err
	}
	pkg, err := installpackage.Verify(body, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return Compile(pkg, DefaultNamespace, Profile137)
}

func independentGenuinePredecessor(previous *Plan) installpackage.Predecessor {
	return installpackage.Predecessor{
		ID:            "independent-prev",
		PackageSHA256: previous.Digest(),
		SourceSHA:     previous.Manifest().SourceSHA,
		Images:        previous.Images(),
		Namespace:     previous.Namespace(),
		ProfileIDs:    []string{previous.Profile().ID},
	}
}

func TestIndependentDeclaresPredecessorNilAndEmptyMetadata(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	current := mustCompile(t, false, DefaultNamespace, Profile137)

	if (*Plan)(nil).DeclaresPredecessor(previous) {
		t.Fatal("nil plan declared a predecessor")
	}
	if current.DeclaresPredecessor(nil) {
		t.Fatal("plan declared a nil predecessor")
	}
	if (*Plan)(nil).DeclaresPredecessor(nil) {
		t.Fatal("nil plan declared a nil predecessor")
	}

	// Even a synthetic plan carrying a zero-value Predecessor entry must never
	// match a nil previous pointer.
	zeroCandidatePlan := &Plan{
		manifest: installpackage.Manifest{
			Predecessors: []installpackage.Predecessor{{ProfileIDs: []string{""}}},
		},
	}
	if zeroCandidatePlan.DeclaresPredecessor(nil) {
		t.Fatal("plan with zero predecessor entry matched nil previous plan")
	}

	// Plans with nil or empty Predecessors slice must refuse both previous and self.
	if len(current.Manifest().Predecessors) != 0 {
		t.Fatal("default current fixture unexpectedly carried predecessor declarations")
	}
	if current.DeclaresPredecessor(previous) || predecessorManifestOracle(current, previous) {
		t.Fatal("plan with empty predecessors slice matched previous plan")
	}
	if current.DeclaresPredecessor(current) || previous.DeclaresPredecessor(previous) {
		t.Fatal("plan without self-declaration matched itself")
	}

	nilPredsPlan := *current
	nilPredsPlan.manifest = current.Manifest()
	nilPredsPlan.manifest.Predecessors = nil
	if nilPredsPlan.DeclaresPredecessor(previous) || predecessorManifestOracle(&nilPredsPlan, previous) {
		t.Fatal("plan with nil predecessors slice matched previous plan")
	}

	emptySigned, err := independentCompileSignedPredecessorPlan(t, []installpackage.Predecessor{})
	if err != nil {
		t.Fatalf("compile empty predecessor slice: %v", err)
	}
	if emptySigned.DeclaresPredecessor(previous) || predecessorManifestOracle(emptySigned, previous) {
		t.Fatal("plan with empty predecessors slice matched previous plan")
	}
}

func TestIndependentDeclaresPredecessorSingleFieldMismatchesAndExactMatch(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	exact := independentGenuinePredecessor(previous)

	clonePlanWithPredecessors := func(base *Plan, preds []installpackage.Predecessor) *Plan {
		copyPlan := *base
		copyPlan.manifest = base.Manifest()
		copyPlan.manifest.Predecessors = make([]installpackage.Predecessor, len(preds))
		for i := range preds {
			copyPlan.manifest.Predecessors[i] = preds[i]
			if preds[i].ProfileIDs != nil {
				copyPlan.manifest.Predecessors[i].ProfileIDs = slices.Clone(preds[i].ProfileIDs)
			}
		}
		return &copyPlan
	}

	baseCurrent := mustCompile(t, false, DefaultNamespace, Profile137)
	altImages := independentPredecessorImages("8")

	// Unhappy paths first: each case alters exactly one identity field (or one
	// sub-field of Images / ProfileIDs) while keeping every other field identical
	// to previous.
	mismatches := []struct {
		name   string
		mutate func(p *installpackage.Predecessor)
	}{
		{
			name: "package-sha256-differs",
			mutate: func(p *installpackage.Predecessor) {
				p.PackageSHA256 = strings.Repeat("e", 64)
			},
		},
		{
			name: "package-sha256-empty",
			mutate: func(p *installpackage.Predecessor) {
				p.PackageSHA256 = ""
			},
		},
		{
			name: "source-sha-differs",
			mutate: func(p *installpackage.Predecessor) {
				p.SourceSHA = strings.Repeat("c", 40)
			},
		},
		{
			name: "source-sha-empty",
			mutate: func(p *installpackage.Predecessor) {
				p.SourceSHA = ""
			},
		},
		{
			name: "controller-image-differs",
			mutate: func(p *installpackage.Predecessor) {
				p.Images.Controller = altImages.Controller
			},
		},
		{
			name: "api-image-differs",
			mutate: func(p *installpackage.Predecessor) {
				p.Images.API = altImages.API
			},
		},
		{
			name: "images-swapped",
			mutate: func(p *installpackage.Predecessor) {
				p.Images.Controller, p.Images.API = p.Images.API, p.Images.Controller
			},
		},
		{
			name: "namespace-differs",
			mutate: func(p *installpackage.Predecessor) {
				p.Namespace = DefaultNamespace + "-other"
			},
		},
		{
			name: "namespace-empty",
			mutate: func(p *installpackage.Predecessor) {
				p.Namespace = ""
			},
		},
		{
			name: "profile-ids-nil",
			mutate: func(p *installpackage.Predecessor) {
				p.ProfileIDs = nil
			},
		},
		{
			name: "profile-ids-empty",
			mutate: func(p *installpackage.Predecessor) {
				p.ProfileIDs = []string{}
			},
		},
		{
			name: "profile-ids-other-profile",
			mutate: func(p *installpackage.Predecessor) {
				p.ProfileIDs = []string{Profile135}
			},
		},
		{
			name: "profile-ids-substring",
			mutate: func(p *installpackage.Predecessor) {
				p.ProfileIDs = []string{Profile137[:len(Profile137)-1]}
			},
		},
	}

	for _, tc := range mismatches {
		t.Run("candidate-"+tc.name, func(t *testing.T) {
			candidate := exact
			candidate.ProfileIDs = slices.Clone(exact.ProfileIDs)
			tc.mutate(&candidate)
			plan := clonePlanWithPredecessors(baseCurrent, []installpackage.Predecessor{candidate})
			if plan.DeclaresPredecessor(previous) || predecessorManifestOracle(plan, previous) {
				t.Fatalf("single-field candidate mismatch %q was accepted", tc.name)
			}
		})
	}

	// Also verify single-field mutations on the previous Plan side against an
	// untouched signed current plan declaring exact.
	signedCurrent, err := independentCompileSignedPredecessorPlan(t, []installpackage.Predecessor{exact})
	if err != nil {
		t.Fatalf("compile signed current plan: %v", err)
	}
	previousMismatches := []struct {
		name   string
		mutate func(prev *Plan)
	}{
		{
			name: "previous-digest-differs",
			mutate: func(prev *Plan) {
				prev.digest = strings.Repeat("d", 64)
			},
		},
		{
			name: "previous-source-sha-differs",
			mutate: func(prev *Plan) {
				prev.manifest.SourceSHA = strings.Repeat("d", 40)
			},
		},
		{
			name: "previous-controller-image-differs",
			mutate: func(prev *Plan) {
				prev.manifest.Images.Controller = altImages.Controller
			},
		},
		{
			name: "previous-api-image-differs",
			mutate: func(prev *Plan) {
				prev.manifest.Images.API = altImages.API
			},
		},
		{
			name: "previous-namespace-differs",
			mutate: func(prev *Plan) {
				prev.namespace = "other-namespace"
			},
		},
		{
			name: "previous-profile-id-differs",
			mutate: func(prev *Plan) {
				prev.profile.ID = Profile135
			},
		},
	}
	for _, tc := range previousMismatches {
		t.Run(tc.name, func(t *testing.T) {
			prevCopy := *previous
			prevCopy.manifest = previous.Manifest()
			tc.mutate(&prevCopy)
			if signedCurrent.DeclaresPredecessor(&prevCopy) || predecessorManifestOracle(signedCurrent, &prevCopy) {
				t.Fatalf("single-field previous mismatch %q was accepted", tc.name)
			}
		})
	}

	// Positive controls: exact match, distinct descriptive ID, and multi-profile list.
	if !signedCurrent.DeclaresPredecessor(previous) || !predecessorManifestOracle(signedCurrent, previous) {
		t.Fatal("exact signed predecessor declaration was rejected")
	}
	if previous.DeclaresPredecessor(signedCurrent) || predecessorManifestOracle(previous, signedCurrent) {
		t.Fatal("predecessor relation was accepted in reverse")
	}

	withAltID := exact
	withAltID.ID = "different-descriptive-id"
	altIDPlan := clonePlanWithPredecessors(baseCurrent, []installpackage.Predecessor{withAltID})
	if !altIDPlan.DeclaresPredecessor(previous) || !predecessorManifestOracle(altIDPlan, previous) {
		t.Fatal("changing non-identity Predecessor.ID rejected an otherwise exact predecessor")
	}

	multiProfile := exact
	multiProfile.ProfileIDs = []string{Profile135, Profile137}
	multiProfilePlan := clonePlanWithPredecessors(baseCurrent, []installpackage.Predecessor{multiProfile})
	if !multiProfilePlan.DeclaresPredecessor(previous) || !predecessorManifestOracle(multiProfilePlan, previous) {
		t.Fatal("predecessor with multiple ProfileIDs containing previous.Profile().ID was rejected")
	}
}

func TestIndependentDeclaresPredecessorDuplicateAndMultiCandidateSets(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	baseCurrent := mustCompile(t, false, DefaultNamespace, Profile137)
	exact := independentGenuinePredecessor(previous)

	missDigest := exact
	missDigest.ID = "miss-digest"
	missDigest.PackageSHA256 = strings.Repeat("1", 64)

	missSource := exact
	missSource.ID = "miss-source"
	missSource.SourceSHA = strings.Repeat("2", 40)

	missController := exact
	missController.ID = "miss-controller"
	missController.Images.Controller = independentPredecessorImages("3").Controller

	missAPI := exact
	missAPI.ID = "miss-api"
	missAPI.Images.API = independentPredecessorImages("4").API

	missNamespace := exact
	missNamespace.ID = "miss-ns"
	missNamespace.Namespace = "other-namespace"

	missProfile := exact
	missProfile.ID = "miss-profile"
	missProfile.ProfileIDs = []string{Profile135}

	cases := []struct {
		name       string
		candidates []installpackage.Predecessor
		want       bool
	}{
		{
			name:       "duplicate-mismatches-only",
			candidates: []installpackage.Predecessor{missDigest, missDigest, missSource, missSource},
			want:       false,
		},
		{
			name:       "all-single-field-mismatches-combined",
			candidates: []installpackage.Predecessor{missDigest, missSource, missController, missAPI, missNamespace, missProfile},
			want:       false,
		},
		{
			name:       "duplicate-exact-entries",
			candidates: []installpackage.Predecessor{exact, exact},
			want:       true,
		},
		{
			name:       "exact-first-then-mismatches",
			candidates: []installpackage.Predecessor{exact, missDigest, missSource},
			want:       true,
		},
		{
			name:       "exact-middle-between-mismatches",
			candidates: []installpackage.Predecessor{missDigest, missController, exact, missNamespace, missProfile},
			want:       true,
		},
		{
			name:       "exact-last-after-mismatches",
			candidates: []installpackage.Predecessor{missDigest, missSource, missController, missAPI, missNamespace, missProfile, exact},
			want:       true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := *baseCurrent
			plan.manifest = baseCurrent.Manifest()
			plan.manifest.Predecessors = slices.Clone(tc.candidates)
			got := plan.DeclaresPredecessor(previous)
			oracle := predecessorManifestOracle(&plan, previous)
			if got != tc.want || oracle != tc.want {
				t.Fatalf("%s: DeclaresPredecessor=%t oracle=%t, want %t", tc.name, got, oracle, tc.want)
			}
		})
	}

	signed, err := independentCompileSignedPredecessorPlan(t, []installpackage.Predecessor{missDigest, exact})
	if err != nil {
		t.Fatalf("compile signed multi-predecessor plan: %v", err)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		if !signed.DeclaresPredecessor(previous) {
			t.Fatal("expected match")
		}
	}); allocs != 0 {
		t.Fatalf("DeclaresPredecessor allocated %v times per call, want 0", allocs)
	}
}
