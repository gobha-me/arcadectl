// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
)

// Adversarial #100 proof: the sealed-metadata comparison that Upgrade and
// Rollback authorization both reduce to (newer.DeclaresPredecessor(older)) must
// keep refusing a deliberately broken SIGNED predecessor declaration. Unlike
// TestDeclaresPredecessorMatchesManifestComparison, which edits private plan
// fields, every fault here travels through real Build/Sign/Verify/Compile.

func predecessorImages(letter string) installpackage.Images {
	return installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat(letter, 64), API: "registry.example/api@sha256:" + strings.Repeat(letter, 64)}
}

// compileSignedPredecessorPlan signs a current (non-legacy) package carrying the
// given predecessors. It returns an error instead of failing the test so that
// refusals at the signing/compile boundary are themselves assertable.
func compileSignedPredecessorPlan(t *testing.T, predecessors []installpackage.Predecessor) (*Plan, error) {
	t.Helper()
	metadata, payloads := fixture(t, false)
	metadata.Predecessors = predecessors
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
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

func genuinePredecessor(previous *Plan) installpackage.Predecessor {
	return installpackage.Predecessor{ID: "old", PackageSHA256: previous.Digest(), SourceSHA: previous.Manifest().SourceSHA, Images: previous.Images(), Namespace: previous.Namespace(), ProfileIDs: []string{previous.Profile().ID}}
}

func TestDeclaresPredecessorRefusesBrokenSignedMetadata(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	good := genuinePredecessor(previous)
	genuine, err := compileSignedPredecessorPlan(t, []installpackage.Predecessor{good})
	if err != nil || !genuine.DeclaresPredecessor(previous) {
		t.Fatal("genuine signed predecessor positive control unavailable")
	}
	foreign := strings.Repeat("f", 64)
	for _, fault := range []struct {
		name string
		edit func(*installpackage.Predecessor)
		// refused means Build/Verify/Compile reject the declaration outright
		// and no plan exists; otherwise a well-formed signed plan exists but
		// must not accept previous.
		refused bool
	}{
		{"package-digest", func(p *installpackage.Predecessor) { p.PackageSHA256 = foreign }, false},
		{"package-digest-uppercase", func(p *installpackage.Predecessor) { p.PackageSHA256 = strings.ToUpper(p.PackageSHA256) }, true},
		{"controller-image", func(p *installpackage.Predecessor) { p.Images.Controller = predecessorImages("9").Controller }, false},
		{"api-image", func(p *installpackage.Predecessor) { p.Images.API = predecessorImages("9").API }, false},
		{"swapped-images", func(p *installpackage.Predecessor) {
			p.Images.Controller, p.Images.API = p.Images.API, p.Images.Controller
		}, false},
		{"foreign-images", func(p *installpackage.Predecessor) { p.Images = predecessorImages("9") }, false},
		{"source", func(p *installpackage.Predecessor) { p.SourceSHA = strings.Repeat("f", 40) }, true},
		{"namespace", func(p *installpackage.Predecessor) { p.Namespace = "foreign" }, true},
		{"profile", func(p *installpackage.Predecessor) { p.ProfileIDs = []string{Profile135} }, true},
		{"profile-superset", func(p *installpackage.Predecessor) { p.ProfileIDs = []string{Profile135, Profile137} }, true},
		{"profile-empty", func(p *installpackage.Predecessor) { p.ProfileIDs = nil }, true},
		{"profile-lookalike", func(p *installpackage.Predecessor) { p.ProfileIDs = []string{Profile137 + "x"} }, true},
	} {
		t.Run(fault.name, func(t *testing.T) {
			broken := good
			broken.ProfileIDs = append([]string(nil), good.ProfileIDs...)
			fault.edit(&broken)
			plan, err := compileSignedPredecessorPlan(t, []installpackage.Predecessor{broken})
			if fault.refused {
				if err == nil || plan != nil {
					t.Fatal("malformed signed predecessor metadata produced a trusted plan")
				}
				return
			}
			if err != nil || plan == nil {
				t.Fatal("signed fixture with well-formed foreign identity unavailable")
			}
			if plan.Digest() == genuine.Digest() || plan.DeclaresPredecessor(previous) || predecessorManifestOracle(plan, previous) {
				t.Fatal("broken signed predecessor metadata accepted")
			}
		})
	}
}

// A declaration is an exact tuple. Mixing one entry's digest with another's
// image, or listing many foreign entries, must not assemble a match.
func TestDeclaresPredecessorRefusesMixedAndForeignDeclarationSets(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	good := genuinePredecessor(previous)
	foreignA, foreignB := good, good
	foreignA.ID, foreignA.PackageSHA256, foreignA.Images = "aaa", strings.Repeat("a", 64), predecessorImages("8")
	foreignB.ID, foreignB.PackageSHA256, foreignB.Images = "bbb", strings.Repeat("b", 64), predecessorImages("7")
	// Digest from the genuine entry, images from a foreign one (and the reverse).
	mixedDigest, mixedImages := foreignA, foreignB
	mixedDigest.ID, mixedDigest.PackageSHA256 = "ccc", good.PackageSHA256
	mixedImages.ID, mixedImages.Images = "ddd", good.Images
	mixedImages.PackageSHA256 = foreignB.PackageSHA256
	for _, scenario := range []struct {
		name         string
		declarations []installpackage.Predecessor
		want         bool
	}{
		{"genuine-only", []installpackage.Predecessor{good}, true},
		{"genuine-among-foreign", []installpackage.Predecessor{foreignA, good, foreignB}, true},
		{"foreign-only", []installpackage.Predecessor{foreignA, foreignB}, false},
		{"digest-from-genuine-images-from-foreign", []installpackage.Predecessor{mixedDigest}, false},
		{"images-from-genuine-digest-from-foreign", []installpackage.Predecessor{mixedImages}, false},
		{"mixed-pair-never-assembles-genuine", []installpackage.Predecessor{mixedDigest, mixedImages}, false},
		{"empty", []installpackage.Predecessor{}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			plan, err := compileSignedPredecessorPlan(t, scenario.declarations)
			if err != nil {
				t.Fatal("well-formed signed declaration set unavailable")
			}
			if got := plan.DeclaresPredecessor(previous); got != scenario.want || predecessorManifestOracle(plan, previous) != scenario.want {
				t.Fatalf("declaration set %q: got %t, want %t", scenario.name, got, scenario.want)
			}
		})
	}
}

// Same signed next plan, but the PREVIOUS plan is a different genuine, signed
// package (other images => other canonical digest). A foreign previous plan is
// never a declared predecessor, in either direction.
func TestDeclaresPredecessorRefusesForeignSignedPreviousPlan(t *testing.T) {
	previous := mustCompile(t, true, DefaultNamespace, Profile137)
	next, err := compileSignedPredecessorPlan(t, []installpackage.Predecessor{genuinePredecessor(previous)})
	if err != nil || !next.DeclaresPredecessor(previous) {
		t.Fatal("signed predecessor positive control unavailable")
	}
	metadata, _ := fixture(t, true)
	images := predecessorImages("9")
	payloads, crds, err := RenderPayloads(images, true)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Images, metadata.CRDs = images, crds
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	body, err := installpackage.Build(metadata, payloads)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(body, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := Compile(pkg, DefaultNamespace, Profile137)
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Digest() == previous.Digest() || foreign.Images() == previous.Images() {
		t.Fatal("foreign previous fixture is not distinct from the declared predecessor")
	}
	if next.DeclaresPredecessor(foreign) || predecessorManifestOracle(next, foreign) || foreign.DeclaresPredecessor(next) || foreign.DeclaresPredecessor(previous) {
		t.Fatal("foreign signed previous plan accepted as a declared predecessor")
	}
}
