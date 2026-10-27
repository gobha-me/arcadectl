// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
)

// Adversarial #100 proofs for the three lifecycle verification modes. Nothing
// here relaxes or replaces an existing assertion: every case is a deliberately
// broken input that must still be refused, paired with a genuine positive
// control that proves the harness would otherwise accept it.

// signedTransitionTarget builds a CURRENT package like lifecycleTransitionPlans'
// target, but with caller-chosen signed predecessor declarations.
func signedTransitionTarget(t *testing.T, predecessors []installpackage.Predecessor) *installrender.Plan {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32)) // fake fixture ONLY
	letter, source := "d", strings.Repeat("e", 40)
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat(letter, 64), API: "registry.example/api@sha256:" + strings.Repeat(letter, 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: source, SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds, Predecessors: predecessors}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(body, sig, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, installrender.DefaultNamespace, installrender.Profile137)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func genuineTransitionPredecessor(previous *installrender.Plan) installpackage.Predecessor {
	return installpackage.Predecessor{ID: "issue-26", PackageSHA256: previous.Digest(), SourceSHA: previous.Manifest().SourceSHA, Images: previous.Manifest().Images, Namespace: previous.Namespace(), ProfileIDs: []string{previous.Profile().ID}}
}

// Signable single-field faults. Source/namespace/profile faults are already
// refused by Build/Compile (see installrender's adversarial predecessor tests),
// so these are exactly the faults that reach Engine.compatible.
func brokenPredecessorFaults(previous *installrender.Plan) map[string][]installpackage.Predecessor {
	foreignImages := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("9", 64), API: "registry.example/api@sha256:" + strings.Repeat("9", 64)}
	edit := func(change func(*installpackage.Predecessor)) []installpackage.Predecessor {
		p := genuineTransitionPredecessor(previous)
		change(&p)
		return []installpackage.Predecessor{p}
	}
	return map[string][]installpackage.Predecessor{
		"package-digest":   edit(func(p *installpackage.Predecessor) { p.PackageSHA256 = strings.Repeat("f", 64) }),
		"controller-image": edit(func(p *installpackage.Predecessor) { p.Images.Controller = foreignImages.Controller }),
		"api-image":        edit(func(p *installpackage.Predecessor) { p.Images.API = foreignImages.API }),
		"swapped-images": edit(func(p *installpackage.Predecessor) {
			p.Images.Controller, p.Images.API = p.Images.API, p.Images.Controller
		}),
		"foreign-images":    edit(func(p *installpackage.Predecessor) { p.Images = foreignImages }),
		"no-declaration":    {},
		"decoy-declaration": edit(func(p *installpackage.Predecessor) { p.ID, p.PackageSHA256 = "decoy", strings.Repeat("a", 64) }),
	}
}

// Upgrade and Rollback authorization both reduce to newer.DeclaresPredecessor(
// older) inside the permission derivation every AdmissionEffective /
// AdmissionConfigured request passes first. A broken signed declaration must
// make that derivation fail for each mode; Uninstall must keep refusing any
// plan that is not the exact active package.
func TestAdmissionAdversarialBrokenPredecessorRefusedByEveryMode(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	control := newFixtureWithPlans(t, false, previous, target)
	controlProof := &ClusterPrerequisites{engine: control.engine}
	derive := func(proof *ClusterPrerequisites, d installstate.Document, mode installstate.Mode, plan *installrender.Plan) ([]proofPermission, error) {
		return proof.documentPermissions(d, mode, plan)
	}
	// Positive controls: the same constructors accept the GENUINE chain.
	upgradeDocument := permissionInventory(t, control, previous)
	rollbackDocument := permissionInventory(t, control, target)
	rollbackDocument.PreviousPackage = previous.Digest()
	if got, err := derive(controlProof, upgradeDocument, installstate.Upgrade, target); err != nil || len(got) == 0 {
		t.Fatal("genuine Upgrade positive control unavailable", err)
	}
	if got, err := derive(controlProof, rollbackDocument, installstate.Rollback, previous); err != nil || len(got) == 0 {
		t.Fatal("genuine Rollback positive control unavailable", err)
	}
	if got, err := derive(controlProof, upgradeDocument, installstate.Uninstall, previous); err != nil || len(got) == 0 {
		t.Fatal("genuine Uninstall positive control unavailable", err)
	}
	for name, declarations := range brokenPredecessorFaults(previous) {
		t.Run(name, func(t *testing.T) {
			broken := signedTransitionTarget(t, declarations)
			if broken.Digest() == target.Digest() || broken.DeclaresPredecessor(previous) {
				t.Fatal("fault fixture did not break the signed predecessor declaration")
			}
			f := newFixtureWithPlans(t, false, previous, broken)
			proof := &ClusterPrerequisites{engine: f.engine}
			t.Run("upgrade", func(t *testing.T) {
				d := permissionInventory(t, f, previous)
				if got, err := derive(proof, d, installstate.Upgrade, broken); err != ErrInvalid || got != nil {
					t.Fatal("Upgrade to an undeclared successor derived admission authority", err)
				}
			})
			t.Run("rollback", func(t *testing.T) {
				// The journal claims the broken plan is active and previous is
				// its recorded predecessor; the signed declaration disagrees.
				d := permissionInventory(t, f, broken)
				d.PreviousPackage = previous.Digest()
				if got, err := derive(proof, d, installstate.Rollback, previous); err != ErrInvalid || got != nil {
					t.Fatal("Rollback past an undeclared predecessor derived admission authority", err)
				}
			})
			t.Run("uninstall", func(t *testing.T) {
				// A package that fails to declare the active one confers no
				// uninstall authority either: only the exact active plan does.
				d := permissionInventory(t, f, previous)
				if got, err := derive(proof, d, installstate.Uninstall, broken); err != ErrInvalid || got != nil {
					t.Fatal("Uninstall target other than the active package derived authority", err)
				}
				d.Installed = false
				if got, err := derive(proof, d, installstate.Uninstall, previous); err != ErrInvalid || got != nil {
					t.Fatal("Uninstall of a non-installed journal derived authority", err)
				}
			})
		})
	}
}

// The same broken declarations through the real journal-opening operation:
// Begin must refuse before any journal write or check, in every applicable mode.
func TestAdmissionAdversarialLifecycleBeginRefusesBrokenChain(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	faults := brokenPredecessorFaults(previous)
	// Each case completes a whole fixture install; the full fault table is
	// already exercised through the permission derivation Begin delegates to.
	for _, name := range []string{"package-digest", "swapped-images", "no-declaration"} {
		declarations := faults[name]
		t.Run(name, func(t *testing.T) {
			broken := signedTransitionTarget(t, declarations)
			v := newLifecycleFixturePlans(t, previous, target, broken)
			s := v.finish(t, v.f.snapshot)
			updates, checks, writes := v.f.nsUpdates, len(v.checks), v.f.access.writes+v.private.writes
			refuse := func(mode installstate.Mode, digest string) {
				t.Helper()
				next, err := v.l.Begin(t.Context(), s, mode, digest, v.opts)
				if !errors.Is(err, ErrInvalid) || !next.SameJournalBytes(s) || v.f.nsUpdates != updates || len(v.checks) != checks || v.f.access.writes+v.private.writes != writes {
					t.Fatalf("%s to %s began over a broken signed chain: %v", mode, digest[:8], err)
				}
			}
			refuse(installstate.Upgrade, broken.Digest())
			refuse(installstate.Rollback, broken.Digest())
			refuse(installstate.Rollback, previous.Digest()) // never upgraded: no recorded predecessor
			refuse(installstate.Uninstall, broken.Digest())
			refuse(installstate.Uninstall, target.Digest()) // not the active package
		})
	}
	// Positive control: the genuine target begins from the identical journal.
	v := newLifecycleFixturePlans(t, previous, target)
	s := v.finish(t, v.f.snapshot)
	if next, err := v.l.Begin(t.Context(), s, installstate.Upgrade, target.Digest(), v.opts); err != nil || next.Document().Mode != installstate.Upgrade {
		t.Fatal("genuine Upgrade Begin positive control unavailable", err)
	}
}

func proofSpecResource(namespace, verb, group, version, resource, subresource, name string) authv1.SelfSubjectAccessReviewSpec {
	return authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: namespace, Verb: verb, Group: group, Version: version, Resource: resource, Subresource: subresource, Name: name}}
}

// Real Upgrade/Rollback/Uninstall recipes are tied into uniqueProofPermissions:
// corrupted copies of those exact recipes must still be refused or fully
// distinguished, and the bound must still apply to a realistic recipe.
func TestAdmissionAdversarialPermissionRecipesPerMode(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	f := newFixtureWithPlans(t, false, previous, target)
	proof := &ClusterPrerequisites{engine: f.engine}
	for _, mode := range []installstate.Mode{installstate.Upgrade, installstate.Rollback, installstate.Uninstall} {
		t.Run(string(mode), func(t *testing.T) {
			active, next := previous, target
			if mode == installstate.Rollback {
				active, next = target, previous
			} else if mode == installstate.Uninstall {
				next = previous
			}
			d := permissionInventory(t, f, active)
			d.PreviousPackage = previous.Digest()
			recipe, err := proof.documentPermissions(d, mode, next)
			if err != nil || len(recipe) < 10 || len(recipe) >= 256 {
				t.Fatal("real transition recipe unavailable or outside its bound", err, len(recipe))
			}
			var resource, nonResource *proofPermission
			for i := range recipe {
				if recipe[i].spec.ResourceAttributes != nil && resource == nil {
					resource = &recipe[i]
				}
				if recipe[i].spec.NonResourceAttributes != nil && nonResource == nil {
					nonResource = &recipe[i]
				}
			}
			if resource == nil || nonResource == nil {
				t.Fatal("recipe lacks both resource and discovery descriptors")
			}
			// Idempotent, duplicate- and order-invariant: re-deduplicating the
			// real recipe (twice, reversed) reproduces exactly itself.
			doubled := append(slices.Clone(recipe), recipe...)
			slices.Reverse(doubled)
			if again, err := uniqueProofPermissions(doubled); err != nil || !reflect.DeepEqual(again, recipe) {
				t.Fatal("duplicated/reordered real recipe changed its descriptor set", err)
			}
			// Corrupted recipes must be refused wherever they are spliced in.
			selector := func(label bool) proofPermission {
				p := *resource
				a := *p.spec.ResourceAttributes
				if label {
					a.LabelSelector = &authv1.LabelSelectorAttributes{RawSelector: "foreign=true"}
				} else {
					a.FieldSelector = &authv1.FieldSelectorAttributes{RawSelector: "metadata.name=foreign"}
				}
				p.spec = authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &a}
				return p
			}
			dual := *resource
			dual.spec = authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: resource.spec.ResourceAttributes, NonResourceAttributes: nonResource.spec.NonResourceAttributes}
			corrupt := map[string]proofPermission{
				"field-selector": selector(false),
				"label-selector": selector(true),
				"dual":           dual,
				"empty":          {},
			}
			for name, bad := range corrupt {
				for _, position := range []int{0, len(recipe) / 2, len(recipe)} {
					input := slices.Insert(slices.Clone(recipe), position, bad)
					if got, err := uniqueProofPermissions(input); err != ErrInvalid || got != nil {
						t.Fatalf("%s recipe with %s descriptor at %d accepted", mode, name, position)
					}
				}
			}
			// Every single native field of every real descriptor is
			// load-bearing: changing one must create exactly the distinct
			// descriptor the independent JSON oracle sees, never collapse.
			for index, original := range recipe {
				for field := range 7 {
					variant := original
					if a := original.spec.ResourceAttributes; a != nil {
						mutated := *a
						for i, value := range []*string{&mutated.Namespace, &mutated.Verb, &mutated.Group, &mutated.Version, &mutated.Resource, &mutated.Subresource, &mutated.Name} {
							if i == field {
								*value += "-mutated"
							}
						}
						variant.spec = authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &mutated}
					} else if field < 2 {
						mutated := *original.spec.NonResourceAttributes
						if field == 0 {
							mutated.Path += "-mutated"
						} else {
							mutated.Verb += "-mutated"
						}
						variant.spec = authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &mutated}
					} else {
						continue
					}
					input := append(slices.Clone(recipe), variant)
					got, err := uniqueProofPermissions(input)
					if err != nil || len(got) != len(recipe)+1 || len(got) != len(jsonProofPermissionOracle(input)) {
						t.Fatalf("%s descriptor %d field %d conflated with another recipe member", mode, index, field)
					}
				}
			}
			// The 256 bound still applies after the real recipe's own members.
			room := 256 - len(recipe)
			filler := func(n int) []proofPermission {
				var extra []proofPermission
				for i := range n {
					extra = append(extra, proofPermission{spec: proofSpecResource("", "get", "", "v1", fmt.Sprintf("adversarial-%d", i), "", "")})
				}
				return extra
			}
			if got, err := uniqueProofPermissions(append(slices.Clone(recipe), filler(room)...)); err != nil || len(got) != 256 {
				t.Fatal("recipe filling exactly the bound refused", err)
			}
			over := append(slices.Clone(recipe), filler(room+1)...)
			if got, err := uniqueProofPermissions(over); err != ErrInvalid || got != nil {
				t.Fatal("real recipe plus 257th distinct descriptor accepted")
			}
			if got, err := uniqueProofPermissions(append(over, recipe...)); err != ErrInvalid || got != nil {
				t.Fatal("duplicates after the bound rescued an oversized recipe")
			}
			if got, err := uniqueProofPermissions(append(slices.Clone(recipe), append(filler(room), recipe...)...)); err != nil || len(got) != 256 {
				t.Fatal("bound counted duplicates of real descriptors")
			}
		})
	}
}
