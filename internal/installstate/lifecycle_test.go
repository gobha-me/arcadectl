// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

func lifecyclePlan(t *testing.T, epoch int64) *installrender.Plan {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: epoch, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signature, err := installpackage.Sign(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(manifest, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, "isolated-install", installrender.Profile135)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func lifecycleResources(t *testing.T, plan *installrender.Plan, retainedOnly bool) []Resource {
	t.Helper()
	keys, _, err := contracts([]*installrender.Plan{plan}, plan.Namespace(), plan.Profile().ID)
	if err != nil {
		t.Fatal(err)
	}
	resources := make([]Resource, 0, len(keys))
	for key, contract := range keys {
		if retainedOnly && !contract.retained {
			continue
		}
		uid := types.UID("owned-" + key.Kind + "-" + key.Name)
		if key.Kind == "Namespace" {
			uid = "namespace-uid"
		}
		hash := strings.Repeat("d", 64)
		if key.Kind == "Secret" {
			hash = ""
		}
		resources = append(resources, Resource{Key: key, UID: uid, TemplateSHA256: hash, Retained: contract.retained, Phase: contract.phase})
	}
	SortResources(resources)
	return resources
}

func lifecycleCopy(t *testing.T, d Document) Document {
	t.Helper()
	var result Document
	if err := jsonCopy(d, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCompleteInventoryContainsEveryReviewedObject(t *testing.T) {
	plan := testPlan(t)
	for _, installed := range []bool{true, false} {
		t.Run(fmt.Sprintf("installed-%t", installed), func(t *testing.T) {
			d := initialDocument(plan)
			d.Stage, d.ActivePackage, d.Installed = Complete, plan.Digest(), installed
			if !installed {
				d.Mode = Uninstall
			}
			d.Resources = lifecycleResources(t, plan, !installed)
			want := 40
			if !installed {
				want = 20
			}
			if len(d.Resources) != want {
				t.Fatalf("inventory=%d want=%d", len(d.Resources), want)
			}
			body, err := Encode(d, plan)
			if err != nil {
				t.Fatal("complete reviewed inventory rejected", err)
			}
			if _, err := Decode(body, plan); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"missing", "wrong-retention", "wrong-phase", "wrong-uid", "secret-hash", "foreign-key"} {
				t.Run(kind, func(t *testing.T) {
					bad := lifecycleCopy(t, d)
					switch kind {
					case "missing":
						bad.Resources = bad.Resources[1:]
					case "wrong-retention":
						bad.Resources[0].Retained = !bad.Resources[0].Retained
					case "wrong-phase":
						bad.Resources[0].Phase = installrender.API
					case "wrong-uid":
						bad.Resources[1].UID = bad.Resources[0].UID
					case "secret-hash":
						for i := range bad.Resources {
							if bad.Resources[i].Key.Kind == "Secret" {
								bad.Resources[i].TemplateSHA256 = strings.Repeat("e", 64)
								break
							}
						}
					case "foreign-key":
						bad.Resources[0].Key.Name += "-foreign"
					}
					if _, err := Encode(bad, plan); !errors.Is(err, ErrInvalid) {
						t.Fatalf("%s accepted: %v", kind, err)
					}
				})
			}
		})
	}
}

func TestLifecycleStageTransitionMatrix(t *testing.T) {
	current, nextPlan := testPlan(t), lifecyclePlan(t, 2)
	stages := []Stage{Preparing, Quiescing, Applying, Verifying, Complete, RecoveryRequired}
	for _, mode := range []Mode{Install, Upgrade, Rollback, Uninstall} {
		for _, from := range stages {
			if from == Complete || mode == Install && from == Quiescing {
				continue
			}
			for _, to := range stages {
				t.Run(string(mode)+"/"+string(from)+"-to-"+string(to), func(t *testing.T) {
					before := initialDocument(current)
					before.Mode, before.Stage = mode, from
					before.Resources = lifecycleResources(t, current, mode == Uninstall)
					if mode != Install {
						before.ActivePackage, before.Installed = current.Digest(), true
					}
					if mode == Upgrade || mode == Rollback {
						before.TargetPackage = nextPlan.Digest()
					}
					after := lifecycleCopy(t, before)
					after.Revision, after.Stage = before.Revision+1, to
					if to == Complete {
						after.ActivePackage, after.Installed = before.TargetPackage, mode != Uninstall
						if before.ActivePackage != "" && before.ActivePackage != before.TargetPackage {
							after.PreviousPackage = before.ActivePackage
						}
					}
					want := from == Preparing && (to == RecoveryRequired || mode == Install && to == Applying || mode != Install && to == Quiescing) ||
						from == Quiescing && (to == Applying || to == RecoveryRequired) ||
						from == Applying && (to == Verifying || to == RecoveryRequired) ||
						from == Verifying && (to == Complete || to == RecoveryRequired) ||
						from == RecoveryRequired && (mode == Install && to == Applying || mode != Install && to == Quiescing)
					if got := validTransition(before, after); got != want {
						t.Fatalf("transition=%t want=%t", got, want)
					}
					if want {
						if _, err := Encode(before, current, nextPlan); err != nil {
							t.Fatal("before", err)
						}
						if _, err := Encode(after, current, nextPlan); err != nil {
							t.Fatal("after", err)
						}
					}
				})
			}
		}
	}
}

func TestLifecycleStartAndMidOperationIdentityGuards(t *testing.T) {
	plan, target := testPlan(t), lifecyclePlan(t, 2)
	for _, installed := range []bool{true, false} {
		before := initialDocument(plan)
		before.ActivePackage, before.Installed, before.Stage = plan.Digest(), installed, Complete
		before.Resources = lifecycleResources(t, plan, !installed)
		if !installed {
			before.Mode = Uninstall
		}
		for _, mode := range []Mode{Install, Upgrade, Rollback, Uninstall} {
			for _, changedPackage := range []bool{false, true} {
				t.Run(fmt.Sprintf("installed-%t/%s/change-%t", installed, mode, changedPackage), func(t *testing.T) {
					after := lifecycleCopy(t, before)
					after.Revision++
					after.Mode, after.Stage = mode, Preparing
					if changedPackage {
						after.TargetPackage = target.Digest()
					}
					want := installed && (mode == Uninstall && !changedPackage || (mode == Upgrade || mode == Rollback) && changedPackage) || !installed && mode == Install && !changedPackage
					if validTransition(before, after) != want {
						t.Fatal("incorrect new-operation gate")
					}
				})
			}
		}
	}
	before := initialDocument(plan)
	before.Stage = Applying
	for _, mutation := range []string{"revision", "identity", "namespace", "profile", "mode", "target", "active", "previous", "installed", "resource"} {
		t.Run("mid-operation/"+mutation, func(t *testing.T) {
			after := lifecycleCopy(t, before)
			after.Revision++
			after.Stage = Verifying
			switch mutation {
			case "revision":
				after.Revision++
			case "identity":
				after.InstallationID = strings.Repeat("f", 32)
			case "namespace":
				after.Namespace = "foreign-install"
			case "profile":
				after.ProfileID = installrender.Profile137
			case "mode":
				after.Mode = Upgrade
			case "target":
				after.TargetPackage = target.Digest()
			case "active":
				after.ActivePackage = target.Digest()
			case "previous":
				after.PreviousPackage = target.Digest()
			case "installed":
				after.Installed = true
			case "resource":
				after.Resources[0].TemplateSHA256 = strings.Repeat("e", 64)
			}
			if validTransition(before, after) {
				t.Fatal("mid-operation mutation accepted")
			}
		})
	}
}

func TestLifecyclePendingCreateAndUpdateSettlement(t *testing.T) {
	plan := testPlan(t)
	all := lifecycleResources(t, plan, false)
	var effect Resource
	for _, r := range all {
		if r.Key.Kind == "Deployment" {
			effect = r
			break
		}
	}
	for _, action := range []Action{Create, Update} {
		t.Run(string(action), func(t *testing.T) {
			before := initialDocument(plan)
			before.Stage = Applying
			if action == Update {
				before.Resources = append(before.Resources, effect)
				SortResources(before.Resources)
			}
			before.Pending = &Pending{Action: action, Key: effect.Key, CreateNonce: strings.Repeat("e", 32), AfterSHA256: strings.Repeat("f", 64)}
			if action == Update {
				before.Pending.BeforeUID, before.Pending.BeforeResourceVersion, before.Pending.BeforeSHA256 = effect.UID, "7", effect.TemplateSHA256
			}
			if _, err := Encode(before, plan); err != nil {
				t.Fatal(err)
			}
			settled := lifecycleCopy(t, before)
			settled.Revision++
			settled.Pending = nil
			settled.Resources = slicesWithout(settled.Resources, effect.Key)
			effectCopy := effect
			effectCopy.TemplateSHA256 = before.Pending.AfterSHA256
			settled.Resources = append(settled.Resources, effectCopy)
			SortResources(settled.Resources)
			if !validTransition(before, settled) {
				t.Fatal("exact settlement rejected")
			}
			if _, err := Encode(settled, plan); err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []string{"wrong-hash", "unrelated-uid", "unrelated-hash", "missing-effect", "pending-overwrite", "retention", "uid"} {
				t.Run(mutation, func(t *testing.T) {
					bad := lifecycleCopy(t, settled)
					for i := range bad.Resources {
						if bad.Resources[i].Key == effect.Key {
							if mutation == "wrong-hash" {
								bad.Resources[i].TemplateSHA256 = strings.Repeat("a", 64)
							}
							if mutation == "retention" {
								bad.Resources[i].Retained = !bad.Resources[i].Retained
							}
							if mutation == "uid" {
								if action == Update {
									bad.Resources[i].UID = "replacement"
								} else {
									bad.Resources[i].UID = before.NamespaceUID
								}
							}
						} else {
							if mutation == "unrelated-uid" {
								bad.Resources[i].UID = "foreign"
							}
							if mutation == "unrelated-hash" {
								bad.Resources[i].TemplateSHA256 = strings.Repeat("a", 64)
							}
						}
					}
					if mutation == "missing-effect" {
						bad.Resources = slicesWithout(bad.Resources, effect.Key)
					}
					if mutation == "pending-overwrite" {
						bad = lifecycleCopy(t, before)
						bad.Revision++
						bad.Pending.CreateNonce = strings.Repeat("a", 32)
						if _, err := Encode(bad, plan); err != nil {
							t.Fatal("overwrite candidate should be individually well-formed", err)
						}
					}
					_, encodeErr := Encode(bad, plan)
					if validTransition(before, bad) && encodeErr == nil {
						t.Fatal("invalid settlement accepted")
					}
				})
			}
		})
	}
}

func TestNamespaceBindResponseAndReadbackMatrix(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	for _, kind := range []string{"lost-committed", "lost-uncommitted", "superseded", "replaced-uid", "unreadable", "forbidden", "unauthorized", "invalid", "conflict", "success-bad-uid", "success-bad-body", "success-stale-rv", "success-nil"} {
		t.Run(kind, func(t *testing.T) {
			client := fake.NewClientset()
			live := testNamespace(plan, d)
			gets, updates := 0, 0
			client.PrependReactor("*", "namespaces", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if action.GetVerb() == "get" {
					gets++
					if gets > 1 && kind == "unreadable" {
						return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, d.Namespace, errors.New("canary"))
					}
					return true, live.DeepCopy(), nil
				}
				if action.GetVerb() != "update" {
					t.Fatal("unexpected cluster effect", action.GetVerb())
				}
				updates++
				candidate := action.(clienttesting.UpdateAction).GetObject().(*corev1.Namespace).DeepCopy()
				if candidate.UID != live.UID || candidate.ResourceVersion != live.ResourceVersion {
					t.Fatal("missing original UID/RV")
				}
				group := schema.GroupResource{Resource: "namespaces"}
				switch kind {
				case "forbidden":
					return true, nil, apierrors.NewForbidden(group, d.Namespace, errors.New("canary"))
				case "unauthorized":
					return true, nil, apierrors.NewUnauthorized("canary")
				case "invalid":
					return true, nil, apierrors.NewInvalid(schema.GroupKind{Kind: "Namespace"}, d.Namespace, nil)
				case "conflict":
					return true, nil, apierrors.NewConflict(group, d.Namespace, errors.New("canary"))
				}
				candidate.ResourceVersion = "2"
				if kind == "success-stale-rv" {
					candidate.ResourceVersion = "1"
				}
				if kind == "success-bad-uid" {
					candidate.UID = "replacement"
				}
				if kind == "success-bad-body" {
					candidate.Annotations[Annotation] = "{}"
				}
				if strings.HasPrefix(kind, "success-") {
					if kind == "success-nil" {
						return true, nil, nil
					}
					return true, candidate, nil
				}
				if kind != "lost-uncommitted" {
					live = candidate.DeepCopy()
				}
				if kind == "replaced-uid" {
					live.UID = "replacement"
				}
				if kind == "superseded" {
					other := lifecycleCopy(t, d)
					other.Revision, other.Stage = 2, Applying
					body, err := Encode(other, plan)
					if err != nil {
						t.Fatal(err)
					}
					live.Annotations[Annotation], live.ResourceVersion = string(body), "3"
				}
				return true, nil, errors.New("lost response canary")
			})
			store, err := New(client.CoreV1().Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := store.Bind(context.Background(), anchor, d)
			want := ErrOutcomeUnknown
			if kind == "lost-committed" {
				want = nil
			}
			if kind == "forbidden" || kind == "unauthorized" || kind == "invalid" {
				want = ErrOwnership
			}
			if kind == "conflict" {
				want = ErrConflict
			}
			if !errors.Is(err, want) || updates != 1 {
				t.Fatalf("bind=%v want=%v updates=%d", err, want, updates)
			}
			if want == nil && (snapshot == nil || snapshot.ResourceVersion() != "2") {
				t.Fatal("missing exact confirmed snapshot")
			}
			wantGets := 2
			if kind == "forbidden" || kind == "unauthorized" || kind == "invalid" || kind == "conflict" || strings.HasPrefix(kind, "success-") {
				wantGets = 1
			}
			if gets != wantGets {
				t.Fatalf("gets=%d want=%d; unexpected retry/readback", gets, wantGets)
			}
		})
	}
}

type nilLifecycleNamespaces struct{ coreclient.NamespaceInterface }

func TestNamespaceConstructorsAndCrossStoreSnapshotFailClosed(t *testing.T) {
	plan := testPlan(t)
	client := fake.NewClientset().CoreV1().Namespaces()
	var nilClient *nilLifecycleNamespaces
	for _, build := range []func() (*Store, error){
		func() (*Store, error) { return New(nil, plan) },
		func() (*Store, error) { return New(nilClient, plan) },
		func() (*Store, error) { return New(client) },
		func() (*Store, error) { return New(client, nil) },
		func() (*Store, error) { return New(client, &installrender.Plan{}) },
		func() (*Store, error) { return New(client, plan, plan) },
	} {
		if _, err := build(); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid constructor accepted", err)
		}
	}
	d := initialDocument(plan)
	server := &namespaceServer{live: testNamespace(plan, d)}
	first, err := New(server.client().CoreV1().Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(server.client().CoreV1().Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := first.Bind(context.Background(), Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}, d)
	if err != nil {
		t.Fatal(err)
	}
	next := snapshot.Document()
	next.Revision++
	next.Stage = Applying
	for _, observed := range []*Snapshot{nil, {}, snapshot} {
		if _, err := second.Commit(context.Background(), observed, next); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsealed/cross-store snapshot accepted", err)
		}
	}
	if server.updates != 1 {
		t.Fatal("invalid snapshot caused cluster mutation")
	}
	if _, err := (*Store)(nil).Load(context.Background(), Anchor{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil store accepted")
	}
}
