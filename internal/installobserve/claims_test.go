// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clienttesting "k8s.io/client-go/testing"
)

func claimsOnlyFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.dynamic.PrependReactor("*", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if a.GetVerb() != "list" || a.GetResource().Resource != "persistentvolumeclaims" || a.GetNamespace() != f.anchor.Namespace {
			t.Fatal("claims report contacted an unrelated resource or mutation")
		}
		return false, nil, nil
	})
	f.metadata.PrependReactor("*", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
		t.Fatal("claims report tried to resolve owners or read Secret metadata")
		return true, nil, errors.New("PRIVATE-CANARY")
	})
	f.o.clients.Discovery = func(context.Context, string) (*metav1.APIResourceList, error) {
		t.Fatal("claims report contacted unrelated discovery")
		return nil, errors.New("PRIVATE-CANARY")
	}
	return f
}

func TestCollectClaimsIncludesUnlabeledWorldsWithoutOwnerResolution(t *testing.T) {
	f := claimsOnlyFixture(t)
	f.claim("unlabeled-retained-world", owner("ConfigMap", "already-removed"))
	f.claim("other-application")
	observation, err := f.o.CollectClaims(context.Background(), f.anchor)
	if err != nil || observation == nil || len(observation.Claims().Items) != 2 || observation.Claims().ResourceVersion != "20" || observation.Journal().Anchor() != f.anchor {
		t.Fatal("complete current claims were not observed", err)
	}
	copy := observation.Claims()
	copy.Items[0].Name = "changed"
	if observation.Claims().Items[0].Name != "unlabeled-retained-world" {
		t.Fatal("mutable claim accessor changed sealed evidence")
	}
	var absent *ClaimsObservation
	if absent.Claims() != nil || absent.Journal() != nil {
		t.Fatal("nil observation produced evidence")
	}
}

func TestCollectClaimsEmptyAndCompletePages(t *testing.T) {
	for _, paged := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "two-pages"}[paged], func(t *testing.T) {
			f := claimsOnlyFixture(t)
			calls := 0
			if paged {
				f.claim("first")
				f.claim("second")
			}
			f.dynamic.PrependReactor("list", "persistentvolumeclaims", func(a clienttesting.Action) (bool, runtime.Object, error) {
				opts := a.(clienttesting.ListActionImpl).ListOptions
				wantContinue := ""
				if calls == 1 {
					wantContinue = "next"
				}
				if opts.Continue != wantContinue || opts.Limit != pageLimit || opts.LabelSelector != "" || opts.FieldSelector != "" || opts.ResourceVersion != "" {
					t.Fatal("PVC list lost its unfiltered pagination contract")
				}
				page := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaimList", "metadata": map[string]any{"resourceVersion": "20"}}, Items: []unstructured.Unstructured{}}
				if paged {
					if calls > 1 {
						t.Fatal("unexpected page replay")
					}
					page.Items = append(page.Items, *f.lists["persistentvolumeclaims"][calls].DeepCopy())
					if calls == 0 {
						page.SetContinue("next")
					}
				}
				calls++
				return true, page, nil
			})
			observation, err := f.o.CollectClaims(context.Background(), f.anchor)
			wantCount, wantCalls := 0, 1
			if paged {
				wantCount, wantCalls = 2, 2
			}
			if err != nil || observation == nil || len(observation.Claims().Items) != wantCount || calls != wantCalls || observation.Claims().ResourceVersion != "20" || observation.Claims().Continue != "" {
				t.Fatal("complete PVC pages were not sealed", err)
			}
		})
	}
}

func TestCollectClaimsRefusesProfileOrUnregisteredPackage(t *testing.T) {
	for _, fault := range []string{"profile", "package"} {
		t.Run(fault, func(t *testing.T) {
			f := claimsOnlyFixture(t)
			m := f.o.plan.Manifest()
			m.Files = nil // Build derives payload identities from supplied bytes.
			profile := installrender.Profile135
			if fault == "profile" {
				profile = installrender.Profile137
			} else {
				m.SourceEpoch++
			}
			payloads, _, err := installrender.RenderPayloads(m.Images, false)
			if err != nil {
				t.Fatal(err)
			}
			body, err := installpackage.Build(m, payloads)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
			sig, err := installpackage.Sign(body, key)
			if err != nil {
				t.Fatal(err)
			}
			pkg, err := installpackage.Verify(body, sig, payloads, key.Public().(ed25519.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			f.o.plan, err = installrender.Compile(pkg, f.anchor.Namespace, profile)
			if err != nil {
				t.Fatal(err)
			}
			f.dynamic.PrependReactor("*", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
				t.Fatal("foreign plan reached PVC enumeration")
				return true, nil, ErrRead
			})
			observation, err := f.o.CollectClaims(context.Background(), f.anchor)
			if err == nil || observation != nil {
				t.Fatal("foreign profile/package produced evidence")
			}
		})
	}
}

func TestCollectClaimsSupportsCompletedRetainingUninstall(t *testing.T) {
	f := claimsOnlyFixture(t)
	f.claim("unlabeled-world")
	s, err := f.o.journal.Load(context.Background(), f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Document()
	d.Mode, d.Stage, d.Installed, d.ActivePackage = installstate.Uninstall, installstate.Complete, false, f.o.plan.Digest()
	d.Resources = nil
	for _, r := range f.o.plan.Resources() {
		if !r.Retained {
			continue
		}
		o := r.Object
		uid := types.UID("retained-" + o.GetKind() + "-" + o.GetName())
		if o.GetKind() == "Namespace" {
			uid = f.anchor.UID
		}
		d.Resources = append(d.Resources, installstate.Resource{Key: installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()},
			UID: uid, TemplateSHA256: strings.Repeat("b", 64), Retained: true, Phase: r.Phase})
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		d.Resources = append(d.Resources, installstate.Resource{Key: installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: d.Namespace, Name: name},
			UID: types.UID("retained-" + name), Retained: true, Phase: installrender.API})
	}
	installstate.SortResources(d.Resources)
	body, err := installstate.Encode(d, f.o.plan)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := f.core.CoreV1().Namespaces().Get(context.Background(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.Annotations[installstate.Annotation] = string(body)
	if _, err := f.core.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	observation, err := f.o.CollectClaims(context.Background(), f.anchor)
	if err != nil || observation == nil || observation.Journal().Document().Installed || len(observation.Claims().Items) != 1 {
		t.Fatal("completed retaining uninstall hid current world claims", err)
	}
}

func TestCollectClaimsRefusesPartialOrForeignEvidence(t *testing.T) {
	for _, fault := range []string{"foreign-namespace", "duplicate", "missing-uid", "wrong-kind", "unknown-field", "partial-page", "remaining", "page-rv", "journal-race", "cancelled", "nil-context"} {
		t.Run(fault, func(t *testing.T) {
			f := claimsOnlyFixture(t)
			f.claim("world")
			ctx := context.Background()
			if fault == "nil-context" {
				ctx = nil
			}
			if fault == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			calls := 0
			f.dynamic.PrependReactor("list", "persistentvolumeclaims", func(a clienttesting.Action) (bool, runtime.Object, error) {
				calls++
				la := a.(clienttesting.ListActionImpl)
				if la.ListOptions.LabelSelector != "" || la.ListOptions.FieldSelector != "" || la.ListOptions.Limit != pageLimit {
					t.Fatal("claim enumeration became filtered or unbounded")
				}
				if calls > 1 && fault == "partial-page" {
					return true, nil, errors.New("PRIVATE-CANARY")
				}
				page := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaimList", "metadata": map[string]any{"resourceVersion": "20"}}, Items: []unstructured.Unstructured{*f.lists["persistentvolumeclaims"][0].DeepCopy()}}
				switch fault {
				case "foreign-namespace":
					page.Items[0].SetNamespace("foreign")
				case "duplicate":
					page.Items = append(page.Items, *page.Items[0].DeepCopy())
				case "missing-uid":
					page.Items[0].SetUID("")
				case "wrong-kind":
					page.Items[0].SetKind("Secret")
				case "unknown-field":
					page.Items[0].Object["PRIVATE-CANARY"] = "unreviewed"
				case "partial-page":
					page.SetContinue("next")
				case "remaining":
					count := int64(1)
					page.SetRemainingItemCount(&count)
				case "page-rv":
					if calls == 1 {
						page.SetContinue("next")
					} else {
						page.SetResourceVersion("21")
					}
				case "journal-race":
					ns, err := f.core.CoreV1().Namespaces().Get(context.Background(), f.anchor.Namespace, metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					ns.ResourceVersion = "2"
					if _, err := f.core.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				return true, page, nil
			})
			observation, err := f.o.CollectClaims(ctx, f.anchor)
			if err == nil || observation != nil || strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatal("partial or foreign claims became recovery evidence")
			}
		})
	}
}
