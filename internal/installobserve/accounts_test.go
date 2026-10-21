// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestServiceAccountsCompleteBoundedAndCopied(t *testing.T) {
	for _, scenario := range []string{"empty", "one", "pages", "partial", "rv-drift", "cycle", "remaining", "duplicate-name", "duplicate-uid", "wrong-kind", "wrong-namespace", "unknown", "cancelled", "journal-change"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			f.dynamic = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{{Version: "v1", Resource: "serviceaccounts"}: "ServiceAccountList"})
			f.o.clients.Dynamic = f.dynamic
			before, err := f.o.journal.Load(t.Context(), f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			f.dynamic.PrependReactor("list", "serviceaccounts", func(action clienttesting.Action) (bool, runtime.Object, error) {
				requests++
				opts := action.(clienttesting.ListActionImpl).ListOptions
				if action.GetNamespace() != f.anchor.Namespace || opts.Limit != pageLimit || opts.LabelSelector != "" || opts.FieldSelector != "" || opts.ResourceVersion != "" {
					t.Fatal("account read escaped complete current collection")
				}
				list := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccountList", "metadata": map[string]any{"resourceVersion": "100"}}, Items: []unstructured.Unstructured{}}
				item := unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "default", "namespace": f.anchor.Namespace, "uid": "account-uid", "resourceVersion": "90"}, "automountServiceAccountToken": false}}
				if scenario != "empty" {
					list.Items = append(list.Items, item)
				}
				switch scenario {
				case "pages", "partial", "rv-drift":
					if requests == 1 {
						list.SetContinue("page-two")
						list.SetRemainingItemCount(new(int64(1)))
					} else {
						if opts.Continue != "page-two" {
							t.Fatal("continuation discarded")
						}
						if scenario == "partial" {
							return true, nil, errors.New("private failure")
						}
						list.Items[0].SetName("second")
						list.Items[0].SetUID("second-uid")
						if scenario == "rv-drift" {
							list.SetResourceVersion("101")
						}
					}
				case "cycle":
					list.Items = nil
					list.SetContinue("same")
				case "remaining":
					list.SetRemainingItemCount(new(int64(1)))
				case "duplicate-name":
					second := item.DeepCopy()
					second.SetUID("second-uid")
					list.Items = append(list.Items, *second)
				case "duplicate-uid":
					second := item.DeepCopy()
					second.SetName("second")
					list.Items = append(list.Items, *second)
				case "wrong-kind":
					list.Items[0].SetKind("Pod")
				case "wrong-namespace":
					list.Items[0].SetNamespace("foreign")
				case "unknown":
					list.Items[0].Object["private"] = true
				case "journal-change":
					ns, e := f.core.CoreV1().Namespaces().Get(t.Context(), f.anchor.Namespace, metav1.GetOptions{})
					if e != nil {
						t.Fatal(e)
					}
					ns.ResourceVersion = "2"
					if _, e = f.core.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{}); e != nil {
						t.Fatal(e)
					}
				}
				return true, list, nil
			})
			ctx := t.Context()
			if scenario == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			observation, err := f.o.CollectServiceAccounts(ctx, f.anchor)
			positive := scenario == "empty" || scenario == "one" || scenario == "pages"
			if !positive {
				if err == nil || observation != nil {
					t.Fatal("incomplete accounts accepted")
				}
				return
			}
			if err != nil || observation == nil || observation.Journal().ResourceVersion() != before.ResourceVersion() {
				t.Fatal("complete accounts refused", err)
			}
			count := 1
			if scenario == "empty" {
				count = 0
			}
			if scenario == "pages" {
				count = 2
			}
			if len(observation.Accounts().Items) != count || len(observation.Whole()) != count {
				t.Fatal("collection omitted members")
			}
			if count > 0 {
				observation.Accounts().Items[0].Name = "changed"
				observation.Whole()[0].SetName("changed")
				if observation.Accounts().Items[0].Name != "default" || observation.Whole()[0].GetName() != "default" {
					t.Fatal("mutable alias escaped")
				}
			}
		})
	}
}
