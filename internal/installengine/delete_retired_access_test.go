// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func testRetiredAccessOriginalEnvelope(t *testing.T) {
	plan := fixturePlan(t)
	contract, err := installcontract.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, resource := range plan.Resources() {
		key := resourceKey(resource)
		if !accessRetirementKey(key) || seen[key.Kind] {
			continue
		}
		seen[key.Kind] = true
		t.Run(key.Kind, func(t *testing.T) {
			before, err := contract.Template(key, false)
			if err != nil {
				t.Fatal(err)
			}
			original, err := before.Candidate(strings.Repeat("a", 32))
			if err != nil {
				t.Fatal(err)
			}
			original.SetUID("original-access")
			original.SetResourceVersion("41")
			pending := installstate.Pending{Action: installstate.Delete, Key: key, BeforeUID: original.GetUID(), BeforeResourceVersion: "41", BeforeSHA256: before.Hash(), CreateNonce: strings.Repeat("b", 32)}
			if !retiredAccessDeletingOriginal(before, &pending, original) {
				t.Fatal("unchanged original before native deletion not recognized")
			}
			for _, fault := range []string{"none", "uid", "name", "api", "kind", "namespace", "same-rv", "malformed-rv", "unknown-field", "unknown-metadata", "bad-grace", "nonzero-grace", "zero-stamp", "no-finalizer", "extra-finalizer", "foreign-finalizer", "label", "owner", "body", "pending-action", "pending-hash", "pending-nonce", "pending-rv", "pending-after"} {
				t.Run(fault, func(t *testing.T) {
					live, p := original.DeepCopy(), pending
					stamp := metav1.Now()
					live.SetResourceVersion("42")
					live.SetDeletionTimestamp(&stamp)
					live.SetFinalizers([]string{metav1.FinalizerDeleteDependents})
					switch fault {
					case "uid":
						live.SetUID("foreign")
					case "name":
						live.SetName("foreign")
					case "api":
						live.SetAPIVersion("foreign/v1")
					case "kind":
						live.SetKind("Pod")
					case "namespace":
						live.SetNamespace("foreign")
					case "same-rv":
						live.SetResourceVersion("41")
					case "malformed-rv":
						live.SetResourceVersion("042")
					case "unknown-field":
						live.Object["foreign"] = true
					case "unknown-metadata":
						_ = unstructured.SetNestedField(live.Object, true, "metadata", "foreign")
					case "bad-grace":
						_ = unstructured.SetNestedField(live.Object, "invalid", "metadata", "deletionGracePeriodSeconds")
					case "nonzero-grace":
						_ = unstructured.SetNestedField(live.Object, int64(1), "metadata", "deletionGracePeriodSeconds")
					case "zero-stamp":
						_ = unstructured.SetNestedField(live.Object, "0001-01-01T00:00:00Z", "metadata", "deletionTimestamp")
					case "no-finalizer":
						live.SetFinalizers(nil)
					case "extra-finalizer":
						live.SetFinalizers([]string{metav1.FinalizerDeleteDependents, "foreign"})
					case "foreign-finalizer":
						live.SetFinalizers([]string{"foreign"})
					case "label":
						live.SetLabels(map[string]string{"foreign": "true"})
					case "owner":
						live.SetOwnerReferences([]metav1.OwnerReference{{UID: "foreign"}})
					case "body":
						if key.Kind == "ServiceAccount" {
							live.Object["automountServiceAccountToken"] = true
						} else if strings.HasSuffix(key.Kind, "Binding") {
							live.Object["subjects"] = []any{}
						} else {
							live.Object["rules"] = []any{}
						}
					case "pending-action":
						p.Action = installstate.Update
					case "pending-hash":
						p.BeforeSHA256 = strings.Repeat("f", 64)
					case "pending-nonce":
						p.CreateNonce = "foreign"
					case "pending-rv":
						p.BeforeResourceVersion = ""
					case "pending-after":
						p.AfterSHA256 = before.Hash()
					}
					body, _ := json.Marshal(live)
					if retiredAccessDeletingOriginal(before, &p, live) != (fault == "none") {
						t.Fatal("foreground comparison changed the original full-object boundary")
					}
					after, _ := json.Marshal(live)
					if !bytes.Equal(body, after) || before.MatchLive(live, pending.BeforeUID) == nil {
						t.Fatal("comparison mutated input or relaxed general MatchLive")
					}
				})
			}
		})
	}
	if len(seen) != 5 {
		t.Fatal("not all five signed retirement families tested")
	}
}

// Actual lifecycle intent, one DELETE, and settlement CAS with trusted fixture
// providers. This is not native Kubernetes or full closed HTTP-provider proof.
func testRetiredAccessACKConvergence(t *testing.T) {
	for _, kind := range []string{"ClusterRoleBinding", "RoleBinding", "ClusterRole", "Role", "ServiceAccount"} {
		t.Run(kind, func(t *testing.T) {
			v, s := retirementFixture(t)
			var target installstate.Key
			var saved map[installstate.Key]*unstructured.Unstructured
			drainingReads, writes, namespaceWrites := 0, 0, 0
			v.f.access.write = func(action installstate.Action, key installstate.Key, _ *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				if action != installstate.Delete {
					t.Fatal("unexpected retirement effect")
				}
				if key.Kind != kind {
					delete(v.f.access.objects, key)
					return nil, nil
				}
				if target.Kind != "" {
					t.Fatal("acknowledged DELETE replayed")
				}
				target = key
				saved = map[installstate.Key]*unstructured.Unstructured{}
				for k, o := range v.f.access.objects {
					if k != key {
						saved[k] = o.DeepCopy()
					}
				}
				live := v.f.access.objects[key]
				rv, err := strconv.ParseUint(live.GetResourceVersion(), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				stamp := metav1.Now()
				live.SetResourceVersion(strconv.FormatUint(rv+1, 10))
				live.SetDeletionTimestamp(&stamp)
				live.SetFinalizers([]string{metav1.FinalizerDeleteDependents})
				return nil, nil
			}
			v.f.access.get = func(key installstate.Key) error {
				if target.Kind != "" && key == target {
					drainingReads++
					if drainingReads == 4 {
						delete(v.f.access.objects, key)
					}
				}
				return nil
			}
			for range 100 {
				writes, namespaceWrites = v.f.access.writes, v.f.nsUpdates
				before := s
				var err error
				s, err = v.l.Step(t.Context(), s, v.opts)
				if err != nil {
					t.Fatal("same acknowledged original did not converge", err)
				}
				if target.Kind == "" {
					continue
				}
				if s.Document().Pending != nil || s.Document().Revision != before.Document().Revision+2 || len(s.Document().Resources) != len(before.Document().Resources)-1 || v.f.access.writes != writes+1 || v.f.nsUpdates != namespaceWrites+2 || drainingReads < 4 || !reflect.DeepEqual(saved, v.f.access.objects) {
					t.Fatal("draining original was settled early, replayed, or changed unrelated resources")
				}
				return
			}
			t.Fatal("signed access family never reached")
		})
	}
}

func testRetiredAccessACKRefusals(t *testing.T) {
	for _, fault := range []string{"uid", "body", "foreign-finalizer", "read-denied", "journal", "policy", "receipt", "reappearance", "cancelled", "lost-ack"} {
		t.Run(fault, func(t *testing.T) {
			v, s := retirementFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var target installstate.Key
			var original *unstructured.Unstructured
			reads, deletes := 0, 0
			writes, namespaceWrites := v.f.access.writes, v.f.nsUpdates
			v.f.access.write = func(action installstate.Action, key installstate.Key, _ *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				if action != installstate.Delete || deletes != 0 {
					t.Fatal("retirement effect escaped single DELETE")
				}
				deletes++
				target = key
				live := v.f.access.objects[key]
				original = live.DeepCopy()
				rv, err := strconv.ParseUint(live.GetResourceVersion(), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				stamp := metav1.Now()
				live.SetResourceVersion(strconv.FormatUint(rv+1, 10))
				live.SetDeletionTimestamp(&stamp)
				live.SetFinalizers([]string{metav1.FinalizerDeleteDependents})
				if fault == "cancelled" {
					cancel()
				}
				if fault == "lost-ack" {
					return nil, ErrOutcomeUnknown
				}
				return nil, nil
			}
			v.f.access.get = func(key installstate.Key) error {
				if target.Kind == "" || key != target {
					return nil
				}
				reads++
				if reads == 1 {
					switch fault {
					case "uid":
						v.f.access.objects[key].SetUID("foreign-original")
					case "body":
						v.f.access.objects[key].SetLabels(map[string]string{"foreign": "true"})
					case "foreign-finalizer":
						v.f.access.objects[key].SetFinalizers([]string{"foreign"})
					case "read-denied":
						return ErrRead
					case "journal":
						ns, err := v.f.access.client.CoreV1().Namespaces().Get(t.Context(), s.Anchor().Namespace, metav1.GetOptions{})
						if err != nil {
							t.Fatal(err)
						}
						ns.ResourceVersion = "999999"
						if v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, "") != nil {
							t.Fatal("journal drift unavailable")
						}
					case "policy":
						for k, o := range v.f.access.objects {
							if k.Kind == "ValidatingAdmissionPolicy" {
								o.SetResourceVersion("999999")
								break
							}
						}
					case "receipt":
						name := retirementName(s.Document(), s.Document().AdmissionRetirementRevision)
						_, identity, err := v.f.engine.files.Read(name, retirementMaxBytes)
						if err != nil {
							t.Fatal(err)
						}
						if changed, err := v.f.engine.files.AtomicWrite(name, []byte("{}"), &identity); err != nil || changed == identity {
							t.Fatal("receipt replacement unavailable", err)
						}
					}
				}
				if reads == 3 && (fault == "policy" || fault == "receipt" || fault == "reappearance") {
					delete(v.f.access.objects, key)
				}
				if reads == 5 && fault == "reappearance" {
					v.f.access.objects[key] = original.DeepCopy()
				}
				return nil
			}
			next, err := v.l.Step(ctx, s, v.opts)
			if err == nil || next == nil || next.Document().Pending == nil || next.Document().Pending.Key != target || deletes != 1 || v.f.access.writes != writes+1 || v.f.nsUpdates != namespaceWrites+1 {
				t.Fatal("refused ACK preparation replayed or settled original intent", err)
			}
			ns, err := v.f.access.client.CoreV1().Namespaces().Get(t.Context(), s.Anchor().Namespace, metav1.GetOptions{})
			if err != nil || !bytes.Equal([]byte(ns.Annotations[installstate.Annotation]), next.Bytes()) {
				t.Fatal("refusal changed exact durable pending bytes", err)
			}
		})
	}
}
