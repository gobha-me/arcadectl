// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func retirementFixture(t *testing.T) (*lifecycleFixture, *installstate.Snapshot) {
	t.Helper()
	v, s := retirementReadyFixture(t)
	s = v.step(t, s)
	if s.Document().AdmissionRetirementRevision == 0 {
		t.Fatal("no durable access-retirement boundary")
	}
	return v, s
}

func TestAdmissionRetirementForegroundDeletionRemainsPendingUntilAbsent(t *testing.T) {
	v, s := retirementFixture(t)
	v.f.access.write = func(action installstate.Action, key installstate.Key, object *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		if action != installstate.Delete {
			t.Fatal("unexpected effect during access retirement")
		}
		now := metav1.Now()
		v.f.access.objects[key].SetDeletionTimestamp(&now)
		v.f.access.objects[key].SetFinalizers([]string{metav1.FinalizerDeleteDependents})
		return nil, nil
	}
	// Simulated GC cannot remove the original until this call returns. Bound
	// only the ACK-observation wait, not the later explicit recovery checks.
	ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
	defer cancel()
	next, err := v.l.Step(ctx, s, v.opts)
	if err == nil || next == nil || next.Document().Pending == nil {
		t.Fatal("foreground acceptance was treated as completed removal")
	}
	s = next
	writes, nsWrites := v.f.access.writes, v.f.nsUpdates
	next, err = v.l.Step(context.Background(), s, v.opts)
	if err == nil || next.Document().Pending == nil || !bytes.Equal(next.Bytes(), s.Bytes()) || v.f.access.writes != writes || v.f.nsUpdates != nsWrites {
		t.Fatal("deleting original access was replayed or prematurely settled")
	}
	delete(v.f.access.objects, s.Document().Pending.Key) // native GC finally settles
	s = v.step(t, s)
	if s.Document().Pending != nil || v.f.access.writes != writes {
		t.Fatal("actual original absence did not settle observation-only recovery")
	}
}

func retirementReadyFixture(t *testing.T) (*lifecycleFixture, *installstate.Snapshot) {
	t.Helper()
	v := newLifecycleFixture(t)
	s := v.finish(t, v.f.snapshot)
	var err error
	s, err = v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		d := s.Document()
		if d.Stage == installstate.Applying && !slices.ContainsFunc(d.Resources, func(r installstate.Resource) bool { return !r.Retained && !accessRetirementKey(r.Key) }) {
			return v, s
		}
		s = v.step(t, s)
	}
	t.Fatal("did not reach live pre-retirement barrier")
	return v, s
}

func TestAdmissionRetirementFailureBeforeLatchHasNoEffect(t *testing.T) {
	for _, scenario := range []string{"behavior", "cold", "runtime", "receipt-durability", "changed-during-proof"} {
		t.Run(scenario, func(t *testing.T) {
			v, s := retirementReadyFixture(t)
			switch scenario {
			case "behavior":
				v.fail = AdmissionEffective
			case "cold":
				v.fail = ColdSafety
			case "runtime":
				v.fail = RuntimeStopped
			default:
				proofCount := 0
				v.probe = func(request LifecycleCheck) error {
					if request.Checkpoint == AdmissionEffective {
						if scenario == "receipt-durability" {
							_ = v.f.engine.files.Close()
						} else {
							proofCount++
							for key, object := range v.f.access.objects {
								if key.Kind == "ValidatingAdmissionPolicy" {
									object.SetResourceVersion(fmt.Sprint(900000 + proofCount))
									break
								}
							}
						}
					}
					return nil
				}
			}
			writes, nsWrites := v.f.access.writes, v.f.nsUpdates
			next, err := v.l.Step(context.Background(), s, v.opts)
			if err == nil || next == nil || next.Document().AdmissionRetirementRevision != 0 || !bytes.Equal(s.Bytes(), next.Bytes()) || v.f.access.writes != writes || v.f.nsUpdates != nsWrites {
				t.Fatal("failed pre-removal evidence withdrew access or latched success")
			}
		})
	}
}

// Production HTTPS providers and observer, with inert fixture responses. This
// is not native Kubernetes authorization, CSI or a whole installer lifecycle.
func TestAdmissionRetirementClosedProvidersObservePendingAccessDeletion(t *testing.T) {
	v, s := retirementFixture(t)
	originalWrite := v.f.access.write
	v.f.access.write = func(action installstate.Action, key installstate.Key, object *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		if action == installstate.Delete {
			return nil, fmt.Errorf("lost acknowledgement")
		}
		return originalWrite(action, key, object)
	}
	next, err := v.l.Step(context.Background(), s, v.opts)
	if !errors.Is(err, ErrOutcomeUnknown) || next.Document().Pending == nil {
		t.Fatal("no original pending access withdrawal")
	}
	s = next
	delete(v.f.access.objects, s.Document().Pending.Key)
	namespace, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), s.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	access := quiescenceServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("post-retirement observation attempted a write/probe")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		for _, gv := range proofGroups {
			path := "/apis/" + gv
			if gv == "v1" {
				path = "/api/v1"
			}
			if r.URL.Path != path {
				continue
			}
			resources := []metav1.APIResource{}
			seen := map[string]bool{}
			for _, resource := range v.f.plan.Resources() {
				key := resourceKey(resource)
				if key.APIVersion != gv {
					continue
				}
				collection, err := resourcePath(key, true)
				if err != nil {
					t.Error(err)
					return
				}
				plural := collection[strings.LastIndex(collection, "/")+1:]
				if !seen[plural] {
					resources = append(resources, metav1.APIResource{Name: plural, Kind: key.Kind, Namespaced: key.Namespace != "", Verbs: metav1.Verbs{"get", "list"}})
					seen[plural] = true
				}
			}
			if gv == "v1" {
				resources = append(resources, metav1.APIResource{Name: "secrets", Kind: "Secret", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}})
			}
			_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
			return
		}
		if r.URL.Path == "/api/v1/namespaces/"+namespace.Name {
			n := namespace.DeepCopy()
			n.APIVersion, n.Kind = "v1", "Namespace"
			encodeStoppedObject(t, w, r, servingObject(t, n))
			return
		}
		for _, collection := range proofCollections {
			path := "/apis/" + collection.gv
			if collection.gv == "v1" {
				path = "/api/v1"
			}
			if collection.namespaced {
				path += "/namespaces/" + namespace.Name
			}
			path += "/" + collection.plural
			if r.URL.Path != path {
				continue
			}
			items := []any{}
			for key, object := range v.f.access.objects {
				if key.Kind == collection.kind {
					items = append(items, object.DeepCopy().Object)
				}
			}
			gv, kind := collection.gv, collection.kind+"List"
			if collection.kind == "Secret" {
				gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
				for _, secret := range v.private.objects {
					object := servingObject(t, secret)
					items = append(items, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": object.Object["metadata"]})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
			return
		}
		for key, object := range v.f.access.objects {
			path, err := resourcePath(key, false)
			if err == nil && r.URL.Path == path {
				encodeStoppedObject(t, w, r, object.DeepCopy())
				return
			}
		}
		for _, secret := range v.private.objects {
			if r.URL.Path == "/api/v1/namespaces/"+namespace.Name+"/secrets/"+secret.Name {
				object := servingObject(t, secret)
				_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": object.Object["metadata"]})
				return
			}
		}
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: 404})
	})
	store, err := installstate.New(access.Namespaces(), v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	input, err := store.Load(context.Background(), s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	request := LifecycleCheck{Checkpoint: RetainedAdmission, Snapshot: input, Mode: installstate.Uninstall, Target: v.f.plan, Options: v.opts}
	admission, err := NewClusterAdmission(engine, access)
	if err != nil || admission.VerifyRetained(context.Background(), request) != nil {
		t.Fatal("closed retained-admission provider rejected original pending withdrawal", err)
	}
	q, err := NewClusterQuiescence(p)
	request.Checkpoint = RuntimeStopped
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Verify(context.Background(), request); err != nil {
		observation, readErr := p.observe(context.Background(), request)
		var stoppedErr error
		if readErr == nil {
			_, stoppedErr = engine.stopped(context.Background(), request, observation)
		}
		t.Fatal("closed runtime observer rejected original pending access withdrawal", err, readErr, stoppedErr)
	}
	cold, err := NewClusterCold(p)
	request.Checkpoint = ColdSafety
	if err != nil {
		t.Fatal(err)
	}
	if err := cold.Verify(context.Background(), request); err != nil {
		t.Fatal("closed cold observer rejected original pending access withdrawal", err)
	}
}

func TestAdmissionRetirementRejectsMissingCorruptOrChangedEvidence(t *testing.T) {
	for _, scenario := range []string{"receipt-missing", "receipt-changed", "receipt-store-closed", "policy-uid", "policy-rv", "binding-rv", "policy-health", "policy-spec", "read-failure", "journal-marker"} {
		t.Run(scenario, func(t *testing.T) {
			v, s := retirementFixture(t)
			d := s.Document()
			switch scenario {
			case "receipt-missing":
				base := t.TempDir()
				if err := os.Chmod(base, 0700); err != nil {
					t.Fatal(err)
				}
				files, err := privatefs.Open(base, false)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = files.Close() })
				v.f.engine.files = files
			case "receipt-changed":
				name := retirementName(d, d.AdmissionRetirementRevision)
				_, identity, err := v.f.engine.files.Read(name, retirementMaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := v.f.engine.files.AtomicWrite(name, []byte("{}"), &identity); err != nil {
					t.Fatal(err)
				}
			case "receipt-store-closed":
				_ = v.f.engine.files.Close()
			case "read-failure":
				v.f.access.get = func(key installstate.Key) error {
					if key.Kind == "ValidatingAdmissionPolicy" {
						return fmt.Errorf("PRIVATE-CANARY")
					}
					return nil
				}
			case "journal-marker":
				d.AdmissionRetirementRevision--
				d.Revision++
				if _, err := v.f.store.Commit(context.Background(), s, d); err == nil {
					t.Fatal("retirement evidence can be replaced")
				}
				return
			default:
				kind := "ValidatingAdmissionPolicy"
				if scenario == "binding-rv" {
					kind = "ValidatingAdmissionPolicyBinding"
				}
				for key, object := range v.f.access.objects {
					if key.Kind != kind {
						continue
					}
					switch scenario {
					case "policy-uid":
						object.SetUID("replacement")
					case "policy-rv", "binding-rv":
						object.SetResourceVersion("9876543")
					case "policy-health":
						_ = unstructured.SetNestedField(object.Object, int64(0), "status", "observedGeneration")
					case "policy-spec":
						_ = unstructured.SetNestedField(object.Object, "Ignore", "spec", "failurePolicy")
					}
					break
				}
			}
			writes, nsWrites := v.f.access.writes, v.f.nsUpdates
			before := s.Bytes()
			if err := v.f.engine.verifyRetiredAdmission(context.Background(), s); err == nil {
				t.Fatal("unproved retired protection accepted")
			}
			next, err := v.l.Step(context.Background(), s, v.opts)
			if err == nil || next == nil || !bytes.Equal(next.Bytes(), before) || v.f.access.writes != writes || v.f.nsUpdates != nsWrites {
				t.Fatal("failed retirement evidence changed authority")
			}
		})
	}
}

func TestAdmissionRetirementRejectsRecreatedWithdrawnAccess(t *testing.T) {
	for _, kind := range []string{"ClusterRoleBinding", "RoleBinding", "Role", "ServiceAccount"} {
		t.Run(kind, func(t *testing.T) {
			v, s := retirementFixture(t)
			var key installstate.Key
			var original *unstructured.Unstructured
			for candidate, object := range v.f.access.objects {
				if candidate.Kind == kind {
					key, original = candidate, object.DeepCopy()
					break
				}
			}
			if original == nil {
				t.Fatal("missing original access fixture")
			}
			for i := 0; i < 100; i++ {
				if entry, _ := v.f.engine.inventory(s.Document(), key); entry == nil {
					break
				}
				s = v.step(t, s)
			}
			original.SetUID("foreign-replacement")
			v.f.access.objects[key] = original
			writes, nsWrites := v.f.access.writes, v.f.nsUpdates
			if v.f.engine.verifyRetiredAdmission(context.Background(), s) == nil {
				t.Fatal("same-name recreated access passed retired observation")
			}
			if _, err := v.l.Step(context.Background(), s, v.opts); err == nil || v.f.access.writes != writes || v.f.nsUpdates != nsWrites {
				t.Fatal("recreated access did not block without effects")
			}
		})
	}
}

func TestAdmissionRetirementResumeRecoveryAndReplayBoundary(t *testing.T) {
	v, s := retirementFixture(t)
	firstRevision := s.Document().AdmissionRetirementRevision
	firstName := retirementName(s.Document(), firstRevision)
	oldReceipt, _, err := v.f.engine.files.Read(firstName, retirementMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	// One delete loses its response: restart must only observe original absence.
	originalWrite := v.f.access.write
	v.f.access.write = func(action installstate.Action, key installstate.Key, object *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		if action == installstate.Delete {
			return nil, fmt.Errorf("lost acknowledgement")
		}
		return originalWrite(action, key, object)
	}
	next, err := v.l.Step(context.Background(), s, v.opts)
	if !errors.Is(err, ErrOutcomeUnknown) || next.Document().Pending == nil {
		t.Fatal("lost delete did not retain exact pending intent")
	}
	s = next
	pendingKey := s.Document().Pending.Key
	delete(v.f.access.objects, pendingKey) // simulate the original request settling
	v.f.access.write = originalWrite
	v.l, err = NewLifecycleWithChecks(v.f.engine, v.l.secrets, v)
	if err != nil {
		t.Fatal(err)
	}
	writes := v.f.access.writes
	s, err = v.l.Step(context.Background(), s, v.opts)
	if err != nil {
		t.Fatalf("pending %s recovery: %v", pendingKey.Kind, err)
	}
	if v.f.access.writes != writes || s.Document().Pending != nil {
		t.Fatal("pending recovery reissued an effect")
	}
	s, err = v.l.stage(context.Background(), s, installstate.RecoveryRequired)
	if err != nil {
		t.Fatal(err)
	}
	v.fail = AdmissionEffective // retired identities must never be probed again
	s = v.finish(t, s)
	if s.Document().AdmissionRetirementRevision != firstRevision {
		t.Fatal("recovery replaced durable original evidence")
	}
	v.fail = 0
	s, err = v.l.Begin(context.Background(), s, installstate.Install, v.f.plan.Digest(), v.opts)
	if err != nil || s.Document().AdmissionRetirementRevision != 0 {
		t.Fatal("next operation did not clear only the completed marker")
	}
	s = v.finish(t, s)
	s, err = v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && s.Document().AdmissionRetirementRevision == 0; i++ {
		s = v.step(t, s)
	}
	if s.Document().AdmissionRetirementRevision <= firstRevision {
		t.Fatal("second uninstall reused an old receipt revision")
	}
	name := retirementName(s.Document(), s.Document().AdmissionRetirementRevision)
	_, identity, err := v.f.engine.files.Read(name, retirementMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.f.engine.files.AtomicWrite(name, oldReceipt, &identity); err != nil {
		t.Fatal(err)
	}
	if v.f.engine.verifyRetiredAdmission(context.Background(), s) == nil {
		t.Fatal("previous uninstall proof certified recreated runtime access")
	}
}
