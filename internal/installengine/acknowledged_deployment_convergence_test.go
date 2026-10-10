// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Explicit synthetic TLS effect fixture, not native lifecycle certification.
// The normal whole-provider responder remains read-only unless this is opted in.
type baselineBehaviorEffectFixture struct {
	namespace                                       *corev1.Namespace
	family                                          map[installstate.Key]*unstructured.Unstructured
	final                                           map[installstate.Key]*unstructured.Unstructured
	raw                                             *unstructured.Unstructured
	resource                                        installstate.Resource
	podName                                         string
	preview                                         *unstructured.Unstructured
	intent                                          installstate.Document
	engine                                          *Engine
	failure                                         string
	injected                                        bool
	lastChange, lastCollection, quietCollection     time.Time
	proofOpening                                    bool
	postCreateRules                                 int
	previews, creates, namespaceWrites, collections int
}

func (f *baselineBehaviorEffectFixture) prepare(t *testing.T, d *installstate.Document, objects map[installstate.Key]*unstructured.Unstructured, plan *installrender.Plan) {
	t.Helper()
	d.Stage = installstate.Applying
	key := deploymentKey(d.Namespace, "arcadectl-api")
	f.family = map[installstate.Key]*unstructured.Unstructured{}
	for k, object := range objects {
		account, _, _ := unstructured.NestedString(object.Object, "spec", "serviceAccountName")
		owners := object.GetOwnerReferences()
		if k == key || k.Kind == "ReplicaSet" && len(owners) == 1 && owners[0].Name == key.Name || k.Kind == "Pod" && account == key.Name {
			f.family[k] = object.DeepCopy()
			delete(objects, k)
			if k.Kind == "Pod" {
				f.podName = k.Name
			}
		}
	}
	resources := []installstate.Resource{}
	for _, resource := range d.Resources {
		if resource.Key == key {
			f.resource = resource
		} else {
			resources = append(resources, resource)
		}
	}
	d.Resources = resources
	for _, resource := range plan.Resources() {
		if baselineObjectKey(resource.Object) == key {
			f.raw = resource.Object.DeepCopy()
		}
	}
	if len(f.family) != 3 || f.raw == nil || f.resource.UID == "" || f.podName == "" || d.Pending != nil {
		t.Fatal("explicit missing API parent fixture unavailable")
	}
}

func (f *baselineBehaviorEffectFixture) serve(t *testing.T, w http.ResponseWriter, r *http.Request, objects map[installstate.Key]*unstructured.Unstructured) bool {
	key := f.resource.Key
	if f.creates == 1 && !f.proofOpening && r.Method == http.MethodGet {
		for _, path := range []string{"/api/v1/namespaces/" + key.Namespace + "/pods", "/apis/apps/v1/namespaces/" + key.Namespace + "/deployments", "/apis/apps/v1/namespaces/" + key.Namespace + "/replicasets", "/apis/batch/v1/namespaces/" + key.Namespace + "/jobs", "/apis/apps/v1/namespaces/" + key.Namespace + "/statefulsets", "/apis/apps/v1/namespaces/" + key.Namespace + "/daemonsets", "/api/v1/namespaces/" + key.Namespace + "/replicationcontrollers", "/apis/batch/v1/namespaces/" + key.Namespace + "/cronjobs"} {
			if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/") {
				f.lastCollection = time.Now()
				break
			}
		}
	}
	if f.creates == 1 && r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" {
		f.postCreateRules++
		if f.failure == "receipt-after-wait" && !f.injected {
			f.replaceReceipt(t)
		}
	}
	if f.failure == "late-status" && !f.injected && f.postCreateRules == 2 && r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" && r.Header.Get("Impersonate-User") != "" {
		objects[key].SetResourceVersion("200")
		objects[key].Object["status"] = map[string]any{"observedGeneration": int64(1), "replicas": int64(0)}
		f.injected = true
	}
	if r.Method == http.MethodGet && f.creates == 1 && r.URL.Path == "/api/v1/namespaces/"+key.Namespace+"/pods" {
		f.collections++
		f.lastCollection = time.Now()
		// Each complete LIST/GET cycle is internally coherent. Changes occur
		// between cycles, exactly where the native denied-window check refuses.
		if f.collections <= 3 {
			for k, original := range f.family {
				if objects[k] == nil {
					objects[k] = original.DeepCopy()
				}
				objects[k].SetResourceVersion(strconv.Itoa(100 + f.collections))
			}
			objects[key].Object["status"] = map[string]any{"observedGeneration": int64(1), "replicas": int64(f.collections % 2)}
			f.lastChange = time.Now()
		}
		if f.collections == 2 && !f.injected {
			switch f.failure {
			case "receipt-in-wait":
				f.replaceReceipt(t)
			case "journal-in-wait":
				var doc installstate.Document
				if json.Unmarshal([]byte(f.namespace.Annotations[installstate.Annotation]), &doc) != nil {
					t.Error("original concurrent journal unavailable")
				}
				doc.Revision++
				body, err := json.Marshal(doc)
				if err != nil {
					t.Error("concurrent journal fixture encoding")
				}
				f.namespace.Annotations[installstate.Annotation] = string(body)
				f.namespace.ResourceVersion = "200"
				f.injected = true
			case "wrong-live-uid":
				objects[key].SetUID("foreign-same-name-parent")
				f.injected = true
			case "changed-live-template":
				_ = unstructured.SetNestedField(objects[key].Object, "foreign-account", "spec", "template", "spec", "serviceAccountName")
				f.injected = true
			}
		}
		return false
	}
	if r.Header.Get("Impersonate-User") != "" {
		return false
	}
	if r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+key.Namespace {
		var candidate corev1.Namespace
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if r.URL.RawQuery != "fieldValidation=Strict" || decoder.Decode(&candidate) != nil {
			t.Error("effect fixture Namespace CAS envelope malformed")
			w.WriteHeader(500)
			return true
		}
		var before, after installstate.Document
		if json.Unmarshal([]byte(f.namespace.Annotations[installstate.Annotation]), &before) != nil || json.Unmarshal([]byte(candidate.Annotations[installstate.Annotation]), &after) != nil {
			t.Error("effect fixture original journal unavailable")
			w.WriteHeader(500)
			return true
		}
		want := before
		want.Revision++
		switch f.namespaceWrites {
		case 0:
			if after.Pending == nil || len(after.Pending.CreateNonce) != 32 {
				t.Error("actual CREATE intent missing nonce")
				w.WriteHeader(500)
				return true
			}
			if _, err := hex.DecodeString(after.Pending.CreateNonce); err != nil || strings.ToLower(after.Pending.CreateNonce) != after.Pending.CreateNonce {
				t.Error("actual CREATE nonce is not canonical hexadecimal")
				w.WriteHeader(500)
				return true
			}
			want.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: after.Pending.CreateNonce, AfterSHA256: f.resource.TemplateSHA256}
		case 1:
			if f.creates != 1 || before.Pending == nil {
				t.Error("settlement preceded the one actual CREATE")
				w.WriteHeader(500)
				return true
			}
			want.Pending = nil
			want.Resources = append(append([]installstate.Resource(nil), before.Resources...), f.resource)
			installstate.SortResources(want.Resources)
		default:
			t.Error("effect fixture observed repeated Namespace mutation")
			w.WriteHeader(500)
			return true
		}
		copy := candidate.DeepCopy()
		copy.Annotations[installstate.Annotation] = f.namespace.Annotations[installstate.Annotation]
		original := f.namespace.DeepCopy()
		original.APIVersion, original.Kind = "v1", "Namespace"
		if !reflect.DeepEqual(want, after) || !reflect.DeepEqual(copy, original) {
			t.Error("effect fixture CAS changed unrelated original journal/Namespace")
			w.WriteHeader(500)
			return true
		}
		rv, err := strconv.ParseUint(original.ResourceVersion, 10, 64)
		if err != nil {
			t.Error("original Namespace RV malformed")
			w.WriteHeader(500)
			return true
		}
		candidate.ResourceVersion = strconv.FormatUint(rv+1, 10)
		if f.namespaceWrites == 0 {
			f.intent = after
		}
		f.namespace = candidate.DeepCopy()
		f.namespaceWrites++
		if f.namespaceWrites == 2 {
			f.final = map[installstate.Key]*unstructured.Unstructured{}
			for k := range f.family {
				if objects[k] != nil {
					f.final[k] = objects[k].DeepCopy()
				}
			}
		}
		if f.namespaceWrites == 2 && f.failure == "receipt-at-settlement" && !f.injected {
			f.replaceReceipt(t)
		}
		_ = json.NewEncoder(w).Encode(candidate)
		return true
	}
	if r.Method != http.MethodPost || r.URL.Path != "/apis/apps/v1/namespaces/"+key.Namespace+"/deployments" {
		return false
	}
	var candidate unstructured.Unstructured
	if json.NewDecoder(r.Body).Decode(&candidate.Object) != nil {
		t.Error("actual original Deployment CREATE malformed")
		w.WriteHeader(500)
		return true
	}
	var doc installstate.Document
	_ = json.Unmarshal([]byte(f.namespace.Annotations[installstate.Annotation]), &doc)
	want := f.raw.DeepCopy()
	annotations := want.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[installstate.MutationAnnotation] = candidate.GetAnnotations()[installstate.MutationAnnotation]
	want.SetAnnotations(annotations)
	query := "fieldValidation=Strict"
	dry := r.URL.Query().Get("dryRun") == "All"
	if dry {
		query = "dryRun=All&" + query
	}
	if r.URL.RawQuery != query || !testBaselineBehaviorJSONEqual(want.Object, candidate.Object) || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" || len(annotations[installstate.MutationAnnotation]) != 32 {
		t.Error("actual CREATE escaped literal signed request")
		w.WriteHeader(500)
		return true
	}
	ack := f.family[key].DeepCopy()
	ack.SetAnnotations(candidate.GetAnnotations())
	if dry {
		if f.previews != 0 || f.creates != 0 || doc.Pending != nil {
			t.Error("original preview repeated or followed intent")
		}
		f.previews++
		f.preview = candidate.DeepCopy()
	} else {
		if f.creates != 0 || f.previews != 1 || doc.Pending == nil || doc.Pending.Key != key || doc.Pending.Action != installstate.Create || doc.Pending.CreateNonce != annotations[installstate.MutationAnnotation] || !testBaselineBehaviorJSONEqual(f.preview.Object, candidate.Object) {
			t.Error("persistent CREATE did not follow exact original intent/preview once")
			w.WriteHeader(500)
			return true
		}
		f.creates++
		f.family[key] = ack.DeepCopy()
		objects[key] = ack.DeepCopy()
		if f.failure == "ambiguous-response" {
			f.injected = true
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ack.Object)
	return true
}

func (f *baselineBehaviorEffectFixture) replaceReceipt(t *testing.T) {
	t.Helper()
	name := "create-" + f.intent.Pending.CreateNonce + ".json"
	body, identity, err := f.engine.files.Read(name, 4096)
	if err != nil {
		t.Error("original ACK receipt unavailable for replacement control")
		return
	}
	if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
		t.Error("identical ACK receipt replacement unavailable")
		return
	}
	f.injected = true
}

func TestAcknowledgedDeploymentConvergesBeforeOriginalRecoveryProof(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "")
}

func TestAcknowledgedDeploymentRejectsLateWholeStatusDrift(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "late-status")
}

func TestAcknowledgedDeploymentRejectsReceiptReplacementDuringWait(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "receipt-in-wait")
}

func TestAcknowledgedDeploymentRejectsReceiptReplacementDuringProof(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "receipt-after-wait")
}

func TestAcknowledgedDeploymentRejectsReceiptReplacementDuringSettlement(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "receipt-at-settlement")
}

func TestAcknowledgedDeploymentRejectsStaleJournalDuringWait(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "journal-in-wait")
}

func TestAcknowledgedDeploymentRejectsForeignUIDDuringWait(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "wrong-live-uid")
}

func TestAcknowledgedDeploymentRejectsUnsignedTemplateDuringWait(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "changed-live-template")
}

func TestAcknowledgedDeploymentDoesNotWaitOrReplayAmbiguousOutcome(t *testing.T) {
	testAcknowledgedDeploymentConvergence(t, "ambiguous-response")
}

func testAcknowledgedDeploymentConvergence(t *testing.T, failure string) {
	t.Helper()
	fixture := &baselineBehaviorEffectFixture{failure: failure}
	testBaselineBehaviorWholeProviderComposition(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		fixture.engine = engine
		original := snapshot.Document()
		if original.Pending != nil || fixture.intent.Pending != nil || fixture.previews != 0 || fixture.creates != 0 || fixture.namespaceWrites != 0 {
			t.Fatal("CREATE regression did not start before genuine intent/effect/ACK")
		}
		if recorded, _ := engine.inventory(original, fixture.resource.Key); recorded != nil {
			t.Fatal("CREATE regression started with an already-recorded API parent")
		}
		ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
		settled, err := engine.Apply(ctx, snapshot, fixture.resource.Key, snapshot.Document().TargetPackage, false)
		if settled == nil || fixture.previews != 1 || fixture.creates != 1 || failure != "" && !fixture.injected {
			t.Fatalf("actual ACK/effect recovery did not await quiet original inventory: %s", diagnostic.BoundarySnapshot())
		}
		if failure != "" && err != ErrOutcomeUnknown || failure == "" && err != nil {
			t.Fatalf("actual ACK convergence confused success and original refusal: %s", diagnostic.BoundarySnapshot())
		}
		var live installstate.Document
		_ = json.Unmarshal([]byte(fixture.namespace.Annotations[installstate.Annotation]), &live)
		completedCAS := failure == "" || failure == "receipt-at-settlement"
		if completedCAS {
			if fixture.namespaceWrites != 2 || !reflect.DeepEqual(settled.Document(), live) || settled.Document().Pending != nil || settled.Document().Revision != original.Revision+2 {
				t.Fatal("actual settlement did not preserve completed original CAS outcome")
			}
		} else if fixture.namespaceWrites != 1 || !reflect.DeepEqual(settled.Document(), fixture.intent) || settled.Document().Pending == nil || live.Pending == nil {
			t.Fatal("refused ACK handoff settled or replaced original Pending")
		}
		if failure == "late-status" && diagnostic.BoundarySnapshot() != "operation=recovery-opening baseline=denied-executables-stable" {
			t.Fatal("late whole drift no longer refused at the actual denied window")
		}
		if failure == "ambiguous-response" {
			if fixture.collections != 1 || fixture.postCreateRules != 0 {
				t.Fatal("unknown response entered ACK-only quiet/proof path")
			}
			resumed, resumeErr := engine.Recover(t.Context(), settled)
			if resumeErr != ErrOutcomeUnknown || resumed == nil || !reflect.DeepEqual(resumed.Document(), fixture.intent) || fixture.collections != 2 || fixture.previews != 1 || fixture.creates != 1 || fixture.namespaceWrites != 1 {
				t.Fatal("public restarted recovery manufactured ACK, waited or replayed effect")
			}
		}
		uid, receiptErr := engine.loadCreateUID(fixture.intent)
		if failure == "ambiguous-response" {
			if receiptErr == nil || uid != "" {
				t.Fatal("unknown response manufactured durable original UID")
			}
		} else if receiptErr != nil || uid != fixture.resource.UID {
			t.Fatal("actual CREATE lost original durable ACK identity")
		}
		if testBaselineReceiptDescriptors(t, "create-"+fixture.intent.Pending.CreateNonce+".json") != 0 {
			t.Fatal("actual CREATE did not retain the original durable ACK or release its pins")
		}
		// No Ready predicate is used: quiet original non-Ready processes remain
		// valid baseline subjects, not authenticated serving or effect authority.
		if completedCAS {
			var deploymentReady int64
			if len(fixture.final) != 3 || fixture.final[fixture.resource.Key] == nil {
				t.Fatal("actual served final family unavailable")
			}
			deploymentReady, _, _ = unstructured.NestedInt64(fixture.final[fixture.resource.Key].Object, "status", "availableReplicas")
			if deploymentReady != 0 || fixture.quietCollection.IsZero() || fixture.quietCollection.Sub(fixture.lastChange) < 5*time.Second {
				t.Fatal("quiet handoff omitted its interval or required availability")
			}
			for key, object := range fixture.final {
				if key.Kind == "Pod" {
					var pod corev1.Pod
					if decodeServing(object, &pod) != nil || readyNamedPod(&pod, pod.Spec.Containers[0].Name) {
						t.Fatal("quiet baseline test lost non-Ready Pod coverage")
					}
				}
			}
		}
		return nil
	}, nil, fixture)
}
