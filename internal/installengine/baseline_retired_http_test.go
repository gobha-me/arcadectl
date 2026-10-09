// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// This explicitly synthetic receipt/status fixture exercises the WHOLE
// private read-only composition through its real HTTPS transports, journal,
// bounded executable reader and complete cold observer. It is not native
// authorization, effective admission, physical storage or installer proof.
// Preserve every original retired scenario as its own indivisible CI tree.
func TestBaselineRetiredHTTPSHealthy(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "healthy")
}

func TestBaselineRetiredHTTPSHarmlessTerminalPod(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "harmless-terminal-pod")
}

func TestBaselineRetiredHTTPSPartiallyWithdrawnOriginalAccess(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "partially-withdrawn-original-access")
}

func TestBaselineRetiredHTTPSPendingOriginalAccessDelete(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "pending-original-access-delete")
}

func TestBaselineRetiredHTTPSPendingAccessReplaced(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "pending-access-replaced")
}

func TestBaselineRetiredHTTPSReceiptReplacedBetweenCores(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "receipt-replaced-between-cores")
}

func TestBaselineRetiredHTTPSFirstColdReservedAlias(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "first-cold-reserved-alias")
}

func TestBaselineRetiredHTTPSSecondColdControllerImage(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "second-cold-controller-image")
}

func TestBaselineRetiredHTTPSOpeningRawControllerImage(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "opening-raw-controller-image")
}

func TestBaselineRetiredHTTPSClosingRawReservedName(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "closing-raw-reserved-name")
}

func TestBaselineRetiredHTTPSSecondColdWorldChange(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "second-cold-world-change")
}

func TestBaselineRetiredHTTPSLastListDenied(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "last-list-denied")
}

func TestBaselineRetiredHTTPSReviewDenied(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "review-denied")
}

func TestBaselineRetiredHTTPSLateListReviewDenied(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "late-list-review-denied")
}

func TestBaselineRetiredHTTPSLateGetReviewDenied(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "late-get-review-denied")
}

func TestBaselineRetiredHTTPSLateRuntimePolicyRv(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "late-runtime-policy-rv")
}

func TestBaselineRetiredHTTPSLateBaselinePolicyRv(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "late-baseline-policy-rv")
}

func TestBaselineRetiredHTTPSLateFixture(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "late-fixture")
}

func TestBaselineRetiredHTTPSLateJournal(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "late-journal")
}

func TestBaselineRetiredHTTPSCompleteHealthy(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-healthy")
}

func TestBaselineRetiredHTTPSCompleteListDenied(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-list-denied")
}

func TestBaselineRetiredHTTPSCompleteRootGetDenied(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-root-get-denied")
}

func TestBaselineRetiredHTTPSCompleteReceiptReplaced(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-receipt-replaced")
}

func TestBaselineRetiredHTTPSCompleteRemovedAccessRecreated(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-removed-access-recreated")
}

func TestBaselineRetiredHTTPSCompleteRetainedCrdReplaced(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-retained-crd-replaced")
}

func TestBaselineRetiredHTTPSCompleteRetainedSecretDeleting(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-retained-secret-deleting")
}

func TestBaselineRetiredHTTPSCompleteLateJournal(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-late-journal")
}

func TestBaselineRetiredHTTPSCompleteWorldChange(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "complete-world-change")
}

func TestBaselineRetiredHTTPSRuntimeHealthy(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "runtime-healthy")
}

func TestBaselineRetiredHTTPSRuntimePendingOriginalAccessDelete(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "runtime-pending-original-access-delete")
}

func TestBaselineRetiredHTTPSRuntimeReceiptReplacedBetweenCores(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "runtime-receipt-replaced-between-cores")
}

func TestBaselineRetiredHTTPSRuntimeCompleteHealthy(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "runtime-complete-healthy")
}

func TestBaselineRetiredHTTPSRuntimeCompleteReceiptReplaced(t *testing.T) {
	testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t, "runtime-complete-receipt-replaced")
}

func testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority(t *testing.T, testCase string) {
	t.Helper()
	runtime := strings.HasPrefix(testCase, "runtime-")
	scenario := strings.TrimPrefix(testCase, "runtime-")
	v, snapshot := retirementFixture(t)
	completed := strings.HasPrefix(scenario, "complete-")
	if completed {
		snapshot = v.finish(t, snapshot)
		if snapshot.Document().Installed || snapshot.Document().Stage != installstate.Complete || len(snapshot.Document().Resources) != 20 {
			t.Fatal("genuine completed retaining uninstall fixture unavailable")
		}
	}
	if scenario == "partially-withdrawn-original-access" {
		before := len(snapshot.Document().Resources)
		snapshot = v.step(t, snapshot)
		if snapshot.Document().Pending != nil || len(snapshot.Document().Resources) != before-1 {
			t.Fatal("settled original access withdrawal fixture unavailable")
		}
	}
	if scenario == "pending-original-access-delete" || scenario == "pending-access-replaced" {
		v.f.access.write = func(action installstate.Action, key installstate.Key, object *unstructured.Unstructured) (*unstructured.Unstructured, error) {
			return nil, fmt.Errorf("synthetic lost acknowledgement")
		}
		next, err := v.l.Step(t.Context(), snapshot, v.opts)
		if !errors.Is(err, ErrOutcomeUnknown) || next == nil || next.Document().Pending == nil || next.Document().Pending.Action != installstate.Delete {
			t.Fatal("original pending access DELETE fixture unavailable")
		}
		snapshot = next
		key := snapshot.Document().Pending.Key
		if scenario == "pending-access-replaced" {
			v.f.access.objects[key].SetUID("same-name-foreign-access")
		} else {
			delete(v.f.access.objects, key)
		}
	}
	baseline := baselineFixturePlan(t, v.f.plan.Namespace(), v.f.plan.Profile().ID, 'd')
	document := snapshot.Document()
	name := retirementName(document, document.AdmissionRetirementRevision)
	body, identity, err := v.f.engine.files.Read(name, retirementMaxBytes)
	if err != nil {
		t.Fatal("original receipt unavailable")
	}
	var receipt retirementReceipt
	if json.Unmarshal(body, &receipt) != nil {
		t.Fatal("original receipt invalid")
	}
	original, err := installstate.Decode(receipt.Journal, v.f.plan)
	if err != nil {
		t.Fatal("original journal invalid")
	}
	security := &installstate.SecurityBaseline{Version: installbaseline.Version, ArtifactDigest: baseline.Digest(), Stage: installstate.BaselineVerified, Resources: []installstate.BaselineResource{}}
	for index, resource := range baseline.Resources() {
		object := resource.Object.DeepCopy()
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
		entry := installstate.BaselineResource{Key: key, UID: types.UID(fmt.Sprintf("retired-http-baseline-%d", index)), TemplateSHA256: resource.TemplateSHA256}
		security.Resources = append(security.Resources, entry)
		object.SetUID(entry.UID)
		object.SetResourceVersion("100")
		object.SetAnnotations(map[string]string{installstate.MutationAnnotation: strings.Repeat("a", 32)})
		if key.Kind == "ValidatingAdmissionPolicy" {
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
		v.f.access.objects[key] = object
	}
	installstate.SortBaselineResources(security.Resources)
	document.SecurityBaseline, original.SecurityBaseline = security, security
	receipt.Version = "v2"
	for _, entry := range security.Resources {
		receipt.Baseline = append(receipt.Baseline, retirementPolicy{entry.Key, admissionIdentity{entry.UID, "100", entry.TemplateSHA256}})
	}
	receipt.Journal, err = installstate.EncodeWithBaseline(original, baseline, v.f.plan)
	if err != nil {
		t.Fatal("synthetic baseline receipt journal encoding failed")
	}
	body, err = json.Marshal(receipt)
	if err == nil {
		body, err = canonicaljson.CanonicalJSON(body)
	}
	if err != nil {
		t.Fatal("synthetic receipt encoding failed")
	}
	if _, err := v.f.engine.files.AtomicWrite(name, body, &identity); err != nil {
		t.Fatal("protected synthetic receipt seeding failed")
	}
	journalBody, err := installstate.EncodeWithBaseline(document, baseline, v.f.plan)
	if err != nil {
		t.Fatal("synthetic baseline current journal encoding failed")
	}
	namespace, err := v.f.access.client.CoreV1().Namespaces().Get(t.Context(), document.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("original Namespace unavailable")
	}
	namespace.Annotations[installstate.Annotation] = string(journalBody)
	if v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
		t.Fatal("synthetic baseline Namespace seeding failed")
	}
	pod := servingObject(t, &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "unrelated-history", Namespace: namespace.Name, UID: "unrelated-history-original", ResourceVersion: "80"}, Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "history", Image: "example.invalid/unrelated@sha256:" + strings.Repeat("e", 64)}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}})
	if scenario == "harmless-terminal-pod" || scenario == "late-get-review-denied" {
		v.f.access.objects[installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: namespace.Name, Name: pod.GetName()}] = pod
	}
	if scenario == "first-cold-reserved-alias" {
		_ = unstructured.SetNestedField(pod.Object, "arcadectl-destroy-admin", "spec", "serviceAccount")
	}
	if strings.HasSuffix(scenario, "controller-image") {
		for _, resource := range v.f.plan.Resources() {
			key := resourceKey(resource)
			if key.Kind == "Deployment" && key.Name == "arcadectl-controller" {
				containers, _, _ := unstructured.NestedSlice(resource.Object.Object, "spec", "template", "spec", "containers")
				_ = unstructured.SetNestedSlice(pod.Object, containers, "spec", "containers")
			}
		}
	}
	if scenario == "closing-raw-reserved-name" {
		pod.SetName("arcadectl-api")
	}
	claim := servingObject(t, &corev1.PersistentVolumeClaim{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"}, ObjectMeta: metav1.ObjectMeta{Name: "retained-unrelated-world", Namespace: namespace.Name, UID: "original-retained-world", ResourceVersion: "80"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}})

	var mu sync.Mutex
	lists, reviews := map[string]int{}, 0
	seenReviews := map[string]int{}
	// Independent protocol oracle: do not derive authorization
	// expectations with the production helper being exercised.
	expectedReviews := map[string]int{}
	for _, target := range []struct{ group, resource string }{{"", "pods"}, {"batch", "jobs"}, {"apps", "deployments"}, {"apps", "replicasets"}, {"apps", "statefulsets"}, {"apps", "daemonsets"}, {"", "replicationcontrollers"}, {"batch", "cronjobs"}} {
		spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: target.group, Version: "v1", Resource: target.resource, Namespace: namespace.Name, Verb: "list"}}
		encoded, _ := json.Marshal(spec)
		expectedReviews[string(encoded)] = 2
	}
	if completed {
		// Independent literal native collection/root resource mapping;
		// no production permission derivation is used as this oracle.
		for _, tuple := range [][4]string{{"arcade.gobha.me", "gameservers", "v1alpha1", namespace.Name}, {"arcade.gobha.me", "gamebackups", "v1alpha1", namespace.Name}, {"arcade.gobha.me", "gamerestores", "v1alpha1", namespace.Name}, {"arcade.gobha.me", "gamedestroys", "v1alpha1", namespace.Name}, {"arcade.gobha.me", "arcadeoperations", "v1alpha1", namespace.Name}, {"batch", "jobs", "v1", namespace.Name}, {"", "pods", "v1", namespace.Name}, {"coordination.k8s.io", "leases", "v1", namespace.Name}, {"", "persistentvolumeclaims", "v1", namespace.Name}, {"", "secrets", "v1", namespace.Name}, {"admissionregistration.k8s.io", "validatingadmissionpolicies", "v1", ""}, {"admissionregistration.k8s.io", "validatingadmissionpolicybindings", "v1", ""}, {"apps", "replicasets", "v1", namespace.Name}, {"apps", "deployments", "v1", namespace.Name}, {"apps", "statefulsets", "v1", namespace.Name}, {"apps", "daemonsets", "v1", namespace.Name}, {"", "replicationcontrollers", "v1", namespace.Name}, {"batch", "cronjobs", "v1", namespace.Name}, {"storage.k8s.io", "volumeattachments", "v1", ""}, {"discovery.k8s.io", "endpointslices", "v1", namespace.Name}} {
			spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: tuple[0], Resource: tuple[1], Version: tuple[2], Namespace: tuple[3], Verb: "list"}}
			encoded, _ := json.Marshal(spec)
			expectedReviews[string(encoded)] += 2
		}
		for _, root := range document.Resources {
			resource, group, version := "", "", "v1"
			switch root.Key.Kind {
			case "Namespace":
				resource = "namespaces"
			case "Secret":
				resource = "secrets"
			case "CustomResourceDefinition":
				resource, group = "customresourcedefinitions", "apiextensions.k8s.io"
			case "ValidatingAdmissionPolicy":
				resource, group = "validatingadmissionpolicies", "admissionregistration.k8s.io"
			case "ValidatingAdmissionPolicyBinding":
				resource, group = "validatingadmissionpolicybindings", "admissionregistration.k8s.io"
			default:
				t.Fatal("retirement root escaped literal read families")
			}
			spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: group, Resource: resource, Version: version, Namespace: root.Key.Namespace, Name: root.Key.Name, Verb: "get"}}
			encoded, _ := json.Marshal(spec)
			expectedReviews[string(encoded)] += 2
		}
	}
	if scenario == "harmless-terminal-pod" || scenario == "late-get-review-denied" || scenario == "opening-raw-controller-image" || scenario == "closing-raw-reserved-name" {
		spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "pods", Namespace: namespace.Name, Name: pod.GetName(), Verb: "get"}}
		encoded, _ := json.Marshal(spec)
		expectedReviews[string(encoded)] = 2
	}
	faultHit := false
	if scenario == "complete-removed-access-recreated" {
		key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: namespace.Name, Name: "arcadectl-controller"}
		template, err := v.f.engine.contracts[v.f.plan.Digest()].Template(key, false)
		if err != nil {
			t.Fatal("recreated access negative unavailable")
		}
		object, err := template.Candidate(strings.Repeat("a", 32))
		if err != nil {
			t.Fatal("recreated access negative unavailable")
		}
		object.SetUID("unowned-recreated-access")
		object.SetResourceVersion("100")
		v.f.access.objects[key], faultHit = object, true
	}
	if scenario == "complete-retained-crd-replaced" {
		for key, object := range v.f.access.objects {
			if key.Kind == "CustomResourceDefinition" {
				object.SetUID("unowned-replaced-crd")
				faultHit = true
				break
			}
		}
	}
	if scenario == "complete-retained-secret-deleting" {
		for _, secret := range v.private.objects {
			stamp := metav1.Now()
			secret.DeletionTimestamp = &stamp
			faultHit = true
			break
		}
	}
	var injectedPod *unstructured.Unstructured
	if scenario == "harmless-terminal-pod" || scenario == "late-get-review-denied" {
		// Workload whole GETs use the private observation route, not
		// the deliberately narrower public installation effect mapper.
		injectedPod = pod.DeepCopy()
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer FAKE-RETIRED-ADMIN" || r.Header.Get("Impersonate-User") != "" || r.URL.Query().Has("dryRun") {
			t.Error("retired proof changed identity or attempted a probe")
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil {
				t.Error("invalid retired permission review")
				w.WriteHeader(500)
				return
			}
			attributes := review.Spec.ResourceAttributes
			encoded, _ := json.Marshal(review.Spec)
			if expectedReviews[string(encoded)] == 0 {
				t.Error("retired proof review escaped exact executable read scope")
			}
			seenReviews[string(encoded)]++
			reviews++
			review.Status.Allowed = scenario != "review-denied"
			if scenario == "complete-list-denied" && attributes.Resource == "gamebackups" && attributes.Verb == "list" || scenario == "complete-root-get-denied" && attributes.Resource == "customresourcedefinitions" && attributes.Verb == "get" {
				review.Status.Allowed, faultHit = false, true
			}
			if scenario == "review-denied" {
				faultHit = true
			}
			if scenario == "late-list-review-denied" && attributes.Resource == "cronjobs" && attributes.Verb == "list" && seenReviews[string(encoded)] == 2 {
				review.Status.Allowed = false
				faultHit = true
			}
			if scenario == "late-get-review-denied" && attributes.Resource == "pods" && attributes.Verb == "get" && seenReviews[string(encoded)] == 2 {
				review.Status.Allowed = false
				faultHit = true
			}
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		if r.Method != http.MethodGet {
			t.Error("retired proof attempted persistent mutation")
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/version" {
			_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + v.f.plan.Profile().KubernetesVersion})
			return
		}
		if r.URL.Path == "/api/v1/namespaces/"+namespace.Name {
			copy := namespace.DeepCopy()
			copy.APIVersion, copy.Kind = "v1", "Namespace"
			encodeStoppedObject(t, w, r, servingObject(t, copy))
			return
		}
		for _, gv := range proofGroups {
			path, _ := discoveryPath(gv)
			if r.URL.Path != path {
				continue
			}
			resources := []metav1.APIResource{}
			seen := map[string]bool{}
			add := func(kind, plural string, namespaced bool) {
				if !seen[plural] {
					seen[plural] = true
					resources = append(resources, metav1.APIResource{Name: plural, Kind: kind, Namespaced: namespaced, Verbs: metav1.Verbs{"get", "list"}})
				}
			}
			for _, c := range proofCollections {
				if c.gv == gv {
					add(c.kind, c.plural, c.namespaced)
				}
			}
			for _, resource := range v.f.plan.Resources() {
				key := resourceKey(resource)
				if key.APIVersion == gv {
					collection, err := resourcePath(key, true)
					if err != nil {
						t.Error("original discovery fixture unavailable")
						return
					}
					add(key.Kind, collection[strings.LastIndex(collection, "/")+1:], key.Namespace != "")
				}
			}
			_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
			return
		}
		for _, c := range proofCollections {
			path, _ := discoveryPath(c.gv)
			if c.namespaced {
				path += "/namespaces/" + namespace.Name
			}
			path += "/" + c.plural
			if r.URL.Path != path {
				continue
			}
			lists[c.kind]++
			if c.kind == "CronJob" && scenario == "last-list-denied" && lists[c.kind] == 4 {
				faultHit = true
				w.WriteHeader(403)
				return
			}
			if c.kind == "Pod" && lists[c.kind] == 4 {
				switch scenario {
				case "late-runtime-policy-rv", "late-baseline-policy-rv":
					for key, object := range v.f.access.objects {
						if key.Kind == "ValidatingAdmissionPolicy" && strings.HasPrefix(key.Name, "arcadectl-identity-") == (scenario == "late-baseline-policy-rv") {
							object.SetResourceVersion("101")
							faultHit = true
							break
						}
					}
				case "late-fixture":
					if _, err := v.f.engine.files.CreateExclusive(fixtureLedgerName(snapshot), []byte("synthetic unresolved fixture")); err != nil {
						t.Error("late fixture injection failed")
					} else {
						faultHit = true
					}
				case "late-journal":
					namespace.ResourceVersion = "999"
					faultHit = true
				}
			}
			// First Pod LIST is after the opening core but before the
			// closing core: neither individual core spans this replacement.
			if c.kind == "Pod" && (scenario == "receipt-replaced-between-cores" || scenario == "complete-receipt-replaced") && !faultHit {
				old, originalID, err := v.f.engine.files.Read(name, retirementMaxBytes)
				if err != nil {
					t.Error("replacement fixture read failed")
				} else {
					newID, err := v.f.engine.files.AtomicWrite(name, old, &originalID)
					if err != nil || newID == originalID {
						t.Error("replacement fixture effect/identity failed")
					} else {
						faultHit = true
					}
				}
			}
			if c.kind == "Pod" && scenario == "complete-late-journal" && lists[c.kind] == 2 {
				namespace.ResourceVersion, faultHit = "999", true
			}
			items := []any{}
			for key, object := range v.f.access.objects {
				if key.Kind == c.kind {
					items = append(items, object.DeepCopy().Object)
				}
			}
			if c.kind == "Pod" && (scenario == "first-cold-reserved-alias" && lists[c.kind] == 2 || scenario == "second-cold-controller-image" && lists[c.kind] == 3 || scenario == "opening-raw-controller-image" && lists[c.kind] == 1 || scenario == "closing-raw-reserved-name" && lists[c.kind] == 4) {
				injectedPod = pod.DeepCopy()
				items = append(items, injectedPod.Object)
				faultHit = true
			}
			if c.kind == "PersistentVolumeClaim" && (scenario == "second-cold-world-change" || scenario == "complete-world-change") {
				copy := claim.DeepCopy()
				if lists[c.kind] == 2 {
					copy.SetResourceVersion("81")
					faultHit = true
				}
				items = append(items, copy.Object)
			}
			gv, kind := c.gv, c.kind+"List"
			if c.kind == "Secret" {
				gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
				for _, secret := range v.private.objects {
					object := servingObject(t, secret)
					items = append(items, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": object.Object["metadata"]})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
			return
		}
		if injectedPod != nil && r.URL.Path == "/api/v1/namespaces/"+namespace.Name+"/pods/"+injectedPod.GetName() {
			encodeStoppedObject(t, w, r, injectedPod.DeepCopy())
			return
		}
		for key, object := range v.f.access.objects {
			path, err := resourcePath(key, false)
			if err == nil && r.URL.Path == path {
				if scenario == "pending-access-replaced" && key == document.Pending.Key {
					faultHit = true
				}
				encodeStoppedObject(t, w, r, object.DeepCopy())
				return
			}
		}
		for _, secret := range v.private.objects {
			if r.URL.Path == "/api/v1/namespaces/"+namespace.Name+"/secrets/"+secret.Name {
				encodeStoppedObject(t, w, r, servingObject(t, secret))
				return
			}
		}
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: 404})
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken, config.QPS, config.Burst = "FAKE-RETIRED-ADMIN", 100, 200
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("retired HTTPS transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, v.f.plan)
	if err != nil {
		t.Fatal("retired baseline store unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, v.f.engine.files, baseline, v.f.plan)
	if err != nil {
		t.Fatal("retired baseline engine unavailable")
	}
	snapshot, err = store.Load(t.Context(), snapshot.Anchor())
	if err != nil {
		t.Fatal("retired original snapshot unavailable")
	}
	provider, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("retired provider unavailable")
	}
	if runtime {
		lifecycle, constructorErr := NewClusterLifecycle(engine, access)
		closed, ok := engine.baseline.runtimeGuard.(*ClusterSecurityBaseline)
		if constructorErr != nil || lifecycle == nil || !ok || closed == nil || closed != engine.baseline.prerequisites || closed.engine != engine || closed.access != access {
			t.Fatal("actual lifecycle did not wire same closed retired/runtime provider")
		}
		provider = closed
	}
	writes, namespaceWrites := v.f.access.writes, v.f.nsUpdates
	if runtime && completed {
		err = engine.baseline.verifyRuntime(t.Context(), snapshot)
	} else if runtime {
		current, currentErr := engine.current(t.Context(), snapshot)
		err = currentErr
		positive := scenario == "healthy" || scenario == "pending-original-access-delete"
		if positive && (current == nil || current.Anchor() != snapshot.Anchor() || current.ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(current.Bytes(), snapshot.Bytes())) || !positive && (current != nil || err != ErrSecurityBaseline) {
			t.Fatal("actual retired current boundary lost original evidence or admitted drift")
		}
	} else {
		err = provider.Verify(t.Context(), snapshot)
	}
	mu.Lock()
	hit, listedCounts, reviewCount := faultHit, maps.Clone(lists), reviews
	mu.Unlock()
	positive := scenario == "healthy" || scenario == "harmless-terminal-pod" || scenario == "partially-withdrawn-original-access" || scenario == "pending-original-access-delete" || scenario == "complete-healthy"
	if !positive {
		if !hit || err != ErrSecurityBaseline {
			t.Fatal("whole provider accepted incomplete or changing evidence", hit, err)
		}
	} else {
		if err != nil {
			t.Fatal("whole retired provider rejected complete original evidence", err, listedCounts, reviewCount)
		}
		mu.Lock()
		for _, c := range proofCollections {
			want := 2
			for _, executable := range baselineExecutableCollections {
				if executable.kind == c.kind {
					want += 2
				}
			}
			if lists[c.kind] != want {
				t.Error("whole proof skipped complete evidence pass", c.kind, lists[c.kind], want)
			}
		}
		wantReviews := 16
		if completed {
			wantReviews += 80 // 20 literal lists + 20 exact retained GETs, twice
		}
		if scenario == "harmless-terminal-pod" {
			wantReviews += 2 // exact whole GET review on both executable passes
		}
		if reviews != wantReviews {
			t.Error("retired executable reader omitted closed administrator reviews", reviews)
		}
		if !reflect.DeepEqual(seenReviews, expectedReviews) {
			t.Error("retired proof did not review exact complete read multiset")
		}
		mu.Unlock()
	}
	fresh, loadErr := store.Load(t.Context(), snapshot.Anchor())
	if scenario == "late-journal" || scenario == "complete-late-journal" {
		if loadErr == nil && fresh.ResourceVersion() == snapshot.ResourceVersion() {
			t.Fatal("late external journal drift not observable")
		}
	} else if loadErr != nil || !bytes.Equal(fresh.Bytes(), snapshot.Bytes()) || fresh.ResourceVersion() != snapshot.ResourceVersion() {
		t.Fatal("read-only proof changed journal")
	}
	if !runtime && engine.baseline.runtimeGuard != nil || runtime && (engine.baseline.runtimeGuard != provider || engine.baseline.prerequisites != provider) || v.f.access.writes != writes || v.f.nsUpdates != namespaceWrites {
		t.Fatal("read-only proof mutated state or changed its explicit authority composition")
	}
}
