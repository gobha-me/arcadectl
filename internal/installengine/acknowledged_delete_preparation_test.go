// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAcknowledgedDeletePreparesWholeAbsenceBeforeProof(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "")
}

func TestAcknowledgedDeleteRejectsLateWholePodDrift(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "late-pod")
}

func TestAcknowledgedDeleteRejectsReplacementDuringPreparation(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "replacement")
}

func TestAcknowledgedDeleteRejectsUnsignedParentDuringPreparation(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "unsigned-parent")
}

func TestAcknowledgedDeleteRejectsReadRefusalDuringPreparation(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "read-refusal")
}

func TestAcknowledgedDeleteRejectsJournalDriftDuringPreparation(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "journal")
}

func TestAcknowledgedDeleteRejectsProtectedFileFenceDuringPreparation(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "protected-file")
}

func TestAcknowledgedDeleteCancellationKeepsOriginalIntent(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "cancel")
}

func TestAcknowledgedDeleteRejectsCollectedTargetReappearance(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "collected-reappearance")
}

func TestAcknowledgedDeleteRejectsTargetReappearanceAfterFullProof(t *testing.T) {
	testAcknowledgedDeletePreparation(t, "postproof-reappearance")
}

// Synthetic whole HTTPS replies exercise the genuine closed runtime provider,
// signed original shapes, journal CAS and one foreground DELETE. This is not a
// native kubelet/GC, release signing or full installer lifecycle certificate.
// The denied behavior oracle is the existing independent literal request/body
// oracle; preparation never changes that oracle or exempts a Pod field.
func testAcknowledgedDeletePreparation(t *testing.T, failure string) {
	t.Helper()
	f := seedBaselineAccessWitness(t)
	v := newBaselineDescendantsFixtureWithPlans(t, f.plan)
	d := f.snapshot.Document()
	d.Mode, d.ActivePackage, d.Installed, d.Stage = installstate.Uninstall, f.plan.Digest(), true, installstate.Quiescing
	objects := map[installstate.Key]*unstructured.Unstructured{}
	for key, original := range f.access.objects {
		objects[key] = original.DeepCopy()
		if key.Kind == "ValidatingAdmissionPolicy" {
			objects[key].SetGeneration(1)
			objects[key].Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
	}
	for _, resource := range v.d.Resources {
		if resource.Key.Kind == "Deployment" {
			d.Resources = append(d.Resources, resource)
		}
	}
	for i := range v.objects.Deployments.Items {
		o := servingObject(t, &v.objects.Deployments.Items[i])
		objects[baselineObjectKey(o)] = o
	}
	for i := range v.objects.ReplicaSets.Items {
		o := servingObject(t, &v.objects.ReplicaSets.Items[i])
		o.SetAPIVersion("apps/v1")
		o.SetKind("ReplicaSet")
		objects[baselineObjectKey(o)] = o
	}
	for i := range v.objects.Pods.Items {
		o := servingObject(t, &v.objects.Pods.Items[i])
		objects[baselineObjectKey(o)] = o
	}
	key := deploymentKey(d.Namespace, "arcadectl-api")
	before := objects[key].DeepCopy()
	serviceKey := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: "arcadectl-api"}
	serviceTemplate, err := f.engine.contracts[d.TargetPackage].Template(serviceKey, false)
	if err != nil {
		t.Fatal("signed original Service unavailable")
	}
	service := testBaselineMetadataLive(t, serviceTemplate, strings.Repeat("b", 32))
	service.SetUID("original-delete-service")
	service.SetResourceVersion("17")
	objects[serviceKey] = service
	d.Resources = append(d.Resources, installstate.Resource{Key: serviceKey, UID: service.GetUID(), TemplateSHA256: serviceTemplate.Hash(), Phase: serviceTemplate.Phase(), Retained: serviceTemplate.Retained()})
	installstate.SortResources(d.Resources)
	d.Revision++
	seedBaselineAccessUnitDocument(t, f, d)
	ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("original Namespace unavailable")
	}
	// Literal collection/discovery oracle, independent of the production list.
	resources := [][3]string{{"v1", "Pod", "pods"}, {"batch/v1", "Job", "jobs"}, {"apps/v1", "Deployment", "deployments"}, {"apps/v1", "ReplicaSet", "replicasets"}, {"apps/v1", "StatefulSet", "statefulsets"}, {"apps/v1", "DaemonSet", "daemonsets"}, {"v1", "ReplicationController", "replicationcontrollers"}, {"batch/v1", "CronJob", "cronjobs"}, {"v1", "ServiceAccount", "serviceaccounts"}, {"v1", "Service", "services"}, {"rbac.authorization.k8s.io/v1", "Role", "roles"}, {"rbac.authorization.k8s.io/v1", "RoleBinding", "rolebindings"}}
	paths := map[string]installstate.Key{}
	for k := range objects {
		path, pathErr := resourcePath(k, false)
		if pathErr != nil {
			path, _, pathErr = baselineExecutableRead(k, "get")
		}
		if pathErr != nil {
			t.Fatal("original object route unavailable")
		}
		paths[path] = k
	}
	targetPath, _ := resourcePath(key, false)
	podPath := "/api/v1/namespaces/" + d.Namespace + "/pods"
	var survivor installstate.Key
	for k, object := range objects {
		account, _, _ := unstructured.NestedString(object.Object, "spec", "serviceAccountName")
		if k.Kind == "Pod" && account == "arcadectl-controller" {
			survivor = k
		}
	}
	if survivor.Name == "" {
		t.Fatal("original surviving Pod unavailable")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var engine *Engine
	var intent installstate.Document
	var mu sync.Mutex
	deletes, writes, targetReads, collections, proofStarts, postRules := 0, 0, 0, 0, 0, 0
	collectedTargetGets := 0
	preparationLists := [8]int{}
	var currentDiagnostic *LifecycleDiagnostic
	injected, proofOpened := false, false
	var lastChange, lastCollection, openingCollection time.Time
	rows, expectedRows := map[string]int{}, map[string]int{}
	rules := map[string]int{}
	producers := map[string]*unstructured.Unstructured{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		user := r.Header.Get("Impersonate-User")
		actor := strings.TrimPrefix(user, "system:serviceaccount:"+d.Namespace+":")
		if r.Header.Get("Authorization") != "Bearer FAKE-DELETE-PREPARATION" || user != "" && actor != "arcadectl-controller" && actor != "arcadectl-destroy-controller" {
			t.Error("delete fixture changed frozen identity")
			w.WriteHeader(500)
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
			var next corev1.Namespace
			if r.URL.RawQuery != "fieldValidation=Strict" || json.NewDecoder(r.Body).Decode(&next) != nil {
				t.Error("Namespace CAS escaped literal envelope")
				w.WriteHeader(500)
				return
			}
			var previous, candidate installstate.Document
			if json.Unmarshal([]byte(ns.Annotations[installstate.Annotation]), &previous) != nil || json.Unmarshal([]byte(next.Annotations[installstate.Annotation]), &candidate) != nil {
				t.Error("Namespace CAS journal malformed")
				w.WriteHeader(500)
				return
			}
			want := previous
			want.Revision++
			if writes == 0 && candidate.Pending != nil {
				entry := previous.Resources[slices.IndexFunc(previous.Resources, func(r installstate.Resource) bool { return r.Key == key })]
				want.Pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: candidate.Pending.CreateNonce, BeforeUID: entry.UID, BeforeResourceVersion: before.GetResourceVersion(), BeforeSHA256: entry.TemplateSHA256}
				if len(candidate.Pending.CreateNonce) != 32 {
					t.Error("original intent nonce malformed")
				}
			} else if writes == 1 && deletes == 1 && previous.Pending != nil && objects[key] == nil {
				want.Pending = nil
				index := slices.IndexFunc(want.Resources, func(r installstate.Resource) bool { return r.Key == key })
				want.Resources = slices.Delete(slices.Clone(want.Resources), index, index+1)
			} else {
				t.Error("Namespace CAS repeated or settled without original absence")
				w.WriteHeader(500)
				return
			}
			copy := next.DeepCopy()
			copy.Annotations[installstate.Annotation] = ns.Annotations[installstate.Annotation]
			original := ns.DeepCopy()
			original.APIVersion, original.Kind = "v1", "Namespace"
			if !reflect.DeepEqual(want, candidate) || !reflect.DeepEqual(copy, original) {
				t.Error("Namespace CAS changed unrelated journal or original shape")
				w.WriteHeader(500)
				return
			}
			rv, _ := strconv.Atoi(ns.ResourceVersion)
			next.ResourceVersion = strconv.Itoa(rv + 1)
			ns = next.DeepCopy()
			writes++
			if writes == 1 {
				intent = candidate
			}
			_ = json.NewEncoder(w).Encode(next)
			return
		}
		if user == "" && r.Method == http.MethodDelete && r.URL.Path == targetPath {
			var opts metav1.DeleteOptions
			if json.NewDecoder(r.Body).Decode(&opts) != nil || r.URL.RawQuery != "" || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != before.GetUID() || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != before.GetResourceVersion() || opts.PropagationPolicy == nil || *opts.PropagationPolicy != metav1.DeletePropagationForeground || len(opts.DryRun) != 0 || deletes != 0 || writes != 1 || intent.Pending == nil {
				t.Error("foreground DELETE did not follow exact original intent once")
				w.WriteHeader(500)
				return
			}
			deletes++
			stamp := metav1.Now()
			objects[key].SetDeletionTimestamp(&stamp)
			objects[key].SetFinalizers([]string{metav1.FinalizerDeleteDependents})
			objects[key].SetResourceVersion("18")
			_ = json.NewEncoder(w).Encode(objects[key].Object)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
				t.Error("original review malformed")
				w.WriteHeader(500)
				return
			}
			a := review.Spec.ResourceAttributes
			if deletes == 1 && !proofOpened && user == "" && a.Verb == "impersonate" {
				proofOpened, openingCollection = true, lastCollection
			}
			if failure == "late-pod" && deletes == 1 && postRules == 2 && user != "" && !injected {
				objects[survivor].SetResourceVersion("900")
				objects[survivor].SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "synthetic-native-status", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: "v1"}})
				objects[survivor].Object["status"] = map[string]any{"phase": "Running"}
				injected = true
			}
			allowed := false
			if user == "" {
				allowed = a.Verb == "get" || a.Verb == "list" || a.Verb == "impersonate" && a.Version == "*" && a.Resource == "serviceaccounts" && a.Namespace == d.Namespace && (a.Name == "arcadectl-controller" || a.Name == "arcadectl-destroy-controller") || a.Verb == "update" && a.Group == "" && a.Resource == "namespaces" && a.Name == d.Namespace && a.Namespace == "" || a.Verb == "delete" && a.Group == "apps" && a.Resource == "deployments" && a.Name == key.Name && a.Namespace == d.Namespace
			} else if a.Version == "v1" && a.Namespace == d.Namespace && a.Subresource == "" && a.FieldSelector == nil && a.LabelSelector == nil {
				collection := a.Verb == "create" && a.Name == ""
				named := a.Name != "" && (a.Verb == "update" || a.Verb == "delete" || a.Verb == "patch")
				switch a.Group + "/" + a.Resource {
				case "batch/jobs":
					allowed = collection
				case "apps/deployments":
					allowed = actor == "arcadectl-controller" && (collection || named)
				case "/pods":
					allowed = named && a.Verb == "update"
				case "/serviceaccounts", "rbac.authorization.k8s.io/roles", "rbac.authorization.k8s.io/rolebindings":
					allowed = collection || named && a.Verb == "delete"
				case "/services":
					allowed = actor == "arcadectl-controller" && (collection || named)
				}
			}
			review.TypeMeta = metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
			review.Status = authv1.SubjectAccessReviewStatus{Allowed: allowed}
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" {
			rules[actor]++
			if deletes == 1 {
				postRules++
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": map[string]any{}, "status": map[string]any{"incomplete": false, "resourceRules": []any{}, "nonResourceRules": []any{}}})
			return
		}
		if r.Method == http.MethodGet {
			if failure == "postproof-reappearance" && deletes == 1 && proofOpened && postRules == 12 && r.URL.Path == targetPath && currentDiagnostic != nil && currentDiagnostic.BoundarySnapshot() == "operation=delete-ack-wait baseline=complete" && !injected {
				objects[key] = before.DeepCopy()
				injected = true
			}
			if deletes == 1 && r.URL.Path == targetPath && !proofOpened {
				targetReads++
				if targetReads == 1 && failure != "" && failure != "late-pod" && failure != "collected-reappearance" && failure != "postproof-reappearance" {
					injected = true
					switch failure {
					case "replacement":
						objects[key].SetUID("foreign-same-name-api")
					case "unsigned-parent":
						_ = unstructured.SetNestedField(objects[key].Object, "foreign-account", "spec", "template", "spec", "serviceAccountName")
					case "read-refusal":
						w.WriteHeader(http.StatusForbidden)
						return
					case "journal":
						ns.ResourceVersion = "999"
					case "protected-file":
						// DELETE has no CREATE receipt. A new active/malformed
						// protected WAL must still fence its exact original intent.
						if _, err := engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("{}")); err != nil {
							t.Error("protected WAL fence injection unavailable")
						}
					case "cancel":
						cancel()
					}
				}
				if targetReads <= 3 {
					// Literal original API Pod churn before foreground absence.
					for k, object := range objects {
						account, _, _ := unstructured.NestedString(object.Object, "spec", "serviceAccountName")
						if k.Kind == "Pod" && account == "arcadectl-api" {
							object.SetResourceVersion(strconv.Itoa(100 + targetReads))
							object.Object["status"] = map[string]any{"phase": "Running"}
						}
					}
				} else if failure != "collected-reappearance" || !injected {
					for k, object := range objects {
						account, _, _ := unstructured.NestedString(object.Object, "spec", "serviceAccountName")
						owners := object.GetOwnerReferences()
						if k == key || k.Kind == "Pod" && account == "arcadectl-api" || k.Kind == "ReplicaSet" && len(owners) == 1 && owners[0].Name == key.Name {
							delete(objects, k)
						}
					}
				}
			}
			if deletes == 1 && r.URL.Path == podPath && !proofOpened {
				collections++
				lastCollection = time.Now()
				if failure == "collected-reappearance" && !injected {
					objects[key] = before.DeepCopy()
					injected = true
				}
				if collections <= 3 {
					objects[survivor].SetResourceVersion(strconv.Itoa(200 + collections))
					objects[survivor].Object["status"] = map[string]any{"phase": "Pending"}
					lastChange = time.Now()
				}
			}
			if r.URL.Path == "/version" {
				_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v1.35.8"})
				return
			}
			if r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
				copy := ns.DeepCopy()
				copy.APIVersion, copy.Kind = "v1", "Namespace"
				_ = json.NewEncoder(w).Encode(copy)
				return
			}
			for _, gv := range []string{"v1", "apps/v1", "batch/v1", "rbac.authorization.k8s.io/v1"} {
				path, _ := discoveryPath(gv)
				if r.URL.Path == path {
					list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv}
					for _, c := range resources {
						if c[0] == gv {
							list.APIResources = append(list.APIResources, metav1.APIResource{Name: c[2], Kind: c[1], Namespaced: true, Verbs: metav1.Verbs{"get", "list", "create", "update", "patch", "delete"}})
						}
					}
					_ = json.NewEncoder(w).Encode(list)
					return
				}
			}
			if k, found := paths[r.URL.Path]; found {
				if failure == "collected-reappearance" && injected && k == key && objects[k] != nil {
					collectedTargetGets++
				}
				if objects[k] == nil {
					w.WriteHeader(http.StatusNotFound)
				} else {
					_ = json.NewEncoder(w).Encode(objects[k].Object)
				}
				return
			}
			for collection, c := range resources {
				prefix := "/apis/" + c[0]
				if c[0] == "v1" {
					prefix = "/api/v1"
				}
				if r.URL.Path == prefix+"/namespaces/"+d.Namespace+"/"+c[2] {
					if deletes == 1 && !proofOpened && collection < len(preparationLists) {
						preparationLists[collection]++
					}
					items := []any{}
					for k, o := range objects {
						if k.APIVersion == c[0] && k.Kind == c[1] && k.Namespace == d.Namespace {
							items = append(items, o.Object)
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": c[0], "kind": c[1] + "List", "metadata": map[string]any{"resourceVersion": "50"}, "items": items})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if user == "" || r.URL.Query().Get("dryRun") != "All" {
			t.Error("delete fixture received unrelated persistent mutation")
			w.WriteHeader(500)
			return
		}
		var object unstructured.Unstructured
		if json.NewDecoder(r.Body).Decode(&object.Object) != nil {
			t.Error("literal behavior body malformed")
			w.WriteHeader(500)
			return
		}
		var resource [3]string
		name := ""
		for _, c := range resources {
			prefix := "/apis/" + c[0]
			if c[0] == "v1" {
				prefix = "/api/v1"
			}
			path := prefix + "/namespaces/" + d.Namespace + "/" + c[2]
			if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/") {
				resource, name = c, strings.TrimPrefix(r.URL.Path, path+"/")
				if r.Method == http.MethodPost {
					name = object.GetName()
				}
			}
		}
		k := installstate.Key{APIVersion: resource[0], Kind: resource[1], Namespace: d.Namespace, Name: name}
		account, _, _ := unstructured.NestedString(object.Object, "spec", "template", "spec", "serviceAccountName")
		if actor == "arcadectl-controller" && r.Method == http.MethodPost && k.Kind == "Job" && account == "default" && strings.HasPrefix(name, "arcadectl-identity-probe-") {
			producers = map[string]*unstructured.Unstructured{}
			proofStarts++
			pods := []corev1.Pod{}
			for key, o := range objects {
				if key.Kind == "Pod" {
					var pod corev1.Pod
					if decodeServing(o, &pod) != nil {
						t.Error("whole literal Pod oracle malformed")
					}
					pods = append(pods, pod)
				}
			}
			want := testBaselineBehaviorLiteralRows(pods)
			if objects[key] == nil {
				for _, method := range []string{"PUT", "PATCH", "DELETE"} {
					delete(want, "arcadectl-controller/"+method+"/Deployment/arcadectl-api")
				}
			}
			for row, count := range want {
				expectedRows[row] += count
			}
		}
		membership, valid := testBaselineBehaviorRequestRow(r, actor, k, &object, objects[k], producers)
		if resource == [3]string{} || !valid {
			t.Error("behavior request differs from independent literal body or variant")
			w.WriteHeader(500)
			return
		}
		rows[actor+"/"+r.Method+"/"+k.Kind+"/"+membership]++
		if r.Method == http.MethodPost && (k.Kind == "Job" || k.Kind == "Deployment") && account == "default" && strings.HasPrefix(name, "arcadectl-identity-probe-") {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(baselineProducerReply(t, &object, time.Now().UTC()).Object)
			return
		}
		family := "identity"
		if k.Kind == "Pod" {
			family = "pod"
		} else if k.Kind == "Job" || k.Kind == "Deployment" {
			family = "template"
		}
		policy := "arcadectl-identity-" + family + "-" + d.Namespace
		group, qualified := "", resource[2]
		if resource[0] != "v1" {
			group = strings.TrimSuffix(resource[0], "/v1")
			qualified += "." + group
		}
		cause := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: Arcadectl installation identities and executables require trusted maintenance authority."
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: 422, Reason: metav1.StatusReasonInvalid, Message: fmt.Sprintf("%s %q is forbidden: %s", qualified, name, cause), Details: &metav1.StatusDetails{Group: group, Kind: resource[2], Name: name, Causes: []metav1.StatusCause{{Message: cause}}}})
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken, config.QPS, config.Burst = "FAKE-DELETE-PREPARATION", 1000, 2000
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("original TLS access unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("original TLS journal unavailable")
	}
	engine, err = NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("original TLS engine unavailable")
	}
	if lifecycle, err := NewClusterLifecycle(engine, access); err != nil || lifecycle == nil {
		t.Fatal("actual closed runtime provider unavailable")
	}
	snapshot, err := store.Load(ctx, f.snapshot.Anchor())
	if err != nil {
		t.Fatal("original TLS snapshot unavailable")
	}
	proofContext, diagnostic := WithLifecycleDiagnostic(ctx)
	mu.Lock()
	currentDiagnostic = diagnostic
	mu.Unlock()
	settled, err := engine.delete(proofContext, snapshot, key, true)
	mu.Lock()
	defer mu.Unlock()
	if deletes != 1 || writes < 1 || intent.Pending == nil || settled == nil {
		t.Fatal("test did not reach one genuine original DELETE ACK", err, diagnostic.BoundarySnapshot(), diagnostic.FailureSnapshot(), deletes, writes, proofStarts)
	}
	if failure == "" {
		if err != nil || writes != 2 || settled.Document().Pending != nil || targetReads < 4 || collections < 8 || !proofOpened || openingCollection.Sub(lastChange) < 5*time.Second || proofStarts != 4 || rules["arcadectl-controller"] != 24 || rules["arcadectl-destroy-controller"] != 24 || !reflect.DeepEqual(rows, expectedRows) {
			t.Fatal("ACK preparation omitted whole quietness, literal full proof or original absence settlement", err, diagnostic.BoundarySnapshot())
		}
		want := intent
		want.Revision++
		want.Pending = nil
		index := slices.IndexFunc(want.Resources, func(r installstate.Resource) bool { return r.Key == key })
		want.Resources = slices.Delete(slices.Clone(want.Resources), index, index+1)
		if !reflect.DeepEqual(want, settled.Document()) {
			t.Fatal("settlement changed unrelated original inventory or journal")
		}
		for _, count := range preparationLists {
			if count != collections {
				t.Fatal("preparation omitted one of eight literal executable collections")
			}
		}
	} else {
		if !errors.Is(err, ErrOutcomeUnknown) || writes != 1 || !injected || !reflect.DeepEqual(intent, settled.Document()) {
			t.Fatal("refused preparation/proof changed or settled original Pending", err, diagnostic.BoundarySnapshot())
		}
		if failure == "late-pod" {
			if diagnostic.FailureSnapshot() != "check=executables-stable family=Pod changes=resource-version,metadata,status" || proofStarts != 2 || postRules != 2 || !proofOpened {
				t.Fatal("late complete Pod drift was exempted, retried or misattributed", diagnostic.FailureSnapshot())
			}
		} else if failure == "postproof-reappearance" {
			if !proofOpened || proofStarts != 3 || postRules != 12 || !reflect.DeepEqual(rows, expectedRows) {
				t.Fatal("prepared target reappearance retried proof or entered recovery")
			}
		} else if proofOpened || proofStarts != 2 || postRules != 0 {
			t.Fatal("refused preparation entered/repeated the full proof")
		}
		if failure == "collected-reappearance" && (collectedTargetGets != 1 || collections != 1) {
			t.Fatal("collected target control did not preserve the whole LIST/GET object")
		}
	}
}
