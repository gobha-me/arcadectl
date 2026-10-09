// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Genuine completed legacy retirement plus explicitly synthetic baseline
// enrollment/status, then the actual production constructor and Begin over TLS.
// This proves Begin composition/CAS, not native enrollment or reinstall effects.
func TestAdmissionReinstallActualBeginHTTPSPreservesSourceAndOriginals(t *testing.T) {
	for _, scenario := range []string{"healthy", "expired-secret", "missing-portforward", "denied-portforward", "crd-storage", "closing-source-replacement", "closing-retirement-replacement", "final-source-replacement", "final-retirement-replacement", "final-ca-replacement", "cas-conflict"} {
		t.Run(scenario, func(t *testing.T) { testAdmissionReinstallActualBeginHTTPS(t, scenario) })
	}
}

type reinstallHTTPResource struct {
	gv, kind, plural string
	namespaced       bool
}

// Literal independent resource and permission oracle. Never call production
// permissions(), publicPermission(), proofCollections or proofGroups to admit
// requests from the implementation under test.
var reinstallHTTPResources = []reinstallHTTPResource{
	{"arcade.gobha.me/v1alpha1", "GameServer", "gameservers", true},
	{"arcade.gobha.me/v1alpha1", "GameBackup", "gamebackups", true},
	{"arcade.gobha.me/v1alpha1", "GameRestore", "gamerestores", true},
	{"arcade.gobha.me/v1alpha1", "GameDestroy", "gamedestroys", true},
	{"arcade.gobha.me/v1alpha1", "ArcadeOperation", "arcadeoperations", true},
	{"batch/v1", "Job", "jobs", true}, {"v1", "Pod", "pods", true},
	{"coordination.k8s.io/v1", "Lease", "leases", true},
	{"v1", "PersistentVolumeClaim", "persistentvolumeclaims", true},
	{"v1", "Secret", "secrets", true},
	{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "validatingadmissionpolicies", false},
	{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", "validatingadmissionpolicybindings", false},
	{"apps/v1", "ReplicaSet", "replicasets", true},
	{"apps/v1", "Deployment", "deployments", true},
	{"apps/v1", "StatefulSet", "statefulsets", true},
	{"apps/v1", "DaemonSet", "daemonsets", true},
	{"v1", "ReplicationController", "replicationcontrollers", true},
	{"batch/v1", "CronJob", "cronjobs", true},
	{"storage.k8s.io/v1", "VolumeAttachment", "volumeattachments", false},
	{"discovery.k8s.io/v1", "EndpointSlice", "endpointslices", true},
	{"v1", "Namespace", "namespaces", false},
	{"v1", "ServiceAccount", "serviceaccounts", true},
	{"v1", "Service", "services", true},
	{"rbac.authorization.k8s.io/v1", "Role", "roles", true},
	{"rbac.authorization.k8s.io/v1", "RoleBinding", "rolebindings", true},
	{"rbac.authorization.k8s.io/v1", "ClusterRole", "clusterroles", false},
	{"rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "clusterrolebindings", false},
	{"apiextensions.k8s.io/v1", "CustomResourceDefinition", "customresourcedefinitions", false},
	{"authorization.k8s.io/v1", "SelfSubjectAccessReview", "selfsubjectaccessreviews", false},
}

func reinstallHTTPGroupPath(gv string) string {
	if gv == "v1" {
		return "/api/v1"
	}
	return "/apis/" + gv
}

func testAdmissionReinstallActualBeginHTTPS(t *testing.T, scenario string) {
	v, original := reinstallReceiptLifecycleFixture(t)
	f := v.f
	d := original.Document()
	namespace, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("original completed Namespace unavailable")
	}
	namespace.APIVersion, namespace.Kind = "v1", "Namespace"
	originalNamespace := namespace.DeepCopy()
	retirementName := retirementName(d, d.AdmissionRetirementRevision)
	retirementBody, retirementIdentity, err := f.engine.files.Read(retirementName, retirementMaxBytes)
	if err != nil {
		t.Fatal("opening original retirement receipt unavailable")
	}
	groups := []string{"v1", "apps/v1", "batch/v1", "coordination.k8s.io/v1", "discovery.k8s.io/v1", "storage.k8s.io/v1", "rbac.authorization.k8s.io/v1", "apiextensions.k8s.io/v1", "admissionregistration.k8s.io/v1", "authorization.k8s.io/v1", "arcade.gobha.me/v1alpha1"}
	allowed := map[string]bool{}
	seen, required := map[string]int{}, map[string]int{}
	add := func(spec authv1.SelfSubjectAccessReviewSpec) {
		body, _ := json.Marshal(spec)
		allowed[string(body)] = true
	}
	resourcePermission := func(resource reinstallHTTPResource, name, verb, subresource string) authv1.SelfSubjectAccessReviewSpec {
		group, version := "", "v1"
		if index := strings.IndexByte(resource.gv, '/'); index >= 0 {
			group, version = resource.gv[:index], resource.gv[index+1:]
		}
		ns := ""
		if resource.namespaced {
			ns = d.Namespace
		}
		return authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: group, Version: version, Namespace: ns, Resource: resource.plural, Name: name, Verb: verb, Subresource: subresource}}
	}
	for index, resource := range reinstallHTTPResources {
		if index < 20 {
			add(resourcePermission(resource, "", "list", ""))
		}
		if resource.kind == "Pod" || resource.kind == "ReplicaSet" {
			add(resourcePermission(resource, "", "get", ""))
		}
		if resource.kind == "Pod" || resource.kind == "PersistentVolumeClaim" || resource.kind == "GameDestroy" {
			add(resourcePermission(resource, "", "create", ""))
		}
		if resource.kind == "Pod" {
			add(resourcePermission(resource, "", "create", "portforward"))
		}
		if resource.kind == "Namespace" {
			add(resourcePermission(resource, d.Namespace, "update", ""))
		}
		if resource.kind == "Secret" {
			for _, name := range []string{"arcadectl-admin-credential", "arcadectl-api-tls"} {
				add(resourcePermission(resource, name, "get", ""))
			}
		}
		for _, signed := range f.plan.Resources() {
			if signed.Object.GetKind() == resource.kind && signed.Object.GetAPIVersion() == resource.gv {
				add(resourcePermission(resource, signed.Object.GetName(), "get", ""))
				if !signed.Retained {
					add(resourcePermission(resource, "", "create", ""))
				}
			}
		}
	}
	for _, gv := range groups {
		add(authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &authv1.NonResourceAttributes{Path: reinstallHTTPGroupPath(gv), Verb: "get"}})
	}
	add(authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/version", Verb: "get"}})
	for spec := range allowed {
		required[spec] = 1 // Actual requested-Install preflight, once.
	}
	for index, resource := range reinstallHTTPResources {
		if index < 20 {
			spec := resourcePermission(resource, "", "list", "")
			body, _ := json.Marshal(spec)
			required[string(body)] += 6 // Three proofs, two complete cold passes.
			if index == 5 || index == 6 || index >= 12 && index <= 17 {
				required[string(body)] += 6 // Two raw executable passes per proof.
			}
		}
		for _, retained := range d.Resources {
			if retained.Key.Kind == resource.kind && retained.Key.APIVersion == resource.gv {
				body, _ := json.Marshal(resourcePermission(resource, retained.Key.Name, "get", ""))
				required[string(body)] += 6
			}
		}
	}
	var mu sync.Mutex
	lists := map[string]int{}
	secretGets, namespaceWrites, namespaceAttempts := 0, 0, 0
	privateSecretGets, metadataSecretGets := 0, 0
	closingBaselineGets, finalNamespaceGets := 0, 0
	faultHit := scenario == "expired-secret"
	status := func(w http.ResponseWriter, reason metav1.StatusReason, code int) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: reason, Code: int32(code)})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer FAKE-REINSTALL-ADMIN" || r.Header.Get("Impersonate-User") != "" || r.URL.Query().Has("dryRun") {
			t.Error("Begin changed original identity or attempted a behavioral effect")
			status(w, metav1.StatusReasonForbidden, 403)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil {
				status(w, metav1.StatusReasonBadRequest, 400)
				return
			}
			body, _ := json.Marshal(review.Spec)
			if !allowed[string(body)] {
				t.Error("permission review escaped independent original scope", review.Spec)
				status(w, metav1.StatusReasonForbidden, 403)
				return
			}
			seen[string(body)]++
			review.Status.Allowed = true
			if attrs := review.Spec.ResourceAttributes; scenario == "denied-portforward" && attrs != nil && attrs.Subresource == "portforward" {
				review.Status.Allowed, faultHit = false, true
			}
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		nsPath := "/api/v1/namespaces/" + d.Namespace
		if r.Method == http.MethodPut && r.URL.Path == nsPath {
			namespaceAttempts++
			var next corev1.Namespace
			if json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != originalNamespace.UID || next.ResourceVersion != original.ResourceVersion() || namespaceAttempts != 1 {
				t.Error("Begin attempted a nonoriginal or repeated Namespace CAS")
				status(w, metav1.StatusReasonConflict, 409)
				return
			}
			want := originalNamespace.DeepCopy()
			want.Annotations[installstate.Annotation] = next.Annotations[installstate.Annotation]
			if !reflect.DeepEqual(want, &next) {
				t.Error("Begin modified Namespace beyond the sealed journal")
			}
			if scenario == "cas-conflict" {
				faultHit = true
				status(w, metav1.StatusReasonConflict, 409)
				return
			}
			namespaceWrites++
			next.ResourceVersion = "777"
			namespace = next.DeepCopy()
			_ = json.NewEncoder(w).Encode(next)
			return
		}
		if r.Method != http.MethodGet {
			t.Error("Begin attempted a workload, Secret or access mutation")
			status(w, metav1.StatusReasonForbidden, 403)
			return
		}
		if r.URL.Path == nsPath {
			if closingBaselineGets == 36 {
				finalNamespaceGets++
			}
			// After raw Pod pass twelve, two configured passes read 24
			// baseline rows, then the last retired core reads twelve. Its two
			// original Namespace reads finish before Begin's final pair. Inject
			// at that third read to isolate Begin's own final receipt closure.
			early := strings.HasPrefix(scenario, "closing-") && lists["Pod"] == 12
			final := strings.HasPrefix(scenario, "final-") && closingBaselineGets == 36 && finalNamespaceGets == 3
			if !faultHit && secretGets >= 4 && (early || final) {
				files := f.engine.files
				name := retirementName
				var nameErr error
				if strings.Contains(scenario, "source-replacement") {
					name, nameErr = reinstallSourceName(d.InstallationID, d.Revision)
				} else if scenario == "final-ca-replacement" {
					files, nameErr = privatefs.Open(filepath.Dir(v.opts.Activation.CAFile), false)
					if nameErr != nil {
						t.Error("test-owned final Begin CA directory unavailable")
						w.WriteHeader(500)
						return
					}
					defer files.Close()
					name = filepath.Base(v.opts.Activation.CAFile)
					if testBaselineReceiptDescriptors(t, name) != 1 {
						t.Error("Begin final Namespace fence lost its outer original CA owner")
					}
				}
				body, identity, readErr := files.Read(name, retirementMaxBytes)
				if nameErr != nil || readErr != nil {
					t.Error("final receipt replacement window was not reached")
				} else {
					for range 2 {
						next, writeErr := files.AtomicWrite(name, body, &identity)
						if writeErr != nil {
							t.Error("test-owned final identical receipt replacement failed")
						}
						identity = next
					}
					faultHit = true
				}
			}
			encodeStoppedObject(t, w, r, servingObject(t, namespace.DeepCopy()))
			return
		}
		if r.URL.Path == "/version" {
			_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + f.plan.Profile().KubernetesVersion})
			return
		}
		for _, gv := range groups {
			if r.URL.Path != reinstallHTTPGroupPath(gv) {
				continue
			}
			resources := []metav1.APIResource{}
			for _, resource := range reinstallHTTPResources {
				if resource.gv == gv {
					verbs := metav1.Verbs{"get", "list", "create", "update"}
					if resource.kind == "SelfSubjectAccessReview" {
						verbs = metav1.Verbs{"create"}
					}
					resources = append(resources, metav1.APIResource{Name: resource.plural, Kind: resource.kind, Namespaced: resource.namespaced, Verbs: verbs})
				}
			}
			if gv == "v1" {
				if scenario == "missing-portforward" {
					faultHit = true
				} else {
					resources = append(resources, metav1.APIResource{Name: "pods/portforward", Kind: "PodPortForwardOptions", Namespaced: true, Verbs: metav1.Verbs{"create"}})
				}
			}
			_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
			return
		}
		for index, resource := range reinstallHTTPResources {
			path := reinstallHTTPGroupPath(resource.gv)
			if resource.namespaced {
				path += "/namespaces/" + d.Namespace
			}
			path += "/" + resource.plural
			if index >= 20 || r.URL.Path != path {
				continue
			}
			lists[resource.kind]++
			items := []any{}
			for key, object := range f.access.objects {
				if key.Kind == resource.kind {
					items = append(items, object.DeepCopy().Object)
				}
			}
			gv, kind := resource.gv, resource.kind+"List"
			if resource.kind == "Secret" {
				gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
				for _, secret := range v.private.objects {
					object := servingObject(t, secret)
					items = append(items, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": object.Object["metadata"]})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": map[string]any{"resourceVersion": "100"}, "items": items})
			return
		}
		for key, object := range f.access.objects {
			path, pathErr := resourcePath(key, false)
			if pathErr == nil && r.URL.Path == path {
				copy := object.DeepCopy()
				if lists["Pod"] == 12 && strings.HasPrefix(key.Name, "arcadectl-identity-") && (key.Kind == "ValidatingAdmissionPolicy" || key.Kind == "ValidatingAdmissionPolicyBinding") {
					closingBaselineGets++
				}
				if scenario == "crd-storage" && key.Kind == "CustomResourceDefinition" {
					_ = unstructured.SetNestedSlice(copy.Object, []any{"foreign-version"}, "status", "storedVersions")
					faultHit = true
				}
				encodeStoppedObject(t, w, r, copy)
				return
			}
		}
		for _, secret := range v.private.objects {
			if r.URL.Path == "/api/v1/namespaces/"+d.Namespace+"/secrets/"+secret.Name {
				secretGets++
				if strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata;") {
					metadataSecretGets++
				} else {
					privateSecretGets++
				}
				// The in-process legacy fake stores a typed Secret without
				// TypeMeta. An actual Kubernetes HTTP reply supplies literal
				// GVK; privateRequest correctly refuses a missing wire GVK.
				copy := secret.DeepCopy()
				copy.APIVersion, copy.Kind = "v1", "Secret"
				encodeStoppedObject(t, w, r, servingObject(t, copy))
				return
			}
		}
		status(w, metav1.StatusReasonNotFound, 404)
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken, config.QPS, config.Burst = "FAKE-REINSTALL-ADMIN", 100, 200
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("actual Begin direct transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("actual Begin store unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("actual Begin engine unavailable")
	}
	lifecycle, err := NewClusterLifecycle(engine, access)
	if err != nil {
		t.Fatal("actual closed Begin constructor unavailable")
	}
	source, err := store.Load(t.Context(), original.Anchor())
	if err != nil || !bytes.Equal(source.Bytes(), original.Bytes()) {
		t.Fatal("actual transport changed the original completed source")
	}
	opts := v.opts
	if scenario == "expired-secret" {
		opts.Now = opts.Now.Add(2 * opts.Credentials.AdminLifetime)
	}
	returned, beginErr := lifecycle.Begin(t.Context(), source, installstate.Install, f.plan.Digest(), opts)
	if testBaselineReceiptDescriptors(t, filepath.Base(opts.Activation.CAFile)) != 0 {
		t.Fatal("actual Begin leaked its original CA descriptor")
	}
	if scenario == "healthy" && beginErr == ErrLifecycle {
		// Fixed public protocol diagnostics only; never print Secret bodies,
		// transport errors or credential files. This branch cannot certify success.
		request := LifecycleCheck{Checkpoint: Prerequisites, Snapshot: source, Mode: installstate.Install, Target: f.plan, Options: opts}
		permissions, deriveErr := lifecycle.checks.(*clusterLifecycleChecks).prerequisites.permissions(request)
		t.Log("prerequisite derivation", deriveErr, "permission count", len(permissions))
		for _, gv := range groups {
			list, discoverErr := access.discover(t.Context(), gv)
			if discoverErr != nil {
				t.Log("discovery refused", gv)
				continue
			}
			for _, permission := range permissions {
				attrs := permission.spec.ResourceAttributes
				if attrs != nil && attrs.Group+"/"+attrs.Version == gv || attrs != nil && attrs.Group == "" && gv == attrs.Version {
					if !discoveredPermission(list, permission) {
						t.Log("required native discovery row missing", gv, permission.kind, attrs.Resource, attrs.Subresource, attrs.Verb)
					}
				}
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if scenario != "healthy" {
		if !faultHit || beginErr == nil || namespaceWrites != 0 || namespace.Annotations[installstate.Annotation] != string(source.Bytes()) {
			t.Fatal("refused actual Begin did not preserve the original journal", scenario, faultHit, beginErr, namespaceWrites)
		}
		if scenario == "cas-conflict" {
			if namespaceAttempts != 1 || beginErr != installstate.ErrConflict || returned != nil {
				t.Fatal("conflicting original CAS was retried or reclassified")
			}
		} else if namespaceAttempts != 0 || returned == nil || !bytes.Equal(returned.Bytes(), source.Bytes()) || returned.ResourceVersion() != source.ResourceVersion() {
			t.Fatal("pre-CAS refusal attempted a journal mutation")
		}
		return
	}
	guard, ok := engine.baseline.runtimeGuard.(*ClusterSecurityBaseline)
	if !ok || guard == nil || guard != engine.baseline.prerequisites || guard.engine != engine || guard.access != access {
		t.Fatal("actual Begin lost closed original runtime/prerequisite composition")
	}
	if beginErr != nil || returned == nil || namespaceWrites != 1 || namespaceAttempts != 1 || privateSecretGets != 4 || metadataSecretGets != 12 {
		t.Fatal("actual Begin did not perform exactly one closed source CAS", beginErr, namespaceWrites, namespaceAttempts, privateSecretGets, metadataSecretGets)
	}
	want := source.Document()
	want.Mode, want.Stage, want.AdmissionRetirementRevision = installstate.Install, installstate.Preparing, 0
	want.Revision++
	digest := sha256.Sum256(source.Bytes())
	want.AdmissionReinstall = &installstate.ReinstallProvenance{SourceRevision: d.Revision, SourceJournalSHA256: hex.EncodeToString(digest[:])}
	if !reflect.DeepEqual(want, returned.Document()) || returned.ResourceVersion() != "777" {
		t.Fatal("actual Begin changed retained identity/history or used an unbound source")
	}
	for index, resource := range reinstallHTTPResources[:20] {
		want := 6
		if index == 5 || index == 6 || index >= 12 && index <= 17 {
			want = 12 // Three whole proofs; each has two additional raw passes.
		}
		if lists[resource.kind] != want {
			t.Error("Begin omitted whole retired evidence", resource.kind, lists[resource.kind], want)
		}
	}
	if !reflect.DeepEqual(seen, required) {
		t.Error("Begin omitted or expanded exact permission-review multiplicities", seen, required)
	}
	closedBody, closedIdentity, err := engine.files.Read(retirementName, retirementMaxBytes)
	if err != nil || closedIdentity != retirementIdentity || !bytes.Equal(closedBody, retirementBody) || closingBaselineGets != 36 || finalNamespaceGets != 4 {
		t.Fatal("healthy Begin replaced the opening retirement receipt or omitted final proof fences", closingBaselineGets, finalNamespaceGets)
	}
	loaded, err := engine.openReinstallSource(returned)
	if err != nil {
		t.Fatal("actual Begin source pin does not authenticate after journal CAS")
	}
	defer loaded.release()
	if engine.closeReinstallSource(loaded) != nil || !bytes.Equal(loaded.sourceBodyForTest(), source.Bytes()) {
		t.Fatal("actual Begin lost original source bytes or receipt continuity")
	}
}

func (w *reinstallSourceWitness) sourceBodyForTest() []byte {
	var receipt reinstallSourceReceipt
	if w == nil || json.Unmarshal(w.body, &receipt) != nil {
		return nil
	}
	return receipt.Journal
}
