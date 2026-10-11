// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

// Synthetic read protocol coverage, not native admission/GC certification.
func TestRetiredAccessLeafRequiresCompleteOriginalReadEvidence(t *testing.T) {
	for _, scenario := range []string{"leaf", "leaf-role", "leaf-serviceaccount", "secret-child", "lease-child", "custom-child", "event-child", "terminal-child", "non-controller-child", "owner-kind-mismatch", "transitive-child", "missing-root", "replaced-root", "root-rv", "root-source", "root-owner", "root-finalizer", "whole-body", "whole-rv", "list-denied", "uncovered-list", "metadata-denied", "discovery-drift", "journal-drift", "policy-rv-drift", "receipt-replaced", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			v, before := retirementFixture(t)
			d := before.Document()
			kind := "RoleBinding"
			if scenario == "leaf-role" {
				kind = "Role"
			} else if scenario == "leaf-serviceaccount" {
				kind = "ServiceAccount"
			}
			var key installstate.Key
			for _, r := range d.Resources {
				if r.Key.Kind == kind && r.Key.Namespace == d.Namespace && !r.Retained {
					key = r.Key
					break
				}
			}
			r, _ := v.f.engine.inventory(d, key)
			live := v.f.access.objects[key].DeepCopy()
			d.Pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: strings.Repeat("a", 32), BeforeUID: r.UID, BeforeResourceVersion: live.GetResourceVersion(), BeforeSHA256: r.TemplateSHA256}
			d.Revision++
			intent, err := v.f.engine.journal.Commit(t.Context(), before, d)
			if err != nil {
				t.Fatal("original intent fixture unavailable", err)
			}
			namespace, err := v.f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal("original journal unavailable")
			}
			namespace.APIVersion, namespace.Kind = "v1", "Namespace"
			root := metav1.ObjectMeta{Name: key.Name, Namespace: d.Namespace, UID: r.UID, ResourceVersion: live.GetResourceVersion()}
			sources := map[string]metav1.APIResourceList{}
			for _, entry := range [][4]string{{"v1", "serviceaccounts", "ServiceAccount", ""}, {"v1", "secrets", "Secret", ""}, {"v1", "events", "Event", ""}, {"rbac.authorization.k8s.io/v1", "rolebindings", "RoleBinding", ""}, {"rbac.authorization.k8s.io/v1", "roles", "Role", ""}, {"coordination.k8s.io/v1", "leases", "Lease", ""}, {"example.invalid/v1", "gadgets", "Gadget", ""}} {
				list := sources[entry[0]]
				list.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}
				list.GroupVersion = entry[0]
				list.APIResources = append(list.APIResources, metav1.APIResource{Name: entry[1], Kind: entry[2], Namespaced: true, Verbs: metav1.Verbs{"get", "list", "delete", "watch"}})
				sources[entry[0]] = list
			}
			if scenario == "uncovered-list" {
				list := sources["example.invalid/v1"]
				list.APIResources[0].Verbs = metav1.Verbs{"get", "list"}
				sources[list.GroupVersion] = list
			}
			items := map[string][]metav1.PartialObjectMetadata{}
			rootPath, _ := resourcePath(key, true)
			items[rootPath] = []metav1.PartialObjectMetadata{{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: root}}
			switch scenario {
			case "missing-root":
				items[rootPath] = nil
			case "replaced-root":
				items[rootPath][0].UID = "foreign-root"
			case "root-rv":
				items[rootPath][0].ResourceVersion = "999"
			case "root-source":
				items["/api/v1/namespaces/"+d.Namespace+"/serviceaccounts"] = items[rootPath]
				items[rootPath] = nil
			case "root-owner":
				items[rootPath][0].OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: "foreign", UID: "foreign-owner"}}
			}
			child := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: "foreign-child", Namespace: d.Namespace, UID: "foreign-child", ResourceVersion: "90", OwnerReferences: []metav1.OwnerReference{{APIVersion: key.APIVersion, Kind: key.Kind, Name: key.Name, UID: r.UID, Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)}}}}
			childPath := "/apis/example.invalid/v1/namespaces/" + d.Namespace + "/gadgets"
			switch scenario {
			case "secret-child":
				childPath = "/api/v1/namespaces/" + d.Namespace + "/secrets"
			case "lease-child":
				childPath = "/apis/coordination.k8s.io/v1/namespaces/" + d.Namespace + "/leases"
			case "event-child":
				childPath = "/api/v1/namespaces/" + d.Namespace + "/events"
			case "terminal-child":
				stamp := metav1.Now()
				child.DeletionTimestamp = &stamp
			case "non-controller-child":
				child.OwnerReferences[0].Controller, child.OwnerReferences[0].BlockOwnerDeletion = ptr.To(false), nil
			case "owner-kind-mismatch":
				child.OwnerReferences[0].APIVersion, child.OwnerReferences[0].Kind, child.OwnerReferences[0].Name = "v1", "Secret", "different-owner-name"
			}
			if strings.HasSuffix(scenario, "child") || scenario == "owner-kind-mismatch" {
				items[childPath] = append(items[childPath], child)
			}
			if scenario == "transitive-child" {
				grandchild := *child.DeepCopy()
				grandchild.Name, grandchild.UID = "foreign-grandchild", "foreign-grandchild"
				grandchild.OwnerReferences[0] = metav1.OwnerReference{APIVersion: "example.invalid/v1", Kind: "Gadget", Name: child.Name, UID: child.UID}
				items["/api/v1/namespaces/"+d.Namespace+"/secrets"] = []metav1.PartialObjectMetadata{grandchild}
			}
			catalogueReads, metadataReads, wholeReads, reviews, writes := 0, 0, 0, 0, 0
			expectedReviews, seenReviews := map[string]int{}, map[string]int{}
			for _, entry := range [][3]string{{"", "v1", "serviceaccounts"}, {"", "v1", "secrets"}, {"", "v1", "events"}, {"rbac.authorization.k8s.io", "v1", "roles"}, {"rbac.authorization.k8s.io", "v1", "rolebindings"}, {"coordination.k8s.io", "v1", "leases"}, {"example.invalid", "v1", "gadgets"}} {
				spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: entry[0], Version: entry[1], Resource: entry[2], Namespace: d.Namespace, Verb: "list"}}
				encoded, _ := json.Marshal(spec)
				expectedReviews[string(encoded)] = 1
			}
			faultHit := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if req.Header.Get("Authorization") != "Bearer FAKE-LEAF-ADMIN" || req.Header.Get("Impersonate-User") != "" {
					t.Error("leaf reader escaped original administrator")
				}
				if req.Method == http.MethodPost && req.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(req.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil || review.Spec.ResourceAttributes.Verb != "list" || review.Spec.ResourceAttributes.Namespace != d.Namespace || review.Spec.ResourceAttributes.Name != "" {
						t.Error("leaf review was not exact namespace LIST")
					}
					reviews++
					encoded, _ := json.Marshal(review.Spec)
					if expectedReviews[string(encoded)] != 1 || seenReviews[string(encoded)] != 0 {
						t.Error("leaf review escaped independent exact source multiset")
					}
					seenReviews[string(encoded)]++
					review.Status.Allowed = scenario != "list-denied"
					faultHit = faultHit || scenario == "list-denied"
					_ = json.NewEncoder(w).Encode(review)
					return
				}
				if req.Method != http.MethodGet {
					writes++
					w.WriteHeader(403)
					return
				}
				if req.URL.Path == "/api" {
					catalogueReads++
					_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
					return
				}
				if req.URL.Path == "/apis" {
					groups := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"}, Groups: []metav1.APIGroup{}}
					for _, name := range []string{"rbac.authorization.k8s.io", "coordination.k8s.io", "example.invalid"} {
						version := metav1.GroupVersionForDiscovery{GroupVersion: name + "/v1", Version: "v1"}
						groups.Groups = append(groups.Groups, metav1.APIGroup{Name: name, Versions: []metav1.GroupVersionForDiscovery{version}, PreferredVersion: version})
					}
					_ = json.NewEncoder(w).Encode(groups)
					return
				}
				for gv, resources := range sources {
					path := "/apis/" + gv
					if gv == "v1" {
						path = "/api/v1"
					}
					if req.URL.Path == path {
						if scenario == "discovery-drift" && catalogueReads >= 2 {
							resources.APIResources = append([]metav1.APIResource(nil), resources.APIResources...)
							resources.APIResources[0].Verbs = metav1.Verbs{"list"}
							faultHit = true
						}
						_ = json.NewEncoder(w).Encode(resources)
						return
					}
					for _, resource := range resources.APIResources {
						collection := path + "/namespaces/" + d.Namespace + "/" + resource.Name
						if req.URL.Path != collection {
							continue
						}
						metadataReads++
						if !strings.Contains(req.Header.Get("Accept"), "PartialObjectMetadataList") || len(req.URL.Query()["labelSelector"]) != 0 || len(req.URL.Query()["fieldSelector"]) != 0 {
							t.Error("leaf reader fetched payload or selected collection")
						}
						if scenario == "metadata-denied" {
							faultHit = true
							w.WriteHeader(403)
							return
						}
						if scenario == "journal-drift" && metadataReads == 1 {
							namespace.ResourceVersion, faultHit = "999", true
						}
						if scenario == "policy-rv-drift" && metadataReads == 1 {
							for key, object := range v.f.access.objects {
								if key.Kind == "ValidatingAdmissionPolicy" {
									object.SetResourceVersion("999") // same signed body, new live RV
									faultHit = true
									break
								}
							}
						}
						if scenario == "receipt-replaced" && metadataReads == 1 {
							name := retirementName(d, d.AdmissionRetirementRevision)
							body, id, err := v.f.engine.files.Read(name, retirementMaxBytes)
							if err != nil {
								t.Error("receipt replacement fixture unavailable")
							} else if _, err := v.f.engine.files.AtomicWrite(name, body, &id); err != nil {
								t.Error("receipt replacement fixture failed")
							} else {
								faultHit = true
							}
						}
						rows := items[collection]
						if rows == nil {
							rows = []metav1.PartialObjectMetadata{}
						}
						_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "100"}, Items: rows})
						return
					}
				}
				if req.URL.Path == rootPath+"/"+key.Name {
					wholeReads++
					object := live.DeepCopy()
					if wholeReads >= 2 { // after original access/policy core closes
						switch scenario {
						case "root-finalizer":
							object.SetFinalizers([]string{"foreign.invalid/retained"})
						case "whole-rv":
							object.SetResourceVersion("999")
						case "whole-body":
							_ = unstructured.SetNestedField(object.Object, "foreign-role", "roleRef", "name")
						}
					}
					_ = json.NewEncoder(w).Encode(object)
					return
				}
				if req.URL.Path == "/api/v1/namespaces/"+d.Namespace {
					_ = json.NewEncoder(w).Encode(namespace)
					return
				}
				for key, object := range v.f.access.objects {
					path, err := resourcePath(key, false)
					if err == nil && req.URL.Path == path {
						_ = json.NewEncoder(w).Encode(object)
						return
					}
				}
				t.Error("leaf reader escaped closed read protocol")
				w.WriteHeader(404)
			}))
			defer server.Close()
			config := serverConfig(server)
			config.BearerToken, config.QPS, config.Burst = "FAKE-LEAF-ADMIN", 100, 200
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("closed original access unavailable")
			}
			store, err := installstate.New(access.Namespaces(), v.f.plan)
			if err != nil {
				t.Fatal("original store unavailable")
			}
			engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
			if err != nil {
				t.Fatal("original engine unavailable")
			}
			// The actual persisted sealed intent, not an invented public snapshot.
			ctx := t.Context()
			if scenario == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			err = engine.prepareRetiredLeafDelete(ctx, intent)
			if strings.HasPrefix(scenario, "leaf") {
				if err != nil || reviews != 7 || metadataReads != 7 || wholeReads != 2 || catalogueReads != 3 {
					t.Fatal("complete original leaf protocol refused or omitted evidence", err, reviews, metadataReads, wholeReads, catalogueReads)
				}
			} else if err == nil {
				t.Fatal("unproved original leaf accepted", scenario)
			}
			switch scenario {
			case "secret-child", "lease-child", "custom-child", "event-child", "terminal-child", "non-controller-child", "owner-kind-mismatch", "transitive-child", "missing-root", "replaced-root", "root-rv", "root-source", "root-owner":
				if err != ErrOwnership || metadataReads != 7 || reviews != 7 || catalogueReads != 3 || wholeReads != 0 {
					t.Fatal("root/descendant negative failed before intended complete closure", err, metadataReads, reviews, catalogueReads, wholeReads)
				}
			case "root-finalizer", "whole-body", "whole-rv":
				if err != ErrOwnership || metadataReads != 7 || reviews != 7 || catalogueReads != 3 || wholeReads != 2 {
					t.Fatal("whole target negative failed before original reread", err, metadataReads, reviews, catalogueReads, wholeReads)
				}
			case "receipt-replaced":
				if err != ErrAdmission || metadataReads != 7 || wholeReads != 2 {
					t.Fatal("same-byte receipt replacement did not reach final pin check", err, metadataReads, wholeReads)
				}
			case "policy-rv-drift":
				if err != ErrAdmission || metadataReads != 7 || wholeReads != 1 || !faultHit {
					t.Fatal("live policy drift during metadata escaped exact original retirement core", err, metadataReads, wholeReads)
				}
			}
			if writes != 0 || !bytes.Equal(intent.Bytes(), mustLeafJournal(t, v, intent)) {
				t.Fatal("leaf refusal/read proof changed authority or settled intent")
			}
			if (scenario == "list-denied" || scenario == "metadata-denied" || scenario == "journal-drift" || scenario == "receipt-replaced" || scenario == "discovery-drift") && !faultHit {
				t.Fatal("negative never reached its mutation/refusal boundary")
			}
		})
	}
}

func mustLeafJournal(t *testing.T, v *lifecycleFixture, intent *installstate.Snapshot) []byte {
	t.Helper()
	snapshot, err := v.f.engine.journal.Load(t.Context(), intent.Anchor())
	if err != nil {
		t.Fatal("original pending journal unavailable")
	}
	return snapshot.Bytes()
}

func TestRetiredAccessLeafSelectionNeverGrantsPublicDeleteAuthority(t *testing.T) {
	d := installstate.Document{Namespace: "isolated", Mode: installstate.Uninstall, Stage: installstate.Applying, AdmissionRetirementRevision: 10, Pending: &installstate.Pending{Action: installstate.Delete, Key: installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "isolated", Name: "arcadectl-api"}}}
	if !retiredNamespaceAccessLeaf(d) {
		t.Fatal("original namespace binding not eligible for separate proof")
	}
	for _, key := range []installstate.Key{{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: "arcadectl-api"}, {APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "foreign", Name: "arcadectl-api"}, {APIVersion: "rbac.authorization.k8s.io/v1beta1", Kind: "RoleBinding", Namespace: "isolated", Name: "arcadectl-api"}, {APIVersion: "v1", Kind: "Secret", Namespace: "isolated", Name: "arcadectl-api"}} {
		d.Pending.Key = key
		if retiredNamespaceAccessLeaf(d) {
			t.Fatal("leaf eligibility escaped finite original namespace families")
		}
	}
	d.Pending.Key = installstate.Key{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "isolated", Name: "arcadectl-api"}
	for _, scenario := range []string{"no-intent", "not-retired", "not-uninstall", "not-applying", "not-delete"} {
		candidate := d
		pending := *d.Pending
		candidate.Pending = &pending
		switch scenario {
		case "no-intent":
			candidate.Pending = nil
		case "not-retired":
			candidate.AdmissionRetirementRevision = 0
		case "not-uninstall":
			candidate.Mode = installstate.Upgrade
		case "not-applying":
			candidate.Stage = installstate.Quiescing
		case "not-delete":
			candidate.Pending.Action = installstate.Update
		}
		if retiredNamespaceAccessLeaf(candidate) {
			t.Fatal("leaf selection escaped the original retirement stage/action")
		}
	}
}
