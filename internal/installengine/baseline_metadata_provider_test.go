// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

// Real frozen transport/discovery/administrator-review/journal composition,
// over explicit synthetic replies. Not native serving or a wired runtime guard.
func TestBaselineMetadataWholeProvider(t *testing.T) {
	for _, mode := range []string{
		"healthy", "service-absent", "fresh-absent", "create-absent", "create-ack", "create-no-receipt", "create-empty-receipt", "create-copied-nonce", "final-receipt-replacement",
		"create-partial-pass-failure", "create-second-pass-failure", "create-final-journal-change",
		"update-before", "update-after", "update-before-rv", "update-new-nonce-old-rv", "update-late-branch-change",
		"delete-before", "delete-draining", "delete-absent", "delete-unauthorized", "delete-extra-finalizer",
		"late-arcadectl-controller", "late-arcadectl-destroy-controller", "late-arcadectl-destroy-admin",
		"recorded-missing", "late-recorded-missing", "late-replacement", "late-whole-rv", "late-whole-status", "late-service-allocation", "late-sa-generation",
		"get-403", "get-409", "get-422", "get-500", "null-success", "malformed-success", "wrong-kind", "unknown-field",
		"read-denied", "absent-read-denied", "read-review-incomplete", "discovery-missing", "final-journal-change", "cancelled",
	} {
		t.Run(mode, func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			d := f.snapshot.Document()
			key := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: "arcadectl-api"}
			template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
			if err != nil {
				t.Fatal("signed API Service unavailable")
			}
			service := testBaselineMetadataLive(t, template, strings.Repeat("b", 32))
			service.SetUID("original-api-service")
			service.SetResourceVersion("17")
			recorded := !strings.HasPrefix(mode, "create-") && mode != "final-receipt-replacement" && mode != "service-absent" && mode != "fresh-absent"
			if recorded {
				d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: service.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
			}
			if strings.HasPrefix(mode, "create-") || mode == "final-receipt-replacement" || strings.HasPrefix(mode, "update-") {
				d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
				if strings.HasPrefix(mode, "update-") {
					d.Pending.Action, d.Pending.BeforeUID, d.Pending.BeforeResourceVersion, d.Pending.BeforeSHA256 = installstate.Update, service.GetUID(), "17", template.Hash()
				}
			}
			if strings.HasPrefix(mode, "delete-") {
				d.Mode, d.Installed, d.ActivePackage = installstate.Uninstall, true, d.TargetPackage
				d.Pending = &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: strings.Repeat("c", 32), BeforeUID: service.GetUID(), BeforeResourceVersion: "17", BeforeSHA256: template.Hash()}
				if mode == "delete-unauthorized" {
					d.Pending, d.Mode, d.ActivePackage, d.Installed = nil, installstate.Install, "", false
				}
			}
			if mode == "fresh-absent" {
				originalResources := d.Resources
				d.Resources = []installstate.Resource{}
				for _, resource := range originalResources {
					if resource.Key.Kind == "Namespace" {
						d.Resources = append(d.Resources, resource)
					}
				}
			}
			installstate.SortResources(d.Resources)
			d.Revision++
			seedBaselineAccessUnitDocument(t, f, d)
			if d.Pending != nil && d.Pending.Action == installstate.Create {
				annotations := service.GetAnnotations()
				annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
				service.SetAnnotations(annotations)
				if mode != "create-no-receipt" {
					if f.engine.prepareCreateReceipt(d) != nil || mode != "create-empty-receipt" && f.engine.saveCreateUID(d, service.GetUID()) != nil {
						t.Fatal("protected synthetic original CREATE ACK refused")
					}
				}
				if mode == "create-copied-nonce" {
					service.SetUID("foreign-copied-nonce")
				}
			}
			if mode == "update-after" || mode == "update-new-nonce-old-rv" {
				annotations := service.GetAnnotations()
				annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
				service.SetAnnotations(annotations)
				if mode == "update-after" {
					service.SetResourceVersion("18")
				}
			} else if mode == "update-before-rv" {
				service.SetResourceVersion("16")
			}
			if strings.HasPrefix(mode, "delete-") && mode != "delete-before" && mode != "delete-absent" {
				stamp := metav1.NewTime(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
				service.SetDeletionTimestamp(&stamp)
				service.SetDeletionGracePeriodSeconds(ptr.To[int64](0))
				service.SetFinalizers([]string{"foregroundDeletion"})
				service.SetResourceVersion("18")
				if mode == "delete-extra-finalizer" {
					service.SetFinalizers([]string{"foregroundDeletion", "foreign.example/hold"})
				}
			}
			ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal("synthetic original namespace unavailable")
			}
			objects := map[installstate.Key]*unstructured.Unstructured{}
			for key, live := range f.access.objects {
				if baselineMetadataKey(d.Namespace, key) && mode != "fresh-absent" {
					objects[key] = live.DeepCopy()
				}
			}
			if mode != "service-absent" && mode != "fresh-absent" && mode != "create-absent" && mode != "delete-absent" && mode != "recorded-missing" {
				objects[key] = service
			}
			literalKeys := testBaselineMetadataKeys(d.Namespace)
			paths := map[string]installstate.Key{}
			for _, expected := range literalKeys {
				plural := map[string]string{"ServiceAccount": "serviceaccounts", "Service": "services", "Role": "roles", "RoleBinding": "rolebindings"}[expected.Kind]
				prefix := "/api/v1"
				if expected.Kind == "Role" || expected.Kind == "RoleBinding" {
					prefix = "/apis/rbac.authorization.k8s.io/v1"
				}
				paths[prefix+"/namespaces/"+d.Namespace+"/"+plural+"/"+expected.Name] = expected
			}
			var mu sync.Mutex
			reads, reviews := map[installstate.Key]int{}, map[installstate.Key]int{}
			var active, changed bool
			var namespaceReads, mutations int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer FAKE-METADATA-PROVIDER" || r.Header.Get("Impersonate-User") != "" {
					t.Error("metadata provider changed frozen administrator identity")
				}
				if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.NonResourceAttributes != nil {
						t.Error("metadata read permission shape unavailable")
						w.WriteHeader(500)
						return
					}
					a := *review.Spec.ResourceAttributes
					var selected installstate.Key
					for _, expected := range literalKeys {
						group := ""
						if expected.APIVersion != "v1" {
							group = "rbac.authorization.k8s.io"
						}
						plural := map[string]string{"ServiceAccount": "serviceaccounts", "Service": "services", "Role": "roles", "RoleBinding": "rolebindings"}[expected.Kind]
						if reflect.DeepEqual(a, authv1.ResourceAttributes{Group: group, Version: "v1", Resource: plural, Namespace: d.Namespace, Name: expected.Name, Verb: "get"}) {
							selected = expected
						}
					}
					if selected == (installstate.Key{}) {
						t.Error("metadata permission escaped fixed named GET domain")
						w.WriteHeader(500)
						return
					}
					reviews[selected]++
					status := map[string]any{"allowed": true}
					if selected == key && mode == "read-denied" || selected.Kind == "Service" && selected.Name == "arcadectl-destroy-admin" && mode == "absent-read-denied" {
						status["allowed"], changed = false, true
					} else if selected == key && mode == "read-review-incomplete" {
						status, changed = map[string]any{}, true
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": review.Spec, "status": status})
					return
				}
				if r.Method != http.MethodGet {
					mutations++
					w.WriteHeader(500)
					return
				}
				if r.URL.Path == "/version" {
					_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + f.plan.Profile().KubernetesVersion})
					return
				}
				if r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
					copy := ns.DeepCopy()
					copy.APIVersion, copy.Kind = "v1", "Namespace"
					if active {
						namespaceReads++
						if namespaceReads == 8 {
							if mode == "final-journal-change" || mode == "create-final-journal-change" {
								copy.ResourceVersion, changed = "9001", true
							} else if mode == "final-receipt-replacement" {
								name := "create-" + d.Pending.CreateNonce + ".json"
								body, identity, readErr := f.engine.files.Read(name, 4096)
								if readErr != nil {
									t.Error("opening protected receipt unavailable")
								} else if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
									t.Error("identical-body final receipt replacement unavailable")
								} else {
									changed = true
								}
							}
						}
						if namespaceReads == 4 && mode == "late-sa-generation" {
							sa := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: "arcadectl-controller"}
							objects[sa].SetGeneration(1)
							changed = true
						}
					}
					_ = json.NewEncoder(w).Encode(copy)
					return
				}
				for _, gv := range []string{"v1", "rbac.authorization.k8s.io/v1"} {
					path, _ := discoveryPath(gv)
					if r.URL.Path == path {
						resources := []metav1.APIResource{}
						for _, pair := range [][2]string{{"ServiceAccount", "serviceaccounts"}, {"Service", "services"}, {"Role", "roles"}, {"RoleBinding", "rolebindings"}} {
							if (gv == "v1") != (pair[0] == "Service" || pair[0] == "ServiceAccount") {
								continue
							}
							if mode == "discovery-missing" && pair[0] == "Service" {
								changed = true
								continue
							}
							resources = append(resources, metav1.APIResource{Name: pair[1], Kind: pair[0], Namespaced: true, Verbs: metav1.Verbs{"get"}})
						}
						_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
						return
					}
				}
				selected, exists := paths[r.URL.Path]
				if !exists || r.URL.RawQuery != "" {
					t.Error("metadata read escaped fixed uncached named addresses")
					w.WriteHeader(500)
					return
				}
				reads[selected]++
				if selected.Kind == "Role" && selected.Name == "arcadectl-destroy-admin" && (mode == "create-partial-pass-failure" || mode == "create-second-pass-failure" && reads[selected] == 2) {
					changed = true
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				live := objects[selected]
				if selected.Kind == "Service" && mode == "late-"+selected.Name && reads[selected] == 2 {
					live = service.DeepCopy()
					live.SetName(selected.Name)
					changed = true
				}
				if live != nil {
					live = live.DeepCopy()
				}
				if selected == key {
					switch mode {
					case "get-403", "get-409", "get-422", "get-500":
						code := map[string]int{"get-403": 403, "get-409": 409, "get-422": 422, "get-500": 500}[mode]
						changed = true
						w.WriteHeader(code)
						return
					case "null-success":
						changed = true
						_, _ = w.Write([]byte("null"))
						return
					case "malformed-success":
						changed = true
						_, _ = w.Write([]byte("{PRIVATE-CANARY"))
						return
					case "wrong-kind":
						live.SetKind("ServiceAccount")
						changed = true
					case "unknown-field":
						live.Object["unknownField"], changed = "PRIVATE-CANARY", true
					}
					if reads[selected] == 2 {
						switch mode {
						case "late-recorded-missing":
							live, changed = nil, true
						case "late-replacement":
							live.SetUID("foreign-same-name")
							changed = true
						case "late-whole-rv":
							live.SetResourceVersion("18")
							changed = true
						case "late-whole-status":
							live.Object["status"], changed = map[string]any{"loadBalancer": map[string]any{"ingress": []any{map[string]any{"ip": "192.0.2.1"}}}}, true
						case "late-service-allocation":
							_ = unstructured.SetNestedField(live.Object, "10.96.0.43", "spec", "clusterIP")
							_ = unstructured.SetNestedStringSlice(live.Object, []string{"10.96.0.43"}, "spec", "clusterIPs")
							changed = true
						case "update-late-branch-change":
							annotations := live.GetAnnotations()
							annotations[installstate.MutationAnnotation] = d.Pending.CreateNonce
							live.SetAnnotations(annotations)
							live.SetResourceVersion("18")
							changed = true
						}
					}
				}
				if live == nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(live.Object)
			}))
			t.Cleanup(server.Close)
			config := serverConfig(server)
			config.BearerToken, config.QPS, config.Burst = "FAKE-METADATA-PROVIDER", 1000, 2000 // In-process synthetic only.
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("frozen metadata transport unavailable")
			}
			store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
			if err != nil {
				t.Fatal("protected metadata journal unavailable")
			}
			engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
			if err != nil {
				t.Fatal("closed metadata engine unavailable")
			}
			snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
			if err != nil {
				t.Fatal("original metadata snapshot unavailable")
			}
			reader, err := NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal("closed metadata collector unavailable")
			}
			guard := &baselineParentRefusingRuntimeGuard{}
			engine.baseline.runtimeGuard = guard // Nonrecursion detection ONLY.
			defer func() { engine.baseline.runtimeGuard = nil }()
			mu.Lock()
			active = true
			mu.Unlock()
			ctx := t.Context()
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			observed, err := reader.originalMetadata(ctx, snapshot)
			t.Cleanup(observed.release)
			positive := mode == "healthy" || mode == "service-absent" || mode == "fresh-absent" || mode == "create-absent" || mode == "create-ack" || mode == "update-before" || mode == "update-after" || mode == "delete-before" || mode == "delete-draining" || mode == "delete-absent"
			if (err == nil) != positive || positive && observed == nil || !positive && observed != nil {
				t.Fatal("whole metadata provider accepted incomplete, changing or foreign evidence")
			}
			if err != nil && (strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "FAKE")) {
				t.Fatal("metadata refusal exposed private protocol data")
			}
			if d.Pending != nil && d.Pending.Action == installstate.Create {
				name := "create-" + d.Pending.CreateNonce + ".json"
				want := 0
				if mode == "create-ack" {
					want = 1
				}
				if testBaselineReceiptDescriptors(t, name) != want {
					t.Fatal("metadata collector leaked a partial, discarded or refused receipt owner")
				}
				if mode == "create-ack" {
					if engine.confirmBaselineMetadataReceipts(observed) != nil {
						t.Fatal("successful metadata collection prematurely released its receipt")
					}
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if mutations != 0 || guard.calls.Load() != 0 || !bytes.Equal(snapshot.Bytes(), f.snapshot.Bytes()) {
				t.Fatal("metadata collector mutated, recursed or changed original journal")
			}
			if positive {
				if len(observed.objects) != 16 || namespaceReads != 8 || !sameBaselineMetadata(observed, observed) {
					t.Fatal("metadata witness omitted complete closing fences or addresses")
				}
				for _, expected := range literalKeys {
					if reads[expected] != 2 || reviews[expected] != 2 {
						t.Fatal("metadata provider omitted an absent/present named read or its permission")
					}
				}
				if mode == "fresh-absent" {
					var missingEngine *Engine
					if missingEngine.confirmBaselineMetadataReceipts(observed) == nil || (&Engine{}).confirmBaselineMetadataReceipts(observed) == nil {
						t.Fatal("all-absent metadata closure accepted a missing engine")
					}
				}
				for _, expected := range literalKeys {
					closed := &baselineMetadata{snapshot: snapshot, objects: make(map[installstate.Key]*baselineOriginalObject, 16)}
					for key, object := range observed.objects {
						if key != expected {
							closed.objects[key] = object
						}
					}
					if sameBaselineMetadata(observed, closed) || engine.confirmBaselineMetadataReceipts(closed) == nil {
						t.Fatal("omitted map entry became native absence")
					}
				}
				if mode == "create-ack" {
					observed.release()
					name := "create-" + d.Pending.CreateNonce + ".json"
					if testBaselineReceiptDescriptors(t, name) != 0 || engine.confirmBaselineMetadataReceipts(observed) != ErrSecurityBaseline {
						t.Fatal("released metadata witness retained authority or leaked its receipt")
					}
				}
			}
			if (strings.HasPrefix(mode, "late-") || mode == "update-late-branch-change" || mode == "final-receipt-replacement" || mode == "final-journal-change" || mode == "create-final-journal-change" || strings.HasSuffix(mode, "pass-failure") || strings.HasPrefix(mode, "get-") || mode == "null-success" || mode == "malformed-success" || mode == "wrong-kind" || mode == "unknown-field" || mode == "read-denied" || mode == "absent-read-denied" || mode == "read-review-incomplete" || mode == "discovery-missing") && !changed {
				t.Fatal("intended provider fault was never injected")
			}
		})
	}
}
