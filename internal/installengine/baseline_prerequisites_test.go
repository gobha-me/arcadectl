// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Deliberate synthetic journal seeding, not an installer mutation or enrollment
// path. The resulting snapshots still pass the actual baseline-aware decoder.
func prerequisiteSnapshotFixture(t *testing.T, f *fixture, document installstate.Document) *installstate.Snapshot {
	t.Helper()
	document.Revision++
	installstate.SortResources(document.Resources)
	body, err := installstate.EncodeWithBaseline(document, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("prerequisite journal fixture encoding failed")
	}
	namespace, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal("prerequisite journal fixture namespace unavailable")
	}
	namespace.Annotations[installstate.Annotation] = string(body)
	namespace.ResourceVersion += "1"
	if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
		t.Fatal("prerequisite journal fixture seeding failed")
	}
	snapshot, err := f.store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("prerequisite original snapshot fixture unavailable")
	}
	return snapshot
}

func TestBaselinePrerequisiteContextCannotBecomeStageOrActionExemption(t *testing.T) {
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	var key, other installstate.Key
	for _, resource := range f.plan.ResourceMetadata() {
		if resource.Kind == "CustomResourceDefinition" {
			other = key
			key = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Name: resource.Name}
		}
	}
	operation, err := f.engine.prerequisiteOperation(f.snapshot, key, f.plan.Digest())
	if err != nil {
		t.Fatal("operation context fixture unavailable")
	}
	base := f.snapshot.Document()
	for _, scenario := range []string{"preparing", "verifying", "recovery-stage", "active", "upgrade", "rollback", "uninstall", "retaining-reinstall", "installed", "incomplete-baseline", "absent-baseline", "other-pending", "wrong-pending-hash", "wrong-pending-nonce", "pending-update", "owned-target", "runtime-inventory"} {
		t.Run(scenario, func(t *testing.T) {
			document := f.snapshot.Document()
			document = base
			document.Resources = append([]installstate.Resource{}, base.Resources...)
			if base.SecurityBaseline != nil {
				copyBaseline := *base.SecurityBaseline
				document.SecurityBaseline = &copyBaseline
			}
			switch scenario {
			case "preparing":
				document.Stage = installstate.Preparing
			case "verifying":
				document.Stage = installstate.Verifying
			case "recovery-stage":
				document.Stage = installstate.RecoveryRequired
			case "active":
				document.ActivePackage = document.TargetPackage
			case "upgrade":
				document.Mode = installstate.Upgrade
				document.ActivePackage = document.TargetPackage
				document.Installed = true
			case "rollback", "uninstall", "retaining-reinstall":
				document.ActivePackage = document.TargetPackage
				if scenario == "rollback" {
					document.Mode = installstate.Rollback
					document.Installed = true
				} else if scenario == "uninstall" {
					document.Mode = installstate.Uninstall
					document.Installed = true
				}
			case "installed":
				document.ActivePackage = document.TargetPackage
				document.Installed = true
			case "incomplete-baseline":
				document.SecurityBaseline.Stage = installstate.BaselineApplying
			case "absent-baseline":
				document.SecurityBaseline = nil
			case "other-pending":
				template, _ := f.engine.contracts[f.plan.Digest()].Template(other, false)
				document.Pending = &installstate.Pending{Action: installstate.Create, Key: other, CreateNonce: strings.Repeat("b", 32), AfterSHA256: template.Hash()}
			case "wrong-pending-hash":
				document.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: strings.Repeat("e", 64)}
			case "wrong-pending-nonce":
				document.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: operation.hash}
			case "pending-update":
				template, _ := f.engine.contracts[f.plan.Digest()].Template(key, false)
				document.Resources = append(document.Resources, installstate.Resource{Key: key, UID: "synthetic-original", TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
				document.Pending = &installstate.Pending{Action: installstate.Update, Key: key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: template.Hash(), BeforeUID: "synthetic-original", BeforeResourceVersion: "33", BeforeSHA256: template.Hash()}
			case "owned-target", "runtime-inventory":
				ownedKey := key
				if scenario == "runtime-inventory" {
					for _, resource := range f.plan.ResourceMetadata() {
						if resource.Kind == "Deployment" {
							ownedKey = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
							break
						}
					}
				}
				template, _ := f.engine.contracts[f.plan.Digest()].Template(ownedKey, false)
				document.Resources = append(document.Resources, installstate.Resource{Key: ownedKey, UID: "synthetic-original", TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
			}
			snapshot := prerequisiteSnapshotFixture(t, f, document)
			if _, err := f.engine.prerequisiteContext(snapshot, operation); err != ErrSecurityBaseline {
				t.Fatal("unrelated stage/action/runtime state acquired bootstrap authority")
			}
		})
	}
}

func TestBaselinePrerequisitePendingEveryKindRequiresProtectedOriginalUID(t *testing.T) {
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	base := f.snapshot.Document()
	seenKinds := map[string]bool{}
	for _, resource := range f.plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		if !baselinePrerequisiteKey(key, f.plan.Namespace()) || seenKinds[key.Kind] {
			continue
		}
		seenKinds[key.Kind] = true
		t.Run(key.Kind, func(t *testing.T) {
			for _, scenario := range []string{"absent", "pinned", "missing-receipt", "empty-receipt", "replacement", "copied-nonce", "changed-template"} {
				t.Run(scenario, func(t *testing.T) {
					template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
					if err != nil {
						t.Fatal("pending prerequisite template unavailable")
					}
					nonce, err := installstate.NewID()
					if err != nil {
						t.Fatal("pending fixture nonce unavailable")
					}
					document := base
					document.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: nonce, AfterSHA256: template.Hash()}
					snapshot := prerequisiteSnapshotFixture(t, f, document)
					candidate, err := template.Candidate(nonce)
					if err != nil {
						t.Fatal("pending candidate fixture unavailable")
					}
					candidate.SetUID("original-pending")
					candidate.SetResourceVersion("40")
					if key.Kind == "CustomResourceDefinition" {
						// Independently reviewed native default, not learned from
						// a response or treated as signed desired input.
						if unstructured.SetNestedMap(candidate.Object, map[string]any{"strategy": "None"}, "spec", "conversion") != nil {
							t.Fatal("native CRD default fixture unavailable")
						}
					}
					if scenario != "missing-receipt" {
						if f.engine.prepareCreateReceipt(snapshot.Document()) != nil {
							t.Fatal("pending fixture receipt unavailable")
						}
						if scenario != "empty-receipt" && f.engine.saveCreateUID(snapshot.Document(), candidate.GetUID()) != nil {
							t.Fatal("pending fixture original UID not durable")
						}
					}
					if scenario == "replacement" || scenario == "copied-nonce" {
						candidate.SetUID("copied-nonce-replacement")
					}
					if scenario == "changed-template" {
						candidate.SetAnnotations(map[string]string{installstate.MutationAnnotation: nonce, "foreign.example/mutation": "changed"})
					}
					path, _ := resourcePath(key, false)
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodGet || r.URL.Path != path {
							t.Error("pending original proof escaped read-only target")
							w.WriteHeader(500)
							return
						}
						w.Header().Set("Content-Type", "application/json")
						if scenario == "absent" {
							w.WriteHeader(404)
							return
						}
						_ = json.NewEncoder(w).Encode(candidate)
					}))
					defer server.Close()
					access, err := NewDirectHTTPAccess(serverConfig(server))
					if err != nil {
						t.Fatal("pending HTTP fixture unavailable")
					}
					configuration := &ClusterSecurityBaseline{engine: f.engine, access: access} // private predicate fixture only
					operation, err := f.engine.prerequisiteOperation(snapshot, key, f.plan.Digest())
					if err != nil {
						t.Fatal("pending descriptor fixture unavailable")
					}
					if operation.nonce != nonce {
						t.Fatal("pending descriptor lost durable nonce binding")
					}
					wrongNonce := *operation
					wrongNonce.nonce = ""
					if _, err := f.engine.prerequisiteContext(snapshot, &wrongNonce); err != ErrSecurityBaseline {
						t.Fatal("correct pending hash/action accepted wrong descriptor nonce")
					}
					witness, err := configuration.prerequisiteOriginals(t.Context(), snapshot, operation)
					if scenario == "absent" {
						if err != nil || len(witness) != 0 {
							t.Fatal("pending absent original could not be observed")
						}
					} else if scenario == "pinned" {
						if err != nil || witness[key].UID != candidate.GetUID() {
							t.Fatal("pending acknowledged original was not proved", err)
						}
					} else if err != ErrSecurityBaseline || witness != nil {
						t.Fatal("uncertain/replaced/changed pending target acquired original identity", err)
					}
				})
			}
		})
	}
	if len(seenKinds) != 8 {
		t.Fatal("pending context tests missed a prerequisite family")
	}
}

func TestBaselinePrerequisiteOperationIsSignedAndNonexecuting(t *testing.T) {
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	accepted := 0
	for _, resource := range f.plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		operation, err := f.engine.prerequisiteOperation(f.snapshot, key, f.plan.Digest())
		if baselinePrerequisiteKey(key, f.plan.Namespace()) {
			if err != nil || operation == nil || operation.key != key || operation.digest != f.plan.Digest() || operation.hash == "" {
				t.Fatal("signed nonexecuting operation refused")
			}
			accepted++
			for _, change := range []func(*baselinePrerequisite){
				func(o *baselinePrerequisite) { o.hash = strings.Repeat("e", 64) },
				func(o *baselinePrerequisite) { o.digest = strings.Repeat("e", 64) },
				func(o *baselinePrerequisite) { o.key.Name = "foreign" },
				func(o *baselinePrerequisite) { o.key.Namespace = "foreign" },
			} {
				copyOperation := *operation
				change(&copyOperation)
				if _, err := f.engine.prerequisiteContext(f.snapshot, &copyOperation); err != ErrSecurityBaseline {
					t.Fatal("forged operation descriptor was authorized")
				}
			}
		} else if err != ErrSecurityBaseline || operation != nil {
			t.Fatal("executable, credential, service or Namespace operation was authorized")
		}
	}
	if accepted == 0 || f.access.writes != 12 || f.access.dryRuns != 12 {
		t.Fatal("operation validation emitted an effect or covered no prerequisites")
	}
	for _, key := range []installstate.Key{
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: f.plan.Namespace(), Name: "foreign"},
		{APIVersion: "batch/v1", Kind: "Job", Namespace: f.plan.Namespace(), Name: "arbitrary"},
		{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: f.plan.Namespace(), Name: "world"},
	} {
		if operation, err := f.engine.prerequisiteOperation(f.snapshot, key, f.plan.Digest()); err != ErrSecurityBaseline || operation != nil {
			t.Fatal("unsigned or world operation was authorized")
		}
	}
}

// Synthetic HTTPS proof of the production collector/authorization composition,
// not native policy enforcement, Kind typechecking or a lifecycle pass. Every
// request is read-only except existing-identity SSARs; no target CREATE occurs.
func TestBaselinePrerequisiteCompleteDiscoveryOriginalAndAbsence(t *testing.T) {
	for _, scenario := range []string{"empty", "benign-defaults", "signed-original", "signed-original-drift", "signed-original-replaced", "signed-original-missing", "signed-SA", "signed-SA-membership", "signed-SA-replaced", "pending-absent", "pending-cluster", "pending-cluster-drift", "pending-cluster-replaced", "pending-missing-receipt", "pending-empty-receipt", "pending-copied-nonce", "pending-SA", "pending-SA-membership", "pending-SA-replaced", "missing-source", "deny-list", "pod", "terminating-pod", "secret", "world", "custom", "custom-no-delete", "custom-list-only", "foreign-account", "default-owner", "default-finalizer", "default-token", "default-replaced", "ca-owner", "ca-finalizer", "baseline-drift", "journal-drift", "late-fixture", "cancelled", "target-present", "target-appears"} {
		t.Run(scenario, func(t *testing.T) { testBaselinePrerequisiteCompleteDiscovery(t, scenario) })
	}
}

// Same signed/HTTPS collector fixture now exercises the actual effect and
// protected journal/receipt path. It remains synthetic native health, not Kind
// behavioral enforcement or full installation certification.
func TestBaselinePrerequisiteMutationBoundarySingleSendAndRecovery(t *testing.T) {
	for _, scenario := range []string{"effect-create", "effect-coordinator-create", "effect-SA-create", "effect-SA-missing-membership", "effect-SA-replaced-membership", "effect-argument-mismatch", "effect-preview-drift", "effect-intent-drift", "effect-ack-lost", "effect-ack-late-copy", "effect-ack-malformed", "effect-replacement", "effect-world-after-create", "effect-settle-response-lost"} {
		t.Run(scenario, func(t *testing.T) { testBaselinePrerequisiteCompleteDiscovery(t, scenario) })
	}
}

func TestBaselinePrerequisiteReceiptLifetimeAndRecovery(t *testing.T) {
	for _, scenario := range []string{"pending-receipt-first-collection", "pending-receipt-second-collection", "pending-receipt-policy", "pending-receipt-current-final", "pending-receipt-recovery-get", "pending-receipt-recovery-final", "pending-recovery", "pending-empty-absent", "pending-missing-absent"} {
		t.Run(scenario, func(t *testing.T) { testBaselinePrerequisiteCompleteDiscovery(t, scenario) })
	}
}

func testBaselinePrerequisiteCompleteDiscovery(t *testing.T, scenario string) {
	t.Helper()
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	baseline := f.engine.baselinePlan()
	var key installstate.Key
	for _, resource := range f.plan.ResourceMetadata() {
		if resource.Kind == "CustomResourceDefinition" {
			key = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Name: resource.Name}
			break
		}
	}
	if strings.HasPrefix(scenario, "pending-SA") || strings.HasPrefix(scenario, "effect-SA") {
		for _, resource := range f.plan.ResourceMetadata() {
			if resource.Kind == "ServiceAccount" {
				key = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
				break
			}
		}
	}
	if scenario == "effect-coordinator-create" {
		key = (&Lifecycle{engine: f.engine}).ordered(f.snapshot.Document())[0]
		if key.Kind != "CustomResourceDefinition" {
			t.Fatal("coordinator first prerequisite fixture unavailable")
		}
	}
	if strings.HasPrefix(scenario, "pending-") {
		template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
		if err != nil {
			t.Fatal("full pending template fixture unavailable")
		}
		nonce, err := installstate.NewID()
		if err != nil {
			t.Fatal("full pending nonce unavailable")
		}
		document := f.snapshot.Document()
		document.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: nonce, AfterSHA256: template.Hash()}
		f.snapshot = prerequisiteSnapshotFixture(t, f, document)
		candidate, err := template.Candidate(nonce)
		if err != nil {
			t.Fatal("full pending candidate unavailable")
		}
		candidate.SetUID("full-pending-original")
		candidate.SetResourceVersion("43")
		if key.Kind == "CustomResourceDefinition" {
			if unstructured.SetNestedMap(candidate.Object, map[string]any{"strategy": "None"}, "spec", "conversion") != nil {
				t.Fatal("full pending native default unavailable")
			}
		}
		if scenario != "pending-missing-receipt" && scenario != "pending-missing-absent" {
			if f.engine.prepareCreateReceipt(f.snapshot.Document()) != nil {
				t.Fatal("full pending protected receipt unavailable")
			}
			if scenario != "pending-empty-receipt" && scenario != "pending-empty-absent" && f.engine.saveCreateUID(f.snapshot.Document(), candidate.GetUID()) != nil {
				t.Fatal("full pending original UID not durable")
			}
		}
		if scenario == "pending-copied-nonce" {
			candidate.SetUID("copied-nonce-replacement")
		}
		if scenario != "pending-absent" && scenario != "pending-empty-absent" && scenario != "pending-missing-absent" {
			f.access.objects[key] = candidate
		}
	}
	var signedKey installstate.Key
	if strings.HasPrefix(scenario, "signed-") {
		kind := "ClusterRole"
		if strings.HasPrefix(scenario, "signed-SA") {
			kind = "ServiceAccount"
		}
		for _, resource := range f.plan.ResourceMetadata() {
			if resource.Kind != kind {
				continue
			}
			signedKey = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
			template, err := f.engine.contracts[f.plan.Digest()].Template(signedKey, false)
			if err != nil {
				t.Fatal("signed original fixture template unavailable")
			}
			object, err := template.Candidate(strings.Repeat("d", 32))
			if err != nil {
				t.Fatal("signed original fixture candidate unavailable")
			}
			object.SetUID("prerequisite-original")
			object.SetResourceVersion("41")
			f.access.objects[signedKey] = object
			document := f.snapshot.Document()
			document.Resources = append(document.Resources, installstate.Resource{Key: signedKey, UID: object.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
			f.snapshot = prerequisiteSnapshotFixture(t, f, document)
			break
		}
	}
	objects := map[string]*unstructured.Unstructured{}
	for originalKey, original := range f.access.objects {
		path, err := resourcePath(originalKey, false)
		if err != nil {
			t.Fatal("baseline route unavailable")
		}
		object := original.DeepCopy()
		if originalKey.Kind == "ValidatingAdmissionPolicy" {
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
		objects[path] = object
	}
	sources := []installobserve.GCResource{}
	for _, source := range proofCollections {
		if !source.namespaced || source.gv == "arcade.gobha.me/v1alpha1" || source.kind == "Lease" {
			continue
		}
		gv, _ := schema.ParseGroupVersion(source.gv)
		sources = append(sources, installobserve.GCResource{GVR: gv.WithResource(source.plural), Kind: source.kind})
	}
	sources = append(sources,
		installobserve.GCResource{GVR: schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}, Kind: "ServiceAccount"},
		installobserve.GCResource{GVR: schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, Kind: "ConfigMap"},
		installobserve.GCResource{GVR: schema.GroupVersionResource{Version: "v1", Resource: "services"}, Kind: "Service"},
		installobserve.GCResource{GVR: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, Kind: "Role"},
		installobserve.GCResource{GVR: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, Kind: "RoleBinding"},
		installobserve.GCResource{GVR: schema.GroupVersionResource{Group: "custom.example", Version: "v1", Resource: "customs"}, Kind: "Custom"},
	)
	rows := map[string][]metav1.PartialObjectMetadata{}
	pathFor := func(source installobserve.GCResource) string {
		prefix := "/api/v1"
		if source.GVR.Group != "" {
			prefix = "/apis/" + source.GVR.Group + "/" + source.GVR.Version
		}
		return prefix + "/namespaces/" + f.plan.Namespace() + "/" + source.GVR.Resource
	}
	defaultAccount := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "default", "namespace": f.plan.Namespace(), "uid": "default-original", "resourceVersion": "22", "creationTimestamp": "2026-01-01T00:00:00Z"}}}
	if signedKey.Kind == "ServiceAccount" && scenario != "signed-SA-membership" {
		for _, source := range sources {
			if source.Kind != "ServiceAccount" {
				continue
			}
			row := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: signedKey.Name, Namespace: signedKey.Namespace, UID: "prerequisite-original", ResourceVersion: "41"}}
			if scenario == "signed-SA-replaced" {
				row.UID = "replacement"
			}
			rows[pathFor(source)] = []metav1.PartialObjectMetadata{row}
		}
	}
	if strings.HasPrefix(scenario, "pending-SA") && scenario != "pending-SA-membership" {
		for _, source := range sources {
			if source.Kind != "ServiceAccount" {
				continue
			}
			row := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "full-pending-original", ResourceVersion: "43"}}
			if scenario == "pending-SA-replaced" {
				row.UID = "replacement"
			}
			rows[pathFor(source)] = []metav1.PartialObjectMetadata{row}
		}
	}
	rootCA := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "kube-root-ca.crt", "namespace": f.plan.Namespace(), "uid": "inert-original", "resourceVersion": "22", "creationTimestamp": "2026-01-01T00:00:00Z"}, "data": map[string]any{"ca.crt": "inert fixture data - NEVER trust evidence"}}}
	addRow := func(group, resource, name string) {
		for _, source := range sources {
			if source.GVR.Group == group && source.GVR.Resource == resource {
				meta := metav1.ObjectMeta{Name: name, Namespace: f.plan.Namespace(), UID: "inert-original", ResourceVersion: "22", CreationTimestamp: metav1.NewTime(defaultAccount.GetCreationTimestamp().Time)}
				if resource == "serviceaccounts" && name == "default" {
					meta.UID = "default-original"
				}
				if scenario == "terminating-pod" {
					now := metav1.Now()
					meta.DeletionTimestamp = &now
				}
				if scenario == "default-owner" || scenario == "ca-owner" {
					meta.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "foreign", UID: "foreign"}}
				}
				if scenario == "default-finalizer" || scenario == "ca-finalizer" {
					meta.Finalizers = []string{"foreign.example/finalizer"}
				}
				rows[pathFor(source)] = append(rows[pathFor(source)], metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta})
				return
			}
		}
		t.Fatal("fault source unavailable")
	}
	switch scenario {
	case "pod", "terminating-pod":
		addRow("", "pods", "foreign")
	case "secret":
		addRow("", "secrets", "foreign")
	case "world":
		addRow("", "persistentvolumeclaims", "world")
	case "custom", "custom-no-delete", "custom-list-only":
		addRow("custom.example", "customs", "foreign")
	case "foreign-account":
		addRow("", "serviceaccounts", "foreign")
	case "benign-defaults":
		addRow("", "serviceaccounts", "default")
		addRow("", "configmaps", "kube-root-ca.crt")
	case "default-owner", "default-finalizer", "default-token", "default-replaced":
		addRow("", "serviceaccounts", "default")
	case "ca-owner", "ca-finalizer":
		addRow("", "configmaps", "kube-root-ca.crt")
	}
	if scenario == "default-token" {
		defaultAccount.Object["secrets"] = []any{map[string]any{"name": "foreign-token"}}
	}
	if scenario == "default-replaced" {
		defaultAccount.SetUID("replacement")
	}
	if scenario == "default-finalizer" {
		defaultAccount.SetFinalizers([]string{"foreign.example/finalizer"})
	}
	if scenario == "ca-finalizer" {
		rootCA.SetFinalizers([]string{"foreign.example/finalizer"})
	}
	groups := map[string][]metav1.APIResource{}
	for _, source := range sources {
		if scenario == "missing-source" && source.Kind == "Pod" {
			continue
		}
		groups[source.GVR.Group] = append(groups[source.GVR.Group], metav1.APIResource{Name: source.GVR.Resource, Kind: source.Kind, Namespaced: true, Verbs: metav1.Verbs{"delete", "list", "watch"}})
	}
	if scenario == "custom-no-delete" {
		groups["custom.example"][0].Verbs = metav1.Verbs{"create", "list", "watch"}
	}
	if scenario == "custom-list-only" {
		groups["custom.example"][0].Verbs = metav1.Verbs{"list"}
	}
	groupNames := []string{}
	for group := range groups {
		if group != "" {
			groupNames = append(groupNames, group)
		}
	}
	sort.Strings(groupNames)
	var mu sync.Mutex
	lists, reviews, policyReads := 0, 0, 0
	previews, creates, journalWrites := 0, 0, 0
	lateReads := 0
	postPolicyNamespaceReads := 0
	var receiptReplaced bool
	replaceReceipt := func() {
		if receiptReplaced {
			t.Error("receipt replacement fault repeated unexpectedly")
			return
		}
		d := f.snapshot.Document()
		name := "create-" + d.Pending.CreateNonce + ".json"
		if testBaselineReceiptDescriptors(t, name) != 1 {
			t.Error("complete prerequisite or recovery did not retain one opening descriptor")
		}
		body, identity, err := f.engine.files.Read(name, 4096)
		if err != nil {
			t.Error("original prerequisite receipt unavailable for test-owned replacement")
			return
		}
		for range 2 {
			identity, err = f.engine.files.AtomicWrite(name, body, &identity)
			if err != nil {
				t.Error("repeated identical prerequisite receipt replacement failed")
				return
			}
		}
		receiptReplaced = true
	}
	var lateCopy *unstructured.Unstructured
	weakenBaseline := func() {
		for _, object := range objects {
			if object.GetKind() == "ValidatingAdmissionPolicy" {
				if unstructured.SetNestedField(object.Object, "Ignore", "spec", "failurePolicy") != nil {
					t.Error("effect-edge negative policy fixture unavailable")
				}
				return
			}
		}
		t.Error("effect-edge baseline fixture unavailable")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Impersonate-User") != "" {
			t.Error("bootstrap read switched identity")
			w.WriteHeader(500)
			return
		}
		if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil || review.Spec.ResourceAttributes.Namespace != f.plan.Namespace() || review.Spec.ResourceAttributes.Verb != "list" || review.Spec.ResourceAttributes.Name != "" {
				t.Error("bootstrap escaped exact namespace LIST authorization")
				w.WriteHeader(500)
				return
			}
			reviews++
			review.Status.Allowed = scenario != "deny-list"
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		if (strings.HasPrefix(scenario, "effect-") || scenario == "pending-recovery") && r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace() {
			var candidate corev1.Namespace
			if json.NewDecoder(r.Body).Decode(&candidate) != nil {
				t.Error("effect journal request invalid")
				w.WriteHeader(500)
				return
			}
			journalWrites++
			updated, err := f.access.client.CoreV1().Namespaces().Update(r.Context(), &candidate, metav1.UpdateOptions{})
			if err != nil {
				t.Error("effect journal original CAS failed")
				w.WriteHeader(409)
				return
			}
			updated.APIVersion, updated.Kind = "v1", "Namespace"
			var document installstate.Document
			if json.Unmarshal([]byte(updated.Annotations[installstate.Annotation]), &document) != nil {
				t.Error("effect journal intent unavailable")
				w.WriteHeader(500)
				return
			}
			if scenario == "effect-intent-drift" && document.Pending != nil {
				weakenBaseline()
			}
			if scenario == "effect-settle-response-lost" && document.Pending == nil && creates == 1 {
				w.WriteHeader(500)
				return
			}
			_ = json.NewEncoder(w).Encode(updated)
			return
		}
		if targetPath, _ := resourcePath(key, true); strings.HasPrefix(scenario, "effect-") && r.Method == http.MethodPost && r.URL.Path == targetPath {
			candidate := &unstructured.Unstructured{}
			if json.NewDecoder(r.Body).Decode(&candidate.Object) != nil || candidate.GetAPIVersion() != key.APIVersion || candidate.GetKind() != key.Kind || candidate.GetName() != key.Name || candidate.GetNamespace() != key.Namespace {
				t.Error("effect target escaped exact signed address")
				w.WriteHeader(500)
				return
			}
			if key.Kind == "CustomResourceDefinition" {
				if unstructured.SetNestedMap(candidate.Object, map[string]any{"strategy": "None"}, "spec", "conversion") != nil {
					t.Error("effect native default unavailable")
				}
			}
			if r.URL.Query().Get("dryRun") == "All" {
				previews++
				if scenario == "effect-preview-drift" {
					weakenBaseline()
				}
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(candidate)
				return
			}
			if r.URL.Query().Has("dryRun") || creates != 0 {
				t.Error("prerequisite CREATE was replayed or misclassified")
				w.WriteHeader(500)
				return
			}
			namespace, err := f.access.client.CoreV1().Namespaces().Get(r.Context(), f.plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				t.Error("effect lacked original intent")
				w.WriteHeader(500)
				return
			}
			var document installstate.Document
			if json.Unmarshal([]byte(namespace.Annotations[installstate.Annotation]), &document) != nil || document.Pending == nil || document.Pending.Action != installstate.Create || document.Pending.Key != key || document.Pending.CreateNonce != candidate.GetAnnotations()[installstate.MutationAnnotation] {
				t.Error("effect lacked durable exact prerequisite intent")
				w.WriteHeader(500)
				return
			}
			creates++
			candidate.SetUID("effect-original")
			candidate.SetResourceVersion("77")
			path, _ := resourcePath(key, false)
			objects[path] = candidate.DeepCopy()
			if key.Kind == "ServiceAccount" && scenario != "effect-SA-missing-membership" {
				for _, source := range sources {
					if source.Kind == "ServiceAccount" {
						row := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: candidate.GetUID(), ResourceVersion: candidate.GetResourceVersion()}}
						if scenario == "effect-SA-replaced-membership" {
							row.UID = "foreign-membership"
						}
						rows[pathFor(source)] = []metav1.PartialObjectMetadata{row}
					}
				}
			}
			if scenario == "effect-ack-late-copy" {
				lateCopy = candidate.DeepCopy()
				lateCopy.SetUID("copied-nonce-replacement")
				delete(objects, path)
			}
			if scenario == "effect-replacement" {
				objects[path].SetUID("copied-nonce-replacement")
			}
			if scenario == "effect-world-after-create" {
				addRow("", "persistentvolumeclaims", "foreign-world")
			}
			if scenario == "effect-ack-lost" || scenario == "effect-ack-late-copy" {
				w.WriteHeader(500)
				return
			}
			if scenario == "effect-ack-malformed" {
				candidate.SetLabels(map[string]string{"foreign.example/mutation": "wrong"})
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(candidate)
			return
		}
		if r.Method != http.MethodGet {
			t.Error("bootstrap proof emitted a mutation")
			w.WriteHeader(500)
			return
		}
		if path, _ := resourcePath(key, false); scenario == "effect-ack-late-copy" && creates == 1 && r.URL.Path == path {
			lateReads++
			// The four complete prerequisite target observations report absence.
			// Only the subsequent effect-recovery GET sees a copied nonce. That
			// late object must never receive its first protected UID pin.
			if lateReads == 5 {
				objects[path] = lateCopy.DeepCopy()
			}
		}
		if r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace() {
			if policyReads == 24 {
				postPolicyNamespaceReads++
				if !receiptReplaced && (scenario == "pending-receipt-current-final" && postPolicyNamespaceReads == 3 || scenario == "pending-receipt-recovery-final" && postPolicyNamespaceReads == 5) {
					replaceReceipt()
				}
			}
			ns, err := f.access.client.CoreV1().Namespaces().Get(r.Context(), f.plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				w.WriteHeader(500)
				return
			}
			ns.APIVersion, ns.Kind = "v1", "Namespace"
			if scenario == "journal-drift" && lists > 0 {
				ns.ResourceVersion = "999"
			}
			_ = json.NewEncoder(w).Encode(ns)
			return
		}
		if object := objects[r.URL.Path]; object != nil {
			if targetPath, _ := resourcePath(key, false); r.URL.Path == targetPath && scenario == "pending-receipt-recovery-get" && postPolicyNamespaceReads == 4 && !receiptReplaced {
				replaceReceipt()
			}
			if targetPath, _ := resourcePath(key, false); r.URL.Path == targetPath && lists >= 2*len(sources) {
				switch scenario {
				case "pending-cluster-drift":
					object = object.DeepCopy()
					object.SetResourceVersion("999")
				case "pending-cluster-replaced":
					object = object.DeepCopy()
					object.SetUID("replacement")
				}
			}
			if signedPath, _ := resourcePath(signedKey, false); r.URL.Path == signedPath && lists >= 2*len(sources) {
				switch scenario {
				case "signed-original-drift":
					object = object.DeepCopy()
					object.SetResourceVersion("999")
				case "signed-original-replaced":
					object = object.DeepCopy()
					object.SetUID("replacement")
				case "signed-original-missing":
					w.WriteHeader(404)
					return
				}
			}
			if object.GetKind() == "ValidatingAdmissionPolicy" {
				policyReads++
				if scenario == "pending-receipt-policy" && lists == 2*len(sources) && !receiptReplaced {
					replaceReceipt()
				}
				if scenario == "baseline-drift" && lists > 0 {
					object = object.DeepCopy()
					object.SetResourceVersion("999")
				}
			}
			_ = json.NewEncoder(w).Encode(object)
			return
		}
		if path, _ := resourcePath(key, false); r.URL.Path == path {
			if scenario == "target-present" || scenario == "target-appears" && lists > 0 {
				_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"name": key.Name, "uid": "foreign", "resourceVersion": "33"}})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace()+"/serviceaccounts/default" {
			_ = json.NewEncoder(w).Encode(defaultAccount)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace()+"/configmaps/kube-root-ca.crt" {
			_ = json.NewEncoder(w).Encode(rootCA)
			return
		}
		switch r.URL.Path {
		case "/api":
			_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
			return
		case "/apis":
			list := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"}, Groups: []metav1.APIGroup{}}
			for _, group := range groupNames {
				v := metav1.GroupVersionForDiscovery{GroupVersion: group + "/v1", Version: "v1"}
				list.Groups = append(list.Groups, metav1.APIGroup{Name: group, Versions: []metav1.GroupVersionForDiscovery{v}, PreferredVersion: v})
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		for group, resources := range groups {
			path, version := "/api/v1", "v1"
			if group != "" {
				version = group + "/v1"
				path = "/apis/" + version
			}
			if r.URL.Path == path {
				_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: version, APIResources: resources})
				return
			}
		}
		for _, source := range sources {
			if r.URL.Path == pathFor(source) {
				lists++
				if !receiptReplaced && (scenario == "pending-receipt-first-collection" && lists == 1 || scenario == "pending-receipt-second-collection" && lists == len(sources)+1) {
					replaceReceipt()
				}
				query := r.URL.Query()
				validQuery := query.Get("limit") == "128" && (!query.Has("timeout") || query.Get("timeout") == "30s")
				for name, values := range query {
					if (name != "limit" && name != "timeout") || len(values) != 1 {
						validQuery = false
					}
				}
				if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" || !validQuery {
					t.Error("bootstrap collection used a filtered or nonmetadata list")
				}
				items := rows[r.URL.Path]
				if items == nil {
					items = []metav1.PartialObjectMetadata{}
				}
				_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadataList", APIVersion: "meta.k8s.io/v1"}, ListMeta: metav1.ListMeta{ResourceVersion: "11"}, Items: items})
				if scenario == "late-fixture" && lists == 1 {
					if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("unresolved")); err != nil {
						t.Error("late fence seed failed")
					}
				}
				return
			}
		}
		t.Error("bootstrap contacted an unaccounted route")
		w.WriteHeader(404)
	}))
	t.Cleanup(server.Close)
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("bootstrap HTTP fixture unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, f.plan)
	if err != nil {
		t.Fatal("bootstrap journal fixture unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, baseline, f.plan)
	if err != nil {
		t.Fatal("bootstrap engine fixture unavailable")
	}
	snapshot, err := store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("bootstrap original fixture unavailable")
	}
	configuration, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("bootstrap closed composition unavailable")
	}
	operation, err := engine.prerequisiteOperation(snapshot, key, f.plan.Digest())
	if err != nil {
		t.Fatal("signed bootstrap operation fixture unavailable")
	}
	if strings.HasPrefix(scenario, "effect-") {
		// A configuration observer alone must not grant mutation authority.
		if _, err := engine.applyPrerequisite(t.Context(), snapshot, key, f.plan.Digest()); err != ErrSecurityBaseline || previews != 0 || creates != 0 || journalWrites != 0 {
			t.Fatal("configuration observer granted prerequisite mutation")
		}
		lifecycle, err := NewClusterLifecycle(engine, access)
		if err != nil {
			t.Fatal("closed lifecycle composition refused synthetic fixture")
		}
		if _, err := engine.Apply(t.Context(), snapshot, key, f.plan.Digest(), false); err != ErrSecurityBaseline {
			t.Fatal("closed prerequisite composition bypassed public Apply")
		}
		if scenario == "effect-argument-mismatch" {
			for _, mismatch := range []struct {
				key    installstate.Key
				digest string
				paused bool
			}{
				{key: key, digest: f.plan.Digest(), paused: true},
				{key: installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: f.plan.Namespace(), Name: "arcadectl-api"}, digest: f.plan.Digest()},
				{key: key, digest: strings.Repeat("e", 64)},
			} {
				if _, err := engine.apply(t.Context(), snapshot, mismatch.key, mismatch.digest, mismatch.paused, operation); err == nil {
					t.Fatal("signed prerequisite proof authorized unrelated actual arguments")
				}
			}
			if previews != 0 || creates != 0 || journalWrites != 0 {
				t.Fatal("argument mismatch emitted preview/intent/effect")
			}
			return
		}
		var result *installstate.Snapshot
		var effectErr error
		if scenario == "effect-coordinator-create" {
			// Instrument only the unrelated prerequisite checkpoint; the actual
			// Step ordering and closed prerequisite CREATE proof remain in use.
			checks := &lifecycleFixture{f: f, l: lifecycle}
			lifecycle.checks = checks
			result, effectErr = lifecycle.Step(t.Context(), snapshot, LifecycleOptions{Now: time.Now().UTC()})
			if !reflect.DeepEqual(checks.checks, []Checkpoint{Prerequisites}) {
				t.Fatal("first prerequisite skipped or weakened coordinator checkpoints")
			}
		} else {
			result, effectErr = engine.applyPrerequisite(t.Context(), snapshot, key, f.plan.Digest())
		}
		fresh, err := store.Load(t.Context(), snapshot.Anchor())
		if err != nil {
			t.Fatal("post-effect original journal unavailable")
		}
		if scenario == "effect-create" || scenario == "effect-coordinator-create" || scenario == "effect-SA-create" || scenario == "effect-settle-response-lost" {
			if effectErr != nil || result == nil || fresh.Document().Pending != nil || previews != 1 || creates != 1 || journalWrites != 2 {
				t.Fatal("prerequisite single CREATE/settlement failed", effectErr)
			}
			entry, _ := engine.inventory(fresh.Document(), key)
			if entry == nil || entry.UID != "effect-original" || len(fresh.Document().Resources) != 2 || len(fresh.Document().SecurityBaseline.Resources) != 12 {
				t.Fatal("prerequisite settlement lost original/separate inventory")
			}
		} else if scenario == "effect-preview-drift" {
			if effectErr == nil || fresh.Document().Pending != nil || previews != 1 || creates != 0 || journalWrites != 0 {
				t.Fatal("post-preview drift reached intent/effect")
			}
		} else if scenario == "effect-intent-drift" {
			if !errors.Is(effectErr, ErrOutcomeUnknown) || fresh.Document().Pending == nil || previews != 1 || creates != 0 || journalWrites != 1 {
				t.Fatal("post-intent drift issued a target CREATE")
			}
		} else {
			if !errors.Is(effectErr, ErrOutcomeUnknown) || previews != 1 || creates != 1 {
				t.Fatal("uncertain/changed effect did not stay fenced", effectErr)
			}
			if scenario != "effect-settle-response-lost" && fresh.Document().Pending == nil {
				t.Fatal("unproved target lost pending intent")
			}
			if scenario == "effect-ack-late-copy" {
				uid, err := engine.loadCreateUID(fresh.Document())
				if lateReads != 5 || err == nil || uid != "" {
					t.Fatal("late copied-nonce object acquired a protected original UID")
				}
			}
		}
		// Reconstruct trusted composition and observe durable state. Neither
		// explicit resume nor invoking the private apply with pending/owned
		// target can ever resend preview or CREATE.
		beforePreview, beforeCreate := previews, creates
		engine, err = NewWithBaselineAccess(access, store, f.engine.files, baseline, f.plan)
		if err != nil {
			t.Fatal("restart engine refused")
		}
		if _, err := NewClusterLifecycle(engine, access); err != nil {
			t.Fatal("restart closed composition refused")
		}
		if fresh.Document().Pending != nil {
			if _, err := engine.applyPrerequisite(t.Context(), fresh, key, f.plan.Digest()); err != ErrSecurityBaseline {
				t.Fatal("pending prerequisite entered another Apply")
			}
			resumed, resumeErr := engine.Recover(t.Context(), fresh)
			if scenario == "effect-ack-malformed" {
				if resumeErr != nil || resumed.Document().Pending != nil {
					t.Fatal("known original ACK identity could not settle on observation-only resume", resumeErr)
				}
			} else if !errors.Is(resumeErr, ErrOutcomeUnknown) {
				t.Fatal("unproved original identity/runtime acquired resume authority", resumeErr)
			}
		} else {
			if _, err := engine.applyPrerequisite(t.Context(), fresh, key, f.plan.Digest()); err == nil {
				t.Fatal("settled original prerequisite was reapplied")
			}
		}
		if previews != beforePreview || creates != beforeCreate {
			t.Fatal("restart/recovery resent prerequisite preview or CREATE")
		}
		if _, err := engine.current(t.Context(), fresh); err == nil {
			t.Fatal("prerequisite mutation authorized ordinary runtime")
		}
		return
	}
	if strings.HasPrefix(scenario, "pending-receipt-recovery-") || scenario == "pending-recovery" || scenario == "pending-receipt-current-final" {
		if _, err := NewClusterLifecycle(engine, access); err != nil {
			t.Fatal("closed prerequisite recovery composition refused")
		}
		var result *installstate.Snapshot
		if scenario == "pending-receipt-current-final" {
			result, err = engine.currentEffect(t.Context(), snapshot, operation)
			if err != ErrSecurityBaseline || result != nil {
				t.Fatal("final currentEffect receipt replacement supplied proof authority")
			}
		} else {
			result, err = engine.Recover(t.Context(), snapshot)
			if scenario == "pending-recovery" {
				if err != nil || result == nil || result.Document().Pending != nil || result.Document().Revision != snapshot.Document().Revision+1 || journalWrites != 1 {
					t.Fatal("genuine protected pending ACK could not settle without replay")
				}
				entry, _ := engine.inventory(result.Document(), key)
				if entry == nil || entry.UID != "full-pending-original" || entry.TemplateSHA256 != snapshot.Document().Pending.AfterSHA256 {
					t.Fatal("recovery settlement lost exact opening ACK identity")
				}
			} else if !errors.Is(err, ErrOutcomeUnknown) || result == nil || !bytes.Equal(result.Bytes(), snapshot.Bytes()) || journalWrites != 0 {
				t.Fatal("late receipt replacement settled or changed an unproved pending intent")
			}
		}
		if scenario != "pending-recovery" && !receiptReplaced || previews != 0 || creates != 0 || testBaselineReceiptDescriptors(t, "create-"+snapshot.Document().Pending.CreateNonce+".json") != 0 {
			t.Fatal("recovery missed its intended receipt fault, replayed an effect or leaked its owner")
		}
		return
	}
	ctx := t.Context()
	if scenario == "cancelled" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}
	beforeWrites, beforeUpdates := f.access.writes, f.nsUpdates
	err = configuration.verifyPrerequisite(ctx, snapshot, operation)
	if scenario == "empty" || scenario == "benign-defaults" || scenario == "signed-original" || scenario == "signed-SA" || scenario == "pending-absent" || scenario == "pending-empty-absent" || scenario == "pending-cluster" || scenario == "pending-SA" {
		if err != nil || reviews != 2*len(sources) || lists != 2*len(sources) || policyReads == 0 {
			t.Fatal("complete bootstrap-only proof failed", err)
		}
	} else if err != ErrSecurityBaseline {
		t.Fatal("unsafe/incomplete bootstrap supplied a proof", err)
	}
	if strings.HasPrefix(scenario, "pending-receipt-") && !receiptReplaced {
		t.Fatal("prerequisite receipt lifetime fault was never reached")
	}
	if strings.HasPrefix(scenario, "pending-") && testBaselineReceiptDescriptors(t, "create-"+snapshot.Document().Pending.CreateNonce+".json") != 0 {
		t.Fatal("prerequisite proof leaked its receipt owner")
	}
	if (scenario == "missing-source" || scenario == "deny-list" || scenario == "cancelled" || scenario == "custom-no-delete" || scenario == "custom-list-only" || scenario == "target-present") && lists != 0 {
		t.Fatal("known incomplete or unauthorized bootstrap sent a list")
	}
	if f.access.writes != beforeWrites || f.nsUpdates != beforeUpdates || !reflect.DeepEqual(snapshot.Document(), f.snapshot.Document()) {
		t.Fatal("read-only bootstrap changed original evidence")
	}
	if _, err := engine.current(t.Context(), snapshot); err == nil {
		t.Fatal("bootstrap proof authorized ordinary runtime")
	}
}
