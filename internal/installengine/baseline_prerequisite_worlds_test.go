// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/installstate"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Current source→Preparing→Applying CAS and protected evidence are real local
// engine operations; baseline enrollment/health, cold typed replies and CREATE
// ACK fixtures are synthetic. HTTPS exercises the complete private production
// prerequisite verifier, not native storage, access effects or runtime wiring.
func TestBaselinePrerequisiteRetainedWorldsHTTPS(t *testing.T) {
	for _, scenario := range []string{"healthy", "acknowledged-access", "unacknowledged-access", "unrecorded-access", "missing-domain-discovery", "unknown-source", "typed-only-claim", "gc-only-claim", "gc-owner-change", "late-claim-rv", "late-pv-rv", "late-history-same-rv", "late-lease-same-rv", "terminal-pod", "active-operation", "data-lease", "wrong-world-uid", "deleting-claim", "attached-world", "late-policy-rv", "closing-source-replacement", "closing-retirement-replacement", "denied-list", "denied-get", "denied-pv-get"} {
		t.Run(scenario, func(t *testing.T) { testBaselinePrerequisiteRetainedWorldsHTTPS(t, scenario) })
	}
}

// Actual lifecycle pending-recovery dispatch with a retained world: only an already
// acknowledged original CREATE may settle. No preview or target write is
// supported by the transport. Storage/ACK/enrollment replies are synthetic.
func TestBaselinePrerequisiteRetainedRecoveryHTTPS(t *testing.T) {
	for _, scenario := range []string{"recover-acknowledged-access", "recover-unacknowledged-access", "recover-final-source-replacement", "recover-final-retirement-replacement", "recover-final-ca-replacement", "recover-settlement-conflict", "recover-without-secret-owner"} {
		t.Run(scenario, func(t *testing.T) { testBaselinePrerequisiteRetainedWorldsHTTPS(t, scenario) })
	}
}

// Real effect engine/HTTP transport and protected intent/ACK/settlement, with
// explicitly synthetic enrollment, storage/status and API acknowledgements.
// Only the original signed ServiceAccount and Namespace CAS are writable.
// This is not native or complete lifecycle/reinstall certification.
func TestBaselinePrerequisiteRetainedCreateHTTPS(t *testing.T) {
	for _, scenario := range []string{"create-healthy", "create-before-intent-source", "create-before-intent-retirement", "create-before-intent-ca", "create-before-effect-source", "create-before-effect-retirement", "create-before-effect-ca"} {
		t.Run(scenario, func(t *testing.T) { testBaselinePrerequisiteRetainedWorldsHTTPS(t, scenario) })
	}
}

func testBaselinePrerequisiteRetainedWorldsHTTPS(t *testing.T, scenario string) {
	v, current, sourceName, retirementName := retainedPrerequisiteLifecycleFixture(t)
	f := v.f
	d := current.Document()
	recovering := strings.HasPrefix(scenario, "recover-")
	creating := strings.HasPrefix(scenario, "create-")
	nonce := strings.Repeat("c", 32)
	if recovering || scenario == "acknowledged-access" || scenario == "unacknowledged-access" {
		template, err := f.engine.contracts[d.TargetPackage].Template(f.key, false)
		if err != nil {
			t.Fatal("signed retained target unavailable")
		}
		d.Revision++
		d.Pending = &installstate.Pending{Action: installstate.Create, Key: f.key, CreateNonce: nonce, AfterSHA256: template.Hash()}
		current, err = f.store.Commit(t.Context(), current, d)
		if err != nil || f.engine.prepareCreateReceipt(d) != nil {
			t.Fatal("retained pending journal/receipt fixture unavailable")
		}
		if (scenario == "acknowledged-access" || recovering && scenario != "recover-unacknowledged-access") && f.engine.saveCreateUID(d, "new-access-original") != nil {
			t.Fatal("synthetic protected original access ACK unavailable")
		}
	}
	namespace, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("current original namespace unavailable")
	}
	namespace.APIVersion, namespace.Kind = "v1", "Namespace"
	namespaceDocument := current.Document()
	var signedTarget *unstructured.Unstructured
	for _, resource := range f.plan.Resources() {
		if resource.Object.GetAPIVersion() == "v1" && resource.Object.GetKind() == "ServiceAccount" && resource.Object.GetNamespace() == d.Namespace && resource.Object.GetName() == f.key.Name {
			signedTarget = resource.Object.DeepCopy()
		}
	}
	if signedTarget == nil || f.key.APIVersion != "v1" || f.key.Kind != "ServiceAccount" {
		t.Fatal("independent signed access CREATE oracle unavailable")
	}
	targetTemplate, err := f.engine.contracts[d.TargetPackage].Template(f.key, false)
	if err != nil {
		t.Fatal("original access journal metadata unavailable")
	}
	targetEntry := installstate.Resource{Key: f.key, UID: "new-access-original", TemplateSHA256: targetTemplate.Hash(), Retained: targetTemplate.Retained(), Phase: targetTemplate.Phase()}
	server := arcade.GameServer{TypeMeta: metav1.TypeMeta{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameServer"}, ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: d.Namespace, UID: "original-server", ResourceVersion: "1", Generation: 1}, Spec: arcade.GameServerSpec{
		Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: arcade.DesiredStateStopped,
		Compute: arcade.ComputeSpec{CPURequest: resource.MustParse("500m"), CPULimit: resource.MustParse("2"), MemoryRequest: resource.MustParse("1Gi"), MemoryLimit: resource.MustParse("2Gi")}, Storage: arcade.StorageSpec{Size: resource.MustParse("10Gi")}, Settings: runtime.RawExtension{Raw: []byte(`{"name":"retained","maxPlayers":16,"visibility":"private"}`)},
	}, Status: arcade.GameServerStatus{ObservedGeneration: 1, Phase: arcade.PhaseStopped}}
	games, err := catalog.Builtins()
	if err != nil {
		t.Fatal("cold game catalog unavailable")
	}
	definition, err := games.Get("factorio")
	if err != nil {
		t.Fatal("cold game definition unavailable")
	}
	planned, err := platformkube.Build(&server, definition)
	if err != nil || len(planned.DataClaims) != 1 {
		t.Fatal("cold retained-world fixture plan unavailable")
	}
	claim := planned.DataClaims[0].Desired.DeepCopy()
	claim.APIVersion, claim.Kind = "v1", "PersistentVolumeClaim"
	claim.UID, claim.ResourceVersion = "original-claim", "1"
	claim.Spec.VolumeName = "world-pv"
	claim.Status.Phase = corev1.ClaimBound
	claim.Status.Capacity = corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}
	server.Status.ObservedData = &arcade.RetainedDataReference{Identity: planned.DataIdentity, Claims: []arcade.RetainedDataClaimReference{{Path: claim.Labels[platformkube.LabelDataPath], ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}
	pv := coldPVFixture()
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}
	metadata := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: d.Namespace, UID: types.UID("original-" + name), ResourceVersion: "1", Generation: 1}
	}
	backup := &arcade.GameBackup{TypeMeta: metav1.TypeMeta{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameBackup"}, ObjectMeta: metadata("backup"), Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}
	restore := &arcade.GameRestore{TypeMeta: metav1.TypeMeta{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameRestore"}, ObjectMeta: metadata("restore"), Status: arcade.GameRestoreStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseFailed}}}
	destroy := &arcade.GameDestroy{TypeMeta: metav1.TypeMeta{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameDestroy"}, ObjectMeta: metadata("destroy"), Status: arcade.GameDestroyStatus{ObservedGeneration: 1, Phase: arcade.DestroyPhaseCancelled}}
	operation := &arcade.ArcadeOperation{TypeMeta: metav1.TypeMeta{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "ArcadeOperation"}, ObjectMeta: metadata("operation"), Status: arcade.ArcadeOperationStatus{ObservedGeneration: 1, Phase: arcade.OperationPhaseSucceeded}}
	lease := &coordinationv1.Lease{TypeMeta: metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: metadata("passive-lease")}
	objects := map[string][]*unstructured.Unstructured{}
	for key, object := range f.access.objects {
		objects[key.Kind] = append(objects[key.Kind], object.DeepCopy())
	}
	for _, object := range []runtime.Object{&server, claim, backup, restore, destroy, operation, lease} {
		converted := servingObject(t, object)
		objects[converted.GetKind()] = append(objects[converted.GetKind()], converted)
	}
	for _, entry := range d.Resources {
		if entry.Key.Kind == "Secret" {
			secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: entry.Key.Name, Namespace: d.Namespace, UID: entry.UID, ResourceVersion: "1"}}
			objects["Secret"] = append(objects["Secret"], servingObject(t, secret))
		}
	}
	// Foreign retained repository metadata must stay read-only and confer no
	// installer identity or credential-generation authority.
	objects["Secret"] = append(objects["Secret"], servingObject(t, &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metadata("retained-repository")}))
	if recovering || strings.HasSuffix(scenario, "access") {
		template, _ := f.engine.contracts[d.TargetPackage].Template(f.key, false)
		candidate, err := template.Candidate(nonce)
		if err != nil {
			t.Fatal("synthetic original access candidate unavailable")
		}
		candidate.SetUID("new-access-original")
		candidate.SetResourceVersion("1")
		objects[f.key.Kind] = append(objects[f.key.Kind], candidate)
	}
	resources := append([]reinstallHTTPResource{}, reinstallHTTPResources...)
	resources = append(resources, reinstallHTTPResource{"v1", "PersistentVolume", "persistentvolumes", false}, reinstallHTTPResource{"v1", "ConfigMap", "configmaps", true}, reinstallHTTPResource{"custom.example/v1", "Custom", "customs", true})
	groupNames := []string{}
	groupVersions := map[string]string{}
	for _, res := range resources {
		if res.gv == "v1" {
			continue
		}
		group, version, _ := strings.Cut(res.gv, "/")
		if groupVersions[group] == "" {
			groupVersions[group] = version
			groupNames = append(groupNames, group)
		}
	}
	sort.Strings(groupNames)
	var mu sync.Mutex
	typedReads, pvReads, gcReads := 0, 0, 0
	targetReads, journalWrites, privateReads := 0, 0, 0
	previews, creates := 0, 0
	lastClosingPrivate, closingNamespaceReads := 0, 0
	var previewBody *unstructured.Unstructured
	faultHit := false
	markFault := func() { faultHit = true }
	replace := func(name string) {
		owners := 1
		if recovering || creating {
			owners = 2
		}
		if testBaselineReceiptDescriptors(t, sourceName) != owners || testBaselineReceiptDescriptors(t, retirementName) != owners {
			t.Error("whole retained proof did not hold its own original source pair")
		}
		body, identity, err := f.engine.files.Read(name, retirementMaxBytes)
		if err != nil {
			t.Error("test-owned replacement evidence unavailable")
			return
		}
		for range 2 {
			identity, err = f.engine.files.AtomicWrite(name, body, &identity)
			if err != nil {
				t.Error("test-owned identical evidence replacement failed")
				return
			}
		}
		markFault()
	}
	pathFor := func(res reinstallHTTPResource) string {
		path := reinstallHTTPGroupPath(res.gv)
		if res.namespaced {
			path += "/namespaces/" + d.Namespace
		}
		return path + "/" + res.plural
	}
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if creating && r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/"+d.Namespace+"/serviceaccounts" {
			var candidate unstructured.Unstructured
			query := r.URL.Query()
			dry := query.Get("dryRun") == "All"
			wantQuery := map[string][]string{"fieldValidation": {"Strict"}}
			if dry {
				wantQuery["dryRun"] = []string{"All"}
			}
			if r.Header.Get("Impersonate-User") != "" || r.Header.Get("Content-Type") != "application/json" || !reflect.DeepEqual(map[string][]string(query), wantQuery) || json.NewDecoder(r.Body).Decode(&candidate) != nil {
				t.Error("access CREATE escaped its fixed MIME/query/identity protocol")
				w.WriteHeader(500)
				return
			}
			mutation := candidate.GetAnnotations()[installstate.MutationAnnotation]
			if len(mutation) != 32 || strings.Trim(mutation, "0123456789abcdef") != "" {
				t.Error("access CREATE nonce was not exact public 32-hex identity")
				w.WriteHeader(500)
				return
			}
			want := signedTarget.DeepCopy()
			annotations := want.GetAnnotations()
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[installstate.MutationAnnotation] = mutation
			want.SetAnnotations(annotations)
			if !reflect.DeepEqual(candidate.Object, want.Object) {
				t.Error("whole access CREATE body differs from original signed raw resource")
				w.WriteHeader(500)
				return
			}
			if dry {
				previews++
				if previews != 1 || creates != 0 || journalWrites != 0 || namespaceDocument.Pending != nil {
					t.Error("access preview repeated or escaped pre-intent observation")
					w.WriteHeader(500)
					return
				}
				previewBody = candidate.DeepCopy()
			} else {
				p := namespaceDocument.Pending
				if previews != 1 || creates != 0 || journalWrites != 1 || p == nil || p.Action != installstate.Create || p.Key != f.key || p.CreateNonce != mutation || p.AfterSHA256 != targetEntry.TemplateSHA256 || !reflect.DeepEqual(candidate.Object, previewBody.Object) {
					t.Error("real access CREATE lacks the exact original committed intent and preview")
					w.WriteHeader(500)
					return
				}
				body, identity, err := f.engine.files.Read("create-"+mutation+".json", 4096)
				var receipt createReceipt
				wantReceipt := createReceipt{Version: "v1", Anchor: current.Anchor(), Pending: *p, TargetPackage: d.TargetPackage}
				if err != nil || json.Unmarshal(body, &receipt) != nil || !reflect.DeepEqual(receipt, wantReceipt) || f.engine.files.ConfirmDurable("create-"+mutation+".json", identity) != nil || testBaselineReceiptDescriptors(t, sourceName) != 1 || testBaselineReceiptDescriptors(t, retirementName) != 1 || testBaselineReceiptDescriptors(t, filepath.Base(v.opts.Activation.CAFile)) != 1 {
					t.Error("real CREATE lacks durable preparation or original outer evidence")
					w.WriteHeader(500)
					return
				}
				creates++
				candidate.SetUID("new-access-original")
				candidate.SetResourceVersion("1")
				objects["ServiceAccount"] = append(objects["ServiceAccount"], candidate.DeepCopy())
			}
			_ = json.NewEncoder(w).Encode(candidate.Object)
			return
		}
		if creating && r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
			var next corev1.Namespace
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if r.Header.Get("Impersonate-User") != "" || decoder.Decode(&next) != nil {
				t.Error("CREATE journal CAS changed identity or included unknown fields")
				w.WriteHeader(500)
				return
			}
			wantNamespace := namespace.DeepCopy()
			wantNamespace.Annotations[installstate.Annotation] = next.Annotations[installstate.Annotation]
			if !reflect.DeepEqual(next, *wantNamespace) {
				t.Error("whole original Namespace changed beyond its journal annotation")
				w.WriteHeader(500)
				return
			}
			var decoded installstate.Document
			journalDecoder := json.NewDecoder(strings.NewReader(next.Annotations[installstate.Annotation]))
			journalDecoder.DisallowUnknownFields()
			if journalDecoder.Decode(&decoded) != nil {
				t.Error("CREATE journal CAS malformed")
				w.WriteHeader(500)
				return
			}
			expected := namespaceDocument
			expected.Revision++
			owners := 1
			if journalWrites == 0 {
				if previews != 1 || creates != 0 || decoded.Pending == nil || decoded.Pending.Action != installstate.Create || decoded.Pending.Key != f.key || decoded.Pending.AfterSHA256 != targetEntry.TemplateSHA256 || decoded.Pending.CreateNonce != previewBody.GetAnnotations()[installstate.MutationAnnotation] || decoded.Pending.BeforeUID != "" || decoded.Pending.BeforeResourceVersion != "" || decoded.Pending.BeforeSHA256 != "" {
					t.Error("intent CAS differs from exact signed preview CREATE")
					w.WriteHeader(500)
					return
				}
				expected.Pending = decoded.Pending
			} else if journalWrites == 1 && creates == 1 && namespaceDocument.Pending != nil {
				expected.Pending = nil
				expected.Resources = append(append([]installstate.Resource{}, namespaceDocument.Resources...), targetEntry)
				installstate.SortResources(expected.Resources)
				owners = 2
				if testBaselineReceiptDescriptors(t, "create-"+namespaceDocument.Pending.CreateNonce+".json") != 1 {
					t.Error("settlement lost original acknowledged CREATE receipt owner")
					w.WriteHeader(500)
					return
				}
			} else {
				t.Error("journal CAS repeated or settled without one real CREATE")
				w.WriteHeader(500)
				return
			}
			if !reflect.DeepEqual(decoded, expected) || testBaselineReceiptDescriptors(t, sourceName) != owners || testBaselineReceiptDescriptors(t, retirementName) != owners || testBaselineReceiptDescriptors(t, filepath.Base(v.opts.Activation.CAFile)) != 1 {
				t.Error("CREATE journal changed original source/roots or lost owned trust evidence")
				w.WriteHeader(500)
				return
			}
			journalWrites++
			namespaceDocument = decoded
			next.ResourceVersion += "1"
			namespace = next.DeepCopy()
			_ = json.NewEncoder(w).Encode(namespace)
			return
		}
		if recovering && r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
			var next corev1.Namespace
			if r.Header.Get("Impersonate-User") != "" || json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != namespace.UID || next.ResourceVersion != namespace.ResourceVersion {
				t.Error("recovery settlement escaped original Namespace CAS")
				w.WriteHeader(500)
				return
			}
			decoded, err := installstate.DecodeWithBaseline([]byte(next.Annotations[installstate.Annotation]), f.engine.baselinePlan(), f.plan)
			expected := current.Document()
			expected.Revision++
			expected.Pending = nil
			targetTemplate, templateErr := f.engine.contracts[d.TargetPackage].Template(f.key, false)
			if templateErr != nil {
				t.Error("original expected recovery template unavailable")
				w.WriteHeader(500)
				return
			}
			expected.Resources = append(expected.Resources, installstate.Resource{Key: f.key, UID: "new-access-original", TemplateSHA256: targetTemplate.Hash(), Phase: targetTemplate.Phase(), Retained: targetTemplate.Retained()})
			installstate.SortResources(expected.Resources)
			if err != nil || !reflect.DeepEqual(decoded, expected) || testBaselineReceiptDescriptors(t, sourceName) != 2 || testBaselineReceiptDescriptors(t, retirementName) != 2 || testBaselineReceiptDescriptors(t, "create-"+d.Pending.CreateNonce+".json") != 1 || testBaselineReceiptDescriptors(t, filepath.Base(v.opts.Activation.CAFile)) != 1 {
				t.Error("recovery settlement omitted original evidence or changed its action")
				w.WriteHeader(500)
				return
			}
			journalWrites++
			if scenario == "recover-settlement-conflict" {
				markFault()
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonConflict, Code: 409})
				return
			}
			next.ResourceVersion += "1"
			namespace = next.DeepCopy()
			_ = json.NewEncoder(w).Encode(namespace)
			return
		}
		if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
				t.Error("retained proof escaped resource-only authorization")
				w.WriteHeader(500)
				return
			}
			a := review.Spec.ResourceAttributes
			known := false
			for i, res := range resources {
				group, version := "", res.gv
				if res.gv != "v1" {
					group, version, _ = strings.Cut(res.gv, "/")
				}
				ns := ""
				if res.namespaced {
					ns = d.Namespace
				}
				if a.Group != group || a.Version != version || a.Resource != res.plural || a.Namespace != ns || a.Subresource != "" {
					continue
				}
				if a.Verb == "list" && a.Name == "" && (i < 20 || res.namespaced) {
					known = true
				}
				if a.Verb == "get" && a.Name != "" {
					if res.kind == "PersistentVolume" && a.Name == pv.Name || res.kind == f.key.Kind && a.Name == f.key.Name || res.kind == "Namespace" && a.Name == d.Namespace {
						known = true
					}
					for _, entry := range d.Resources {
						if entry.Key.APIVersion == res.gv && entry.Key.Kind == res.kind && entry.Key.Name == a.Name {
							known = true
						}
					}
				}
			}
			if !known {
				t.Error("retained proof requested mutation, wildcard, unnamed GET or foreign authorization")
				w.WriteHeader(500)
				return
			}
			review.Status.Allowed = true
			if scenario == "denied-list" && a.Resource == "volumeattachments" || scenario == "denied-get" && a.Resource == "customresourcedefinitions" || scenario == "denied-pv-get" && a.Resource == "persistentvolumes" {
				review.Status.Allowed = false
				markFault()
			}
			_ = json.NewEncoder(w).Encode(review)
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Impersonate-User") != "" {
			t.Error("retained proof emitted a persistent mutation or changed identity")
			w.WriteHeader(500)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/"+d.Namespace+"/serviceaccounts/"+f.key.Name {
			targetReads++ // include independently observed absence before CREATE
		}
		if r.URL.Path == "/api" {
			_ = json.NewEncoder(w).Encode(metav1.APIVersions{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIVersions"}, Versions: []string{"v1"}})
			return
		}
		if r.URL.Path == "/apis" {
			groups := []metav1.APIGroup{}
			for _, group := range groupNames {
				version := groupVersions[group]
				v := metav1.GroupVersionForDiscovery{GroupVersion: group + "/" + version, Version: version}
				groups = append(groups, metav1.APIGroup{Name: group, Versions: []metav1.GroupVersionForDiscovery{v}, PreferredVersion: v})
			}
			_ = json.NewEncoder(w).Encode(metav1.APIGroupList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"}, Groups: groups})
			return
		}
		for _, res := range resources {
			if r.URL.Path == reinstallHTTPGroupPath(res.gv) {
				catalog := []metav1.APIResource{}
				for _, item := range resources {
					if item.gv != res.gv {
						continue
					}
					if scenario == "missing-domain-discovery" && item.kind == "GameRestore" {
						markFault()
						continue
					}
					catalog = append(catalog, metav1.APIResource{Name: item.plural, Kind: item.kind, Namespaced: item.namespaced, Verbs: metav1.Verbs{"get", "list", "watch", "delete"}})
				}
				_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: res.gv, APIResources: catalog})
				return
			}
		}
		if r.URL.Path == "/api/v1/namespaces/"+d.Namespace {
			if creating {
				if lastClosingPrivate != privateReads {
					lastClosingPrivate, closingNamespaceReads = privateReads, 0
				}
				closingNamespaceReads++
				intentFault := strings.HasPrefix(scenario, "create-before-intent-") && privateReads == 12
				effectFault := strings.HasPrefix(scenario, "create-before-effect-") && privateReads == 16
				if !faultHit && (intentFault || effectFault) && closingNamespaceReads == 4 {
					wantWrites, wantTargets := 0, 9
					if effectFault {
						wantWrites, wantTargets = 1, 13
					}
					if previews != 1 || creates != 0 || journalWrites != wantWrites || targetReads != wantTargets {
						t.Error("CREATE closing fault did not reach exact intent/effect boundary")
					}
					if strings.HasSuffix(scenario, "-source") {
						replace(sourceName)
					} else if strings.HasSuffix(scenario, "-retirement") {
						replace(retirementName)
					} else {
						caFile := v.opts.Activation.CAFile
						if testBaselineReceiptDescriptors(t, filepath.Base(caFile)) != 1 {
							t.Error("CREATE closing fence lost original CA owner")
						}
						files, err := privatefs.Open(filepath.Dir(caFile), false)
						if err != nil {
							t.Error("test-owned CREATE CA directory unavailable")
							w.WriteHeader(500)
							return
						}
						defer files.Close()
						body, identity, err := files.Read(filepath.Base(caFile), 65536)
						if err != nil {
							t.Error("test-owned CREATE CA unavailable")
							w.WriteHeader(500)
							return
						}
						for range 2 {
							identity, err = files.AtomicWrite(filepath.Base(caFile), body, &identity)
							if err != nil {
								t.Error("test-owned identical CREATE CA replacement failed")
								w.WriteHeader(500)
								return
							}
						}
						markFault()
					}
				}
			}
			if strings.HasPrefix(scenario, "recover-final-") && targetReads == 5 && !faultHit {
				switch scenario {
				case "recover-final-source-replacement":
					replace(sourceName)
				case "recover-final-retirement-replacement":
					replace(retirementName)
				case "recover-final-ca-replacement":
					caFile := v.opts.Activation.CAFile
					if testBaselineReceiptDescriptors(t, filepath.Base(caFile)) != 1 {
						t.Error("pending recovery lost its opening original CA descriptor")
					}
					files, err := privatefs.Open(filepath.Dir(caFile), false)
					if err != nil {
						t.Error("test-owned recovery CA directory unavailable")
						w.WriteHeader(500)
						return
					}
					defer files.Close()
					body, identity, err := files.Read(filepath.Base(caFile), 65536)
					if err != nil {
						t.Error("test-owned recovery CA unavailable")
						w.WriteHeader(500)
						return
					}
					for range 2 {
						identity, err = files.AtomicWrite(filepath.Base(caFile), body, &identity)
						if err != nil {
							t.Error("test-owned identical recovery CA replacement failed")
							w.WriteHeader(500)
							return
						}
					}
					markFault()
				}
			}
			encodeStoppedObject(t, w, r, servingObject(t, namespace))
			return
		}
		if r.URL.Path == "/api/v1/persistentvolumes/"+pv.Name {
			pvReads++
			copy := pv.DeepCopy()
			if scenario == "late-pv-rv" && pvReads == 2 {
				copy.ResourceVersion = "2"
				markFault()
			}
			encodeStoppedObject(t, w, r, servingObject(t, copy))
			return
		}
		for _, res := range resources {
			if r.URL.Path != pathFor(res) {
				continue
			}
			partial := strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList;")
			if res.kind == "Secret" && !partial {
				t.Error("retained world proof attempted a full-content Secret LIST")
				w.WriteHeader(500)
				return
			}
			if res.kind == "GameServer" && !partial {
				typedReads++
				if typedReads == 2 && scenario == "closing-source-replacement" {
					replace(sourceName)
				}
				if typedReads == 2 && scenario == "closing-retirement-replacement" {
					replace(retirementName)
				}
			}
			items := []any{}
			for _, original := range objects[res.kind] {
				copy := original.DeepCopy()
				if !partial && scenario == "wrong-world-uid" && res.kind == "GameServer" {
					wrong := server.DeepCopy()
					wrong.Status.ObservedData.Claims[0].ClaimRef.UID = "foreign-world-claim"
					copy = servingObject(t, wrong)
					markFault()
				}
				if !partial && scenario == "deleting-claim" && res.kind == "PersistentVolumeClaim" {
					now := metav1.Now()
					copy.SetDeletionTimestamp(&now)
					markFault()
				}
				if res.kind == "PersistentVolumeClaim" && partial {
					if scenario == "typed-only-claim" {
						markFault()
						continue
					}
					if scenario == "gc-owner-change" {
						copy.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: "foreign", UID: "foreign-owner"}})
						markFault()
					}
				}
				if typedReads == 2 && !partial {
					if scenario == "late-claim-rv" && res.kind == "PersistentVolumeClaim" {
						copy.SetResourceVersion("2")
						markFault()
					}
					if scenario == "late-history-same-rv" && res.kind == "GameBackup" || scenario == "late-lease-same-rv" && res.kind == "Lease" {
						copy.SetAnnotations(map[string]string{"fixture.example/revision": "closing"})
						markFault()
					}
				}
				if scenario == "active-operation" && res.kind == "ArcadeOperation" {
					_ = unstructured.SetNestedField(copy.Object, string(arcade.OperationPhaseRunning), "status", "phase")
					markFault()
				}
				if scenario == "data-lease" && res.kind == "Lease" {
					copy.SetName("data-operation-foreign")
					markFault()
				}
				if partial {
					items = append(items, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": copy.Object["metadata"]})
				} else {
					items = append(items, copy.Object)
				}
			}
			if scenario == "terminal-pod" && res.kind == "Pod" && !partial {
				items = append(items, servingObject(t, &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metadata("terminal-history"), Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "history", Image: "example.invalid/other@sha256:" + strings.Repeat("e", 64)}}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}).Object)
				markFault()
			}
			if scenario == "attached-world" && res.kind == "VolumeAttachment" && !partial {
				volumeName := pv.Name
				items = append(items, servingObject(t, &storagev1.VolumeAttachment{TypeMeta: metav1.TypeMeta{APIVersion: "storage.k8s.io/v1", Kind: "VolumeAttachment"}, ObjectMeta: metav1.ObjectMeta{Name: "current-world-attachment", UID: "current-attachment", ResourceVersion: "1"}, Spec: storagev1.VolumeAttachmentSpec{Attacher: "test.example", NodeName: "node-1", Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &volumeName}}, Status: storagev1.VolumeAttachmentStatus{Attached: true}}).Object)
				markFault()
			}
			if partial && (scenario == "unknown-source" && res.kind == "Custom" || scenario == "gc-only-claim" && res.kind == "PersistentVolumeClaim") {
				items = append(items, map[string]any{"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata", "metadata": map[string]any{"name": "foreign", "namespace": d.Namespace, "uid": "foreign-object", "resourceVersion": "1"}})
				markFault()
			}
			gv, kind := res.gv, res.kind+"List"
			if partial {
				gv, kind = "meta.k8s.io/v1", "PartialObjectMetadataList"
				gcReads++
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": gv, "kind": kind, "metadata": map[string]any{"resourceVersion": "1"}, "items": items})
			return
		}
		for _, res := range resources {
			for _, object := range objects[res.kind] {
				if r.URL.Path == pathFor(res)+"/"+object.GetName() {
					if scenario == "late-policy-rv" && res.kind == "ValidatingAdmissionPolicy" && typedReads == 1 {
						for _, entry := range d.Resources {
							if entry.Key.Kind == res.kind && entry.Key.Name == object.GetName() {
								copy := object.DeepCopy()
								copy.SetResourceVersion(object.GetResourceVersion() + "1")
								markFault()
								encodeStoppedObject(t, w, r, copy)
								return
							}
						}
					}
					if res.kind == f.key.Kind && object.GetName() == f.key.Name && (scenario == "unrecorded-access" || scenario == "unacknowledged-access" || scenario == "recover-unacknowledged-access") {
						markFault() // reached the present, unowned/unacknowledged target
					}
					if res.kind == "Secret" && !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata;") {
						if recovering || creating {
							if secret := v.private.objects[object.GetName()]; secret != nil {
								copy := secret.DeepCopy()
								copy.APIVersion, copy.Kind = "v1", "Secret"
								privateReads++
								_ = json.NewEncoder(w).Encode(copy)
								return
							}
						}
						t.Error("retained world proof attempted to read private Secret contents")
						w.WriteHeader(500)
						return
					}
					encodeStoppedObject(t, w, r, object.DeepCopy())
					return
				}
			}
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(endpoint.Close)
	config := serverConfig(endpoint)
	config.QPS, config.Burst = 100, 200 // serialize requests, without test limiter sleeps
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("retained-world TLS transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("current retained-world HTTP store unavailable")
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("current retained-world HTTP engine unavailable")
	}
	current, err = store.Load(t.Context(), current.Anchor())
	if err != nil {
		t.Fatal("current sealed retained-world snapshot unavailable")
	}
	operationDescriptor, err := engine.prerequisiteOperation(current, f.key, d.TargetPackage)
	if err != nil {
		t.Fatal("closed retained-world operation unavailable")
	}
	provider, err := NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal("closed retained-world verifier unavailable")
	}
	before := bytes.Clone(current.Bytes())
	var verifyErr error
	var returned *installstate.Snapshot
	if recovering || creating {
		lifecycle, err := NewClusterLifecycle(engine, access)
		if err != nil {
			t.Fatal("actual retained recovery lifecycle unavailable")
		}
		if creating {
			owned, err := lifecycle.secrets.openRetainedBootstrapSecrets(t.Context(), current, v.opts.Activation.CAFile, v.opts.Now)
			if err != nil {
				t.Fatal("actual retained CREATE Secret/CA owner unavailable")
			}
			returned, verifyErr = engine.applyPrerequisiteOwned(t.Context(), current, f.key, d.TargetPackage, owned)
			owned.release()
		} else if scenario == "recover-without-secret-owner" {
			returned, verifyErr = engine.Recover(t.Context(), current)
		} else {
			returned, verifyErr = lifecycle.Step(t.Context(), current, v.opts)
		}
	} else {
		verifyErr = provider.verifyPrerequisite(t.Context(), current, operationDescriptor)
	}
	mu.Lock()
	typedCount, pvCount, metadataCount, faultReached := typedReads, pvReads, gcReads, faultHit
	writeCount, targetCount, privateCount := journalWrites, targetReads, privateReads
	previewCount, createCount := previews, creates
	closedDocument := namespaceDocument
	mu.Unlock()
	positive := scenario == "healthy" || scenario == "acknowledged-access" || scenario == "recover-acknowledged-access" || scenario == "create-healthy"
	if positive {
		wantTyped := 4
		if creating {
			wantTyped = 16
		}
		if verifyErr != nil || typedCount != wantTyped || pvCount != wantTyped || metadataCount < 44 {
			t.Fatalf("complete retained-world positive refused or omitted repeated proof: err=%v typed=%d pv=%d gc=%d", verifyErr, typedCount, pvCount, metadataCount)
		}
	} else if (!recovering && !creating || creating && strings.HasPrefix(scenario, "create-before-intent-")) && verifyErr != ErrSecurityBaseline || (recovering || creating && strings.HasPrefix(scenario, "create-before-effect-")) && !errors.Is(verifyErr, ErrOutcomeUnknown) {
		t.Fatal("unsafe retained-world observation acquired prerequisite authority")
	}
	if !positive && !faultReached && scenario != "recover-without-secret-owner" {
		t.Fatal("negative passed without reaching its independent fault")
	}
	if recovering {
		if scenario == "recover-without-secret-owner" && (privateCount != 0 || targetCount != 0 || typedCount != 0 || writeCount != 0) {
			t.Fatal("public recovery without original Secret/CA ownership acquired effect authority")
		}
		if positive {
			entry, _ := engine.inventory(returned.Document(), f.key)
			if writeCount != 1 || targetCount != 5 || privateCount != 8 || returned.Document().Pending != nil || entry == nil || entry.UID != "new-access-original" {
				t.Fatal("actual recovery did not settle exactly one acknowledged original access identity")
			}
		} else if returned == nil || !bytes.Equal(returned.Bytes(), before) || writeCount != 0 && scenario != "recover-settlement-conflict" || writeCount != 1 && scenario == "recover-settlement-conflict" {
			t.Fatal("refused recovery changed original intent or replayed settlement")
		}
	}
	if creating {
		if positive {
			if returned == nil || returned.Document().Pending != nil || writeCount != 2 || previewCount != 1 || createCount != 1 || privateCount != 20 || targetCount != 18 || !reflect.DeepEqual(returned.Document(), closedDocument) {
				t.Fatal("actual access CREATE did not complete one exact intent/ACK/settlement")
			}
		} else if previewCount != 1 || createCount != 0 {
			t.Fatal("refused retained CREATE replayed preview or emitted its target effect")
		} else if strings.HasPrefix(scenario, "create-before-intent-") {
			if writeCount != 0 || returned != nil || !reflect.DeepEqual(closedDocument, current.Document()) {
				t.Fatal("pre-intent refusal changed original journal")
			}
		} else if writeCount != 1 || returned == nil || returned.Document().Pending == nil || !reflect.DeepEqual(returned.Document(), closedDocument) {
			t.Fatal("pre-effect refusal lost the exact pending intent")
		}
		if previewBody != nil && testBaselineReceiptDescriptors(t, "create-"+previewBody.GetAnnotations()[installstate.MutationAnnotation]+".json") != 0 {
			t.Fatal("actual CREATE leaked its original receipt descriptor")
		}
	}
	if recovering || creating {
		guard, ok := engine.baseline.runtimeGuard.(*ClusterSecurityBaseline)
		if !ok || guard == nil || guard != engine.baseline.prerequisites || guard.engine != engine || guard.access != access {
			t.Fatal("actual lifecycle lost same-engine closed runtime/prerequisite proof")
		}
	} else if engine.baseline.runtimeGuard != nil {
		t.Fatal("standalone read-only proof installed runtime authority")
	}
	if !bytes.Equal(before, current.Bytes()) || testBaselineReceiptDescriptors(t, sourceName) != 0 || testBaselineReceiptDescriptors(t, retirementName) != 0 || testBaselineReceiptDescriptors(t, filepath.Base(v.opts.Activation.CAFile)) != 0 {
		t.Fatal("retained proof mutated original snapshot or leaked source owners")
	}
	if d.Pending != nil && testBaselineReceiptDescriptors(t, "create-"+d.Pending.CreateNonce+".json") != 0 {
		t.Fatal("retained pending proof leaked its original CREATE receipt")
	}
	t.Log(fmt.Sprintf("whole current retained proof: typed=%d pv=%d metadata=%d", typedCount, pvCount, metadataCount))
}
