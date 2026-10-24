// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Faults belong only to this synthetic HTTPS responder. No production hook,
// cached authority, native serving claim or persistent mutation is introduced.
type testBaselineProbeSuiteFault struct {
	mode                           string
	objects                        map[installstate.Key]*unstructured.Unstructured
	access, policy                 installstate.Key
	originalPolicy                 *unstructured.Unstructured
	liveNamespace                  *corev1.Namespace
	originalNamespace              *corev1.Namespace
	injected, restored             bool
	finalVersions, namespaceWrites int
}

func (f *testBaselineProbeSuiteFault) prepare(t *testing.T, objects map[installstate.Key]*unstructured.Unstructured, namespace *corev1.Namespace) {
	t.Helper()
	f.objects, f.liveNamespace, f.originalNamespace = objects, namespace, namespace.DeepCopy()
	// Select deterministic signed originals outside behavioral target
	// metadata, so a target before/after read cannot hide a missing final fence.
	for key := range objects {
		if key.Kind == "ClusterRole" && (f.access == (installstate.Key{}) || key.String() < f.access.String()) {
			f.access = key
		}
		if key.Kind == "ValidatingAdmissionPolicy" && (f.policy == (installstate.Key{}) || key.String() < f.policy.String()) {
			f.policy = key
		}
	}
	if f.access == (installstate.Key{}) || f.policy == (installstate.Key{}) {
		t.Fatal("suite fault lacks complete original access/configuration")
	}
	f.originalPolicy = objects[f.policy].DeepCopy()
}

func (f *testBaselineProbeSuiteFault) change(t *testing.T, mode string) {
	t.Helper()
	switch mode {
	case "access-uid":
		f.objects[f.access].SetUID("foreign-suite-access")
	case "access-rv":
		f.objects[f.access].SetResourceVersion("9001")
	case "namespace-uid":
		f.liveNamespace.UID = "foreign-suite-namespace"
	case "journal-rv":
		f.liveNamespace.ResourceVersion = "9001"
	case "policy-uid":
		f.objects[f.policy].SetUID("foreign-suite-policy")
	case "policy-rv":
		f.objects[f.policy].SetResourceVersion("9001")
	case "policy-shape", "edit-restore":
		if unstructured.SetNestedField(f.objects[f.policy].Object, "Ignore", "spec", "failurePolicy") != nil {
			t.Error("suite policy edit unavailable")
		}
	case "policy-status":
		if unstructured.SetNestedField(f.objects[f.policy].Object, int64(0), "status", "observedGeneration") != nil {
			t.Error("suite policy status edit unavailable")
		}
	default:
		t.Error("unknown suite fault")
	}
	f.injected = true
}

// Called under the original responder mutex, including all injected edits.
func (f *testBaselineProbeSuiteFault) before(t *testing.T, r *http.Request, objects map[installstate.Key]*unstructured.Unstructured, probes int, rules map[string]int, files *privatefs.Store, document installstate.Document) {
	t.Helper()
	if r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+document.Namespace {
		f.namespaceWrites++
	}
	if strings.HasPrefix(f.mode, "repeat-") {
		return // The protocol edits only after its first complete Verify returns.
	}
	if strings.HasPrefix(f.mode, "late-") || f.mode == "receipt" {
		if r.Method != http.MethodGet || r.URL.Path != "/version" || probes != 97 || rules["arcadectl-destroy-controller"] != 6 {
			return
		}
		f.finalVersions++
		// First: original final denied-catalog actor fence. Second: the new
		// trailing full suite fence, after all existing closes have succeeded.
		if f.finalVersions != 2 || f.injected {
			return
		}
		if f.mode != "receipt" {
			f.change(t, strings.TrimPrefix(f.mode, "late-"))
			return
		}
		if document.Pending == nil {
			t.Error("suite closing receipt fault has no original pending ACK")
			return
		}
		name := "create-" + document.Pending.CreateNonce + ".json"
		if testBaselineReceiptDescriptors(t, name) != 1 {
			t.Error("suite final remote window lost its original receipt owner")
			return
		}
		body, identity, err := files.Read(name, 4096)
		if err != nil {
			t.Error("suite original receipt unavailable")
			return
		}
		for range 2 {
			identity, err = files.AtomicWrite(name, body, &identity)
			if err != nil {
				t.Error("suite identical-byte receipt replacement refused")
				return
			}
		}
		f.injected = true
		return
	}
	if r.URL.Query().Get("dryRun") != "All" {
		return
	}
	if !f.injected && probes == 0 {
		f.change(t, f.mode)
	} else if f.mode == "edit-restore" && f.injected && !f.restored && probes == 1 {
		objects[f.policy] = f.originalPolicy.DeepCopy()
		objects[f.policy].SetResourceVersion("9002")
		f.restored = true
	}
}

func (f *testBaselineProbeSuiteFault) assert(t *testing.T, objects map[installstate.Key]*unstructured.Unstructured, namespace *corev1.Namespace, probes, persistent int) {
	t.Helper()
	expectedNamespace := f.originalNamespace.DeepCopy()
	// These are deliberate external changes, never installer intent/effects.
	// Every other field, including the sealed journal annotation, stays exact.
	if f.mode == "namespace-uid" {
		expectedNamespace.UID = "foreign-suite-namespace"
	} else if f.mode == "journal-rv" {
		expectedNamespace.ResourceVersion = "9001"
	}
	if !f.injected || probes != 97 || persistent != 0 || f.namespaceWrites != 0 || !reflect.DeepEqual(namespace, expectedNamespace) {
		t.Fatal("suite refusal omitted its fault/behavior rows or reached persistent intent/effects")
	}
	if f.mode == "edit-restore" {
		restored := objects[f.policy].DeepCopy()
		if !f.restored || restored.GetResourceVersion() == f.originalPolicy.GetResourceVersion() {
			t.Fatal("suite restoration did not retain a new resource version")
		}
		restored.SetResourceVersion(f.originalPolicy.GetResourceVersion())
		if !reflect.DeepEqual(restored.Object, f.originalPolicy.Object) {
			t.Fatal("suite restoration changed fields beyond resource version")
		}
	}
	if (strings.HasPrefix(f.mode, "late-") || f.mode == "receipt") && f.finalVersions != 2 {
		t.Fatal("suite fault did not reach the new trailing global verification")
	}
}

func TestBaselineProbeSuiteWholeProviderRejectsDeferredAuthorityDrift(t *testing.T) {
	for _, mode := range []string{"access-uid", "access-rv", "namespace-uid", "journal-rv", "policy-uid", "policy-rv", "policy-shape", "policy-status", "edit-restore", "late-access-rv", "late-policy-rv"} {
		t.Run(mode, func(t *testing.T) {
			testBaselineBehaviorWholeProviderSuite(t, "healthy", nil, nil, nil, &testBaselineProbeSuiteFault{mode: mode})
		})
	}
}

func TestBaselineProbeSuiteFinalRemoteWindowRetainsOriginalReceipts(t *testing.T) {
	for _, scenario := range []string{"pending-service", "pending-parent"} {
		t.Run(scenario, func(t *testing.T) {
			testBaselineBehaviorWholeProviderSuite(t, scenario, nil, nil, nil, &testBaselineProbeSuiteFault{mode: "receipt"})
		})
	}
}

func TestBaselineProbeSuiteRuntimeRefusalPrecedesIntentAndEffects(t *testing.T) {
	for _, boundary := range []string{"current", "apply"} {
		t.Run(boundary, func(t *testing.T) {
			fault := &testBaselineProbeSuiteFault{mode: "access-rv"}
			testBaselineBehaviorWholeProviderSuite(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
				var err error
				if boundary == "current" {
					_, err = engine.current(t.Context(), snapshot)
				} else {
					_, err = engine.Apply(t.Context(), snapshot, deploymentKey(snapshot.Anchor().Namespace, "arcadectl-controller"), snapshot.Document().TargetPackage, false)
				}
				if err != ErrSecurityBaseline {
					t.Fatal("runtime mutation boundary accepted failed final suite authority")
				}
				fresh, loadErr := engine.journal.Load(t.Context(), snapshot.Anchor())
				if loadErr != nil || fresh.ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(fresh.Bytes(), snapshot.Bytes()) || !reflect.DeepEqual(fresh.Document(), snapshot.Document()) {
					t.Fatal("failed suite proof changed live journal/Pending before intent")
				}
				return err
			}, nil, nil, fault)
		})
	}
}

func TestBaselineProbeSuiteSameCallerContextNeverCachesAcrossVerifyOrReconstruction(t *testing.T) {
	for _, reconstruct := range []bool{false, true} {
		name := "same-provider"
		if reconstruct {
			name = "reconstructed-provider"
		}
		t.Run(name, func(t *testing.T) {
			fault := &testBaselineProbeSuiteFault{mode: "repeat-access-uid"}
			testBaselineBehaviorWholeProviderSuite(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, provider *ClusterSecurityBaseline, requests func() int) error {
				ctx, _ := WithLifecycleDiagnostic(t.Context())
				if provider.Verify(ctx, snapshot) != nil {
					t.Fatal("first complete suite proof refused original authority")
				}
				before := requests()
				// The journal pins original UID across invocations; a resource
				// version is freshly observed and pinned only within each suite.
				fault.change(t, "access-uid")
				if reconstruct {
					plans := []*installrender.Plan{engine.plans[snapshot.Document().TargetPackage]}
					rebuilt, err := NewWithBaselineAccess(provider.access, engine.journal, engine.files, engine.baselinePlan(), plans...)
					if err != nil {
						t.Fatal("suite restart engine unavailable")
					}
					if _, err = NewClusterLifecycle(rebuilt, provider.access); err != nil {
						t.Fatal("suite restart closed runtime guard unavailable")
					}
					var ok bool
					provider, ok = rebuilt.baseline.runtimeGuard.(*ClusterSecurityBaseline)
					if !ok {
						t.Fatal("suite restart lost complete production provider")
					}
				}
				if err := provider.Verify(ctx, snapshot); err != ErrSecurityBaseline || requests() <= before {
					t.Fatal("second Verify reused suite authority across calls or reconstruction")
				}
				return ErrSecurityBaseline
			}, nil, nil, fault)
		})
	}
}
