// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"errors"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"
)

func TestCollectionDiagnosticActualRefusalsKeepEvidenceClosed(t *testing.T) {
	for _, fault := range []string{"healthy", "typed-list", "identity", "decode", "owner", "journal"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			want := "stage=complete collection=unknown reason=complete pages=unknown inner=active caller=active"
			wantErr := error(nil)
			switch fault {
			case "typed-list":
				f.dynamic.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("PRIVATE-token=canary save-path namespace server")
				})
				want = "stage=list-pages collection=Pod reason=read pages=fetch-unclassified inner=active caller=active"
				wantErr = ErrRead
			case "identity", "decode":
				f.claim("world")
				if fault == "identity" {
					f.lists["persistentvolumeclaims"][0].SetUID("")
					want = "stage=list-identity collection=PersistentVolumeClaim reason=read pages=unknown inner=active caller=active"
				} else {
					f.lists["persistentvolumeclaims"][0].Object["spec"] = map[string]any{"PRIVATE-token": "canary"}
					want = "stage=list-decode collection=PersistentVolumeClaim reason=read pages=unknown inner=active caller=active"
				}
				wantErr = ErrRead
			case "owner":
				f.claim("world", owner("ConfigMap", "PRIVATE-canary"))
				want = "stage=owners collection=unknown reason=ownership pages=unknown inner=active caller=active"
				wantErr = ErrOwnership
			case "journal":
				reads := 0
				f.core.PrependReactor("get", "namespaces", func(clienttesting.Action) (bool, runtime.Object, error) {
					reads++
					if reads != 2 {
						return false, nil, nil
					}
					object, err := f.core.Tracker().Get(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, "", f.anchor.Namespace)
					if err != nil {
						return true, nil, err
					}
					namespace := object.(*corev1.Namespace).DeepCopy()
					namespace.ResourceVersion = "PRIVATE-new-rv"
					return true, namespace, nil
				})
				want = "stage=journal-closing collection=unknown reason=concurrent pages=unknown inner=active caller=active"
				wantErr = ErrConcurrent
			}
			ctx, diagnostic := WithCollectionDiagnostic(t.Context())
			observation, err := f.o.Collect(ctx, f.anchor)
			if err != wantErr || (observation != nil) != (wantErr == nil) || diagnostic.Snapshot() != want {
				t.Fatal("diagnostic changed refusal or attributed the wrong closed branch", err, diagnostic.Snapshot())
			}
			for _, action := range append(append(f.dynamic.Actions(), f.metadata.Actions()...), f.core.Actions()...) {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("diagnostic observer mutated evidence")
				}
			}
		})
	}
}

func TestCollectionDiagnosticFreshAttemptAndLateConcurrentFinish(t *testing.T) {
	ctx, diagnostic := WithCollectionDiagnostic(t.Context())
	oldCtx, old := beginCollectionDiagnostic(ctx)
	traceCollection(oldCtx, collectionPages, "Pod")
	traceCollectionPages(oldCtx, pagesRefusalFetch)
	newCtx, current := beginCollectionDiagnostic(ctx)
	traceCollection(newCtx, collectionComplete, "")
	current.finish(newCtx, newCtx, nil)
	want := "stage=complete collection=unknown reason=complete pages=unknown inner=active caller=active"
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		old.finish(oldCtx, oldCtx, ErrRead)
	}()
	go func() {
		defer workers.Done()
		for range 100 {
			if diagnostic.Snapshot() != want {
				t.Error("late completion replaced a newer complete attempt")
			}
		}
	}()
	workers.Wait()
	if diagnostic.Snapshot() != want {
		t.Fatal("late attempt republished itself")
	}
	f := newFixture(t)
	if observation, err := f.o.Collect(ctx, f.anchor); observation == nil || err != nil || diagnostic.Snapshot() != want {
		t.Fatal("actual subsequent observation inherited stale refusal", err, diagnostic.Snapshot())
	}
}

func TestCollectionDiagnosticUnknownInputsAndAbnormalCompletion(t *testing.T) {
	if ctx, diagnostic := WithCollectionDiagnostic(nil); ctx != nil || diagnostic != nil {
		t.Fatal("nil diagnostic made an execution context")
	}
	ctx, diagnostic := WithCollectionDiagnostic(t.Context())
	attemptCtx, attempt := beginCollectionDiagnostic(ctx)
	traceCollection(attemptCtx, collectionStage(255), "PRIVATE-secret-kind")
	traceCollectionPages(attemptCtx, pagesRefusalReason(255))
	attempt.finish(attemptCtx, attemptCtx, errors.New("PRIVATE-token=canary"))
	if got := diagnostic.Snapshot(); got != "stage=unknown collection=unknown reason=unknown pages=unknown inner=active caller=active" || strings.Contains(got, "PRIVATE") {
		t.Fatal("unknown inputs entered diagnostic output", got)
	}
	attemptCtx, attempt = beginCollectionDiagnostic(ctx)
	traceCollection(attemptCtx, collectionJournalOpening, "")
	// A nil named error during panic/Goexit must not claim complete evidence.
	attempt.finish(attemptCtx, attemptCtx, nil)
	if got := diagnostic.Snapshot(); !strings.Contains(got, "stage=journal-opening collection=unknown reason=unknown") {
		t.Fatal("incomplete attempt claimed successful collection", got)
	}
}

func TestCollectionDiagnosticOnlyReviewedCollectionLabels(t *testing.T) {
	ctx, diagnostic := WithCollectionDiagnostic(t.Context())
	// Literal public diagnostic vocabulary, independent of the collection
	// construction table. Addresses, aliases and user-supplied kinds stay unknown.
	for _, kind := range []string{"GameServer", "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation", "Job", "Pod", "Lease", "PersistentVolumeClaim", "Secret", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "VolumeAttachment", "EndpointSlice", "PRIVATE-kind", "Pod/PRIVATE-name", "pod"} {
		attemptCtx, attempt := beginCollectionDiagnostic(ctx)
		traceCollection(attemptCtx, collectionPages, kind)
		traceCollectionPages(attemptCtx, pagesRefusalFetch)
		attempt.finish(attemptCtx, attemptCtx, ErrRead)
		wantKind := kind
		if strings.Contains(kind, "PRIVATE") || kind == "pod" {
			wantKind = "unknown"
		}
		want := "stage=list-pages collection=" + wantKind + " reason=read pages=fetch-unclassified inner=active caller=active"
		if diagnostic.Snapshot() != want {
			t.Fatal("collection diagnostic vocabulary changed", diagnostic.Snapshot())
		}
	}
}
