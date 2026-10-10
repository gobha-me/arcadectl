//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"reflect"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This runs inside the existing exact-version test-owned API server. No fake
// DELETE implementation or controller-written status is native API evidence.
// There is no scheduler/Job controller; every Job is suspended/parallelism-zero.
func testNativeDestroyJobCleanup(t *testing.T, ctx context.Context, api client.Client) {
	t.Helper()
	t.Run("native-destroy-job-cleanup/unchanged-original", func(t *testing.T) {
		f := newDestroyFixture(t, true)
		d := f.destroy(t)
		d.Name, d.Namespace, d.UID, d.ResourceVersion = "cleanup-unchanged", "games", "", ""
		d.Spec.CancelRequested = true
		if err := api.Create(ctx, d); err != nil {
			t.Fatal("native parent fixture: ", err)
		}
		job := destroyCleanupJob(d)
		if err := api.Create(ctx, job); err != nil {
			t.Fatal("native suspended Job fixture: ", err)
		}
		p := &destroyCleanupDeleteProbe{Client: api}
		f.r.Client, f.r.APIReader = p, api
		if pending, err := f.r.cleanupWorker(ctx, d); err != nil || !pending {
			t.Fatalf("unchanged native cleanup: pending %v, error %v", pending, err)
		}
		got := &batchv1.Job{}
		if err := api.Get(ctx, client.ObjectKeyFromObject(job), got); err != nil ||
			got.UID != job.UID || got.DeletionTimestamp == nil || got.Spec.Suspend == nil || !*got.Spec.Suspend {
			t.Fatalf("native foreground deletion did not preserve original identity: %v", err)
		}
		// Envtest has no garbage collector: successful foreground DELETE is
		// observable deletion-in-progress, not automatically proven absence.
		if p.calls != 1 {
			t.Fatalf("native DELETE calls %d", p.calls)
		}
	})
	for _, replacement := range []bool{true, false} {
		name := "ownership-change"
		if replacement {
			name = "replacement"
		}
		t.Run("native-destroy-job-cleanup/"+name, func(t *testing.T) {
			f := newDestroyFixture(t, true)
			d := f.destroy(t)
			d.Name, d.Namespace, d.UID, d.ResourceVersion = "cleanup-"+name, "games", "", ""
			d.Spec.CancelRequested = true
			if err := api.Create(ctx, d); err != nil {
				t.Fatal("native parent fixture: ", err)
			}
			if d.UID == "" || d.ResourceVersion == "" {
				t.Fatal("native parent identity absent")
			}
			job := destroyCleanupJob(d)
			if err := api.Create(ctx, job); err != nil {
				t.Fatal("native suspended Job fixture: ", err)
			}
			if job.UID == "" || job.ResourceVersion == "" {
				t.Fatal("native Job identity absent")
			}
			originalUID := job.UID
			p := &destroyCleanupDeleteProbe{Client: api}
			var raced *batchv1.Job
			p.beforeDelete = func(ctx context.Context, seen *batchv1.Job, _ *client.DeleteOptions) error {
				if replacement {
					if err := api.Delete(ctx, seen, client.Preconditions{UID: ptr.To(seen.UID)}, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
						t.Fatal("native old Job removal: ", err)
					}
					raced = destroyCleanupJob(d)
					raced.OwnerReferences = nil
					if err := api.Create(ctx, raced); err != nil {
						t.Fatal("native replacement Job create: ", err)
					}
					if raced.UID == "" || raced.UID == originalUID {
						t.Fatal("replacement lacks a distinct native UID")
					}
				} else {
					raced = seen.DeepCopy()
					raced.OwnerReferences = nil
					if err := api.Update(ctx, raced); err != nil {
						t.Fatal("native ownership change: ", err)
					}
					if raced.UID != originalUID || raced.ResourceVersion == seen.ResourceVersion {
						t.Fatal("ownership-change witness did not advance")
					}
				}
				return nil // Forward the actual stale DELETE to the native API.
			}
			f.r.Client, f.r.APIReader = p, api
			if _, err := f.r.cleanupWorker(ctx, d); !apierrors.IsConflict(err) {
				t.Fatalf("native stale DELETE should conflict, got %v", err)
			}
			got := &batchv1.Job{}
			if err := api.Get(ctx, client.ObjectKeyFromObject(job), got); err != nil || !reflect.DeepEqual(got, raced) || got.DeletionTimestamp != nil {
				t.Fatalf("native racing Job was changed or deleted: %v", err)
			}
			if _, err := f.r.cleanupWorker(ctx, d); err == nil {
				t.Fatal("native retry adopted the foreign Job")
			}
			if p.calls != 1 {
				t.Fatalf("native DELETE calls %d", p.calls)
			}
		})
	}
}
