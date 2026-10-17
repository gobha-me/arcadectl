// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type destroyCleanupDeleteProbe struct {
	client.Client
	beforeDelete func(context.Context, *batchv1.Job, *client.DeleteOptions) error
	calls        int
}

func (p *destroyCleanupDeleteProbe) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if job, ok := object.(*batchv1.Job); ok {
		p.calls++
		d := &client.DeleteOptions{}
		d.ApplyOptions(options)
		if p.beforeDelete != nil {
			if err := p.beforeDelete(ctx, job, d); err != nil {
				return err
			}
		}
	}
	return p.Client.Delete(ctx, object, options...)
}

func destroyCleanupJob(d *arcade.GameDestroy) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: platformkube.DestroyResourceName(d.UID), Namespace: d.Namespace,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: arcade.GroupVersion.String(), Kind: "GameDestroy", Name: d.Name, UID: d.UID, Controller: ptr.To(true)}}},
		Spec: batchv1.JobSpec{Suspend: ptr.To(true), Parallelism: ptr.To(int32(0)),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{{Name: "probe", Image: testWorkerImage}}}}},
	}
}

func TestGameDestroyCleanupWorkerPinsJobIdentityAndRevision(t *testing.T) {
	f := newDestroyFixture(t, true)
	ctx := context.Background()
	job := destroyCleanupJob(f.destroy(t))
	job.UID = "original-cleanup-job"
	if err := f.client.Create(ctx, job); err != nil {
		t.Fatal(err)
	}
	p := &destroyCleanupDeleteProbe{Client: f.client}
	p.beforeDelete = func(_ context.Context, seen *batchv1.Job, options *client.DeleteOptions) error {
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != seen.UID ||
			options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != seen.ResourceVersion || seen.ResourceVersion == "" ||
			options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationForeground {
			t.Fatal("cleanup must condition foreground deletion on the complete original Job witness")
		}
		return nil
	}
	f.r.Client = p
	if pending, err := f.r.cleanupWorker(ctx, f.destroy(t)); err != nil || !pending {
		t.Fatalf("cleanup: pending %v, error %v", pending, err)
	}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(job), &batchv1.Job{}); !apierrors.IsNotFound(err) {
		t.Fatalf("original Job still present: %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("DELETE calls %d", p.calls)
	}
	requireDestroyClaim(t, f, f.claim)
}

// The fake client is not native API evidence. This interceptor models a server
// checking explicit DELETE preconditions after a race; tagged envtest separately
// exercises the same controller path against a real API server.
func TestGameDestroyCleanupWorkerPreservesRacingJob(t *testing.T) {
	for _, replacement := range []bool{true, false} {
		name := "ownership-change"
		if replacement {
			name = "same-name-replacement"
		}
		t.Run(name, func(t *testing.T) {
			f := newDestroyFixture(t, true)
			ctx := context.Background()
			d := f.destroy(t)
			job := destroyCleanupJob(d)
			job.UID = "original-cleanup-job"
			if err := f.client.Create(ctx, job); err != nil {
				t.Fatal(err)
			}
			p := &destroyCleanupDeleteProbe{Client: f.client}
			var raced *batchv1.Job
			p.beforeDelete = func(ctx context.Context, seen *batchv1.Job, options *client.DeleteOptions) error {
				raced = seen.DeepCopy()
				raced.OwnerReferences = nil
				if replacement {
					if err := f.client.Delete(ctx, seen); err != nil {
						t.Fatal(err)
					}
					raced.UID, raced.ResourceVersion = types.UID("replacement-cleanup-job"), ""
					if err := f.client.Create(ctx, raced); err != nil {
						t.Fatal(err)
					}
				} else if err := f.client.Update(ctx, raced); err != nil {
					t.Fatal(err)
				}
				if err := f.client.Get(ctx, client.ObjectKeyFromObject(seen), raced); err != nil {
					t.Fatal(err)
				}
				if options.Preconditions != nil &&
					(options.Preconditions.UID != nil && *options.Preconditions.UID != raced.UID ||
						options.Preconditions.ResourceVersion != nil && *options.Preconditions.ResourceVersion != raced.ResourceVersion) {
					return apierrors.NewConflict(schema.GroupResource{Group: "batch", Resource: "jobs"}, seen.Name, errors.New("original witness changed"))
				}
				return nil
			}
			f.r.Client = p
			if _, err := f.r.cleanupWorker(ctx, d); !apierrors.IsConflict(err) {
				t.Fatalf("expected original-witness conflict, got %v", err)
			}
			got := &batchv1.Job{}
			if err := f.client.Get(ctx, client.ObjectKeyFromObject(job), got); err != nil || got.UID != raced.UID || len(got.OwnerReferences) != 0 {
				t.Fatalf("racing Job not preserved: %v", err)
			}
			if _, err := f.r.cleanupWorker(ctx, d); err == nil {
				t.Fatal("retry adopted the foreign Job")
			}
			if p.calls != 1 {
				t.Fatalf("retry DELETE calls %d", p.calls)
			}
			requireDestroyClaim(t, f, f.claim)
		})
	}
}
