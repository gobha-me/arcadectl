// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestLifecycleAcknowledgedDeleteConvergesWithoutReplay(t *testing.T) {
	for _, mode := range []string{"delayed-absence", "replacement", "lost-response", "read-refusal", "journal-changed", "cancelled", "still-present"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, true)
			original := f.access.objects[f.key].DeepCopy()
			ctx, cancel := context.WithTimeout(t.Context(), 2500*time.Millisecond)
			defer cancel()
			reads := 0
			f.access.write = func(action installstate.Action, key installstate.Key, _ *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				if action != installstate.Delete || key != f.key {
					t.Fatal("convergence sent a different effect")
				}
				if mode == "lost-response" {
					return nil, ErrOutcomeUnknown
				}
				now := metav1.Now()
				f.access.objects[key].SetDeletionTimestamp(&now)
				f.access.objects[key].SetResourceVersion("43")
				if mode == "replacement" {
					f.access.objects[key].SetUID("foreign-replacement")
				}
				if mode == "cancelled" {
					cancel()
				}
				return nil, nil
			}
			f.access.get = func(key installstate.Key) error {
				if key != f.key || f.access.writes == 0 {
					return nil
				}
				reads++
				switch mode {
				case "delayed-absence":
					if reads == 2 {
						delete(f.access.objects, key)
					}
				case "read-refusal":
					return ErrRead
				case "journal-changed":
					ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					ns.ResourceVersion = "999"
					if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, "") != nil {
						t.Fatal("journal drift injection refused")
					}
				}
				return nil
			}
			started := time.Now()
			s, err := f.engine.delete(ctx, f.snapshot, f.key, true)
			if s == nil || f.access.writes != 1 || f.access.dryRuns != 0 || f.access.deleteOptions.Preconditions == nil || *f.access.deleteOptions.Preconditions.UID != original.GetUID() || *f.access.deleteOptions.Preconditions.ResourceVersion != original.GetResourceVersion() || f.access.deleteOptions.PropagationPolicy == nil || *f.access.deleteOptions.PropagationPolicy != metav1.DeletePropagationForeground {
				t.Fatal("delete convergence changed/replayed its original UID/RV effect")
			}
			if mode == "delayed-absence" {
				if err != nil || s.Document().Pending != nil || len(s.Document().Resources) != 1 || reads < 3 || time.Since(started) < time.Second {
					t.Fatal("acknowledged deletion skipped repeated actual absence", err)
				}
				return
			}
			if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil || s.Document().Pending.Action != installstate.Delete || s.Document().Pending.BeforeUID != original.GetUID() {
				t.Fatal("refused or uncertain original DELETE became settled")
			}
			if mode == "still-present" && time.Since(started) < 2*time.Second {
				t.Fatal("present acknowledged original did not respect parent observation budget")
			}
			if mode == "lost-response" && (reads != 1 || time.Since(started) >= time.Second) {
				t.Fatal("unknown DELETE was automatically retried/waited")
			}
		})
	}
}
