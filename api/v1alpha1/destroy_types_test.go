// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToSchemeRegistersDestroy(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for kind, expected := range map[string]any{
		"GameDestroy": &GameDestroy{}, "GameDestroyList": &GameDestroyList{},
	} {
		object, err := scheme.New(GroupVersion.WithKind(kind))
		if err != nil || reflect.TypeOf(object) != reflect.TypeOf(expected) {
			t.Errorf("scheme.New(%s) = %T, %v; want %T", kind, object, err, expected)
		}
	}
}

func TestDestroyDeepCopySeparatesRequestAndJournal(t *testing.T) {
	t.Parallel()
	original := &GameDestroy{
		Spec: GameDestroySpec{Target: GameDestroyTarget{Data: RetainedDataReference{Claims: []RetainedDataClaimReference{{Path: "world", ClaimRef: ExactLocalReference{Name: "world", UID: "original"}}}}}},
		Status: GameDestroyStatus{
			Preview:         &GameDestroyPreview{Challenge: "original-challenge"},
			DeletionJournal: []GameDestroyClaimDeletion{{Path: "world", ClaimRef: ExactLocalReference{Name: "world", UID: "original"}, ObservedDeletedAt: &metav1.Time{}}},
		},
	}
	clone := original.DeepCopy()
	clone.Spec.Target.Data.Claims[0].ClaimRef.UID = "changed"
	clone.Status.Preview.Challenge = "changed"
	clone.Status.DeletionJournal[0].ClaimRef.UID = "changed"
	clone.Status.DeletionJournal[0].ObservedDeletedAt = nil
	if original.Spec.Target.Data.Claims[0].ClaimRef.UID != "original" || original.Status.Preview.Challenge != "original-challenge" || original.Status.DeletionJournal[0].ClaimRef.UID != "original" || original.Status.DeletionJournal[0].ObservedDeletedAt == nil {
		t.Fatal("GameDestroy.DeepCopy aliased request or journal")
	}
}
