// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToSchemeRegistersDataOperations(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}
	for kind, expected := range map[string]any{
		"GameBackup":      &GameBackup{},
		"GameBackupList":  &GameBackupList{},
		"GameRestore":     &GameRestore{},
		"GameRestoreList": &GameRestoreList{},
	} {
		object, err := scheme.New(GroupVersion.WithKind(kind))
		if err != nil {
			t.Fatalf("create registered %s: %v", kind, err)
		}
		if reflect.TypeOf(object) != reflect.TypeOf(expected) {
			t.Errorf("registered %s type = %T, want %T", kind, object, expected)
		}
	}
}

func TestOperationDeepCopyIsolatesStatus(t *testing.T) {
	t.Parallel()

	original := &GameRestore{Status: GameRestoreStatus{
		DataOperationStatus: DataOperationStatus{
			Conditions: []metav1.Condition{{Type: ConditionVerified, Message: "original"}},
			Source: &DataSourceSnapshot{Paths: []DataPathIdentity{{
				Name:     "world",
				ClaimRef: ExactLocalReference{UID: "claim-original"},
			}}},
		},
		CandidateData: []DataPathIdentity{{Name: "world", ClaimRef: ExactLocalReference{UID: "candidate-original"}}},
	}}
	clone := original.DeepCopy()
	clone.Status.Conditions[0].Message = "changed"
	clone.Status.Source.Paths[0].ClaimRef.UID = "changed"
	clone.Status.CandidateData[0].ClaimRef.UID = "changed"
	if original.Status.Conditions[0].Message != "original" ||
		original.Status.Source.Paths[0].ClaimRef.UID != "claim-original" ||
		original.Status.CandidateData[0].ClaimRef.UID != "candidate-original" {
		t.Fatal("DeepCopy() aliased operation status data")
	}
}
