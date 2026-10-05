// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDestroyPreviewPinsImmutableOriginalIdentity(t *testing.T) {
	target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: "world", UID: "original-uid"}, Game: "factorio", Data: arcade.RetainedDataReference{Identity: "original-world", Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: "world-claim", UID: "claim-uid"}}}}}
	backup := arcade.ExactLocalReference{Name: "cold-backup", UID: "backup-uid"}
	preview := &arcade.GameDestroyPreview{Challenge: "abcdefghijklmnop", ExpiresAt: metav1.NewTime(time.Now().Add(time.Minute)), RestoreGuidance: "SECRET-CANARY"}
	parent := &arcade.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Namespace: "games"}, Spec: arcade.ArcadeOperationSpec{Action: arcade.OperationWorldDestroyPreview}, Status: arcade.ArcadeOperationStatus{Plan: &arcade.OperationPlan{BackupRef: &backup, RepositorySecretRef: &arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "SECRET-CANARY", UID: "secret-canary"}}}, RetainedWorld: &arcade.OperationRetainedWorld{Target: target}, DestroyPreview: preview}}
	got := operationPreviewOutput(parent)
	native := previewOutput(preview, "games", &target, &backup)
	if got == nil || !reflect.DeepEqual(got, native) || got.Target.OriginalServer.UID != "original-uid" || got.Target.Claims[0].ClaimRef.UID != "claim-uid" || got.BackupRef.UID != "backup-uid" {
		t.Fatal("preview lost exact original identity")
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "CANARY") || strings.Contains(string(data), "secret-canary") || strings.Contains(string(data), "repositorySecret") {
		t.Fatal("preview exposed repository identity or raw guidance")
	}
	// Projection is independent of any live same-name server or Secret lookup.
	parent.Status.RetainedWorld.Target.GameServer.UID = "replacement-uid"
	if got.Target.OriginalServer.UID != "original-uid" {
		t.Fatal("projection aliased mutable source")
	}
	parent.Status.Plan.BackupRef = nil
	if operationPreviewOutput(parent) != nil {
		t.Fatal("confirmable preview without exact backup")
	}
}

func TestMalformedDestroyPreviewIsNotConfirmable(t *testing.T) {
	if previewOutput(nil, "games", nil, nil) != nil {
		t.Fatal("missing sources confirmable")
	}
	target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: "world", UID: "uid"}, Game: "factorio", Data: arcade.RetainedDataReference{Identity: "world", Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: "claim", UID: "claim-uid"}}}}}
	backup := arcade.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	preview := &arcade.GameDestroyPreview{Challenge: "abcdefghijklmnop", ExpiresAt: metav1.NewTime(time.Now().Add(time.Minute))}
	target.Data.Claims = append(target.Data.Claims, target.Data.Claims[0])
	if previewOutput(preview, "games", &target, &backup) != nil {
		t.Fatal("duplicate inventory confirmable")
	}
}
