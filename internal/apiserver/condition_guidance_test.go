// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"encoding/json"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServerConditionGuidancePreservesCodesWithoutRawText(t *testing.T) {
	server := &arcadev1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: "arcadectl-system", UID: "server-uid", Generation: 3, Annotations: map[string]string{"private": "SECRET-CANARY annotation"}},
		Status: arcadev1.GameServerStatus{Conditions: []metav1.Condition{
			{Type: "StorageReady", Status: metav1.ConditionFalse, Reason: "RetainedDataConflict", Message: "SECRET-CANARY storage provider", ObservedGeneration: 2},
			{Type: "NetworkReady", Status: metav1.ConditionFalse, Reason: "PlayerEndpointPending", Message: "SECRET-CANARY endpoint", ObservedGeneration: 3},
			{Type: "Ready", Status: metav1.ConditionFalse, Reason: "SECRET-CANARY reason", Message: "SECRET-CANARY message", ObservedGeneration: 3},
			{Type: "SECRET-CANARY type", Status: metav1.ConditionFalse, Reason: "Ready", ObservedGeneration: 3},
		}},
	}
	boundary, store, _, audit := operationFixture(t, server)
	response := operationHTTP(boundary, "GET", "/v1/servers/factory", "", "", "")
	if response.Code != 200 || strings.Contains(response.Body.String()+audit.String(), "SECRET-CANARY") {
		t.Fatal("condition read failed or disclosed private input")
	}
	var output adminv1.Server
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Conditions) != 3 || output.Conditions[0].Reason != "RetainedDataConflict" || output.Conditions[1].Reason != "PlayerEndpointPending" || output.Conditions[2].Reason != "Unknown" {
		t.Fatal("actionable reasons lost or untrusted reason admitted")
	}
	if output.Conditions[0].ObservedGeneration != 2 || output.Generation != 3 {
		t.Fatal("stale evidence was relabeled current")
	}
	if _, _, creates := store.counts(); creates != 0 {
		t.Fatal("diagnostic read created a receipt")
	}
}
