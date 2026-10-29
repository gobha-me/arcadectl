// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestLifecycleLogCorrelationContract(t *testing.T) {
	const uid = types.UID("123e4567-e89b-12d3-a456-426614174000")
	// Independently calculated compatibility vector for SHA-256/128.
	if got := lifecycleCorrelation(uid); got != "986c0dc956dc822b5d8f698661b9eb1e" {
		t.Fatal("diagnostic correlation schema changed")
	}
	if lifecycleCorrelation("") != "unknown" || lifecycleCorrelation("different-uid") == lifecycleCorrelation(uid) {
		t.Fatal("absent or distinct identities lost their correlation semantics")
	}
}

func TestLifecycleOperationLogsHaveClosedPrivateSafeFields(t *testing.T) {
	var lines []string
	logger := funcr.NewJSON(func(line string) { lines = append(lines, line) }, funcr.Options{})
	emitOperationStatus(logger, "receipt", "SECRET-CANARY-action", "Running", "Failed", "SECRET-CANARY-uid")
	emitOperationStatus(logger, "backup", "SECRET-CANARY-action", "Running", "Cancelled", "backup-uid")
	emitOperationStatus(logger, "SECRET-CANARY-kind", "server.start", "Running", "Succeeded", "private-uid")
	emitOperationStatus(logger, "receipt", "server.start", "Succeeded", "Failed", "private-uid")
	emitOperationStatus(logger, "receipt", "server.start", "Running", "SECRET-CANARY-phase", "private-uid")
	if len(lines) != 2 {
		t.Fatal("nonterminal, repeated-terminal or unknown-kind input emitted an event")
	}
	for index, line := range lines {
		if strings.Contains(line, "SECRET-CANARY") {
			t.Fatal("raw private input entered structured logs")
		}
		var fields map[string]any
		if json.Unmarshal([]byte(line), &fields) != nil || fields["schema"] != lifecycleLogSchema || fields["event"] != "operation_completed" {
			t.Fatal("operation event lost its versioned schema")
		}
		correlation, ok := fields["correlation"].(string)
		if !ok || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(correlation) {
			t.Fatal("raw or unbounded correlation identity was emitted")
		}
		if index == 0 && (fields["kind"] != "receipt" || fields["action"] != "unknown" || fields["result"] != "failed") {
			t.Fatal("untrusted receipt action was not normalized")
		}
		if index == 1 && (fields["kind"] != "backup" || fields["action"] != "world.backup" || fields["result"] != "cancelled") {
			t.Fatal("native boundary or cancellation meaning was lost")
		}
	}
}

func TestLifecycleServerLogsIgnorePrivateAndStaleFields(t *testing.T) {
	var lines []string
	logger := funcr.NewJSON(func(line string) { lines = append(lines, line) }, funcr.Options{})
	before := &arcade.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "SECRET-CANARY-name", Namespace: "SECRET-CANARY-namespace", UID: "SECRET-CANARY-uid", Generation: 2, Annotations: map[string]string{"private": "SECRET-CANARY-annotation"}}}
	after := before.DeepCopy()
	after.Status.Conditions = []metav1.Condition{
		{Type: "StorageReady", Status: metav1.ConditionFalse, Reason: "RetainedDataConflict", Message: "SECRET-CANARY-provider", ObservedGeneration: 2},
		{Type: "Ready", Status: metav1.ConditionFalse, Reason: "ReadySECRET-CANARY-reason", Message: "SECRET-CANARY-message", ObservedGeneration: 2},
		{Type: "SECRET-CANARY-type", Status: metav1.ConditionTrue, Reason: "Ready", ObservedGeneration: 2},
		{Type: "NetworkReady", Status: metav1.ConditionStatus("SECRET-CANARY-status"), Reason: "Ready", ObservedGeneration: 2},
		{Type: "WorkloadReady", Status: metav1.ConditionTrue, Reason: "WorkloadAvailable", ObservedGeneration: 1},
	}
	emitServerStatus(logger, before, after)
	if len(lines) != 2 {
		t.Fatal("invalid or stale condition became a current event")
	}
	for _, line := range lines {
		if strings.Contains(line, "SECRET-CANARY") {
			t.Fatal("private object, condition, annotation or UID text was logged")
		}
		var fields map[string]any
		if json.Unmarshal([]byte(line), &fields) != nil || fields["event"] != "server_condition_changed" || fields["schema"] != lifecycleLogSchema {
			t.Fatal("server event lost its stable schema")
		}
		if fields["condition"] == "Ready" && (fields["reason"] != "Unknown" || fields["class"] != "unknown") {
			t.Fatal("unknown reason escaped the closed vocabulary")
		}
	}
	emitServerStatus(logger, after, after.DeepCopy())
	if len(lines) != 2 {
		t.Fatal("unchanged status recheck emitted events")
	}
}
