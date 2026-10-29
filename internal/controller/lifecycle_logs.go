// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/go-logr/logr"
	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const lifecycleLogSchema = "arcadectl.lifecycle-log/v1"

// A dedicated process logger avoids inheriting object names or arbitrary
// per-request values. Correlation is diagnostic only, never mutation authority.
func lifecycleCorrelation(uid types.UID) string {
	if uid == "" {
		return "unknown"
	}
	digest := sha256.Sum256([]byte(uid))
	return hex.EncodeToString(digest[:16])
}

func logOperationStatus(kind, action, before, after string, uid types.UID) {
	emitOperationStatus(logf.Log.WithName("lifecycle"), kind, action, before, after, uid)
}

func emitOperationStatus(logger logr.Logger, kind, action, before, after string, uid types.UID) {
	result := terminalMetricResult(after)
	if result == "" || terminalMetricResult(before) != "" {
		return
	}
	action, known := fixedOperationAction(kind, action)
	if !known {
		return
	}
	logger.Info("Lifecycle operation completed", "schema", lifecycleLogSchema, "event", "operation_completed",
		"kind", kind, "action", action, "result", result, "correlation", lifecycleCorrelation(uid))
}

func logServerStatus(before, after *arcade.GameServer) {
	emitServerStatus(logf.Log.WithName("lifecycle"), before, after)
}

func emitServerStatus(logger logr.Logger, before, after *arcade.GameServer) {
	if before == nil || after == nil || after.Generation <= 0 {
		return
	}
	for _, name := range conditionOrder {
		next := meta.FindStatusCondition(after.Status.Conditions, name)
		if next == nil || next.ObservedGeneration != after.Generation {
			continue
		}
		status := "unknown"
		switch next.Status {
		case metav1.ConditionTrue:
			status = "true"
		case metav1.ConditionFalse:
			status = "false"
		case metav1.ConditionUnknown:
		default:
			continue
		}
		previous := meta.FindStatusCondition(before.Status.Conditions, name)
		if previous != nil && previous.Status == next.Status && previous.Reason == next.Reason {
			continue
		}
		class, reason := conditionMetricClass(next.Reason), "Unknown"
		if class != "unknown" {
			reason = next.Reason // class mapping accepts only exact repository constants
		}
		logger.Info("Server condition changed", "schema", lifecycleLogSchema, "event", "server_condition_changed",
			"condition", name, "status", status, "class", class, "reason", reason,
			"correlation", lifecycleCorrelation(after.UID), "generation", after.Generation)
	}
}
