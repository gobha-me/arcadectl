// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metric producers accept only fixed vocabularies. Names, UIDs, namespaces,
// adapter IDs, provider errors, messages and credentials are never label values.
// These best-effort process counters are not durable operation/audit evidence.
type lifecycleTelemetry struct {
	operations *prometheus.CounterVec
	duration   *prometheus.HistogramVec
	conditions *prometheus.CounterVec
}

func newLifecycleTelemetry(registry prometheus.Registerer) *lifecycleTelemetry {
	t := &lifecycleTelemetry{
		operations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arcadectl_operation_completions_total",
			Help: "First observed persisted terminal transitions, by fixed operation kind, action and result.",
		}, []string{"kind", "action", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "arcadectl_operation_duration_seconds",
			Help:    "Persisted operation start-to-completion duration; invalid or missing timestamps are omitted.",
			Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600, 21600, 86400},
		}, []string{"kind", "action", "result"}),
		conditions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arcadectl_server_condition_transitions_total",
			Help: "Persisted server condition status/reason changes, grouped into fixed diagnostic classes.",
		}, []string{"condition", "status", "class"}),
	}
	registry.MustRegister(t.operations, t.duration, t.conditions)
	return t
}

var defaultLifecycleTelemetry = newLifecycleTelemetry(metrics.Registry)

func terminalMetricResult(phase string) string {
	switch phase {
	case "Succeeded":
		return "succeeded"
	case "Failed":
		return "failed"
	case "Cancelled":
		return "cancelled"
	default:
		return ""
	}
}

func metricAction(input string) string {
	switch arcade.ArcadeOperationAction(input) {
	case arcade.OperationServerCreate, arcade.OperationServerConfigure, arcade.OperationServerStart,
		arcade.OperationServerStop, arcade.OperationServerRestart, arcade.OperationServerUpdate,
		arcade.OperationServerDecommission, arcade.OperationWorldBackup, arcade.OperationWorldRestore,
		arcade.OperationWorldDestroyPreview, arcade.OperationWorldDestroyConfirm, arcade.OperationWorldDestroyCancel:
		return input
	default:
		return "unknown"
	}
}

func fixedOperationAction(kind, action string) (string, bool) {
	switch kind {
	case "receipt":
		return metricAction(action), true
	case "backup":
		return "world.backup", true
	case "restore":
		return "world.restore", true
	case "destroy":
		return "world.destroy.confirm", true
	default:
		return "", false
	}
}

func (t *lifecycleTelemetry) observeOperation(kind, action, before, after string, start, end *metav1.Time) {
	result := terminalMetricResult(after)
	if result == "" || terminalMetricResult(before) != "" {
		return
	}
	action, known := fixedOperationAction(kind, action)
	if !known {
		return
	}
	if t == nil {
		t = defaultLifecycleTelemetry
	}
	t.operations.WithLabelValues(kind, action, result).Inc()
	if start != nil && end != nil && !start.IsZero() && !end.IsZero() && !end.Before(start) {
		t.duration.WithLabelValues(kind, action, result).Observe(end.Sub(start.Time).Seconds())
	}
}

func conditionMetricClass(reason string) string {
	switch reason {
	case arcade.ReasonInvalidSpec:
		return "validation"
	case arcade.ReasonControllerMisconfigured, arcade.ReasonReconcileFailed:
		return "dependency"
	case arcade.ReasonClaimsProvisioning, arcade.ReasonClaimExpansionPending, arcade.ReasonStorageOperationFailed, arcade.ReasonStoragePending:
		return "storage"
	case arcade.ReasonRetainedDataReferenceRequired, arcade.ReasonRetainedDataMissing, arcade.ReasonRetainedDataConflict:
		return "retained-data"
	case arcade.ReasonWorkloadProgressing, arcade.ReasonWorkloadUnavailable, arcade.ReasonWorkloadOperationFailed, arcade.ReasonWorkloadPending:
		return "workload"
	case arcade.ReasonPlayerEndpointPending, arcade.ReasonNetworkOperationFailed:
		return "network"
	case arcade.ReasonResourceCollision:
		return "collision"
	case arcade.ReasonBlocked, arcade.ReasonRuntimeStopping, arcade.ReasonDataOperationActive:
		return "progress"
	case arcade.ReasonValid, arcade.ReasonClaimsReady, arcade.ReasonConfigurationReady, arcade.ReasonWorkloadAvailable, arcade.ReasonPlayerEndpointReady, arcade.ReasonRuntimeStopped, arcade.ReasonReady:
		return "healthy"
	case arcade.ReasonConfigurationOperationFailed:
		return "configuration"
	default:
		return "unknown"
	}
}

func (t *lifecycleTelemetry) observeServer(before, after *arcade.GameServer) {
	if t == nil {
		t = defaultLifecycleTelemetry
	}
	// Iterate the six canonical types, never arbitrary condition.Type input.
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
		t.conditions.WithLabelValues(name, status, conditionMetricClass(next.Reason)).Inc()
	}
}
