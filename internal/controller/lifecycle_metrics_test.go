// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type telemetrySample struct {
	labels map[string]string
	count  float64
	sum    float64
}

func telemetrySamples(t *testing.T, registry *prometheus.Registry, family string) []telemetrySample {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var result []telemetrySample
	for _, item := range families {
		if strings.Contains(item.String(), "SECRET-CANARY") {
			t.Fatal("private input became a telemetry label")
		}
		if item.GetName() != family {
			continue
		}
		for _, metric := range item.Metric {
			sample := telemetrySample{labels: map[string]string{}}
			for _, label := range metric.Label {
				sample.labels[label.GetName()] = label.GetValue()
			}
			if metric.Counter != nil {
				sample.count = metric.GetCounter().GetValue()
			} else if metric.Histogram != nil {
				sample.count = float64(metric.GetHistogram().GetSampleCount())
				sample.sum = metric.GetHistogram().GetSampleSum()
			}
			result = append(result, sample)
		}
	}
	return result
}

func TestLifecycleMetricVocabulariesAndTerminalBoundaries(t *testing.T) {
	registry := prometheus.NewRegistry()
	telemetry := newLifecycleTelemetry(registry)
	start, end := metav1.NewTime(time.Unix(1000, 0)), metav1.NewTime(time.Unix(1005, 0))
	for i := 0; i < 1000; i++ {
		telemetry.observeOperation("receipt", fmt.Sprintf("SECRET-CANARY-%d", i), "Running", "Succeeded", &start, &end)
	}
	// Repeat terminal observations and unknown phases/kinds must not count.
	telemetry.observeOperation("receipt", "server.start", "Succeeded", "Failed", &start, &end)
	telemetry.observeOperation("receipt", "server.start", "Running", "SECRET-CANARY", &start, &end)
	telemetry.observeOperation("SECRET-CANARY", "server.start", "Running", "Failed", &start, &end)
	for _, kind := range []string{"backup", "restore", "destroy"} {
		telemetry.observeOperation(kind, "SECRET-CANARY", "Running", "Failed", &start, &end)
	}
	samples := telemetrySamples(t, registry, "arcadectl_operation_completions_total")
	if len(samples) != 4 {
		t.Fatal("unbounded inputs increased label cardinality")
	}
	for _, sample := range samples {
		if len(sample.labels) != 3 {
			t.Fatal("object identity or another unexpected label was introduced")
		}
		if sample.labels["kind"] == "receipt" && (sample.labels["action"] != "unknown" || sample.labels["result"] != "succeeded" || sample.count != 1000) {
			t.Fatal("unknown actions were not folded into one fixed series")
		}
	}
	for _, sample := range telemetrySamples(t, registry, "arcadectl_operation_duration_seconds") {
		if sample.sum != 5*sample.count {
			t.Fatal("persisted duration boundary drifted")
		}
	}
}

func TestLifecycleMetricInvalidTimesKeepResultsWithoutDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	telemetry := newLifecycleTelemetry(registry)
	start, end, zero := metav1.NewTime(time.Unix(1000, 0)), metav1.NewTime(time.Unix(999, 0)), metav1.Time{}
	for _, pair := range [][2]*metav1.Time{{nil, nil}, {&zero, &end}, {&start, &end}, {&start, nil}} {
		telemetry.observeOperation("receipt", "server.stop", "Running", "Cancelled", pair[0], pair[1])
	}
	counts := telemetrySamples(t, registry, "arcadectl_operation_completions_total")
	if len(counts) != 1 || counts[0].count != 4 || len(telemetrySamples(t, registry, "arcadectl_operation_duration_seconds")) != 0 {
		t.Fatal("invalid timing became a sample or erased the real terminal result")
	}
}

func failMetricStatusWrite(ctx context.Context, c client.Client, subresource string, object client.Object, options ...client.SubResourceUpdateOption) error {
	return errors.New("SECRET-CANARY private API error")
}

func TestReceiptMetricRequiresSuccessfulStatusWriteAndDoesNotRecount(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			r, receipt, _ := newOperationTest(t, arcade.OperationServerStart)
			registry := prometheus.NewRegistry()
			r.telemetry = newLifecycleTelemetry(registry)
			now := metav1.NewTime(time.Unix(2000, 0))
			r.Now = func() metav1.Time { return now }
			start := metav1.NewTime(now.Add(-5 * time.Second))
			receipt.Status.Phase, receipt.Status.StartedAt = arcade.OperationPhasePlanning, &start
			if err := r.Status().Update(context.Background(), receipt); err != nil {
				t.Fatal(err)
			}
			if fail {
				r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{SubResourceUpdate: failMetricStatusWrite})
			}
			err := r.operationStatus(context.Background(), receipt, arcade.OperationPhaseSucceeded, nil)
			if fail {
				if err == nil || strings.Contains(err.Error(), "SECRET-CANARY") || len(telemetrySamples(t, registry, "arcadectl_operation_completions_total")) != 0 {
					t.Fatal("failed private write became a successful metric or leaked error text")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			counts := telemetrySamples(t, registry, "arcadectl_operation_completions_total")
			if len(counts) != 1 || counts[0].count != 1 {
				t.Fatal("persisted terminal transition was not counted once")
			}
			if err := r.Get(context.Background(), client.ObjectKeyFromObject(receipt), receipt); err != nil {
				t.Fatal(err)
			}
			if err := r.operationStatus(context.Background(), receipt, arcade.OperationPhaseSucceeded, nil); err != nil {
				t.Fatal(err)
			}
			if samples := telemetrySamples(t, registry, "arcadectl_operation_completions_total"); len(samples) != 1 || samples[0].count != 1 {
				t.Fatal("terminal recheck was counted again")
			}
		})
	}
}

func TestServerConditionMetricIsCurrentClosedAndPersistenceBound(t *testing.T) {
	server := controllerTestServer(arcade.DesiredStateStopped)
	server.Name = "SECRET-CANARY"
	r, kube := newTestReconciler(t, server)
	registry := prometheus.NewRegistry()
	r.telemetry = newLifecycleTelemetry(registry)
	progress := newConditionProgress()
	progress.set(arcade.ConditionStorageReady, metav1.ConditionFalse, arcade.ReasonResourceCollision, "SECRET-CANARY provider message")
	if err := r.updateStatus(context.Background(), server, arcade.PhaseFailed, progress, nil); err != nil {
		t.Fatal(err)
	}
	before := telemetrySamples(t, registry, "arcadectl_server_condition_transitions_total")
	if len(before) != 6 {
		t.Fatal("canonical condition transitions missing")
	}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(server), server); err != nil {
		t.Fatal(err)
	}
	if err := r.updateStatus(context.Background(), server, arcade.PhaseFailed, progress, nil); err != nil {
		t.Fatal(err)
	}
	for _, sample := range telemetrySamples(t, registry, "arcadectl_server_condition_transitions_total") {
		if sample.count != 1 || len(sample.labels) != 3 {
			t.Fatal("unchanged status or object identifiers changed metric schema")
		}
	}
	r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{SubResourceUpdate: failMetricStatusWrite})
	progress.set(arcade.ConditionStorageReady, metav1.ConditionFalse, arcade.ReasonStorageOperationFailed, "SECRET-CANARY")
	if err := r.updateStatus(context.Background(), server, arcade.PhaseFailed, progress, nil); err == nil {
		t.Fatal("failed write was accepted")
	}
	if after := telemetrySamples(t, registry, "arcadectl_server_condition_transitions_total"); len(after) != len(before) {
		t.Fatal("failed status persistence emitted a transition")
	}
	// Exercise the producer's boundary independently of the canonical writer.
	changed := server.DeepCopy()
	changed.Status.Conditions = []metav1.Condition{
		{Type: "SECRET-CANARY", Status: metav1.ConditionTrue, Reason: "Ready", ObservedGeneration: changed.Generation},
		{Type: "Ready", Status: metav1.ConditionStatus("SECRET-CANARY"), Reason: "Ready", ObservedGeneration: changed.Generation},
		{Type: "StorageReady", Status: metav1.ConditionFalse, Reason: "SECRET-CANARY", ObservedGeneration: changed.Generation - 1},
	}
	r.telemetry.observeServer(server, changed)
	if after := telemetrySamples(t, registry, "arcadectl_server_condition_transitions_total"); len(after) != len(before) {
		t.Fatal("untrusted or stale condition became a current metric")
	}
}
