// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestLifecycleCostsBoundedCommandAndInvocationIsolation(t *testing.T) {
	t.Run("nested-invocations-and-final-stages", func(t *testing.T) {
		ctx, costs := WithLifecycleCosts(t.Context())
		outer, finishOuter := beginAdmissionCost(ctx)
		traceAdmission(outer, admissionCaseObservation, 0)
		inner, finishInner := beginAdmissionCost(outer)
		traceAdmission(inner, admissionCleanup, 0)
		traceAdmission(inner, admissionRetire, -1)
		traceAdmission(inner, admissionFinalWitness, -1)
		traceAdmission(inner, admissionComplete, -1)
		finishOuter()
		if costs.metrics[costAdmission].calls.Load() != 2 || costs.metrics[costAdmission].returned.Load() != 1 || costs.metrics[costAdmissionMatrix].returned.Load() != 1 || costs.metrics[costAdmissionFinal].returned.Load() != 0 {
			t.Fatal("nested invocation borrowed outer stage ownership")
		}
		finishInner()
		for _, kind := range []lifecycleCostKind{costAdmissionDrain, costAdmissionRetirement, costAdmissionFinal} {
			if costs.metrics[kind].calls.Load() != 1 || costs.metrics[kind].returned.Load() != 1 {
				t.Fatal("nested final stages did not close independently")
			}
		}
		if costs.metrics[costAdmission].returned.Load() != 2 || costs.metrics[costAdmissionConstruction].returned.Load() != 2 {
			t.Fatal("nested command aggregate lost a returned invocation")
		}
	})
	if ctx, costs := WithLifecycleCosts(nil); ctx != nil || costs != nil {
		t.Fatal("nil parent became executable")
	}
	var absent *LifecycleCosts
	zero := absent.Snapshot()
	ctx, costs := WithLifecycleCosts(t.Context())
	if costs.Snapshot() != zero {
		t.Fatal("new command inherited observations")
	}
	beginLifecycleCost(nil, costBaseline)()
	beginLifecycleCost(ctx, costKinds)()
	beginLifecycleCost(context.WithValue(ctx, lifecycleCostKey{}, "PRIVATE-CANARY"), costBaseline)()
	if costs.Snapshot() != zero {
		t.Fatal("invalid metric or recorder created observations")
	}
	first, finish := beginAdmissionCost(ctx)
	traceAdmission(first, admissionSetupObservation, 11)
	traceAdmission(first, admissionSetupPreview, 11)
	traceAdmission(first, admissionSetupSettle, 11)
	traceAdmission(first, admissionStep(255), 255)
	step, _ := WithLifecycleDiagnostic(first)
	traceLifecycleCheckpoint(step, AdmissionEffective, lifecycleDiagnosticEntered)
	traceAdmission(step, admissionCaseObservation, 0)
	beginLifecycleCost(step, costPhase)()
	beginLifecycleCost(step, costBaseline)()
	traceLifecycleCheckpoint(step, ColdSafety, lifecycleDiagnosticEntered)
	if costs.metrics[costAdmissionSetup].calls.Load() != 1 || costs.metrics[costAdmissionMatrix].calls.Load() != 1 || costs.metrics[costPhase].returned.Load() != 1 || costs.metrics[costBaseline].returned.Load() != 1 {
		t.Fatal("checkpoint resets erased totals or same-stage indices reopened spans")
	}
	fresh, next := WithLifecycleCosts(first)
	traceAdmission(fresh, admissionCleanup, 0)
	if next.Snapshot() != zero || costs.metrics[costAdmissionDrain].calls.Load() != 0 {
		t.Fatal("new command continued an inherited invocation")
	}
	second, finishSecond := beginAdmissionCost(fresh)
	traceAdmission(second, admissionCleanup, 0)
	finish() // Old command may close after a new command has begun.
	finish()
	traceAdmission(first, admissionRetire, -1)
	finishSecond()
	if costs.metrics[costAdmission].calls.Load() != 1 || costs.metrics[costAdmission].returned.Load() != 1 || costs.metrics[costAdmissionMatrix].returned.Load() != 1 || costs.metrics[costAdmissionRetirement].calls.Load() != 0 || next.metrics[costAdmissionDrain].returned.Load() != 1 {
		t.Fatal("late or duplicate closure crossed command/invocation ownership")
	}
	for _, snapshot := range []string{zero, costs.Snapshot(), next.Snapshot()} {
		fields := strings.Fields(snapshot)
		if len(snapshot) > 2048 || len(fields) != 3*int(costKinds) || strings.Contains(snapshot, "CANARY") {
			t.Fatal("cost snapshot escaped bounded fixed fields")
		}
		for index, field := range fields {
			parts := strings.SplitN(field, "=", 2)
			suffix := []string{"-calls", "-returned", "-inclusive-wall-ns"}[index%3]
			if len(parts) != 2 || parts[0] != lifecycleCostLabels[index/3]+suffix {
				t.Fatal("dynamic label escaped command snapshot")
			}
			if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
				t.Fatal("non-numeric diagnostic escaped")
			}
		}
	}
}

func TestLifecycleCostsConcurrentRefusalsAndCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancelCause(t.Context())
	privateCause := errors.New("PRIVATE-CANARY")
	cancel(privateCause)
	ctx, costs := WithLifecycleCosts(cancelled)
	if ctx.Err() != context.Canceled || context.Cause(ctx) != privateCause {
		t.Fatal("recorder changed cancellation")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 20 {
				call, finish := beginAdmissionCost(ctx)
				traceAdmission(call, admissionCaseObservation, 54)
				traceAdmission(call, admissionCleanup, 0)
				beginLifecycleCost(call, costPhase)()
				beginLifecycleCost(call, costBaseline)()
				finish()
				finish()
			}
		})
	}
	group.Wait()
	for _, kind := range []lifecycleCostKind{costAdmission, costPhase, costBaseline, costAdmissionConstruction, costAdmissionMatrix, costAdmissionDrain} {
		if costs.metrics[kind].calls.Load() != 160 || costs.metrics[kind].returned.Load() != 160 || costs.metrics[kind].wallNS.Load() == 0 {
			t.Fatal("concurrent refusal lost or duplicated invocation timing")
		}
	}
	var admission *ClusterAdmission
	if admission.VerifyEffective(ctx, LifecycleCheck{}) != ErrInvalid {
		t.Fatal("recorder changed actual invalid admission refusal")
	}
	var baseline *ClusterSecurityBaseline
	if baseline.Verify(ctx, nil) != ErrSecurityBaseline || costs.metrics[costBaseline].calls.Load() != 161 || costs.metrics[costBaseline].returned.Load() != 161 || costs.metrics[costAdmission].calls.Load() != 161 || costs.metrics[costAdmission].returned.Load() != 161 {
		t.Fatal("actual early refusal did not close cost span")
	}
	if strings.Contains(costs.Snapshot(), "CANARY") {
		t.Fatal("cancellation cause escaped")
	}
}
