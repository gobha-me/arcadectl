// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestLifecycleDiagnosticClosedBoundedAndFreshAttempt(t *testing.T) {
	if ctx, diagnostic := WithLifecycleDiagnostic(nil); ctx != nil || diagnostic != nil {
		t.Fatal("nil parent became executable")
	}
	var absent *LifecycleDiagnostic
	unknown := absent.Snapshot()
	if strings.Contains(unknown, "CANARY") || len(unknown) > 256 {
		t.Fatal("nil diagnostic escaped fixed output")
	}
	labels := map[Checkpoint]string{Prerequisites: "prerequisites", CRDsAvailable: "crds-available", AdmissionEffective: "admission-effective", ColdSafety: "cold-safety", APIStopped: "api-stopped", RuntimeStopped: "runtime-stopped", ControllersAvailable: "controllers-available", TargetAuthenticated: "target-authenticated", AdmissionConfigured: "admission-configured", RetainedAdmission: "retained-admission", BootstrapAdmission: "bootstrap-admission"}
	for value := range 256 {
		kind := Checkpoint(value)
		label, valid := labels[kind]
		if !valid {
			label = "unknown"
		}
		if lifecycleDiagnosticCheckpoint(kind) != label {
			t.Fatal("checkpoint escaped closed labels")
		}
		for state := range 5 {
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			traceLifecycleCheckpoint(ctx, kind, lifecycleDiagnosticState(state))
			snapshot := diagnostic.Snapshot()
			if !valid || state < 1 || state > 3 {
				if snapshot != unknown {
					t.Fatal("unknown checkpoint/state manufactured progress")
				}
			} else if !strings.Contains(snapshot, "checkpoint="+label+" ") || len(snapshot) > 256 {
				t.Fatal("fixed checkpoint missing or diagnostic unbounded")
			}
		}
	}
	ctx, original := WithLifecycleDiagnostic(t.Context())
	traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
	traceAdmission(ctx, admissionCasePostObservation, 54)
	traceAdmissionPhase(ctx, admissionPhaseGCLeaseCorrelation, -1)
	traceActivation(ctx, activationSelfIdentity)
	traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticRefused)
	if got := original.Snapshot(); !strings.Contains(got, "phase=gc-lease-correlation slot=-1") || !strings.Contains(got, "activation=auth-self-identity") {
		t.Fatal("same-attempt inner progress was lost")
	}
	freshCtx, fresh := WithLifecycleDiagnostic(ctx)
	if fresh.Snapshot() != unknown || original == fresh {
		t.Fatal("prior attempt's diagnostic contaminated a fresh Step")
	}
	traceLifecycleCheckpoint(freshCtx, ColdSafety, lifecycleDiagnosticEntered)
	traceAdmission(freshCtx, admissionCaseProbe, 54)
	traceActivation(freshCtx, activationSelf)
	traceLifecycleCheckpoint(freshCtx, APIStopped, lifecycleDiagnosticEntered)
	if got := fresh.Snapshot(); !strings.Contains(got, "admission=unknown index=-1 phase=unknown slot=-1 activation=unknown") {
		t.Fatal("previous checkpoint's inner progress contaminated current checkpoint")
	}
	for _, corrupt := range []uint32{0, 255, 0xffffffff, uint32(Prerequisites)<<8 | 255, uint32(255)<<8 | 1} {
		fresh.checkpoint.Store(corrupt)
		if fresh.Snapshot() != unknown {
			t.Fatal("corrupt state escaped closed labels")
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	ctx, fresh = WithLifecycleDiagnostic(cancelled)
	if ctx.Err() != context.Canceled || fresh.Snapshot() != unknown {
		t.Fatal("diagnostic changed cancellation")
	}
	traceLifecycleCheckpoint(nil, Prerequisites, lifecycleDiagnosticEntered)
	traceLifecycleCheckpoint(context.WithValue(t.Context(), lifecycleDiagnosticKey{}, "PRIVATE-CANARY"), Prerequisites, lifecycleDiagnosticEntered)
	traceAdmission(ctx, admissionStep(255), 1000000)
	traceAdmissionPhase(ctx, admissionPhaseStep(255), 1000000)
	traceActivation(ctx, activationStep(1000000))
	if got := fresh.Snapshot(); got != unknown || strings.Contains(got, "CANARY") {
		t.Fatal("arbitrary values became output")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 100 {
				traceLifecycleCheckpoint(ctx, Prerequisites, lifecycleDiagnosticEntered)
				traceLifecycleCheckpoint(ctx, Prerequisites, lifecycleDiagnosticRefused)
				if got := fresh.Snapshot(); !strings.Contains(got, "checkpoint=prerequisites ") || len(got) > 256 {
					t.Error("concurrent diagnostic escaped bounds")
				}
			}
		})
	}
	group.Wait()
}

func TestLifecycleDiagnosticActualStepPreservesRefusalAndEffectBoundary(t *testing.T) {
	for _, scenario := range []string{"provider", "later-effect", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			v := newLifecycleFixture(t)
			beforeWrites, beforeJournal := v.f.access.writes+v.private.writes, v.f.nsUpdates
			before := v.f.snapshot.Bytes()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			operationCtx := ctx
			ctx, diagnostic := WithLifecycleDiagnostic(ctx)
			var cancelledBaseline *lifecycleFixture
			var cancelledError error
			cancelledJournalDelta := 0
			if scenario == "provider" {
				v.probe = func(LifecycleCheck) error {
					traceAdmission(ctx, admissionCasePostObservation, 54)
					traceAdmissionPhase(ctx, admissionPhaseGCLeaseCorrelation, -1)
					return errors.New("PRIVATE-PROVIDER-CANARY")
				}
			} else if scenario == "later-effect" {
				// Fail the first public effect's preview AFTER prerequisites
				// pass. Do not falsely label its last successful checkpoint
				// as the refusal that stopped the later inventory/effect.
				v.f.access.dry = func(*unstructured.Unstructured) *unstructured.Unstructured { return nil }
			} else {
				cancel()
				// Fake access can still return local objects for a cancelled
				// context. Compare a separate untraced Step's actual behavior;
				// tracing must preserve it, not invent stronger cancellation.
				cancelledBaseline = newLifecycleFixture(t)
				journal := cancelledBaseline.f.nsUpdates
				_, cancelledError = cancelledBaseline.l.Step(operationCtx, cancelledBaseline.f.snapshot, cancelledBaseline.opts)
				cancelledJournalDelta = cancelledBaseline.f.nsUpdates - journal
			}
			_, err := v.l.Step(ctx, v.f.snapshot, v.opts)
			if err == nil || v.f.access.writes+v.private.writes != beforeWrites || len(v.effects) != 0 {
				t.Fatal("diagnostic retried or altered the failed effect boundary")
			}
			got := diagnostic.Snapshot()
			if len(got) > 256 || strings.Contains(got, "CANARY") || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("private error escaped fixed diagnostic")
			}
			switch scenario {
			case "provider":
				if err != ErrLifecycle || len(v.checks) != 1 || v.f.nsUpdates != beforeJournal || !strings.Contains(got, "checkpoint=prerequisites checkpoint-status=refused") || !strings.Contains(got, "phase=gc-lease-correlation") {
					t.Fatal("same actual checkpoint lost its original refusal")
				}
			case "later-effect":
				if !strings.Contains(got, "checkpoint=prerequisites checkpoint-status=passed") || v.f.nsUpdates-beforeJournal > 1 {
					t.Fatal("later effect failure was falsely attributed to successful checkpoint", got)
				}
			case "cancelled":
				if err != cancelledError || len(v.checks) != len(cancelledBaseline.checks) || v.f.nsUpdates-beforeJournal != cancelledJournalDelta || cancelledBaseline.f.access.writes+cancelledBaseline.private.writes != 0 {
					t.Fatal("diagnostic altered actual untraced cancellation behavior")
				}
			}
			// Caller snapshot remains immutable even if an effect's original
			// durable pending intent was recorded before its failed preview.
			if string(before) != string(v.f.snapshot.Bytes()) {
				t.Fatal("diagnostic changed original caller evidence")
			}
			_, fresh := WithLifecycleDiagnostic(ctx)
			if fresh.Snapshot() != (*LifecycleDiagnostic)(nil).Snapshot() {
				t.Fatal("completed attempt's progress was reused")
			}
		})
	}
	// Checkpoint-only success reports passed, not overall Step completion.
	v := newLifecycleFixture(t)
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	if v.l.checkOperation(ctx, Prerequisites, v.f.snapshot, installstate.Install, v.f.plan.Digest(), v.opts) != nil || !strings.Contains(diagnostic.Snapshot(), "checkpoint-status=passed") {
		t.Fatal("complete original checkpoint did not report successful progress")
	}
}
