// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clienttest "k8s.io/client-go/testing"
)

func TestLifecycleBoundaryDiagnosticClosedFreshAndConcurrent(t *testing.T) {
	var absent *LifecycleDiagnostic
	unknown := "operation=unknown baseline=unknown"
	if absent.BoundarySnapshot() != unknown {
		t.Fatal("nil boundary diagnostic became evidence")
	}
	operations := map[operationBoundary]string{
		boundaryRetainedOpening: "retained-opening", boundaryRetainedRead: "retained-read", boundaryRetainedClosing: "retained-closing", boundaryRetainedComplete: "retained-complete",
		boundaryApplyOpening: "apply-opening", boundaryApplyCandidate: "apply-candidate", boundaryApplyPreview: "apply-preview", boundaryApplyPreviewResult: "apply-preview-result", boundaryApplyAfterPreview: "apply-after-preview",
		boundaryApplyIntent: "apply-intent", boundaryApplyReceipt: "apply-receipt", boundaryApplyEffectOpening: "apply-effect-opening", boundaryApplyEffectRequest: "apply-effect-request", boundaryApplyEffectResult: "apply-effect-result",
		boundaryRecoveryOpening: "recovery-opening", boundaryRecoveryRead: "recovery-read", boundaryRecoveryReceipt: "recovery-receipt", boundaryRecoverySettlement: "recovery-settlement", boundaryRecoveryComplete: "recovery-complete",
		boundaryDeleteOpening: "delete-opening", boundaryDeleteIntent: "delete-intent", boundaryDeleteEffectOpening: "delete-effect-opening", boundaryDeleteEffectRequest: "delete-effect-request", boundaryDeleteEffectResult: "delete-effect-result", boundaryDeleteACKWait: "delete-ack-wait", boundaryDeleteACKClose: "delete-ack-close",
	}
	baselines := map[baselineBoundary]string{baselineBoundaryScope: "scope", baselineBoundarySource: "source", baselineBoundaryActors: "actors", baselineBoundaryExecutables: "executables", baselineBoundaryMetadata: "metadata", baselineBoundaryParents: "parents", baselineBoundaryFamily: "family", baselineBoundaryActorClose: "actor-close", baselineBoundaryDeniedOpening: "denied-opening", baselineBoundaryProducerBefore: "producer-before", baselineBoundaryProducerWire: "producer-wire", baselineBoundaryProducerResult: "producer-result", baselineBoundaryProducerAfter: "producer-after", baselineBoundaryProducerNegative: "producer-negative", baselineBoundaryIdentity: "identity-probe", baselineBoundaryParentProbe: "parent-probe", baselineBoundaryPodProbe: "pod-probe", baselineBoundaryClosing: "closing", baselineBoundarySourceClose: "source-close", baselineBoundaryRetired: "retired", baselineBoundaryComplete: "complete"}
	for boundary, label := range map[baselineBoundary]string{
		baselineBoundaryDeniedActorsOpening: "denied-actors-opening", baselineBoundaryDeniedCatalog: "denied-catalog", baselineBoundaryDeniedRulesOpening: "denied-rules-opening", baselineBoundaryDeniedClients: "denied-clients", baselineBoundaryDeniedReviews: "denied-reviews", baselineBoundaryDeniedExecutablesClosing: "denied-executables-closing", baselineBoundaryDeniedExecutablesStable: "denied-executables-stable", baselineBoundaryDeniedOriginalsClosing: "denied-originals-closing", baselineBoundaryDeniedActorsClosing: "denied-actors-closing", baselineBoundaryDeniedRulesClosing: "denied-rules-closing", baselineBoundaryDeniedActorsFinal: "denied-actors-final", baselineBoundaryClosingMetadata: "closing-metadata", baselineBoundaryClosingParents: "closing-parents", baselineBoundaryClosingFamily: "closing-family", baselineBoundaryRuntimeDeadline: "runtime-deadline",
	} {
		baselines[boundary] = label
	}
	for value := range 256 {
		ctx, d := WithLifecycleDiagnostic(t.Context())
		operation, validOperation := operations[operationBoundary(value)]
		if !validOperation {
			operation = "unknown"
		}
		baseline, validBaseline := baselines[baselineBoundary(value)]
		if !validBaseline {
			baseline = "unknown"
		}
		if operationBoundary(value).label() != operation || baselineBoundary(value).label() != baseline {
			t.Fatal("boundary label escaped independent closed catalog")
		}
		traceOperationBoundary(ctx, operationBoundary(value))
		traceBaselineBoundary(ctx, baselineBoundary(value))
		if d.BoundarySnapshot() != "operation="+operation+" baseline="+baseline || len(d.BoundarySnapshot()) > 96 {
			t.Fatal("diagnostic accepted unbounded or unknown numeric state")
		}
	}
	ctx, d := WithLifecycleDiagnostic(t.Context())
	traceOperationBoundary(ctx, boundaryRetainedOpening)
	traceBaselineBoundary(ctx, baselineBoundaryProducerResult)
	if d.BoundarySnapshot() != "operation=retained-opening baseline=producer-result" {
		t.Fatal("nested proof lost outer operation")
	}
	traceOperationBoundary(ctx, boundaryApplyOpening)
	if d.BoundarySnapshot() != "operation=apply-opening baseline=unknown" {
		t.Fatal("new operation retained prior baseline progress")
	}
	freshCtx, fresh := WithLifecycleDiagnostic(ctx)
	if fresh == d || fresh.BoundarySnapshot() != unknown {
		t.Fatal("fresh attempt retained previous boundary")
	}
	traceOperationBoundary(freshCtx, boundaryRetainedClosing)
	traceBaselineBoundary(freshCtx, baselineBoundaryActors)
	traceLifecycleCheckpoint(freshCtx, TargetAuthenticated, lifecycleDiagnosticEntered)
	if fresh.BoundarySnapshot() != unknown {
		t.Fatal("new checkpoint retained prior boundary")
	}
	for _, value := range []uint32{256, 0xffffffff} {
		fresh.operationBoundary.Store(value)
		fresh.baselineBoundary.Store(value)
		if fresh.BoundarySnapshot() != unknown {
			t.Fatal("corrupted recorder wrapped into valid progress")
		}
	}
	traceBaselineBoundary(nil, baselineBoundaryActors)
	traceOperationBoundary(context.WithValue(t.Context(), lifecycleDiagnosticKey{}, "PRIVATE-CANARY"), boundaryRetainedRead)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 100 {
				traceOperationBoundary(ctx, boundaryRetainedOpening)
				traceBaselineBoundary(ctx, baselineBoundaryActors)
				if snapshot := d.BoundarySnapshot(); len(snapshot) > 96 || strings.Contains(snapshot, "CANARY") {
					t.Error("concurrent boundary escaped fixed bounded output")
				}
			}
		})
	}
	group.Wait()
}

func TestLifecycleBoundaryDiagnosticActualRefusalsPreserveEffects(t *testing.T) {
	x := newServingFixture(t)
	x.secrets.objects["arcadectl-admin-credential"].UID = "foreign-secret"
	ctx, d := WithLifecycleDiagnostic(t.Context())
	before := x.f.snapshot.Bytes()
	writes, updates, privateWrites := x.f.access.writes, x.f.nsUpdates, x.secrets.writes
	workflow, err := NewSecretWorkflow(x.f.engine, x.secrets)
	if err != nil || workflow.VerifyRetained(ctx, x.f.snapshot, x.options.CAFile, time.Now()) != ErrOwnership || d.BoundarySnapshot() != "operation=retained-read baseline=unknown" {
		t.Fatal("actual original Secret refusal lost its exact boundary")
	}
	if string(before) != string(x.f.snapshot.Bytes()) || x.f.access.writes != writes || x.f.nsUpdates != updates || x.secrets.writes != privateWrites {
		t.Fatal("diagnostic changed an original Secret refusal")
	}
	f := newFixture(t, false)
	f.access.dry = func(*unstructured.Unstructured) *unstructured.Unstructured { return nil }
	ctx, d = WithLifecycleDiagnostic(t.Context())
	writes, updates = f.access.writes, f.nsUpdates
	if snapshot, err := f.engine.Apply(ctx, f.snapshot, f.key, f.plan.Digest(), false); snapshot != nil || err != ErrRead || d.BoundarySnapshot() != "operation=apply-preview-result baseline=unknown" {
		t.Fatal("actual failed preview lost its refusal or diagnostic boundary")
	}
	if f.access.writes != writes || f.nsUpdates != updates || f.snapshot.Document().Pending != nil {
		t.Fatal("preview diagnostic persisted or retried an effect")
	}
}

func TestLifecycleDeadlineDiagnosticKeepsFixedPreExpirationProgress(t *testing.T) {
	var absent *LifecycleDiagnostic
	if absent.DeadlineSnapshot() != "" {
		t.Fatal("absent recorder manufactured a deadline")
	}
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	for _, boundary := range []baselineBoundary{baselineBoundaryDeniedReviews, baselineBoundaryProducerNegative, baselineBoundaryIdentity} {
		traceOperationBoundary(ctx, boundaryDeleteOpening)
		traceBaselineBoundary(ctx, boundary)
		if diagnostic.DeadlineSnapshot() != "" {
			t.Fatal("progress alone became an observed deadline")
		}
		traceBaselineBoundary(ctx, baselineBoundaryRuntimeDeadline)
		traceBaselineBoundary(ctx, baselineBoundaryRuntimeDeadline)
		if diagnostic.BoundarySnapshot() != "operation=delete-opening baseline=runtime-deadline" || diagnostic.DeadlineSnapshot() != "baseline-before-deadline="+boundary.label() {
			t.Fatal("deadline overwrote prior progress or changed existing output")
		}
		traceBaselineBoundary(ctx, baselineBoundaryScope)
		if diagnostic.DeadlineSnapshot() != "" || diagnostic.baselineBeforeDeadline.Load() != 0 {
			t.Fatal("a new proof retained an earlier deadline")
		}
	}
	for _, value := range []uint32{0, 255, 256, 0xffffffff, uint32(baselineBoundaryRuntimeDeadline)} {
		diagnostic.baselineBoundary.Store(uint32(baselineBoundaryRuntimeDeadline))
		diagnostic.baselineBeforeDeadline.Store(value)
		if diagnostic.DeadlineSnapshot() != "baseline-before-deadline=unknown" {
			t.Fatal("unknown or corrupted enum escaped the fixed deadline catalog")
		}
	}
	traceOperationBoundary(ctx, boundaryDeleteEffectOpening)
	if diagnostic.DeadlineSnapshot() != "" || diagnostic.baselineBeforeDeadline.Load() != 0 {
		t.Fatal("new operation retained an earlier deadline")
	}
	traceBaselineBoundary(ctx, baselineBoundaryDeniedReviews)
	traceBaselineBoundary(ctx, baselineBoundaryRuntimeDeadline)
	traceLifecycleCheckpoint(ctx, APIStopped, lifecycleDiagnosticEntered)
	if diagnostic.DeadlineSnapshot() != "" || diagnostic.baselineBeforeDeadline.Load() != 0 {
		t.Fatal("new checkpoint retained an earlier deadline")
	}
}

func TestLifecycleBoundaryDiagnosticDistinguishesActualDeleteGuards(t *testing.T) {
	for _, boundary := range []string{"delete-opening", "delete-effect-opening", "delete-ack-wait", "delete-ack-close"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t, true)
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			before := string(f.snapshot.Bytes())
			injected := false
			f.access.client.PrependReactor("get", "namespaces", func(clienttest.Action) (bool, runtime.Object, error) {
				if diagnostic.BoundarySnapshot() == "operation="+boundary+" baseline=unknown" {
					injected = true
					return true, nil, errors.New("PRIVATE-CANARY")
				}
				return false, nil, nil
			})
			// Keep the acknowledged original present so the second observation
			// fence is reached. Only the test's read refusal stops that wait.
			f.access.write = func(action installstate.Action, key installstate.Key, object *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				if action != installstate.Delete || key != f.key || object != nil {
					t.Fatal("DELETE diagnostic changed its original effect")
				}
				return nil, nil
			}
			snapshot, err := f.engine.delete(ctx, f.snapshot, f.key, true)
			wantWrites, wantCAS := 1, 1
			if boundary == "delete-opening" {
				wantWrites, wantCAS = 0, 0
			} else if boundary == "delete-effect-opening" {
				wantWrites = 0
			}
			if err == nil || !injected || f.access.writes != wantWrites || f.nsUpdates != wantCAS || diagnostic.BoundarySnapshot() != "operation="+boundary+" baseline=unknown" || diagnostic.DeadlineSnapshot() != "" || string(f.snapshot.Bytes()) != before {
				t.Fatal("actual DELETE guard lost its stage or changed effects/intent")
			}
			if boundary == "delete-opening" {
				if snapshot != nil {
					t.Fatal("opening refusal manufactured an intent")
				}
			} else if snapshot == nil || snapshot.Document().Pending == nil || snapshot.Document().Pending.Action != installstate.Delete || snapshot.Document().Revision != f.snapshot.Document().Revision+1 {
				t.Fatal("refused DELETE guard lost its committed original intent")
			}
		})
	}
}

func TestLifecycleBoundaryDiagnosticActualWholeProofRefusal(t *testing.T) {
	testBaselineBehaviorWholeProviderWithProtocol(t, "bad-positive", func(engine *Engine, snapshot *installstate.Snapshot, baseline *ClusterSecurityBaseline, _ func() int) error {
		ctx, d := WithLifecycleDiagnostic(t.Context())
		workflow, err := NewSecretWorkflow(engine, baseline.access.PrivateSecrets())
		if err != nil {
			t.Fatal("actual retained Secret provider unavailable")
		}
		// The opening guard must refuse BEFORE any private Secret/CA read.
		err = workflow.VerifyRetained(ctx, snapshot, "/missing-native-ca.pem", time.Now())
		if err != ErrSecurityBaseline || d.BoundarySnapshot() != "operation=retained-opening baseline=producer-result" {
			t.Fatal("actual whole provider refusal was attributed to the wrong closed boundary")
		}
		return err // Shared fixture independently requires its fault was reached.
	})
}

func TestLifecycleBoundaryDiagnosticIntentEffectAndSettlement(t *testing.T) {
	for _, which := range []string{"success", "intent_failure", "malformed_ack", "settlement_failure"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t, false)
			switch which {
			case "intent_failure":
				f.nsUpdate = func(*corev1.Namespace) error { return errors.New("PRIVATE-CANARY") }
			case "malformed_ack":
				f.access.write = func(action installstate.Action, key installstate.Key, candidate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
					if action != installstate.Create || key != f.key {
						t.Fatal("unexpected real effect")
					}
					ack := candidate.DeepCopy()
					ack.SetUID("original-ack")
					ack.SetResourceVersion("25")
					ack.SetAnnotations(map[string]string{})
					return ack, nil
				}
			case "settlement_failure":
				f.nsUpdate = func(*corev1.Namespace) error {
					if f.nsUpdates == 2 {
						return errors.New("PRIVATE-CANARY")
					}
					return nil
				}
			}
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			snapshot, err := f.engine.Apply(ctx, f.snapshot, f.key, f.plan.Digest(), false)
			want := "operation=recovery-complete baseline=unknown"
			switch which {
			case "success":
				if err != nil || snapshot == nil || snapshot.Document().Pending != nil || f.access.writes != 1 || f.nsUpdates != 2 {
					t.Fatal("diagnostic changed successful single-effect settlement", err)
				}
			case "intent_failure":
				want = "operation=apply-intent baseline=unknown"
				if err == nil || snapshot != nil || f.access.writes != 0 || f.nsUpdates != 1 {
					t.Fatal("diagnostic changed unconfirmed-intent refusal")
				}
			case "malformed_ack":
				want = "operation=apply-effect-result baseline=unknown"
				if err != ErrOutcomeUnknown || snapshot == nil || snapshot.Document().Pending == nil || f.access.writes != 1 || f.nsUpdates != 1 {
					t.Fatal("diagnostic accepted malformed ACK or retried effect", err)
				}
				uid, loadErr := f.engine.loadCreateUID(snapshot.Document())
				if loadErr != nil || uid != "original-ack" {
					t.Fatal("diagnostic changed ACK identity persistence")
				}
			case "settlement_failure":
				want = "operation=recovery-settlement baseline=unknown"
				if err != ErrOutcomeUnknown || snapshot == nil || snapshot.Document().Pending == nil || f.access.writes != 1 || f.nsUpdates != 2 {
					t.Fatal("diagnostic changed uncertain settlement", err)
				}
			}
			if diagnostic.BoundarySnapshot() != want || strings.Contains(diagnostic.BoundarySnapshot(), "CANARY") || f.access.dryRuns != 1 {
				t.Fatal("same-attempt boundary was wrong, leaked a provider error, or repeated preview")
			}
			if which == "settlement_failure" {
				ctx, diagnostic = WithLifecycleDiagnostic(t.Context())
				snapshot, err = f.engine.Recover(ctx, snapshot)
				if err != nil || snapshot == nil || snapshot.Document().Pending != nil || diagnostic.BoundarySnapshot() != "operation=recovery-complete baseline=unknown" || f.access.writes != 1 || f.access.dryRuns != 1 || f.nsUpdates != 3 {
					t.Fatal("diagnostic changed observation-only recovery", err)
				}
			}
		})
	}
}
