// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAcknowledgedDeleteDiagnosticClosedFreshAndConcurrent(t *testing.T) {
	t.Run("completed-observation", testAcknowledgedDeleteCompletedObservation)
	steps := map[acknowledgedDeleteStep]string{
		ackOriginalOpening: "original-opening", ackTargetRead: "target-read", ackOriginalClosing: "original-closing",
		ackTargetOriginalCheck: "target-original-check", ackDraining: "draining", ackExecutableCollection: "executable-collection",
		ackExecutableClosing: "executable-closing", ackTargetAbsentCheck: "target-absent-check", ackQuietness: "quietness", ackFullGuardOpening: "full-guard-opening",
		ackRetiredAdmissionCheck: "retired-admission-check", ackPostGuardTargetRead: "post-guard-target-read",
	}
	statuses := map[acknowledgedDeleteStatus]string{ackActive: "active", ackRefused: "refused", ackCancelled: "cancelled", ackDeadline: "deadline"}
	var absent *LifecycleDiagnostic
	if absent.AcknowledgedDeleteSnapshot() != "" {
		t.Fatal("absent recorder invented ACK preparation")
	}
	for value := range 256 {
		step, known := steps[acknowledgedDeleteStep(value)]
		if !known {
			step = "unknown"
		}
		status, known := statuses[acknowledgedDeleteStatus(value)]
		if !known {
			status = "unknown"
		}
		if acknowledgedDeleteStep(value).label() != step || acknowledgedDeleteStatus(value).label() != status {
			t.Fatal("numeric state escaped literal closed catalogs")
		}
		ctx, d := WithLifecycleDiagnostic(t.Context())
		traceAcknowledgedDeleteStep(ctx, acknowledgedDeleteStep(value))
		want := "step=" + step + " status=active"
		if step == "unknown" {
			want = ""
		}
		if d.AcknowledgedDeleteSnapshot() != want {
			t.Fatal("unknown stage manufactured a progress record")
		}
		d.ackPreparation.Store(uint32(ackTargetRead)<<8 | uint32(value))
		if d.AcknowledgedDeleteSnapshot() != "step=target-read status="+status {
			t.Fatal("unknown status escaped closed output")
		}
	}
	for _, row := range []struct {
		name   string
		ctx    func(context.Context) (context.Context, context.CancelFunc)
		err    error
		status string
	}{
		{"active-refusal", context.WithCancel, errors.New("PRIVATE-PROVIDER-CANARY"), "refused"},
		{"parent-cancelled", func(ctx context.Context) (context.Context, context.CancelFunc) {
			child, cancel := context.WithCancelCause(ctx)
			cancel(errors.New("PRIVATE-CANCELLATION-CANARY"))
			return child, func() { cancel(nil) }
		}, errors.New("PRIVATE-PROVIDER-CANARY"), "cancelled"},
		{"parent-deadline", func(ctx context.Context) (context.Context, context.CancelFunc) {
			return context.WithDeadline(ctx, time.Time{})
		}, nil, "deadline"},
		{"poll-deadline-parent-active", context.WithCancel, context.DeadlineExceeded, "deadline"},
		{"poll-cancelled-parent-active", context.WithCancel, context.Canceled, "cancelled"},
	} {
		t.Run(row.name, func(t *testing.T) {
			parent, cancel := row.ctx(t.Context())
			defer cancel()
			ctx, d := WithLifecycleDiagnostic(parent)
			traceAcknowledgedDeleteStep(ctx, ackQuietness)
			traceAcknowledgedDeleteRefusal(ctx, row.err)
			want := "step=quietness status=" + row.status
			if d.AcknowledgedDeleteSnapshot() != want || strings.Contains(d.AcknowledgedDeleteSnapshot(), "PRIVATE") {
				t.Fatal("diagnostic leaked error/cause or conflated caller and poll outcome")
			}
			freshCtx, fresh := WithLifecycleDiagnostic(ctx)
			if fresh == d || fresh.AcknowledgedDeleteSnapshot() != "" {
				t.Fatal("new attempt retained old evidence")
			}
			traceAcknowledgedDeleteStep(freshCtx, ackOriginalOpening)
			traceLifecycleCheckpoint(freshCtx, ColdSafety, lifecycleDiagnosticEntered)
			if fresh.AcknowledgedDeleteSnapshot() != "" {
				t.Fatal("new checkpoint retained previous preparation")
			}
			traceOperationBoundary(ctx, boundaryDeleteOpening)
			if d.AcknowledgedDeleteSnapshot() != "" {
				t.Fatal("next operation retained previous preparation")
			}
		})
	}
	ctx, d := WithLifecycleDiagnostic(t.Context())
	traceAcknowledgedDeleteStep(ctx, ackExecutableCollection)
	child, cancel := context.WithDeadline(ctx, time.Time{})
	defer cancel()
	traceAcknowledgedDeleteRefusal(child, child.Err())
	traceAcknowledgedDeleteRefusal(ctx, errors.New("PRIVATE-COLLAPSED-COLLECTOR-ERROR"))
	if ctx.Err() != nil || d.AcknowledgedDeleteSnapshot() != "step=executable-collection status=deadline" {
		t.Fatal("active parent erased observed collector child deadline")
	}
	traceAcknowledgedDeleteStep(nil, ackTargetRead)
	traceAcknowledgedDeleteRefusal(context.WithValue(t.Context(), lifecycleDiagnosticKey{}, "PRIVATE"), errors.New("PRIVATE"))
	for _, value := range []uint32{256 << 8, ^uint32(0)} {
		d.ackPreparation.Store(value)
		if !strings.HasPrefix(d.AcknowledgedDeleteSnapshot(), "step=unknown status=") {
			t.Fatal("corrupt recorder wrapped into valid stage")
		}
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 100 {
				traceAcknowledgedDeleteStep(ctx, ackTargetRead)
				traceAcknowledgedDeleteRefusal(ctx, errors.New("PRIVATE"))
				if got := d.AcknowledgedDeleteSnapshot(); len(got) > 80 || strings.Contains(got, "PRIVATE") {
					t.Error("concurrent recorder escaped bounded labels")
				}
			}
		})
	}
	group.Wait()
}

func testAcknowledgedDeleteCompletedObservation(t *testing.T) {
	var absent *LifecycleDiagnostic
	if absent.AcknowledgedDeleteObservationSnapshot() != "" {
		t.Fatal("absent recorder invented a completed observation")
	}
	for value := range 256 {
		ctx, d := WithLifecycleDiagnostic(t.Context())
		label := "unknown"
		switch acknowledgedDeleteObservation(value) {
		case ackObservedDraining:
			label = "draining"
		case ackObservedQuietness:
			label = "quietness"
		}
		if acknowledgedDeleteObservation(value).label() != label {
			t.Fatal("observation escaped closed labels")
		}
		traceAcknowledgedDeleteStep(ctx, ackOriginalOpening)
		traceAcknowledgedDeleteObservation(ctx, acknowledgedDeleteObservation(value))
		if got := d.AcknowledgedDeleteObservationSnapshot(); got != "last-completed="+label {
			t.Fatal("unknown observation manufactured completed progress", got)
		}
	}
	for _, observation := range []acknowledgedDeleteObservation{ackObservedDraining, ackObservedQuietness} {
		ctx, d := WithLifecycleDiagnostic(t.Context())
		traceAcknowledgedDeleteStep(ctx, ackDraining)
		traceAcknowledgedDeleteObservation(ctx, observation)
		traceOperationBoundary(ctx, boundaryDeleteACKWait)
		traceAcknowledgedDeleteStep(ctx, ackOriginalOpening)
		traceAcknowledgedDeleteRefusal(ctx, context.DeadlineExceeded)
		if d.AcknowledgedDeleteSnapshot() != "step=original-opening status=deadline" || d.AcknowledgedDeleteObservationSnapshot() != "last-completed="+observation.label() {
			t.Fatal("later opening erased completed observation")
		}
		traceAcknowledgedDeleteStep(ctx, ackExecutableCollection)
		child, cancel := context.WithDeadline(ctx, time.Time{})
		traceAcknowledgedDeleteRefusal(child, child.Err())
		cancel()
		traceAcknowledgedDeleteRefusal(ctx, errors.New("PRIVATE-COLLECTOR-CANARY"))
		if d.AcknowledgedDeleteSnapshot() != "step=executable-collection status=deadline" || d.AcknowledgedDeleteObservationSnapshot() != "last-completed="+observation.label() {
			t.Fatal("collector deadline changed separate completed observation")
		}
		_, fresh := WithLifecycleDiagnostic(ctx)
		if fresh.AcknowledgedDeleteObservationSnapshot() != "" {
			t.Fatal("new Step retained previous observation")
		}
		for _, checkpoint := range []bool{true, false} {
			if checkpoint {
				traceLifecycleCheckpoint(ctx, ColdSafety, lifecycleDiagnosticEntered)
			} else {
				traceOperationBoundary(ctx, boundaryDeleteOpening)
			}
			if d.AcknowledgedDeleteObservationSnapshot() != "" || d.ackObservation.Load() != 0 {
				t.Fatal("new operation/checkpoint retained previous observation")
			}
			traceAcknowledgedDeleteStep(ctx, ackOriginalOpening)
			if d.AcknowledgedDeleteObservationSnapshot() != "last-completed=unknown" {
				t.Fatal("fresh preparation inherited previous observation")
			}
			traceAcknowledgedDeleteObservation(ctx, observation)
		}
	}
	ctx, d := WithLifecycleDiagnostic(t.Context())
	traceAcknowledgedDeleteStep(ctx, ackTargetRead)
	for _, value := range []uint32{256, ^uint32(0)} {
		d.ackObservation.Store(value)
		if d.AcknowledgedDeleteObservationSnapshot() != "last-completed=unknown" {
			t.Fatal("corrupt observation wrapped into a known label")
		}
	}
	traceAcknowledgedDeleteObservation(nil, ackObservedDraining)
	traceAcknowledgedDeleteObservation(context.WithValue(t.Context(), lifecycleDiagnosticKey{}, "PRIVATE"), ackObservedQuietness)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 100 {
				traceAcknowledgedDeleteObservation(ctx, ackObservedQuietness)
				traceAcknowledgedDeleteStep(ctx, ackOriginalOpening)
				traceAcknowledgedDeleteRefusal(ctx, errors.New("PRIVATE"))
				if got := d.AcknowledgedDeleteObservationSnapshot(); got != "last-completed=quietness" {
					t.Error("concurrent recorder escaped fixed completed label", got)
				}
			}
		})
	}
	group.Wait()
}

// Synthetic already-pending state exercises diagnostic early refusals only.
// It does not claim a native DELETE ACK, admission effectiveness, or settlement.
func TestAcknowledgedDeleteDiagnosticActualEarlyRefusals(t *testing.T) {
	for _, opening := range []bool{true, false} {
		t.Run(map[bool]string{true: "opening-fence", false: "unavailable-collector"}[opening], func(t *testing.T) {
			f := seedBaselineAccessWitness(t)
			d := f.snapshot.Document()
			d.Mode, d.ActivePackage, d.Installed, d.Stage = installstate.Uninstall, f.plan.Digest(), true, installstate.Quiescing
			key := deploymentKey(d.Namespace, "arcadectl-api")
			before, err := f.engine.contracts[d.TargetPackage].Template(key, false)
			if err != nil {
				t.Fatal("signed original Deployment unavailable")
			}
			uid := installstate.Resource{Key: key, UID: "diagnostic-original-api", TemplateSHA256: before.Hash(), Retained: before.Retained(), Phase: before.Phase()}
			d.Resources = append(d.Resources, uid)
			installstate.SortResources(d.Resources)
			d.Pending = &installstate.Pending{Action: installstate.Delete, Key: key, BeforeUID: uid.UID, BeforeResourceVersion: "17", BeforeSHA256: before.Hash(), CreateNonce: strings.Repeat("b", 32)}
			d.Revision++
			seedBaselineAccessUnitDocument(t, f, d)
			// An unavailable collector must refuse; no permissive guard/provider
			// is installed to make this synthetic early refusal succeed.
			f.engine.baseline.prerequisites = &ClusterSecurityBaseline{}
			want := "step=executable-collection status=refused"
			if opening {
				ns, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
				if err != nil {
					t.Fatal("original Namespace unavailable")
				}
				ns.ResourceVersion = "99999"
				if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, "") != nil {
					t.Fatal("original fence drift injection unavailable")
				}
				want = "step=original-opening status=refused"
			}
			writes, updates := f.access.writes, f.nsUpdates
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			settled, err := f.engine.waitAcknowledgedDelete(ctx, f.snapshot)
			if !errors.Is(err, ErrOutcomeUnknown) || settled != f.snapshot || !reflect.DeepEqual(settled.Document(), d) || f.access.writes != writes || f.nsUpdates != updates || diagnostic.AcknowledgedDeleteSnapshot() != want || diagnostic.BoundarySnapshot() != "operation=delete-ack-wait baseline=unknown" {
				t.Fatal("early preparation refusal mutated evidence or lost its exact diagnostic", diagnostic.AcknowledgedDeleteSnapshot())
			}
		})
	}
}
