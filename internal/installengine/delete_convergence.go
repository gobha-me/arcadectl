// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
)

// Called only by the same invocation after its one original UID/RV DELETE was
// acknowledged. Unknown sends and explicit recovery keep their existing
// observation semantics. This never sends or repeats a resource effect.
func (e *Engine) waitAcknowledgedDelete(ctx context.Context, intent *installstate.Snapshot) (*installstate.Snapshot, error) {
	if e == nil || ctx == nil || intent == nil || intent.Document().Pending == nil || intent.Document().Pending.Action != installstate.Delete {
		return intent, ErrInvalid
	}
	p := intent.Document().Pending
	settled := intent
	// Only a successfully acknowledged lifecycle Deployment DELETE needs
	// native descendant preparation. Public Delete and uncertain sends never
	// enter this function. Preparation grants no authority: the original full
	// guard and independent absence/recovery proof still precede settlement.
	prepare := e.baseline != nil && p.Key.Kind == "Deployment"
	var previous *baselineExecutables
	var quiet time.Time
	if prepare {
		d := intent.Document()
		original, before := e.inventory(d, p.Key)
		if e.baseline.prerequisites == nil || original == nil || before == nil || !deletionAllowed(d, original, before) || p.BeforeUID != original.UID || p.BeforeSHA256 != before.Hash() || !baselineParentRV(p.BeforeResourceVersion) || !nonceID.MatchString(p.CreateNonce) || p.AfterSHA256 != "" {
			return intent, ErrOutcomeUnknown
		}
	}
	err := wait.PollUntilContextTimeout(ctx, time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		traceOperationBoundary(ctx, boundaryDeleteACKWait)
		if prepare {
			// Keep every preparation observation inside this SAME five-minute
			// budget and bracket it with exact original Namespace/journal reads.
			// Never retry a refused full proof or exempt draining Pod fields.
			if _, err := e.currentOriginal(ctx, intent); err != nil {
				return false, ErrOutcomeUnknown
			}
			live, readErr := e.access.Get(ctx, p.Key)
			if _, err := e.currentOriginal(ctx, intent); err != nil || ctx.Err() != nil {
				return false, ErrOutcomeUnknown
			}
			if !apierrors.IsNotFound(readErr) {
				_, before := e.inventory(intent.Document(), p.Key)
				if readErr != nil || !baselineDeletingOriginal(before, p, live) {
					return false, ErrOutcomeUnknown
				}
				previous, quiet = nil, time.Time{}
				return false, nil // acknowledged original is still draining
			}
			whole, err := e.baseline.prerequisites.collectExecutables(ctx, intent)
			if _, fenceErr := e.currentOriginal(ctx, intent); err != nil || fenceErr != nil || whole == nil || ctx.Err() != nil || whole.whole[p.Key] != nil {
				return false, ErrOutcomeUnknown
			}
			if previous == nil || !sameBaselineExecutables(previous, whole) {
				previous, quiet = whole, time.Now()
			}
			if time.Since(quiet) < 5*time.Second {
				return false, nil // complete read-only observations only
			}
		}
		fresh, err := e.current(ctx, intent)
		if err != nil {
			return false, ErrOutcomeUnknown
		}
		if fresh.Document().AdmissionRetirementRevision != 0 && e.verifyRetiredAdmission(ctx, fresh) != nil {
			return false, ErrOutcomeUnknown
		}
		live, readErr := e.access.Get(ctx, p.Key)
		if apierrors.IsNotFound(readErr) {
			// Recover independently repeats original journal, action, inventory
			// and actual absence guards, then CAS-settles this exact intent.
			settled, err = e.recover(ctx, intent, nil, false, false)
			return err == nil, err
		}
		if readErr != nil || live == nil || live.GetUID() != p.BeforeUID || live.GetResourceVersion() == "" {
			return false, ErrOutcomeUnknown // replacement/refusal is permanent
		}
		if prepare {
			return false, ErrOutcomeUnknown // prepared absence cannot be undone
		}
		traceOperationBoundary(ctx, boundaryDeleteACKClose)
		if _, err := e.current(ctx, intent); err != nil {
			return false, ErrOutcomeUnknown
		}
		return false, nil // original still present: only read again
	})
	if err != nil {
		return settled, ErrOutcomeUnknown
	}
	return settled, nil
}
