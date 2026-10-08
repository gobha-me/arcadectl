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
	err := wait.PollUntilContextTimeout(ctx, time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
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
