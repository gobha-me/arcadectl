// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
)

// A successful original Deployment ACK can precede asynchronous native status
// and descendant changes. Observe complete executable quietness BEFORE opening
// the recovery proof, never by retrying a failed proof or ignoring whole fields.
// This is not readiness, effect permission, recovery settlement or authentication.
// Its caller retains the returned original ACK receipt through the actual full
// proof and settlement. Unknown responses never enter this ACK-only path.
func (e *Engine) waitAcknowledgedDeployment(ctx context.Context, s *installstate.Snapshot, ack *unstructured.Unstructured) (*baselineParent, error) {
	if e == nil || e.baseline == nil || e.baseline.prerequisites == nil || ctx == nil || ctx.Err() != nil || s == nil || ack == nil {
		return nil, ErrOutcomeUnknown
	}
	d := s.Document()
	p := d.Pending
	if p == nil || p.Key.Kind != "Deployment" || p.Action != installstate.Create && p.Action != installstate.Update {
		return nil, ErrOutcomeUnknown
	}
	if _, err := e.currentOriginal(ctx, s); err != nil {
		return nil, ErrOutcomeUnknown
	}
	owner, err := e.originalBaselineParent(d, p.Key, ack)
	if err != nil || owner == nil || owner.template.Hash() != p.AfterSHA256 || !effectMatches(owner.template, p, ack) {
		owner.release()
		return nil, ErrOutcomeUnknown
	}
	transferred := false
	defer func() {
		if !transferred {
			owner.release()
		}
	}()
	confirm := func() error {
		return e.confirmBaselineOriginalReceipt(d, p.Key, &baselineOriginalObject{whole: owner.whole, template: owner.template, receipt: owner.receipt})
	}
	var previous *baselineExecutables
	var quiet time.Time
	err = wait.PollUntilContextTimeout(ctx, time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		if _, err := e.currentOriginal(ctx, s); err != nil || confirm() != nil {
			return false, ErrOutcomeUnknown
		}
		fresh, collectErr := e.baseline.prerequisites.collectExecutables(ctx, s)
		if _, err := e.currentOriginal(ctx, s); err != nil || confirm() != nil || ctx.Err() != nil {
			return false, ErrOutcomeUnknown
		}
		if collectErr != nil || fresh == nil {
			previous, quiet = nil, time.Time{}
			return false, nil // repeat ONLY whole read-only observations
		}
		parent, err := e.originalBaselineParent(d, p.Key, fresh.whole[p.Key])
		if parent != nil {
			defer parent.release()
		}
		if err != nil || parent == nil || parent.whole.GetUID() != owner.whole.GetUID() || parent.template.Hash() != owner.template.Hash() || !sameBaselineOriginalReceipt(owner.receipt, parent.receipt) || confirm() != nil {
			return false, ErrOutcomeUnknown
		}
		if previous == nil || !sameBaselineExecutables(previous, fresh) {
			previous, quiet = fresh, time.Now()
		}
		return time.Since(quiet) >= 5*time.Second, nil
	})
	if err != nil || ctx.Err() != nil || confirm() != nil {
		return nil, ErrOutcomeUnknown
	}
	transferred = true
	return owner, nil
}
