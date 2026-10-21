// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// A distinct verification-only reader for genuine completed retirement.
// Ordinary current/retained/activation eligibility remains unchanged. It
// returns no private objects or credential candidate and creates nothing.
func (w *SecretWorkflow) verifyCompletedRetirementSecrets(ctx context.Context, s *installstate.Snapshot, caFile string, now time.Time) error {
	if w == nil || w.engine == nil || ctx == nil || ctx.Err() != nil || s == nil || now.IsZero() || !w.engine.baselineRetiredObservable(s.Document()) {
		return ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	e := w.engine
	opening, err := e.openRetirementEvidence(s.Document())
	if err != nil {
		return ErrSecurityBaseline
	}
	defer opening.release()
	_, originalCA, caPin, err := privatefs.PinAbsolute(caFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		return ErrCredentials
	}
	defer caPin.Close()
	fresh, err := (&Lifecycle{engine: e}).original(ctx, s)
	if err != nil || e.verifyRetiredAdmissionCore(ctx, fresh) != nil {
		return ErrSecurityBaseline
	}
	_, caID, err := w.readRetainedObjects(ctx, fresh, caFile, now)
	if err != nil || caID != originalCA {
		if err == nil {
			return ErrCredentials
		}
		return err
	}
	if e.verifyRetiredAdmissionCore(ctx, fresh) != nil {
		return ErrSecurityBaseline
	}
	if _, err := (&Lifecycle{engine: e}).original(ctx, fresh); err != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	// CA identity includes its content digest and inode; close it only after
	// the final remote namespace/policy observations, then both local receipts.
	if caPin.Confirm() != nil || e.closeRetirementEvidence(opening) != nil || ctx.Err() != nil {
		return ErrCredentials
	}
	return nil
}
