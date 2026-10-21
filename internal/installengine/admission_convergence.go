// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/util/wait"
)

// An acknowledged controller CREATE/restore does not yet prove readiness or
// leader election. Wait for the existing complete initial-phase proof BEFORE
// preparing any fixture WAL. This does not retry a matrix, actor effect, setup,
// authentication or recovery. Missing not-yet-created families remain governed
// by the initializer's exact partial-family rules, not full-controller readiness.
func (a *ClusterAdmission) waitInitialPhase(ctx context.Context, request LifecycleCheck) (*initialAdmissionPhase, error) {
	if a == nil || a.prerequisites == nil || a.prerequisites.engine == nil || a.prerequisites.access == nil || ctx == nil || request.Checkpoint != AdmissionEffective || request.Snapshot == nil || !request.Target.IsTrusted() || request.Options.Now.IsZero() {
		return nil, ErrInvalid
	}
	p := a.prerequisites
	if _, err := p.permissions(request); err != nil {
		return nil, ErrInvalid // invalid target/mode never consumes a readiness wait
	}
	d := request.Snapshot.Document()
	api, template := p.engine.inventory(d, deploymentKey(d.Namespace, apiFamily))
	if d.Mode != installstate.Uninstall && (d.Stage == installstate.Verifying || d.Stage == installstate.Applying && api != nil) {
		// Once Applying has acknowledged the original API, the next admission
		// proof also includes its WHOLE Deployment/RS/Pod/EndpointSlice rows.
		// Waiting only in Verifying seals transient startup rows one step too
		// early. An ACK or briefly identical Pending reads do not prove serving.
		// Partial Applying without an API and uninstall keep their contracts.
		if api == nil || template == nil || p.engine.fixtureFence(request.Snapshot) != nil || p.original(ctx, request.Snapshot) != nil {
			return nil, ErrAdmission
		}
		traceAdmissionPhase(ctx, admissionPhaseInitialServing, -1)
		if p.waitOriginalServingStage(ctx, request.Snapshot, true) != nil {
			return nil, ErrAdmission
		}
	}
	var initial *initialAdmissionPhase
	err := wait.PollUntilContextTimeout(ctx, time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		if p.engine.fixtureFence(request.Snapshot) != nil || p.original(ctx, request.Snapshot) != nil {
			return false, ErrAdmission // never wait over an active/uncertain run
		}
		fresh, err := a.captureInitialPhase(ctx, request)
		if p.original(ctx, request.Snapshot) != nil || p.engine.fixtureFence(request.Snapshot) != nil {
			return false, ErrAdmission
		}
		if errors.Is(err, ErrInvalid) {
			return false, ErrInvalid
		}
		if err != nil || fresh == nil {
			return false, nil // only repeat complete observations; no WAL exists
		}
		initial = fresh
		return true, nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			return nil, ErrInvalid
		}
		return nil, ErrAdmission
	}
	return initial, nil
}
