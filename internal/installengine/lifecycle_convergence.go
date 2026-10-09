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

// waitObserved handles ONLY asynchronous read-only checkpoints. It never calls
// Step, admission behavior, recovery, a write, or authentication. No failed
// effect is retried. A refusal merely keeps the installer at the same barrier;
// only the existing complete strict proof can let the next step proceed.
func (c *clusterLifecycleChecks) waitObserved(ctx context.Context, request LifecycleCheck) error {
	if c == nil || c.prerequisites == nil || ctx == nil || request.Snapshot == nil {
		return ErrInvalid
	}
	refusal := ErrInvalid
	switch request.Checkpoint {
	case CRDsAvailable:
		refusal = ErrCRDs
	case AdmissionConfigured:
		refusal = ErrAdmission
	case ControllersAvailable:
		refusal = ErrControllers
	case APIStopped, RuntimeStopped:
		refusal = ErrQuiescence
	default:
		return ErrInvalid // closed scope: no caller-selected function or effect
	}
	err := wait.PollUntilContextTimeout(ctx, time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		if c.prerequisites.original(ctx, request.Snapshot) != nil {
			return false, refusal // journal change never becomes convergence
		}
		var err error
		switch request.Checkpoint {
		case CRDsAvailable:
			err = c.prerequisites.VerifyCRDs(ctx, request)
		case AdmissionConfigured:
			err = c.admission.VerifyConfigured(ctx, request)
		case ControllersAvailable:
			err = c.controllers.Verify(ctx, request)
		case APIStopped, RuntimeStopped:
			err = c.quiescence.Verify(ctx, request)
		}
		if errors.Is(err, ErrInvalid) {
			return false, ErrInvalid
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if c.prerequisites.original(ctx, request.Snapshot) != nil {
			return false, refusal
		}
		return err == nil, nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			return ErrInvalid
		}
		return refusal
	}
	return nil
}

// Kubernetes Deployment/EndpointSlice readiness can still be settling after
// CREATE ACK. Observe the complete original serving fingerprint continuously
// unchanged for five seconds BEFORE the one authentication attempt. This
// reads no client credential/Secret and opens no forwarding/authentication
// channel. Activation still independently repeats all its own exact guards.
func (c *clusterLifecycleChecks) waitServing(ctx context.Context, request LifecycleCheck) error {
	if c == nil || c.prerequisites == nil || c.activation == nil || ctx == nil || request.Snapshot == nil || request.Checkpoint != TargetAuthenticated {
		return ErrInvalid
	}
	p := c.prerequisites
	d := request.Snapshot.Document()
	if request.Options.Now.IsZero() || d.Pending != nil || d.Stage != installstate.Verifying || request.Mode != d.Mode || request.Mode == installstate.Uninstall || request.Target == nil || request.Target.Digest() != d.TargetPackage {
		return ErrInvalid
	}
	return p.waitOriginalServing(ctx, request.Snapshot)
}

// Shared READ-only original-serving convergence. Admission invokes this only
// before capturing/sealing its initial phase. The activation wrapper retains
// its Verifying/checkpoint/target validation. No WAL,
// Secret, forwarding channel or authentication is created by this wait.
func (p *ClusterPrerequisites) waitOriginalServing(ctx context.Context, snapshot *installstate.Snapshot) error {
	return p.waitOriginalServingStage(ctx, snapshot, false)
}

func (p *ClusterPrerequisites) waitOriginalServingStage(ctx context.Context, snapshot *installstate.Snapshot, admissionApplying bool) error {
	if p == nil || p.engine == nil || p.access == nil || ctx == nil || snapshot == nil {
		return ErrInvalid
	}
	var previous *Serving
	var quiet time.Time
	err := wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		if p.engine.fixtureFence(snapshot) != nil || p.original(ctx, snapshot) != nil {
			return false, ErrActivation
		}
		fresh, err := p.engine.observeServing(ctx, snapshot, p.access.Serving(), admissionApplying)
		if p.original(ctx, snapshot) != nil || p.engine.fixtureFence(snapshot) != nil {
			return false, ErrActivation
		}
		if err != nil || fresh == nil {
			previous, quiet = nil, time.Time{}
			return false, nil
		}
		if previous == nil || previous.fingerprint != fresh.fingerprint {
			previous, quiet = fresh, time.Now()
		}
		return time.Since(quiet) >= 5*time.Second, nil
	})
	if err != nil {
		return ErrActivation
	}
	return nil
}
