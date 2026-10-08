// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import "context"

// clusterLifecycleChecks is the closed production composition. It is never
// populated by CLI flags, callbacks, shell statuses or caller-supplied evidence.
// Every component shares the SAME frozen cluster identity and journal engine.
type clusterLifecycleChecks struct {
	prerequisites *ClusterPrerequisites
	admission     *ClusterAdmission
	cold          *ClusterCold
	quiescence    *ClusterQuiescence
	controllers   *ClusterControllers
	activation    *ClusterTargetAuthenticated
}

// NewClusterLifecycle binds every checkpoint to its actual implementation.
// Selecting an already-held admin identity does not create accounts, grant
// permissions, mint runtime tokens or provide fallback authentication.
func NewClusterLifecycle(e *Engine, access *HTTPAccess) (*Lifecycle, error) {
	if e == nil || access == nil || e.access != access || !access.actorCompatible() || access.native == nil {
		return nil, ErrInvalid
	}
	p, err := NewClusterPrerequisites(e, access)
	if err != nil {
		return nil, err
	}
	a, err := NewClusterAdmission(e, access)
	if err != nil {
		return nil, err
	}
	cold, err := NewClusterCold(p)
	if err != nil {
		return nil, err
	}
	quiescence, err := NewClusterQuiescence(p)
	if err != nil {
		return nil, err
	}
	controllers, err := NewClusterControllers(p)
	if err != nil {
		return nil, err
	}
	activation, err := NewClusterTargetAuthenticated(p)
	if err != nil {
		return nil, err
	}
	secrets, err := NewSecretWorkflow(e, access.PrivateSecrets())
	if err != nil {
		return nil, err
	}
	checks := &clusterLifecycleChecks{p, a, cold, quiescence, controllers, activation}
	return NewLifecycleWithChecks(e, secrets, checks)
}

func (c *clusterLifecycleChecks) Check(ctx context.Context, request LifecycleCheck) error {
	if c == nil || c.prerequisites == nil || c.admission == nil || c.cold == nil || c.quiescence == nil || c.controllers == nil || c.activation == nil || ctx == nil {
		return ErrInvalid
	}
	switch request.Checkpoint {
	case Prerequisites:
		return c.prerequisites.Verify(ctx, request)
	case CRDsAvailable:
		return c.waitObserved(ctx, request)
	case AdmissionConfigured:
		return c.waitObserved(ctx, request)
	case BootstrapAdmission:
		return c.admission.VerifyBootstrap(ctx, request)
	case AdmissionEffective:
		return c.admission.VerifyEffective(ctx, request)
	case RetainedAdmission:
		return c.admission.VerifyRetained(ctx, request)
	case ColdSafety:
		return c.cold.Verify(ctx, request)
	case APIStopped, RuntimeStopped:
		return c.waitObserved(ctx, request)
	case ControllersAvailable:
		return c.waitObserved(ctx, request)
	case TargetAuthenticated:
		if err := c.waitServing(ctx, request); err != nil {
			return err
		}
		return c.activation.Verify(ctx, request)
	default:
		return ErrInvalid
	}
}
