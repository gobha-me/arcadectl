// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	activationAuthUnused uint32 = iota
	activationAuthStarted
	activationAuthVerified
	activationAuthFinishing
	activationAuthFinished
)

// Authentication evidence stays private to its one original owner. It is not
// a replacement for the lifecycle's trailing original read or closing proof.
type activationEvidence struct {
	self    *activationEvidence
	owner   *activationEpoch
	serving *Serving
	binding credentialBinding
}

// Unlike the public serving observer, this private readiness wait does not
// claim admission effectiveness. It reads no credential and authorizes no
// connection. A successful wait must still be followed by the complete fresh
// opening proof; original-journal drift is terminal, not convergence.
func (c *ClusterTargetAuthenticated) waitEpochServing(ctx context.Context, request LifecycleCheck) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrActivation
	}
	if _, err := c.activationEpochScope(request); err != nil {
		return ErrActivation
	}
	var previous *Serving
	var quiet time.Time
	err := wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		if _, err := c.activationEpochScope(request); err != nil || c.prerequisites.original(ctx, request.Snapshot) != nil {
			return false, ErrActivation
		}
		fresh, err := c.prerequisites.engine.readOriginalServing(ctx, request.Snapshot, c.activation.serving, false)
		if c.prerequisites.original(ctx, request.Snapshot) != nil {
			return false, ErrActivation
		}
		if _, scopeErr := c.activationEpochScope(request); scopeErr != nil || ctx.Err() != nil {
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

// The actual production composition returns ownership, not merely a cached
// successful Check. Lifecycle must retain it through its own trailing read.
func (c *clusterLifecycleChecks) beginTargetEpoch(ctx context.Context, request LifecycleCheck) (*activationEpoch, *activationEvidence, error) {
	if c == nil || c.prerequisites == nil || c.admission == nil || c.cold == nil || c.quiescence == nil || c.controllers == nil || c.activation == nil || c.activation.prerequisites != c.prerequisites {
		return nil, nil, ErrActivation
	}
	if c.activation.waitEpochServing(ctx, request) != nil {
		return nil, nil, ErrActivation
	}
	owner, err := c.activation.openActivationEpoch(ctx, request)
	if err != nil {
		return nil, nil, ErrActivation
	}
	evidence, err := owner.authenticate(ctx)
	if err != nil {
		owner.release()
		return nil, nil, ErrActivation
	}
	return owner, evidence, nil
}

// Original-only joint reader. Its caller holds the opening proof and must
// reclose that SAME proof before token transmission and after authentication.
// Neither this reader nor readiness can be used as a public guarded observer.
func (o *activationEpoch) readJoint(ctx context.Context) (*Serving, credentialBinding, error) {
	if o.confirmLocal(ctx) != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	engine, snapshot := o.baseline.engine, o.request.Snapshot
	if _, err := engine.currentOriginal(ctx, snapshot); err != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	a := o.target.activation
	serving, err := engine.readOriginalServing(ctx, snapshot, a.serving, false)
	if err != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	workflow, err := NewSecretWorkflow(engine, a.secrets)
	if err != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	retained, caID, err := workflow.readRetainedObjects(ctx, snapshot, o.request.Options.Activation.CAFile, time.Now())
	if err != nil || caID != o.caID {
		return nil, credentialBinding{}, ErrActivation
	}
	binding, err := a.bindOriginalCredentials(retained, caID, o.request.Options.Activation)
	if err != nil || binding.client != o.clientID || binding.ca != o.caID {
		return nil, credentialBinding{}, ErrActivation
	}
	if _, err := engine.currentOriginal(ctx, snapshot); err != nil || o.confirmLocal(ctx) != nil {
		return nil, credentialBinding{}, ErrActivation
	}
	return serving, binding, nil
}

func (o *activationEpoch) matchesJoint(ctx context.Context, evidence *activationEvidence) error {
	if evidence == nil || evidence.self != evidence || evidence.owner != o || evidence.serving == nil {
		return ErrActivation
	}
	serving, binding, err := o.readJoint(ctx)
	if err != nil || serving.fingerprint != evidence.serving.fingerprint || binding != evidence.binding {
		return ErrActivation
	}
	return nil
}

func (o *activationEpoch) authenticate(ctx context.Context) (*activationEvidence, error) {
	if o.confirmLocal(ctx) != nil || !o.authPhase.CompareAndSwap(activationAuthUnused, activationAuthStarted) {
		return nil, ErrActivation
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	serving, binding, err := o.readJoint(ctx)
	if err != nil {
		traceActivation(ctx, activationBindingBefore)
		return nil, ErrActivation
	}
	evidence := &activationEvidence{owner: o, serving: serving, binding: binding}
	evidence.self = evidence
	// Open exactly one native connection BEFORE starting the HTTP client's
	// unchanged 30-second timer. Do not put a complete cluster proof inside its
	// DialContext, and never reconnect when proof or authentication refuses.
	conn, err := o.target.prerequisites.access.forwardPod(ctx, serving)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil || conn == nil {
		traceActivation(ctx, activationConnectionOpen)
		return nil, ErrActivation
	}
	// The substantial policy/catalog fence does not observe retained Secrets.
	// Keep its post-joint policy closure, then reject Secret/serving drift during
	// that fence against the SAME evidence before handing over the connection.
	// This is a finite closing observation, not an atomic cluster-read claim.
	if o.matchesJoint(ctx, evidence) != nil || o.fence(ctx) != nil || o.matchesJoint(ctx, evidence) != nil {
		traceActivation(ctx, activationBindingDialMatch)
		return nil, ErrActivation
	}
	address := net.JoinHostPort(serving.address, "8443")
	options := o.request.Options.Activation
	var handedOff atomic.Bool
	client, err := adminclient.LoadBoundWithDialer(adminclient.ContextConfig{Version: "v1", Name: "installation", APIOrigin: "https://" + address, TLSServerName: "arcadectl-api." + serving.namespace + ".svc", CAFile: options.CAFile, CredentialFile: options.CredentialFile}, binding.client, binding.ca, binding.peerSHA256, func(dialCtx context.Context, network, requestedAddress string) (net.Conn, error) {
		if dialCtx == nil || dialCtx.Err() != nil || network != "tcp" || requestedAddress != address || !handedOff.CompareAndSwap(false, true) || o.confirmLocal(ctx) != nil {
			return nil, ErrActivation
		}
		if _, err := o.baseline.engine.currentOriginal(ctx, o.request.Snapshot); err != nil || o.confirmLocal(ctx) != nil {
			return nil, ErrActivation
		}
		return conn, nil
	})
	if err != nil {
		traceActivation(ctx, activationClientLoad)
		return nil, ErrActivation
	}
	defer client.Close()
	identity, err := client.Verify(ctx)
	if err != nil {
		traceActivation(ctx, activationSelf)
		return nil, ErrActivation
	}
	if identity.Namespace != serving.namespace || identity.PrincipalID != adminauth.AdminPrincipalID {
		traceActivation(ctx, activationSelfIdentity)
		return nil, ErrActivation
	}
	if o.matchesJoint(ctx, evidence) != nil || !o.authPhase.CompareAndSwap(activationAuthStarted, activationAuthVerified) {
		traceActivation(ctx, activationBindingAfterMatch)
		return nil, ErrActivation
	}
	return evidence, nil
}

// Caller context is the lifecycle context, not the now-canceled two-minute
// authentication context. Repeat the complete behavioral proof (including
// producers), then all joint evidence and original/local fences before success.
// A refused, copied or consumed owner cannot be retried or recaptured.
func (o *activationEpoch) finish(ctx context.Context, evidence *activationEvidence) error {
	if o.confirmLocal(ctx) != nil || evidence == nil || evidence.self != evidence || evidence.owner != o || !o.authPhase.CompareAndSwap(activationAuthVerified, activationAuthFinishing) {
		return ErrActivation
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	if o.behavior.prove(ctx) != nil || o.matchesJoint(ctx, evidence) != nil || o.fence(ctx) != nil || o.matchesJoint(ctx, evidence) != nil {
		return ErrActivation
	}
	if _, err := o.baseline.engine.currentOriginal(ctx, o.request.Snapshot); err != nil || o.confirmLocal(ctx) != nil || ctx.Err() != nil || !o.authPhase.CompareAndSwap(activationAuthFinishing, activationAuthFinished) {
		return ErrActivation
	}
	traceActivation(ctx, activationComplete)
	return nil
}
