// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
)

// ClusterSecurityBaseline is the closed READ-only baseline observation
// composition. Configuration health alone is NOT effective enforcement; Verify
// performs separate complete live/retired proofs. Production runtime wiring and
// retained-reinstall provenance remain separate mandatory lifecycle obligations.
type ClusterSecurityBaseline struct {
	engine *Engine
	access *HTTPAccess
}

func NewClusterSecurityBaseline(engine *Engine, access *HTTPAccess) (*ClusterSecurityBaseline, error) {
	if engine == nil || engine.baseline == nil || !engine.baselinePlan().IsTrusted() || engine.journal == nil || engine.journal.BaselineDigest() != engine.baselinePlan().Digest() || access == nil || engine.access != access || access.native == nil || !access.actorCompatible() {
		return nil, ErrInvalid
	}
	return &ClusterSecurityBaseline{engine: engine, access: access}, nil
}

// VerifyConfigured reobserves complete original policy/binding identities,
// signed whole shapes and generation-current native typechecking. Two complete
// uncached passes must agree on every UID/RV. No result or health is cached.
func (c *ClusterSecurityBaseline) VerifyConfigured(ctx context.Context, snapshot *installstate.Snapshot) error {
	_, err := c.configured(ctx, snapshot)
	return err
}

func (c *ClusterSecurityBaseline) configured(ctx context.Context, snapshot *installstate.Snapshot) (map[installstate.Key]admissionIdentity, error) {
	if c == nil || c.engine == nil || c.engine.baseline == nil || c.access == nil || c.engine.access != c.access || ctx == nil || snapshot == nil || !c.access.actorCompatible() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var previous map[installstate.Key]admissionIdentity
	for pass := 0; pass < 2; pass++ {
		observed, err := c.configuredPass(ctx, snapshot)
		if err != nil {
			return nil, err
		}
		if pass != 0 && !reflect.DeepEqual(previous, observed) {
			return nil, ErrSecurityBaseline
		}
		previous = observed
	}
	return previous, nil
}

func (c *ClusterSecurityBaseline) configuredPass(ctx context.Context, snapshot *installstate.Snapshot) (map[installstate.Key]admissionIdentity, error) {
	lifecycle := &Lifecycle{engine: c.engine}
	fresh, err := lifecycle.original(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	document := fresh.Document()
	baseline := document.SecurityBaseline
	if baseline == nil || baseline.Stage != installstate.BaselineVerified || baseline.Pending != nil || baseline.Version != installbaseline.Version || baseline.ArtifactDigest != c.engine.baselinePlan().Digest() || len(baseline.Resources) != installbaseline.ResourceCount {
		return nil, ErrSecurityBaseline
	}
	witness := make(map[installstate.Key]admissionIdentity, installbaseline.ResourceCount)
	policies := make(map[string]bool, installbaseline.ResourceCount/2)
	bindings := make(map[string]string, installbaseline.ResourceCount/2)
	for _, resource := range baseline.Resources {
		template, err := c.engine.baseline.contract.Template(resource.Key, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 || resource.Key.Namespace != "" || witness[resource.Key].UID != "" {
			return nil, ErrSecurityBaseline
		}
		live, err := c.access.Get(ctx, resource.Key)
		if err != nil || template.MatchLive(live, resource.UID) != nil {
			return nil, ErrSecurityBaseline
		}
		switch resource.Key.Kind {
		case "ValidatingAdmissionPolicy":
			var policy admissionv1.ValidatingAdmissionPolicy
			if decodeServing(live, &policy) != nil || !healthyAdmissionPolicy(&policy) || policies[resource.Key.Name] {
				return nil, ErrSecurityBaseline
			}
			policies[resource.Key.Name] = true
		case "ValidatingAdmissionPolicyBinding":
			var binding admissionv1.ValidatingAdmissionPolicyBinding
			if decodeServing(live, &binding) != nil || bindings[resource.Key.Name] != "" {
				return nil, ErrSecurityBaseline
			}
			bindings[resource.Key.Name] = binding.Spec.PolicyName
		default:
			return nil, ErrSecurityBaseline
		}
		witness[resource.Key] = admissionIdentity{UID: resource.UID, ResourceVersion: live.GetResourceVersion(), TemplateSHA256: template.Hash()}
	}
	if len(witness) != installbaseline.ResourceCount || len(policies) != installbaseline.ResourceCount/2 || len(bindings) != installbaseline.ResourceCount/2 {
		return nil, ErrSecurityBaseline
	}
	for _, policy := range bindings {
		if !policies[policy] {
			return nil, ErrSecurityBaseline
		}
	}
	if _, err := lifecycle.original(ctx, fresh); err != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return witness, nil
}
