// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
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
	// Freeze and validate the entire signed membership before either read lane
	// starts. Each lane preserves its original resource order; observations are
	// still uncached and both complete passes retain separate closing fences.
	type configuredResource struct {
		resource installstate.BaselineResource
		template *installcontract.Template
	}
	frozen := make([]configuredResource, 0, installbaseline.ResourceCount)
	var lanes [2][]int
	seen := make(map[installstate.Key]bool, installbaseline.ResourceCount)
	for _, resource := range baseline.Resources {
		template, err := c.engine.baseline.contract.Template(resource.Key, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 || resource.Key.Namespace != "" || seen[resource.Key] {
			return nil, ErrSecurityBaseline
		}
		lane := 0
		switch resource.Key.Kind {
		case "ValidatingAdmissionPolicy":
		case "ValidatingAdmissionPolicyBinding":
			lane = 1
		default:
			return nil, ErrSecurityBaseline
		}
		seen[resource.Key] = true
		lanes[lane] = append(lanes[lane], len(frozen))
		frozen = append(frozen, configuredResource{resource: resource, template: template})
	}
	if len(lanes[0]) != installbaseline.ResourceCount/2 || len(lanes[1]) != installbaseline.ResourceCount/2 {
		return nil, ErrSecurityBaseline
	}
	type configuredObservation struct {
		identity   admissionIdentity
		policyName string
	}
	observed := make([]configuredObservation, len(frozen))
	var failures [2]error
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var readers sync.WaitGroup
	for lane, indices := range lanes {
		readers.Go(func() {
			for _, index := range indices {
				entry := frozen[index]
				live, err := c.access.Get(readCtx, entry.resource.Key)
				if err != nil || entry.template.MatchLive(live, entry.resource.UID) != nil {
					failures[lane] = ErrSecurityBaseline
					cancel()
					return
				}
				if lane == 0 {
					var policy admissionv1.ValidatingAdmissionPolicy
					if decodeServing(live, &policy) != nil || !healthyAdmissionPolicy(&policy) {
						failures[lane] = ErrSecurityBaseline
						cancel()
						return
					}
				} else {
					var binding admissionv1.ValidatingAdmissionPolicyBinding
					if decodeServing(live, &binding) != nil {
						failures[lane] = ErrSecurityBaseline
						cancel()
						return
					}
					observed[index].policyName = binding.Spec.PolicyName
				}
				observed[index].identity = admissionIdentity{UID: entry.resource.UID, ResourceVersion: live.GetResourceVersion(), TemplateSHA256: entry.template.Hash()}
			}
		})
	}
	// No early return, second pass or journal close may outlive either reader.
	// Workers own disjoint result slots; only this joined caller builds maps.
	readers.Wait()
	if failures[0] != nil || failures[1] != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	witness := make(map[installstate.Key]admissionIdentity, installbaseline.ResourceCount)
	policies := make(map[string]bool, installbaseline.ResourceCount/2)
	bindings := make(map[string]string, installbaseline.ResourceCount/2)
	for index, entry := range frozen {
		key := entry.resource.Key
		witness[key] = observed[index].identity
		if key.Kind == "ValidatingAdmissionPolicy" {
			policies[key.Name] = true
		} else {
			bindings[key.Name] = observed[index].policyName
		}
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
