// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Only read-only eligibility, not the retirement receipt proof or permission
// to recreate access. Keep the genuine completed Uninstall state unchanged.
func (e *Engine) baselineRetiredObservable(d installstate.Document) bool {
	if e == nil || e.baseline == nil || !e.baselinePlan().IsTrusted() || d.Mode != installstate.Uninstall || d.Stage != installstate.Complete || d.Installed || d.Pending != nil ||
		d.ActivePackage != d.TargetPackage || d.AdmissionRetirementRevision == 0 || d.AdmissionRetirementRevision >= d.Revision || len(d.Resources) != 20 ||
		d.SecurityBaseline == nil || d.SecurityBaseline.Stage != installstate.BaselineVerified || d.SecurityBaseline.Pending != nil || d.SecurityBaseline.ArtifactDigest != e.baselinePlan().Digest() {
		return false
	}
	plan := e.plans[d.TargetPackage]
	if !plan.IsTrusted() || plan.Digest() != d.TargetPackage || plan.Namespace() != d.Namespace || plan.Profile().ID != d.ProfileID {
		return false
	}
	for _, resource := range d.Resources {
		if !resource.Retained {
			return false
		}
	}
	return true
}

// Exact fixed namespace/cluster collection LISTs and retained-root GETs only.
// No fake Installed flag, operation-mode rewrite, mutating permission catalog
// or port-forward capability. The sealed observer additionally performs bounded
// server-authorized recursive owner metadata GETs and enforces recorded UIDs.
func (p *ClusterPrerequisites) observeCompletedRetirement(ctx context.Context, request LifecycleCheck) (*installobserve.Observation, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil || ctx == nil || request.Snapshot == nil ||
		request.Checkpoint != ColdSafety || request.Mode != installstate.Uninstall || request.Options.Now.IsZero() || !p.engine.baselineRetiredObservable(request.Snapshot.Document()) ||
		request.Target != p.engine.plans[request.Snapshot.Document().TargetPackage] {
		return nil, ErrSecurityBaseline
	}
	if p.original(ctx, request.Snapshot) != nil || p.engine.verifyRetiredAdmissionCore(ctx, request.Snapshot) != nil {
		return nil, ErrSecurityBaseline
	}
	if p.authorizeObservationReads(ctx, request.Snapshot, nil) != nil {
		return nil, ErrSecurityBaseline
	}
	return p.collectOriginalObservation(ctx, request)
}

// This is a READ-only catalog shared by two separately authenticated callers.
// It is not an eligibility gate, observer result, mutation capability or the
// ordinary operation permission catalog. Additional keys are private signed
// prerequisite targets; the enclosing caller must bind them to its receipt.
func (p *ClusterPrerequisites) authorizeObservationReads(ctx context.Context, snapshot *installstate.Snapshot, additional []installstate.Key) error {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil || ctx == nil || ctx.Err() != nil || snapshot == nil {
		return ErrSecurityBaseline
	}
	d := snapshot.Document()
	permissions := make([]proofPermission, 0, len(proofCollections)+len(d.Resources))
	for _, collection := range proofCollections {
		gv, err := schema.ParseGroupVersion(collection.gv)
		if err != nil {
			return ErrSecurityBaseline
		}
		namespace := ""
		if collection.namespaced {
			namespace = d.Namespace
		}
		permissions = append(permissions, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: collection.plural, Namespace: namespace, Verb: "list"}}, kind: collection.kind})
	}
	keys := make([]installstate.Key, 0, len(d.Resources)+len(additional))
	for _, resource := range d.Resources {
		keys = append(keys, resource.Key)
	}
	keys = append(keys, additional...)
	for _, key := range keys {
		permission, err := publicPermission(key, "get")
		if key.Kind == "Secret" && key.APIVersion == "v1" && key.Namespace == d.Namespace {
			permission, err = proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "secrets", Namespace: d.Namespace, Name: key.Name, Verb: "get"}}, kind: "Secret"}, nil
		}
		if err != nil {
			return ErrSecurityBaseline
		}
		permissions = append(permissions, permission)
	}
	discoveries := map[string]*metav1.APIResourceList{}
	for _, permission := range permissions {
		attrs := permission.spec.ResourceAttributes
		gv := schema.GroupVersion{Group: attrs.Group, Version: attrs.Version}.String()
		if discoveries[gv] == nil {
			var err error
			discoveries[gv], err = p.access.discover(ctx, gv)
			if err != nil {
				return ErrSecurityBaseline
			}
		}
		if !discoveredPermission(discoveries[gv], permission) || p.access.authorize(ctx, permission.spec) != nil {
			return ErrSecurityBaseline
		}
	}
	if ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (c *ClusterCold) collectCompletedRetirementEvidence(ctx context.Context, request LifecycleCheck) (*coldWorldTuple, *installobserve.Observation, []*corev1.PersistentVolume, [32]byte, error) {
	var zero [32]byte
	if c == nil || c.prerequisites == nil {
		return nil, nil, nil, zero, ErrColdSafety
	}
	observation, err := c.prerequisites.observeCompletedRetirement(ctx, request)
	if err != nil {
		return nil, nil, nil, zero, ErrColdSafety
	}
	return c.evaluateEvidence(ctx, request, observation)
}
