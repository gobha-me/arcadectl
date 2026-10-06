// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
)

var ErrColdSafety = errors.New("installation cold-data safety is unproved")

// ClusterCold is the closed cold-data portion, not a complete LifecycleChecks
// provider. It grants no PVC/PV deletion authority or runtime-stop fallback.
type ClusterCold struct {
	prerequisites *ClusterPrerequisites
	games         *catalog.Catalog
}

func NewClusterCold(p *ClusterPrerequisites) (*ClusterCold, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil {
		return nil, ErrInvalid
	}
	games, err := catalog.Builtins()
	if err != nil {
		return nil, ErrInvalid
	}
	return &ClusterCold{p, games}, nil
}

// Verify repeats whole authoritative observations and exact current-world/PV
// identity across the read interval. Leader-election renewals and unrelated
// global attachment changes are not world identity, but both complete snapshots
// must independently satisfy every obligation. This is not a cluster lock.
func (c *ClusterCold) Verify(ctx context.Context, request LifecycleCheck) error {
	if c == nil || c.prerequisites == nil || c.games == nil || ctx == nil || request.Checkpoint != ColdSafety || request.Options.Now.IsZero() {
		return ErrInvalid
	}
	p := c.prerequisites
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	admission, err := NewClusterAdmission(p.engine, p.access)
	if err != nil {
		return ErrInvalid
	}
	before, err := admission.configured(ctx, request)
	if err != nil {
		return ErrColdSafety
	}
	first, err := c.collect(ctx, request)
	if err != nil {
		return ErrColdSafety
	}
	second, err := c.collect(ctx, request)
	if err != nil || first != second {
		return ErrColdSafety
	}
	after, err := admission.configured(ctx, request)
	if err != nil || !sameAdmissionConfiguration(before, after) || p.original(ctx, request.Snapshot) != nil {
		return ErrColdSafety
	}
	return nil
}

func (c *ClusterCold) collect(ctx context.Context, request LifecycleCheck) ([32]byte, error) {
	var zero [32]byte
	observation, err := c.prerequisites.observe(ctx, request)
	if err != nil {
		return zero, ErrColdSafety
	}
	s := observation.Snapshot()
	r := observation.Runtime()
	volumes, err := c.prerequisites.coldVolumes(ctx, s, r)
	if err != nil || installsafety.ValidateCold(request.Target, s, r, request.Snapshot.Document().Resources, volumes, c.games) != nil {
		return zero, ErrColdSafety
	}
	return coldWorldWitness(observation, volumes)
}

// Each PV read is an exact-name GET derived from the complete live namespace
// claim inventory and global attachment sources, separately discovery/SSAR-authorized. No PV list,
// wildcard authority, preferred-version mapper or provisioner is introduced.
func (p *ClusterPrerequisites) coldVolumes(ctx context.Context, s *installsafety.Snapshot, r *installsafety.RuntimeSnapshot) ([]*corev1.PersistentVolume, error) {
	if p == nil || p.access == nil || ctx == nil || s == nil || s.Claims == nil || r == nil || r.Attachments == nil || len(s.Claims.Items) > installsafety.MaxObjectsPerList || len(r.Attachments.Items) > installsafety.MaxObjectsPerList {
		return nil, ErrColdSafety
	}
	var names []string
	seen := map[string]bool{}
	for _, claim := range s.Claims.Items {
		if claim.Spec.VolumeName == "" {
			continue
		}
		if !addressPart(claim.Spec.VolumeName) || seen[claim.Spec.VolumeName] {
			return nil, ErrColdSafety
		}
		seen[claim.Spec.VolumeName] = true
		names = append(names, claim.Spec.VolumeName)
	}
	// Differently named PVs may alias the same physical CSI volume. Prove
	// their sources, not just that attachment names differ from claim names.
	if len(names) != 0 {
		for _, attachment := range r.Attachments.Items {
			name := attachment.Spec.Source.PersistentVolumeName
			if name == nil {
				continue
			}
			if !addressPart(*name) {
				return nil, ErrColdSafety
			}
			if !seen[*name] {
				seen[*name] = true
				names = append(names, *name)
			}
		}
	}
	sort.Strings(names)
	volumes := make([]*corev1.PersistentVolume, 0, len(names))
	if len(names) == 0 {
		return volumes, nil
	}
	discovery, err := p.access.discover(ctx, "v1")
	if err != nil {
		return nil, ErrColdSafety
	}
	budget := 32 * 1024 * 1024
	for _, name := range names {
		permission := proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "persistentvolumes", Name: name, Verb: "get"}}, kind: "PersistentVolume"}
		if !discoveredPermission(discovery, permission) || p.access.authorize(ctx, permission.spec) != nil {
			return nil, ErrColdSafety
		}
		volume := &corev1.PersistentVolume{}
		raw, err := p.access.proofRequest(ctx, http.MethodGet, "/api/v1/persistentvolumes/"+name, nil, volume)
		if err != nil || volume.APIVersion != "v1" || volume.Kind != "PersistentVolume" || volume.Name != name || volume.Namespace != "" {
			return nil, ErrColdSafety
		}
		body, err := json.Marshal(raw)
		budget -= len(body)
		if err != nil || budget < 0 {
			return nil, ErrColdSafety
		}
		volumes = append(volumes, volume)
	}
	return volumes, nil
}

func coldWorldWitness(o *installobserve.Observation, volumes []*corev1.PersistentVolume) ([32]byte, error) {
	var zero [32]byte
	if o == nil || o.Snapshot() == nil {
		return zero, ErrColdSafety
	}
	s := o.Snapshot()
	sort.Slice(s.GameServers.Items, func(i, j int) bool { return s.GameServers.Items[i].Name < s.GameServers.Items[j].Name })
	sort.Slice(s.Claims.Items, func(i, j int) bool { return s.Claims.Items[i].Name < s.Claims.Items[j].Name })
	protected := map[string]bool{}
	for _, claim := range s.Claims.Items {
		if claim.Spec.VolumeName != "" {
			protected[claim.Spec.VolumeName] = true
		}
	}
	var worlds []*corev1.PersistentVolume
	for _, volume := range volumes {
		if protected[volume.Name] {
			worlds = append(worlds, volume)
		}
	}
	body, err := json.Marshal(struct {
		Servers any
		Claims  any
		Volumes any
	}{s.GameServers.Items, s.Claims.Items, worlds})
	if err != nil || len(body) > 32*1024*1024 {
		return zero, ErrColdSafety
	}
	return sha256.Sum256(body), nil
}
