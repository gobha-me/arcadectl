// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func bootstrapRBACKey(key installstate.Key) bool {
	switch key.Kind {
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		return true
	}
	return false
}

// bootstrapAccess is also enforced by the coordinator, independently of the
// provider. It is not full cold/runtime proof: those need sealed complete lists.
func (e *Engine) bootstrapAccess(ctx context.Context, s *installstate.Snapshot) (map[installstate.Key]admissionIdentity, error) {
	if e == nil || ctx == nil || s == nil {
		return nil, ErrInvalid
	}
	d := s.Document()
	if d.Mode != installstate.Install || d.Stage != installstate.Applying || d.Installed || d.Pending != nil || d.AdmissionRetirementRevision != 0 || d.ActivePackage != "" && d.ActivePackage != d.TargetPackage {
		return nil, ErrAdmission
	}
	plan, contract := e.plans[d.TargetPackage], e.contracts[d.TargetPackage]
	if plan == nil || contract == nil {
		return nil, ErrAdmission
	}
	identities := map[installstate.Key]admissionIdentity{}
	accountCount := 0
	if d.ActivePackage == "" {
		for _, resource := range d.Resources {
			if resource.Key.Kind == "Secret" {
				return nil, ErrAdmission
			}
		}
	}
	for _, resource := range plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		entry, _ := e.inventory(d, key)
		switch key.Kind {
		case "Service", "Deployment":
			if entry != nil {
				return nil, ErrAdmission
			}
			if _, err := e.access.Get(ctx, key); !apierrors.IsNotFound(err) {
				return nil, ErrAdmission
			}
		case "ServiceAccount":
			template, err := contract.Template(key, false)
			if err != nil || entry == nil || entry.TemplateSHA256 != template.Hash() {
				return nil, ErrAdmission
			}
			live, err := e.access.Get(ctx, key)
			if err != nil || template.MatchLive(live, entry.UID) != nil {
				return nil, ErrAdmission
			}
			identities[key] = admissionIdentity{entry.UID, live.GetResourceVersion(), template.Hash()}
			accountCount++
		case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
			if entry == nil {
				if _, err := e.access.Get(ctx, key); !apierrors.IsNotFound(err) {
					return nil, ErrAdmission
				}
				identities[key] = admissionIdentity{} // exact original address absent
				continue
			}
			template, err := contract.Template(key, false)
			if err != nil || entry.TemplateSHA256 != template.Hash() {
				return nil, ErrAdmission
			}
			live, err := e.access.Get(ctx, key)
			if err != nil || template.MatchLive(live, entry.UID) != nil {
				return nil, ErrAdmission
			}
			identities[key] = admissionIdentity{entry.UID, live.GetResourceVersion(), template.Hash()}
		}
	}
	if accountCount == 0 {
		return nil, ErrAdmission
	}
	return identities, nil
}

// VerifyBootstrap proves only the narrow RBAC-bootstrap obligation. It does not
// certify identity-specific UPDATE/DELETE/subresource behavior, stand in for
// AdmissionEffective, or grant any additional runtime actor permissions.
func (a *ClusterAdmission) VerifyBootstrap(ctx context.Context, request LifecycleCheck) error {
	if a == nil || a.prerequisites == nil || ctx == nil || request.Snapshot == nil || request.Checkpoint != BootstrapAdmission || request.Mode != installstate.Install || request.Target == nil || request.Target.Digest() != request.Snapshot.Document().TargetPackage {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	p := a.prerequisites
	identities, err := p.engine.bootstrapAccess(ctx, request.Snapshot)
	if err != nil {
		return ErrAdmission
	}
	before, err := a.configured(ctx, request)
	if err != nil {
		return ErrAdmission
	}
	cold, err := NewClusterCold(p)
	if err != nil {
		return ErrAdmission
	}
	collect := func() ([32]byte, error) {
		observation, err := p.observe(ctx, request)
		if err != nil || observation == nil {
			return [32]byte{}, ErrAdmission
		}
		s, r := observation.Snapshot(), observation.Runtime()
		if !bootstrapRuntimeAbsent(s, r) || !bootstrapCredentials(request.Snapshot.Document(), s) {
			return [32]byte{}, ErrAdmission
		}
		volumes, err := p.coldVolumes(ctx, s, r)
		if err != nil || installsafety.ValidateCold(request.Target, s, r, request.Snapshot.Document().Resources, volumes, cold.games) != nil {
			return [32]byte{}, ErrAdmission
		}
		return coldWorldWitness(observation, volumes)
	}
	first, err := collect()
	if err != nil || a.verifyCreateProbes(ctx, request) != nil {
		return ErrAdmission
	}
	second, err := collect()
	if err != nil || first != second {
		return ErrAdmission
	}
	after, err := a.configured(ctx, request)
	if err != nil || !sameAdmissionConfiguration(before, after) {
		return ErrAdmission
	}
	finalIdentities, err := p.engine.bootstrapAccess(ctx, request.Snapshot)
	if err != nil || !reflect.DeepEqual(identities, finalIdentities) || p.original(ctx, request.Snapshot) != nil {
		return ErrAdmission
	}
	return nil
}

func bootstrapRuntimeAbsent(s *installsafety.Snapshot, r *installsafety.RuntimeSnapshot) bool {
	if !completeStoppedLists(s, r) {
		return false
	}
	// Deliberately stricter than stopped installation-family classification:
	// even suspended, deleting or terminal workloads must be absent. No actor
	// receives new signed permissions while any namespace workload can use them.
	return len(s.Pods.Items) == 0 && len(s.Jobs.Items) == 0 &&
		len(r.Deployments.Items) == 0 && len(r.ReplicaSets.Items) == 0 &&
		len(r.StatefulSets.Items) == 0 && len(r.DaemonSets.Items) == 0 &&
		len(r.ReplicationControllers.Items) == 0 && len(r.CronJobs.Items) == 0 &&
		len(r.EndpointSlices.Items) == 0
}

// Secret data is not part of observations. Retaining reinstall additionally
// verifies these originals through SecretWorkflow at the coordinator boundary.
func bootstrapCredentials(d installstate.Document, s *installsafety.Snapshot) bool {
	if s == nil || s.Secrets == nil || s.Secrets.ResourceVersion == "" || s.Secrets.Continue != "" || s.Secrets.RemainingItemCount != nil && *s.Secrets.RemainingItemCount != 0 {
		return false
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		var recorded *installstate.Resource
		for i := range d.Resources {
			if d.Resources[i].Key == secretKey(d.Namespace, name) {
				recorded = &d.Resources[i]
			}
		}
		found := false
		for _, live := range s.Secrets.Items {
			if live.Name != name {
				continue
			}
			if found || d.ActivePackage == "" || recorded == nil || !recorded.Retained || live.UID != recorded.UID || live.Namespace != d.Namespace || live.ResourceVersion == "" || live.DeletionTimestamp != nil {
				return false
			}
			found = true
		}
		if d.ActivePackage == "" && recorded != nil || d.ActivePackage != "" && !found {
			return false
		}
	}
	return true
}
