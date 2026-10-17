// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func validateDomain(namespace string, s *Snapshot, removable map[types.UID]bool) error {
	seen := map[string]bool{}
	for i := range s.GameServers.Items {
		o := &s.GameServers.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if !settled(o, o.Status.ObservedGeneration) || o.Spec.DesiredState != arcade.DesiredStateStopped || o.Status.Phase != arcade.PhaseStopped {
			return ErrDomain
		}
		if gcHazard(o, removable) {
			return ErrRetention
		}
	}
	seen = map[string]bool{}
	for i := range s.Backups.Items {
		o := &s.Backups.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if !settled(o, o.Status.ObservedGeneration) || !dataTerminal(o.Status.Phase) {
			return ErrDomain
		}
		if gcHazard(o, removable) {
			return ErrRetention
		}
	}
	seen = map[string]bool{}
	for i := range s.Restores.Items {
		o := &s.Restores.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if !settled(o, o.Status.ObservedGeneration) || !dataTerminal(o.Status.Phase) {
			return ErrDomain
		}
		if gcHazard(o, removable) {
			return ErrRetention
		}
	}
	seen = map[string]bool{}
	for i := range s.Destroys.Items {
		o := &s.Destroys.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if !settled(o, o.Status.ObservedGeneration) || !(o.Status.Phase == arcade.DestroyPhaseSucceeded || o.Status.Phase == arcade.DestroyPhaseFailed || o.Status.Phase == arcade.DestroyPhaseCancelled) {
			return ErrDomain
		}
		if gcHazard(o, removable) {
			return ErrRetention
		}
	}
	seen = map[string]bool{}
	for i := range s.Operations.Items {
		o := &s.Operations.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		if !settled(o, o.Status.ObservedGeneration) || len(o.Finalizers) != 0 || !(o.Status.Phase == arcade.OperationPhaseSucceeded || o.Status.Phase == arcade.OperationPhaseFailed || o.Status.Phase == arcade.OperationPhaseCancelled) {
			return ErrDomain
		}
		if gcHazard(o, removable) {
			return ErrRetention
		}
	}
	seen = map[string]bool{}
	for i := range s.Secrets.Items {
		o := &s.Secrets.Items[i]
		if !namespaced(o, namespace, seen) {
			return ErrInvalid
		}
		// Refuse GC of foreign Secrets too: deleting runtime authority must not
		// remove namespace data that was not an installer-owned delete target.
		if gcHazard(o, removable) {
			return ErrRetention
		}
	}
	return nil
}

func dataTerminal(phase arcade.DataOperationPhase) bool {
	return phase == arcade.DataPhaseSucceeded || phase == arcade.DataPhaseFailed || phase == arcade.DataPhaseCancelled
}

func recordedClaims(s *Snapshot) map[string]bool {
	claims := map[string]bool{}
	add := func(data *arcade.RetainedDataReference) {
		if data != nil {
			for _, claim := range data.Claims {
				if claim.ClaimRef.Name != "" {
					claims[claim.ClaimRef.Name] = true
				}
			}
		}
	}
	paths := func(data []arcade.DataPathIdentity) {
		for _, path := range data {
			if path.ClaimRef.Name != "" {
				claims[path.ClaimRef.Name] = true
			}
		}
	}
	for _, o := range s.GameServers.Items {
		add(o.Spec.Storage.Reattach)
		add(o.Status.ActiveData)
		add(o.Status.ObservedData)
	}
	for _, o := range s.Backups.Items {
		if o.Status.Source != nil {
			paths(o.Status.Source.Paths)
		}
	}
	for _, o := range s.Restores.Items {
		if o.Status.Source != nil {
			paths(o.Status.Source.Paths)
		}
		paths(o.Status.PreviousData)
		paths(o.Status.CandidateData)
		paths(o.Status.ActiveData)
	}
	for _, o := range s.Destroys.Items {
		add(&o.Spec.Target.Data)
	}
	for _, o := range s.Operations.Items {
		if o.Status.Plan != nil {
			add(o.Status.Plan.Data)
			if o.Status.Plan.ServerIntent != nil {
				add(o.Status.Plan.ServerIntent.Storage.Reattach)
			}
		}
		if o.Status.RetainedWorld != nil {
			add(&o.Status.RetainedWorld.Target.Data)
		}
	}
	return claims
}

func operationOwner(metadata metav1.Object) bool {
	for _, owner := range metadata.GetOwnerReferences() {
		if owner.APIVersion == arcade.GroupVersion.String() {
			switch owner.Kind {
			case "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation":
				return true
			}
		}
	}
	return false
}
