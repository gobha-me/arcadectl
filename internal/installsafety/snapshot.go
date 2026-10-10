// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installsafety validates complete, uncached observations before an
// installer removes runtime authority. It performs no reads or mutations. A
// successful check is not a lock, admission-behavior proof, or proof that API
// and controller Pods have stopped: the engine must establish those separately
// and repeat the snapshot after quiescence and before authority removal.
package installsafety

import (
	"errors"
	"strings"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const MaxObjectsPerList = 10000

var (
	ErrInvalid   = errors.New("installation safety observation is incomplete or invalid")
	ErrOwnership = errors.New("installation safety ownership could not be proved")
	ErrDomain    = errors.New("installation has unsettled lifecycle intent")
	ErrWorker    = errors.New("installation data-operation workers or fences remain")
	ErrRetention = errors.New("installation retained objects remain in use or would be garbage collected")
	ErrAdmission = errors.New("installation retained admission specifications are not proved current")
)

// Snapshot lists must have been obtained without selectors, from authoritative
// clients. The engine combines every page, preserves its collection RV, and
// leaves Continue empty only after the final page. Nil lists are never empty
// evidence. These public fields are borrowed read-only for the duration of a
// call; concurrent mutation by callers is unsupported. Secrets are metadata
// only: credential and TLS bytes have no place in a safety observation.
type Snapshot struct {
	GameServers *arcade.GameServerList
	Backups     *arcade.GameBackupList
	Restores    *arcade.GameRestoreList
	Destroys    *arcade.GameDestroyList
	Operations  *arcade.ArcadeOperationList
	Jobs        *batchv1.JobList
	Pods        *corev1.PodList
	Leases      *coordinationv1.LeaseList
	Claims      *corev1.PersistentVolumeClaimList
	Secrets     *metav1.PartialObjectMetadataList
	Policies    *admissionv1.ValidatingAdmissionPolicyList
	Bindings    *admissionv1.ValidatingAdmissionPolicyBindingList
	// Owners supplies metadata-only authoritative recursive owner GETs, including
	// retained inventory anchors not covered by the lists. Missing/NotFound,
	// replaced, cyclic, or contradictory owner evidence is never GC-safe.
	Owners []OwnerNode
}

// Validate checks domain settlement, broad worker evidence, retained mounts and
// GC hazards, and exact current admission specifications. Inventory must come
// from the original-identity Namespace journal, not labels or name-based
// adoption. The caller must additionally correlate live resources with the
// trusted plan and perform actual dry-run admission probes.
func Validate(plan *installrender.Plan, snapshot *Snapshot, inventory []installstate.Resource) error {
	if !plan.IsTrusted() || !complete(snapshot) {
		return ErrInvalid
	}
	owned, removable, err := inventoryContract(plan, inventory)
	if err != nil {
		return err
	}
	if err := validateDomain(plan.Namespace(), snapshot, removable); err != nil {
		return err
	}
	if err := validateWorkers(plan.Namespace(), snapshot, removable); err != nil {
		return err
	}
	if err := validateAdmission(plan, snapshot, owned, removable); err != nil {
		return err
	}
	return validateOwnerClosure(plan, snapshot, inventory, owned, removable)
}

func complete(s *Snapshot) bool {
	if s == nil || s.GameServers == nil || s.Backups == nil || s.Restores == nil || s.Destroys == nil || s.Operations == nil || s.Jobs == nil || s.Pods == nil || s.Leases == nil || s.Claims == nil || s.Secrets == nil || s.Policies == nil || s.Bindings == nil {
		return false
	}
	for _, list := range []struct {
		meta  metav1.ListMeta
		count int
	}{
		{s.GameServers.ListMeta, len(s.GameServers.Items)}, {s.Backups.ListMeta, len(s.Backups.Items)},
		{s.Restores.ListMeta, len(s.Restores.Items)}, {s.Destroys.ListMeta, len(s.Destroys.Items)},
		{s.Operations.ListMeta, len(s.Operations.Items)}, {s.Jobs.ListMeta, len(s.Jobs.Items)},
		{s.Pods.ListMeta, len(s.Pods.Items)}, {s.Leases.ListMeta, len(s.Leases.Items)},
		{s.Claims.ListMeta, len(s.Claims.Items)}, {s.Secrets.ListMeta, len(s.Secrets.Items)},
		{s.Policies.ListMeta, len(s.Policies.Items)}, {s.Bindings.ListMeta, len(s.Bindings.Items)},
	} {
		if list.meta.ResourceVersion == "" || len(list.meta.ResourceVersion) > 128 || list.meta.Continue != "" || list.meta.RemainingItemCount != nil && *list.meta.RemainingItemCount != 0 || list.count > MaxObjectsPerList {
			return false
		}
	}
	return true
}

func inventoryContract(plan *installrender.Plan, inventory []installstate.Resource) (map[installstate.Key]types.UID, map[types.UID]bool, error) {
	if len(inventory) == 0 || len(inventory) > installstate.MaxResources {
		return nil, nil, ErrOwnership
	}
	contracts := map[installstate.Key]installrender.Resource{}
	for _, r := range plan.Resources() {
		o := r.Object
		contracts[installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}] = r
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		contracts[installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: plan.Namespace(), Name: name}] = installrender.Resource{Retained: true, Phase: installrender.API}
	}
	owned := map[installstate.Key]types.UID{}
	removable := map[types.UID]bool{}
	seenUID := map[types.UID]bool{}
	for _, r := range inventory {
		contract, ok := contracts[r.Key]
		if !ok || r.UID == "" || len(r.UID) > 128 || strings.ContainsAny(string(r.UID), "\r\n\x00") || seenUID[r.UID] || owned[r.Key] != "" || r.Retained != contract.Retained || r.Phase != contract.Phase {
			return nil, nil, ErrOwnership
		}
		owned[r.Key], seenUID[r.UID] = r.UID, true
		if !r.Retained {
			removable[r.UID] = true
		}
	}
	if owned[installstate.Key{APIVersion: "v1", Kind: "Namespace", Name: plan.Namespace()}] == "" {
		return nil, nil, ErrOwnership
	}
	return owned, removable, nil
}

func gcHazard(metadata metav1.Object, removable map[types.UID]bool) bool {
	for _, owner := range metadata.GetOwnerReferences() {
		if removable[owner.UID] {
			return true
		}
	}
	return false
}

// A complete list cannot contain duplicate identities or foreign-namespace
// items. These checks prevent malformed adapters from quietly skipping work.
func namespaced(metadata metav1.Object, namespace string, seen map[string]bool) bool {
	if metadata.GetNamespace() != namespace || metadata.GetName() == "" || len(metadata.GetName()) > 253 || !boundedIdentity(string(metadata.GetUID())) || !boundedIdentity(metadata.GetResourceVersion()) || seen[metadata.GetName()] {
		return false
	}
	seen[metadata.GetName()] = true
	return true
}

func boundedIdentity(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00")
}

func settled(metadata metav1.Object, observed int64) bool {
	return metadata.GetDeletionTimestamp() == nil && metadata.GetGeneration() > 0 && observed == metadata.GetGeneration()
}
