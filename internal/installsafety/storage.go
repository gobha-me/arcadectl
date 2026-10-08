// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ValidateCSIDetachment is ONLY the pure physical storage-source portion of
// cold safety, shared with admission's complete phase observation. It accepts
// no exemption/fixture identities and treats EVERY claim's named backing as
// protected regardless of labels/status. Inputs must come from the complete
// bound observer plus exact derived named PV GETs; typed values cannot prove
// that provenance. A success does not prove world identity, PVC/PV binding,
// retention, mounts, workers, owner closure or admission and is no effect permit.
// In particular an empty-volume Lost claim may pass this component but MUST
// still fail ordinary ValidateCold. Phase fixtures require separate whole WAL
// identity/inertness checks, never a projected snapshot passed to ordinary Cold.
func ValidateCSIDetachment(claims *corev1.PersistentVolumeClaimList, attachments *storagev1.VolumeAttachmentList, volumes []*corev1.PersistentVolume) error {
	if claims == nil || attachments == nil || len(claims.Items) > MaxObjectsPerList || len(attachments.Items) > MaxObjectsPerList {
		return ErrCold
	}
	// Recheck the envelopes here as well as in the bound observer. The phase
	// caller must not mistake a partial attachment page for physical absence.
	// These checks still cannot authenticate an arbitrary caller's typed values.
	for _, list := range []runtime.Object{claims, attachments} {
		metadata, err := meta.ListAccessor(list)
		items, itemErr := meta.ExtractList(list)
		if err != nil || itemErr != nil || !boundedIdentity(metadata.GetResourceVersion()) || metadata.GetContinue() != "" || metadata.GetRemainingItemCount() != nil && *metadata.GetRemainingItemCount() != 0 {
			return ErrCold
		}
		names, uids := map[string]bool{}, map[types.UID]bool{}
		namespace := ""
		for _, item := range items {
			object, err := meta.Accessor(item)
			if err != nil || object.GetName() == "" || !boundedIdentity(string(object.GetUID())) || !boundedIdentity(object.GetResourceVersion()) || names[object.GetName()] || uids[object.GetUID()] {
				return ErrCold
			}
			if list == attachments {
				if object.GetNamespace() != "" {
					return ErrCold
				}
			} else {
				if len(validation.IsDNS1123Label(object.GetNamespace())) != 0 || namespace != "" && object.GetNamespace() != namespace {
					return ErrCold
				}
				namespace = object.GetNamespace()
			}
			names[object.GetName()], uids[object.GetUID()] = true, true
		}
	}
	backing := map[string]bool{}
	wanted := map[string]bool{}
	for _, claim := range claims.Items {
		if name := claim.Spec.VolumeName; name != "" {
			if len(validation.IsDNS1123Subdomain(name)) != 0 || backing[name] {
				return ErrCold
			}
			backing[name], wanted[name] = true, true
		}
	}
	for _, attachment := range attachments.Items {
		if !validCSIDriver(attachment.Spec.Attacher) || len(validation.IsDNS1123Subdomain(attachment.Spec.NodeName)) != 0 {
			return ErrCold
		}
		source := attachment.Spec.Source
		if (source.PersistentVolumeName == nil) == (source.InlineVolumeSpec == nil) || source.PersistentVolumeName != nil && len(validation.IsDNS1123Subdomain(*source.PersistentVolumeName)) != 0 {
			return ErrCold
		}
		if len(backing) != 0 && source.PersistentVolumeName != nil {
			wanted[*source.PersistentVolumeName] = true
		}
	}
	if len(volumes) != len(wanted) {
		return ErrCold
	}
	seen := map[string]bool{}
	seenUIDs := map[types.UID]bool{}
	sources := map[string]csiIdentity{}
	protected := map[csiIdentity]bool{}
	for _, volume := range volumes {
		if volume == nil || !wanted[volume.Name] || volume.Namespace != "" || !boundedIdentity(string(volume.UID)) || !boundedIdentity(volume.ResourceVersion) || volume.DeletionTimestamp != nil || seen[volume.Name] || seenUIDs[volume.UID] {
			return ErrCold
		}
		identity, ok := csiBacking(volume.Spec.PersistentVolumeSource)
		if !ok {
			return ErrCold
		}
		sources[volume.Name] = identity
		if backing[volume.Name] {
			protected[identity] = true
		}
		seen[volume.Name], seenUIDs[volume.UID] = true, true
	}
	if len(seen) != len(wanted) {
		return ErrCold
	}
	for _, attachment := range attachments.Items {
		source := attachment.Spec.Source
		// Attached=false is not detached: any remaining object is attach
		// intent, including pending, deleting and error states. Require absence.
		if source.PersistentVolumeName != nil {
			if len(protected) != 0 && protected[sources[*source.PersistentVolumeName]] {
				return ErrCold
			}
		} else {
			inline := source.InlineVolumeSpec
			identity, ok := csiBacking(inline.PersistentVolumeSource)
			if !ok || !validAccessModes(inline.AccessModes) || inline.ClaimRef != nil || len(inline.Capacity) != 0 || inline.NodeAffinity != nil || inline.StorageClassName != "" || volumeMode(inline.VolumeMode) != corev1.PersistentVolumeFilesystem || inline.PersistentVolumeReclaimPolicy != "" && inline.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain || protected[identity] {
				return ErrCold
			}
		}
	}
	return nil
}
