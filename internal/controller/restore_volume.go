// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// verifyRestoreVolumeIsolation uses uncached API reads to prove every exact
// candidate claim is backed by a PV distinct from every previous PV and any
// still-existing exact backup-source PV.
// PVC names alone are insufficient: two PV objects can alias one CSI handle.
// Unknown volume sources fail closed until their physical identity has a
// certified comparison rule. No PV source details enter status or logs.
func (r *GameRestoreReconciler) verifyRestoreVolumeIsolation(ctx context.Context, namespace string, restoreCreated metav1.Time, previous, candidate []arcadev1alpha1.DataPathIdentity, backupSource ...[]arcadev1alpha1.DataPathIdentity) error {
	if restoreCreated.IsZero() || len(previous) == 0 || len(previous) != len(candidate) {
		return errors.New("restore volume isolation requires complete data sets")
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	seenClaim := make(map[string]struct{}, len(previous)+len(candidate))
	seenPV := make(map[string]struct{}, len(previous)+len(candidate))
	seenSource := make(map[string]struct{}, len(previous)+len(candidate))
	candidateSource := make(map[string]struct{}, len(candidate))
	for setIndex, set := range [][]arcadev1alpha1.DataPathIdentity{previous, candidate} {
		for _, path := range set {
			claimRef := path.ClaimRef
			if _, duplicate := seenClaim[claimRef.Name]; duplicate {
				return errors.New("restore data sets alias one claim")
			}
			seenClaim[claimRef.Name] = struct{}{}
			binding, err := boundRestoreVolumeFingerprint(ctx, reader, namespace, claimRef)
			if err != nil {
				return err
			}
			if setIndex == 1 && (binding.claimCreated.IsZero() || binding.pvCreated.IsZero() ||
				binding.claimCreated.Time.Before(restoreCreated.Time) || binding.pvCreated.Time.Before(binding.claimCreated.Time)) {
				return errors.New("candidate claim or backing volume predates the restore-owned fresh provisioning")
			}
			if _, duplicate := seenPV[binding.pvName]; duplicate {
				return errors.New("restore data sets alias one PersistentVolume")
			}
			seenPV[binding.pvName] = struct{}{}
			if _, duplicate := seenSource[binding.fingerprint]; duplicate {
				return errors.New("restore data sets alias one backing volume source")
			}
			seenSource[binding.fingerprint] = struct{}{}
			if setIndex == 1 {
				candidateSource[binding.fingerprint] = struct{}{}
			}
		}
	}
	for _, sourceSet := range backupSource {
		if len(sourceSet) != len(previous) {
			return errors.New("backup source volume set is incomplete")
		}
		for _, path := range sourceSet {
			ref := path.ClaimRef
			if ref.Namespace != nil || ref.Name == "" || ref.UID == "" {
				return errors.New("backup source volume identity is incomplete")
			}
			// The exact backup-source PVC may have been removed after backup.
			// A replacement at the same name is not the source identity.
			claim := &corev1.PersistentVolumeClaim{}
			err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, claim)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return errors.New("inspect backup source volume failed")
			}
			if string(claim.UID) != ref.UID {
				continue
			}
			binding, err := boundRestoreVolumeFingerprint(ctx, reader, namespace, ref)
			if err != nil {
				return err
			}
			if _, aliases := candidateSource[binding.fingerprint]; aliases {
				return errors.New("candidate data aliases a still-existing backup source volume")
			}
		}
	}
	return nil
}

type restoreVolumeBinding struct {
	pvName, fingerprint     string
	claimCreated, pvCreated metav1.Time
}

func boundRestoreVolumeFingerprint(ctx context.Context, reader client.Reader, namespace string, ref arcadev1alpha1.ExactLocalReference) (restoreVolumeBinding, error) {
	if ref.Namespace != nil || ref.Name == "" || ref.UID == "" {
		return restoreVolumeBinding{}, errors.New("restore volume identity is incomplete")
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, claim); err != nil ||
		string(claim.UID) != ref.UID || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" || !claim.DeletionTimestamp.IsZero() {
		return restoreVolumeBinding{}, errors.New("restore data claim is not exactly bound")
	}
	pv := &corev1.PersistentVolume{}
	if err := reader.Get(ctx, types.NamespacedName{Name: claim.Spec.VolumeName}, pv); err != nil ||
		pv.Status.Phase != corev1.VolumeBound || pv.Spec.ClaimRef == nil ||
		pv.Spec.ClaimRef.Namespace != namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.UID != claim.UID {
		return restoreVolumeBinding{}, errors.New("restore backing volume is not bound to its exact claim")
	}
	fingerprint, err := restoreVolumeSourceFingerprint(pv)
	return restoreVolumeBinding{pvName: claim.Spec.VolumeName, fingerprint: fingerprint,
		claimCreated: claim.CreationTimestamp, pvCreated: pv.CreationTimestamp}, err
}

func restoreVolumeSourceFingerprint(pv *corev1.PersistentVolume) (string, error) {
	if pv == nil {
		return "", errors.New("restore backing volume source is unavailable")
	}
	source := pv.Spec.PersistentVolumeSource
	switch {
	case source.CSI != nil && source.CSI.Driver != "" && source.CSI.VolumeHandle != "":
		return "csi:" + source.CSI.Driver + ":" + source.CSI.VolumeHandle, nil
	default:
		return "", errors.New("restore backing volume source is not certified for isolation")
	}
}
