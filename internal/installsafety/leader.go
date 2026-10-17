// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func controllerElectionAddress(name string) bool {
	// These are the two existing managerOptionsForMode IDs. Do not rename
	// either: old and new election addresses could otherwise elect two leaders.
	return name == "controller.arcade.gobha.me" || name == "destroy-controller.arcade.gobha.me"
}

// ControllerElectionBookkeeping exposes only intrinsic shape classification
// to the bound phase observer. It is NOT ownership, readiness, leadership or
// permission: that caller independently binds the original signed Pod chain.
func ControllerElectionBookkeeping(namespace string, lease *coordinationv1.Lease) bool {
	return controllerElectionBookkeeping(namespace, lease)
}

// controllerElectionBookkeeping is an intrinsic non-data Lease classifier,
// NOT proof of its creator, installation ownership, runtime readiness or effect
// authority. The current worker/data-fence contracts require different derived
// addresses, operation metadata and a bare operation UID holder. Callers must
// still reject those independent signals BEFORE invoking this classifier.
//
// Ownerless native election Leases outlive paused/removed controller Pods. No
// surviving Pod, recent renewal or controller presence is required here: those
// are separate lifecycle obligations. Empty/released holders are not produced
// by the current manager (ReleaseOnCancel=false) and are deliberately refused.
func controllerElectionBookkeeping(namespace string, l *coordinationv1.Lease) bool {
	if l == nil || !controllerElectionAddress(l.Name) || l.Namespace != namespace ||
		len(l.Labels) != 0 || len(l.Annotations) != 0 || len(l.OwnerReferences) != 0 ||
		l.GenerateName != "" || len(l.Finalizers) != 0 || l.DeletionTimestamp != nil ||
		l.DeletionGracePeriodSeconds != nil || l.Generation != 0 || l.CreationTimestamp.IsZero() ||
		l.CreationTimestamp.Year() < 1 || l.CreationTimestamp.Year() > 9999 ||
		l.APIVersion != "" && l.APIVersion != coordinationv1.SchemeGroupVersion.String() ||
		l.Kind != "" && l.Kind != "Lease" || !electionUUID(string(l.UID)) {
		return false
	}
	rv, err := strconv.ParseUint(l.ResourceVersion, 10, 64)
	if err != nil || rv == 0 || strconv.FormatUint(rv, 10) != l.ResourceVersion {
		return false
	}
	s := l.Spec
	if s.HolderIdentity == nil || s.LeaseDurationSeconds == nil || *s.LeaseDurationSeconds != 15 ||
		s.LeaseTransitions == nil || *s.LeaseTransitions < 0 || s.Strategy != nil || s.PreferredHolder != nil ||
		!electionMicroTime(s.AcquireTime) || !electionMicroTime(s.RenewTime) || s.RenewTime.Before(s.AcquireTime) {
		return false
	}
	// controller-runtime's native identity is os.Hostname()+"_"+NewUUID().
	// Signed Pods use the default DNS-label hostname. Never accept a bare UID,
	// ambiguous extra parts, upper-case/alternate UUID spelling or a nil UUID.
	host, suffix, found := strings.Cut(*s.HolderIdentity, "_")
	return found && host != "" && len(validation.IsDNS1123Label(host)) == 0 && electionUUID(suffix)
}

func electionUUID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && u != uuid.Nil && u.String() == value && u.Version() == 4 && u.Variant() == uuid.RFC4122
}

func electionMicroTime(value *metav1.MicroTime) bool {
	if value == nil || value.IsZero() || value.Year() < 1 || value.Year() > 9999 || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}
