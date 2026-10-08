// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"errors"
	"reflect"
	"strconv"
	"strings"

	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

var ErrCold = errors.New("installation current world or storage detachment is unproved")

// ValidateCold adds current-world UID/binding and future-remount checks to the
// complete domain/worker/fence/admission/GC obligations. Reads and provenance
// belong to the bound observer; no typed value or successful check is a lock.
// Volumes are ONLY exact named GETs derived from bound namespace claims and,
// when backing worlds exist, the complete global attachment-source closure.
func ValidateCold(plan *installrender.Plan, s *Snapshot, r *RuntimeSnapshot, inventory []installstate.Resource, volumes []*corev1.PersistentVolume, games *catalog.Catalog) error {
	if games == nil || !plan.IsTrusted() || !runtimeComplete(r, plan.Namespace()) {
		return ErrInvalid
	}
	if err := Validate(plan, s, inventory); err != nil {
		return err
	}
	claims := recordedClaims(s)
	byName := map[string]*corev1.PersistentVolumeClaim{}
	boundVolumes := map[string]*corev1.PersistentVolumeClaim{}
	for i := range s.Claims.Items {
		claim := &s.Claims.Items[i]
		// Every namespace claim is retained, even without Arcadectl labels or
		// history. Deletion in progress is never a retention guarantee.
		if claim.DeletionTimestamp != nil {
			return ErrCold
		}
		claims[claim.Name], byName[claim.Name] = true, claim
		switch claim.Status.Phase {
		case corev1.ClaimPending:
			if claim.Spec.VolumeName != "" {
				return ErrCold
			}
		case corev1.ClaimBound:
			if claim.Spec.VolumeName == "" || boundVolumes[claim.Spec.VolumeName] != nil {
				return ErrCold
			}
			boundVolumes[claim.Spec.VolumeName] = claim
		default:
			return ErrCold
		}
	}
	if err := currentWorlds(s, byName, games); err != nil {
		return err
	}
	// Shared physical-source proof works on the COMPLETE claim/attachment/PV
	// evidence. It does not waive any ordinary world, binding, owner or worker
	// obligation; all those checks remain here unchanged.
	if err := ValidateCSIDetachment(s.Claims, r.Attachments, volumes); err != nil {
		return err
	}
	for _, volume := range volumes {
		claim := boundVolumes[volume.Name]
		ref := volume.Spec.ClaimRef
		if claim != nil {
			// Separately read PVs do not enter the namespace GC owner graph.
			// Never retain one whose parent could delete it through GC.
			if len(volume.OwnerReferences) != 0 || ref == nil || ref.Name != claim.Name || ref.Namespace != claim.Namespace || ref.UID != claim.UID || ref.Kind != "" && ref.Kind != "PersistentVolumeClaim" || ref.APIVersion != "" && ref.APIVersion != "v1" || ref.FieldPath != "" || volume.Status.Phase != corev1.VolumeBound || volumeMode(volume.Spec.VolumeMode) != volumeMode(claim.Spec.VolumeMode) || volume.Spec.StorageClassName != claimClass(claim) {
				return ErrCold
			}
			capacity := volume.Spec.Capacity[corev1.ResourceStorage]
			boundCapacity := claim.Status.Capacity[corev1.ResourceStorage]
			if capacity.Sign() <= 0 || boundCapacity.Sign() <= 0 || capacity.Cmp(boundCapacity) < 0 || len(claim.Spec.AccessModes) == 0 {
				return ErrCold
			}
			for _, mode := range claim.Spec.AccessModes {
				covered := false
				for _, supported := range volume.Spec.AccessModes {
					covered = covered || mode == supported
				}
				if !covered {
					return ErrCold
				}
			}
		}
	}
	check := func(metadata metav1.Object, template *corev1.PodTemplateSpec) error {
		if template == nil {
			return ErrInvalid
		}
		if workerSignals(metadata) || workerSignals(template) || workerName(template.Spec.ServiceAccountName) || workerName(template.Spec.DeprecatedServiceAccount) {
			return ErrWorker
		}
		if coldMounts(metadata, template.Spec, claims) {
			return ErrCold
		}
		return nil
	}
	for i := range s.Pods.Items {
		if coldMounts(&s.Pods.Items[i], s.Pods.Items[i].Spec, claims) {
			return ErrCold
		}
	}
	for i := range s.Jobs.Items {
		if err := check(&s.Jobs.Items[i], &s.Jobs.Items[i].Spec.Template); err != nil {
			return err
		}
	}
	for i := range r.Deployments.Items {
		if err := check(&r.Deployments.Items[i], &r.Deployments.Items[i].Spec.Template); err != nil {
			return err
		}
	}
	for i := range r.ReplicaSets.Items {
		if err := check(&r.ReplicaSets.Items[i], &r.ReplicaSets.Items[i].Spec.Template); err != nil {
			return err
		}
	}
	for i := range r.DaemonSets.Items {
		if err := check(&r.DaemonSets.Items[i], &r.DaemonSets.Items[i].Spec.Template); err != nil {
			return err
		}
	}
	for i := range r.ReplicationControllers.Items {
		if err := check(&r.ReplicationControllers.Items[i], r.ReplicationControllers.Items[i].Spec.Template); err != nil {
			return err
		}
	}
	for i := range r.CronJobs.Items {
		if err := check(&r.CronJobs.Items[i], &r.CronJobs.Items[i].Spec.JobTemplate.Spec.Template); err != nil {
			return err
		}
	}
	for i := range r.StatefulSets.Items {
		set := &r.StatefulSets.Items[i]
		if err := check(set, &set.Spec.Template); err != nil {
			return err
		}
		for _, template := range set.Spec.VolumeClaimTemplates {
			prefix := template.Name + "-" + set.Name + "-"
			for name := range claims {
				if strings.HasPrefix(name, prefix) {
					ordinal := strings.TrimPrefix(name, prefix)
					if n, err := strconv.ParseUint(ordinal, 10, 31); err == nil && strconv.FormatUint(n, 10) == ordinal {
						return ErrCold
					}
				}
			}
		}
	}
	return nil
}

func currentWorlds(s *Snapshot, claims map[string]*corev1.PersistentVolumeClaim, games *catalog.Catalog) error {
	for i := range s.GameServers.Items {
		server := &s.GameServers.Items[i]
		definition, err := games.Get(server.Spec.Game)
		if err != nil {
			return ErrCold
		}
		plan, err := platformkube.Build(server, definition)
		if err != nil || len(plan.DataClaims) == 0 {
			return ErrCold
		}
		observed := server.Status.ObservedData
		if observed != nil && (observed.Identity != plan.DataIdentity || len(observed.Claims) != len(plan.DataClaims)) {
			return ErrCold
		}
		paths := map[string]bool{}
		for _, planned := range plan.DataClaims {
			claim := claims[planned.Desired.Name]
			if claim == nil || planned.RequiredUID != "" && claim.UID != planned.RequiredUID || len(claim.OwnerReferences) != 0 {
				return ErrCold
			}
			for _, label := range []string{platformkube.LabelManagedBy, platformkube.LabelName, platformkube.LabelInstance, platformkube.LabelGame, platformkube.LabelDataPolicy, platformkube.LabelDataPath, platformkube.LabelDataIdentity} {
				if claim.Labels[label] != planned.Desired.Labels[label] {
					return ErrCold
				}
			}
			if !reflect.DeepEqual(claim.Spec.AccessModes, planned.Desired.Spec.AccessModes) || planned.Desired.Spec.StorageClassName != nil && !reflect.DeepEqual(claim.Spec.StorageClassName, planned.Desired.Spec.StorageClassName) || planned.ExternallySelected && planned.Desired.Spec.StorageClassName == nil && claim.Spec.StorageClassName != nil {
				return ErrCold
			}
			if volumeMode(claim.Spec.VolumeMode) != corev1.PersistentVolumeFilesystem {
				return ErrCold
			}
			if observed == nil {
				// Only a new, never-observed generated Pending set can lack a
				// bound-world receipt. Exact selections never waive UID/binding.
				if plan.Reattach || claim.Status.Phase != corev1.ClaimPending || claim.Spec.VolumeName != "" {
					return ErrCold
				}
				continue
			}
			path := planned.Desired.Labels[platformkube.LabelDataPath]
			matched := false
			for _, reference := range observed.Claims {
				if reference.Path == path {
					if matched || paths[path] || reference.ClaimRef.Namespace != nil || reference.ClaimRef.Name != claim.Name || types.UID(reference.ClaimRef.UID) != claim.UID {
						return ErrCold
					}
					matched = true
				}
			}
			if !matched || claim.Status.Phase != corev1.ClaimBound {
				return ErrCold
			}
			paths[path] = true
		}
	}
	return nil
}

// The installation's declared storage prerequisite is CSI. Unknown physical
// sources cannot prove non-aliasing; translated inline attachments use the
// same tuple. Keep the pair separate rather than concatenating opaque handles.
type csiIdentity struct{ driver, handle string }

func csiBacking(source corev1.PersistentVolumeSource) (csiIdentity, bool) {
	if source.CSI == nil || !validCSIDriver(source.CSI.Driver) || source.CSI.VolumeHandle == "" {
		return csiIdentity{}, false
	}
	fields := reflect.ValueOf(source)
	count := 0
	for i := 0; i < fields.NumField(); i++ {
		if !fields.Field(i).IsNil() {
			count++
		}
	}
	return csiIdentity{source.CSI.Driver, source.CSI.VolumeHandle}, count == 1
}

func validCSIDriver(driver string) bool {
	// Native validation is caseless; physical identity is never case-folded.
	return len(driver) <= 63 && len(validation.IsDNS1123Subdomain(strings.ToLower(driver))) == 0
}

func validAccessModes(modes []corev1.PersistentVolumeAccessMode) bool {
	if len(modes) == 0 {
		return false
	}
	other, oncePod := false, false
	for _, mode := range modes {
		switch mode {
		case corev1.ReadWriteOncePod:
			oncePod = true
		case corev1.ReadWriteOnce, corev1.ReadWriteMany, corev1.ReadOnlyMany:
			other = true
		default:
			return false
		}
	}
	return !other || !oncePod
}

func volumeMode(mode *corev1.PersistentVolumeMode) corev1.PersistentVolumeMode {
	if mode == nil {
		return corev1.PersistentVolumeFilesystem
	}
	return *mode
}

func claimClass(claim *corev1.PersistentVolumeClaim) string {
	if claim.Spec.StorageClassName == nil {
		return ""
	}
	return *claim.Spec.StorageClassName
}

func coldMounts(metadata metav1.Object, spec corev1.PodSpec, claims map[string]bool) bool {
	if mountsRetained(spec, claims) {
		return true
	}
	for _, volume := range spec.Volumes {
		if volume.Ephemeral != nil && claims[metadata.GetName()+"-"+volume.Name] {
			return true
		}
	}
	return false
}

func runtimeComplete(r *RuntimeSnapshot, namespace string) bool {
	if r == nil || r.Deployments == nil || r.ReplicaSets == nil || r.StatefulSets == nil || r.DaemonSets == nil || r.ReplicationControllers == nil || r.CronJobs == nil || r.Attachments == nil {
		return false
	}
	for _, list := range []runtime.Object{r.Deployments, r.ReplicaSets, r.StatefulSets, r.DaemonSets, r.ReplicationControllers, r.CronJobs, r.Attachments} {
		m, err := meta.ListAccessor(list)
		items, listErr := meta.ExtractList(list)
		if err != nil || listErr != nil || !boundedIdentity(m.GetResourceVersion()) || m.GetContinue() != "" || m.GetRemainingItemCount() != nil && *m.GetRemainingItemCount() != 0 || len(items) > MaxObjectsPerList {
			return false
		}
		seenNames, seenUIDs := map[string]bool{}, map[types.UID]bool{}
		for _, item := range items {
			metadata, err := meta.Accessor(item)
			if err != nil || metadata.GetName() == "" || !boundedIdentity(metadata.GetResourceVersion()) || !boundedIdentity(string(metadata.GetUID())) || seenNames[metadata.GetName()] || seenUIDs[metadata.GetUID()] || list == r.Attachments && metadata.GetNamespace() != "" || list != r.Attachments && metadata.GetNamespace() != namespace {
				return false
			}
			seenNames[metadata.GetName()], seenUIDs[metadata.GetUID()] = true, true
		}
	}
	return true
}
