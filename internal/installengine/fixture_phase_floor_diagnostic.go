// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Only closed numeric labels survive the actual refused comparison. No row,
// address, UID, RV, hash, context, callback or provider error is retained.
// This diagnostic never validates, collects, retries or advances a floor.
type phaseFloorDiagnostic struct {
	value atomic.Uint32
	pod   atomic.Uint32 // 0 absent, 1 unavailable, 2 RV only, 3 body beyond RV
}

const (
	phaseFloorInput uint32 = iota + 1
	phaseFloorCandidate
	phaseFloorVersion
	phaseFloorRows
	phaseFloorPublic
	phaseFloorAccounts
	phaseFloorLeaders
)

var phaseFloorCategories = [...]string{
	"unknown", "input-floor-or-recipe", "candidate-validation", "version",
	"rows", "public", "accounts", "leaders",
}

var phaseFloorKinds = [...]string{
	"unknown", "GameServer", "GameBackup", "GameRestore", "GameDestroy",
	"ArcadeOperation", "Job", "Pod", "Lease", "PersistentVolumeClaim", "Secret",
	"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Deployment",
	"ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob",
	"EndpointSlice", "ServiceAccount", "Namespace", "CustomResourceDefinition",
	"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Service",
}

const (
	phaseFloorMembership uint32 = 1 << iota
	phaseFloorIdentity
	phaseFloorRV
	phaseFloorHash
	phaseFloorOther
	phaseFloorFlags = phaseFloorMembership | phaseFloorIdentity | phaseFloorRV | phaseFloorHash | phaseFloorOther
)

// A fresh recorder belongs to each accounting invocation. Late writers retain
// only their old numeric recorder, not the trace pointer used by a later read.
func beginPhaseFloorDiagnostic(ctx context.Context) *phaseFloorDiagnostic {
	if ctx != nil {
		if trace, ok := ctx.Value(admissionTraceKey{}).(*admissionTrace); ok && trace != nil {
			recorder := &phaseFloorDiagnostic{}
			trace.phaseFloor.Store(recorder)
			return recorder
		}
	}
	return nil
}

func (d *phaseFloorDiagnostic) record(category, kind, flags uint32) {
	if d != nil && category > 0 && category < uint32(len(phaseFloorCategories)) && kind < uint32(len(phaseFloorKinds)) && flags&^phaseFloorFlags == 0 {
		d.pod.Store(0)
		d.value.Store(category | kind<<8 | flags<<16)
	}
}

func phaseFloorKind(kind string) uint32 {
	for id, label := range phaseFloorKinds {
		if kind == label {
			return uint32(id)
		}
	}
	return 0
}

// Valid floors are already sorted by full key. Report only the first changed
// key's closed kind. A hash includes the whole object and RV: it is NOT a
// diagnosis of a spec/status change or evidence of which read is newer.
func phaseFloorRowDifference(before, after []fixtureWorldRow) (uint32, uint32) {
	for index := 0; index < len(before) || index < len(after); index++ {
		if index >= len(before) {
			return phaseFloorKind(after[index].Key.Kind), phaseFloorMembership
		}
		if index >= len(after) {
			return phaseFloorKind(before[index].Key.Kind), phaseFloorMembership
		}
		original, fresh := before[index], after[index]
		if original == fresh {
			continue
		}
		if original.Key != fresh.Key {
			kind := original.Key.Kind
			if fixtureWorldOrder(fresh.Key) < fixtureWorldOrder(original.Key) {
				kind = fresh.Key.Kind
			}
			return phaseFloorKind(kind), phaseFloorMembership
		}
		var flags uint32
		if original.UID != fresh.UID {
			flags |= phaseFloorIdentity
		}
		if original.ResourceVersion != fresh.ResourceVersion {
			flags |= phaseFloorRV
		}
		if original.SHA256 != fresh.SHA256 {
			flags |= phaseFloorHash
		}
		return phaseFloorKind(original.Key.Kind), flags
	}
	return 0, phaseFloorOther // exact nil/empty representation, not membership
}

// Invoked only after the actual comparator refused. Family order mirrors
// samePhaseBaseline; its acceptance logic and monotonic leader rules stay the
// sole authority. Public here is copied from the floor, not a fresh GET.
func (d *phaseFloorDiagnostic) difference(before, after fixturePhaseBaseline) {
	if d == nil {
		return
	}
	switch {
	case before.Version != after.Version:
		d.record(phaseFloorVersion, 0, phaseFloorOther)
	case !reflect.DeepEqual(before.Rows, after.Rows):
		kind, flags := phaseFloorRowDifference(before.Rows, after.Rows)
		d.record(phaseFloorRows, kind, flags)
	case !reflect.DeepEqual(before.Public, after.Public):
		kind, flags := phaseFloorRowDifference(before.Public, after.Public)
		d.record(phaseFloorPublic, kind, flags)
	case !reflect.DeepEqual(before.Accounts, after.Accounts):
		kind, flags := phaseFloorKind("ServiceAccount"), phaseFloorOther
		if before.Accounts != nil && after.Accounts != nil && before.Accounts.Version == after.Accounts.Version {
			kind, flags = phaseFloorRowDifference(before.Accounts.Rows, after.Accounts.Rows)
		}
		d.record(phaseFloorAccounts, kind, flags)
	case len(before.Leaders) != len(after.Leaders):
		d.record(phaseFloorLeaders, phaseFloorKind("Lease"), phaseFloorMembership)
	default:
		for index, original := range before.Leaders {
			fresh := after.Leaders[index]
			// An earlier allowed renewal is not the refused leader. Use the
			// original comparator on a single leader, without normalizing it.
			a := fixturePhaseBaseline{Version: before.Version, Leaders: []fixturePhaseLeader{original}}
			b := fixturePhaseBaseline{Version: after.Version, Leaders: []fixturePhaseLeader{fresh}}
			if !samePhaseBaseline(a, b) {
				_, flags := phaseFloorRowDifference([]fixtureWorldRow{original.Row}, []fixtureWorldRow{fresh.Row})
				if original.ParentUID != fresh.ParentUID || original.SetUID != fresh.SetUID || original.PodUID != fresh.PodUID || original.RenewTime != fresh.RenewTime || !reflect.DeepEqual(original.ManagedTimes, fresh.ManagedTimes) {
					flags |= phaseFloorOther
				}
				d.record(phaseFloorLeaders, phaseFloorKind("Lease"), flags)
				return
			}
		}
	}
}

// Classify only the first row of an already-refused Rows/Pod comparison.
// Both fingerprints use the same typed representation as the original floor.
// This does not establish harmlessness, chronology or which body field changed.
// Only a numeric category survives; no row or object is retained or authorized.
func (d *phaseFloorDiagnostic) recordPodDifference(before, after fixturePhaseBaseline, observed map[types.UID]runtime.Object) {
	if d == nil {
		return
	}
	value := d.value.Load()
	if value&255 != phaseFloorRows || value>>8&255 != phaseFloorKind("Pod") {
		return
	}
	d.pod.Store(1)
	for index := 0; index < len(before.Rows) && index < len(after.Rows); index++ {
		original, fresh := before.Rows[index], after.Rows[index]
		if original == fresh {
			continue
		}
		if original.Key != fresh.Key || original.Key.APIVersion != "v1" || original.Key.Kind != "Pod" || original.UID != fresh.UID || original.ResourceVersion == fresh.ResourceVersion {
			return
		}
		pod, ok := observed[fresh.UID].(*corev1.Pod)
		if !ok || pod == nil || pod.Name != fresh.Key.Name || pod.Namespace != fresh.Key.Namespace || pod.UID != fresh.UID || pod.ResourceVersion != fresh.ResourceVersion || pod.APIVersion != "" && pod.APIVersion != "v1" || pod.Kind != "" && pod.Kind != "Pod" {
			return
		}
		// phaseRow does not validate its arguments against object metadata.
		// Bind the actual unmodified candidate before touching its private copy.
		actual, err := phaseRow(fresh.Key, pod.UID, pod.ResourceVersion, pod)
		if err != nil || actual != fresh {
			return
		}
		copy := pod.DeepCopy()
		copy.ResourceVersion = original.ResourceVersion
		restored, err := phaseRow(original.Key, copy.UID, copy.ResourceVersion, copy)
		if err != nil {
			return
		}
		if restored == original {
			d.pod.Store(2)
		} else {
			d.pod.Store(3)
		}
		return
	}
}

func (trace *admissionTrace) phaseFloorSnapshot() string {
	if trace == nil {
		return ""
	}
	recorder := trace.phaseFloor.Load()
	if recorder == nil {
		return ""
	}
	value := recorder.value.Load()
	category, kind, flags := value&255, value>>8&255, value>>16
	if category == 0 || category >= uint32(len(phaseFloorCategories)) || kind >= uint32(len(phaseFloorKinds)) || flags&^phaseFloorFlags != 0 {
		return ""
	}
	return fmt.Sprintf("category=%s kind=%s membership=%t identity=%t resource-version=%t hash=%t other=%t", phaseFloorCategories[category], phaseFloorKinds[kind], flags&phaseFloorMembership != 0, flags&phaseFloorIdentity != 0, flags&phaseFloorRV != 0, flags&phaseFloorHash != 0, flags&phaseFloorOther != 0)
}

// PhaseFloorSnapshot is optional progress from the SAME refused comparison,
// not cause, successful observation, authority or a recovery/retry route.
func (d *LifecycleDiagnostic) PhaseFloorSnapshot() string {
	if d == nil {
		return ""
	}
	return d.admission.phaseFloorSnapshot()
}

// PhaseFloorPodSnapshot describes only the same refused typed-row comparison.
// It never changes the original whole-row/RV refusal or publishes a new floor.
func (d *LifecycleDiagnostic) PhaseFloorPodSnapshot() string {
	if d == nil {
		return ""
	}
	recorder := d.admission.phaseFloor.Load()
	if recorder == nil {
		return ""
	}
	switch recorder.pod.Load() {
	case 1:
		return "change=unavailable"
	case 2:
		return "change=rv-only"
	case 3:
		return "change=body-beyond-rv"
	}
	return ""
}
