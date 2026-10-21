// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
)

// Only closed numeric labels survive the actual refused comparison. No row,
// address, UID, RV, hash, context, callback or provider error is retained.
// This diagnostic never validates, collects, retries or advances a floor.
type phaseFloorDiagnostic struct{ value atomic.Uint32 }

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
