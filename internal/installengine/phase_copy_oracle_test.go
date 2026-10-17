// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Frozen fa85256 pre-optimization calculations. These intentionally retain the
// independent literal projection and redundant accessor copies. They are a local
// equivalence/allocation oracle, not native admission or lifecycle evidence.
func phaseCopyLegacyCollections(o *installobserve.Observation) []phaseCollection {
	if o == nil {
		return nil
	}
	s, r := o.Snapshot(), o.Runtime()
	return phaseCopyLegacySnapshotCollections(s, r)
}

func phaseCopyLegacySnapshotCollections(s *installsafety.Snapshot, r *installsafety.RuntimeSnapshot) []phaseCollection {
	if s == nil || r == nil {
		return nil
	}
	return []phaseCollection{
		{"arcade.gobha.me/v1alpha1", "GameServer", s.GameServers}, {"arcade.gobha.me/v1alpha1", "GameBackup", s.Backups},
		{"arcade.gobha.me/v1alpha1", "GameRestore", s.Restores}, {"arcade.gobha.me/v1alpha1", "GameDestroy", s.Destroys},
		{"arcade.gobha.me/v1alpha1", "ArcadeOperation", s.Operations}, {"batch/v1", "Job", s.Jobs}, {"v1", "Pod", s.Pods},
		{"coordination.k8s.io/v1", "Lease", s.Leases}, {"v1", "PersistentVolumeClaim", s.Claims}, {"v1", "Secret", s.Secrets},
		{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", s.Policies}, {"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", s.Bindings},
		{"apps/v1", "Deployment", r.Deployments}, {"apps/v1", "ReplicaSet", r.ReplicaSets}, {"apps/v1", "StatefulSet", r.StatefulSets},
		{"apps/v1", "DaemonSet", r.DaemonSets}, {"v1", "ReplicationController", r.ReplicationControllers}, {"batch/v1", "CronJob", r.CronJobs},
		{"discovery.k8s.io/v1", "EndpointSlice", r.EndpointSlices},
	}
}

func phaseCopyLegacyBaseline(o *installobserve.Observation, families [2]admissionControllerState, now time.Time) (fixturePhaseBaseline, error) {
	baseline := fixturePhaseBaseline{Version: "admission-phase-v1", Rows: []fixtureWorldRow{}, Leaders: []fixturePhaseLeader{}}
	if o == nil || o.Journal() == nil || now.IsZero() || !completeStoppedLists(o.Snapshot(), o.Runtime()) {
		return fixturePhaseBaseline{}, ErrAdmission
	}
	namespace := o.Journal().Anchor().Namespace
	warm := map[string]int{}
	for index, state := range families {
		if state.Name != controllerFamilies[index] {
			return fixturePhaseBaseline{}, ErrAdmission
		}
		if state.Executing {
			name := "controller.arcade.gobha.me"
			if index == 1 {
				name = "destroy-controller.arcade.gobha.me"
			}
			warm[name] = index
		}
	}
	seen := map[installstate.Key]bool{}
	uids := map[types.UID]bool{}
	for _, collection := range phaseCopyLegacyCollections(o) {
		items, err := meta.ExtractList(collection.list)
		if err != nil || len(items) > installsafety.MaxObjectsPerList {
			return fixturePhaseBaseline{}, ErrAdmission
		}
		for _, object := range items {
			metadata, err := meta.Accessor(object)
			if err != nil {
				return fixturePhaseBaseline{}, ErrAdmission
			}
			key := installstate.Key{APIVersion: collection.version, Kind: collection.kind, Namespace: metadata.GetNamespace(), Name: metadata.GetName()}
			if seen[key] || uids[metadata.GetUID()] {
				return fixturePhaseBaseline{}, ErrAdmission
			}
			seen[key], uids[metadata.GetUID()] = true, true
			if collection.kind == "Lease" {
				if family, active := warm[key.Name]; active {
					lease, ok := object.(*coordinationv1.Lease)
					if !ok {
						return fixturePhaseBaseline{}, ErrAdmission
					}
					leader, err := capturePhaseLeader(namespace, lease, families[family], now)
					if err != nil {
						return fixturePhaseBaseline{}, ErrAdmission
					}
					baseline.Leaders = append(baseline.Leaders, leader)
					delete(warm, key.Name)
					continue
				}
			}
			row, err := phaseRow(key, metadata.GetUID(), metadata.GetResourceVersion(), object)
			if err != nil {
				return fixturePhaseBaseline{}, ErrAdmission
			}
			baseline.Rows = append(baseline.Rows, row)
		}
	}
	if len(warm) != 0 {
		return fixturePhaseBaseline{}, ErrAdmission
	}
	sortFixtureWorlds(baseline.Rows)
	if len(baseline.Leaders) == 2 && fixtureWorldOrder(baseline.Leaders[0].Row.Key) > fixtureWorldOrder(baseline.Leaders[1].Row.Key) {
		baseline.Leaders[0], baseline.Leaders[1] = baseline.Leaders[1], baseline.Leaders[0]
	}
	if baseline.validate(namespace) != nil {
		return fixturePhaseBaseline{}, ErrAdmission
	}
	return baseline, nil
}

func phaseCopyLegacyCollectionsWithAccounts(o *installobserve.Observation, accounts *phaseServiceAccounts) []phaseCollection {
	collections := phaseCopyLegacyCollections(o)
	if accounts != nil && accounts.observation != nil {
		collections = append(collections, phaseCollection{"v1", "ServiceAccount", accounts.observation.Accounts()})
	}
	return collections
}

func (f *fixtureLedger) phaseCopyLegacyAccount(ctx context.Context, o *installobserve.Observation, floor fixturePhaseBaseline, now time.Time, accounts *phaseServiceAccounts) (fixturePhaseBaseline, [fixtureMaxSlots]runtime.Object, error) {
	var fixtures [fixtureMaxSlots]runtime.Object
	zero := fixturePhaseBaseline{}
	if f == nil || o == nil || o.Journal() == nil || !o.Journal().MatchesJournalBytes(f.document.Journal) || o.Journal().ResourceVersion() != f.document.JournalResourceVersion {
		traceAdmissionPhase(ctx, admissionPhaseRowInput, -1)
		return zero, fixtures, ErrFixtures
	}
	if !completeStoppedLists(o.Snapshot(), o.Runtime()) {
		traceAdmissionPhase(ctx, admissionPhaseRowLists, -1)
		return zero, fixtures, ErrFixtures
	}
	if floor.validate(o.Journal().Anchor().Namespace) != nil || !fixtureAccountsRecipeMatches(f.document, &floor) || (f.document.Recipe == fixtureRecipeV3) != (accounts != nil) {
		traceAdmissionPhase(ctx, admissionPhaseRowFloor, -1)
		return zero, fixtures, ErrFixtures
	}
	addresses := map[installstate.Key]int{}
	for slot, entry := range f.document.Entries {
		addresses[entry.Key] = slot
	}
	leaders := map[installstate.Key]fixturePhaseLeader{}
	for _, leader := range floor.Leaders {
		leaders[leader.Row.Key] = leader
	}
	phase := fixturePhaseBaseline{Version: floor.Version, Rows: []fixtureWorldRow{}, Leaders: []fixturePhaseLeader{}, Public: floor.Public}
	if accounts != nil {
		if accounts.observation == nil || accounts.observation.Journal() == nil || accounts.observation.Journal().ResourceVersion() != f.document.JournalResourceVersion || !accounts.observation.Journal().MatchesJournalBytes(f.document.Journal) {
			return zero, fixtures, ErrFixtures
		}
		var err error
		phase.Accounts, err = accounts.baseline(floor.Public, f)
		if err != nil {
			return zero, fixtures, ErrFixtures
		}
	}
	observed := map[types.UID]runtime.Object{}
	seen := map[installstate.Key]bool{}
	leases := map[installstate.Key]*coordinationv1.Lease{}
	for _, collection := range phaseCopyLegacyCollectionsWithAccounts(o, accounts) {
		items, err := meta.ExtractList(collection.list)
		if err != nil || len(items) > installsafety.MaxObjectsPerList {
			traceAdmissionPhase(ctx, admissionPhaseRowCollection, -1)
			return zero, fixtures, ErrFixtures
		}
		for _, object := range items {
			m, err := meta.Accessor(object)
			if err != nil || observed[m.GetUID()] != nil {
				traceAdmissionPhase(ctx, admissionPhaseRowUID, -1)
				return zero, fixtures, ErrFixtures
			}
			key := installstate.Key{APIVersion: collection.version, Kind: collection.kind, Namespace: m.GetNamespace(), Name: m.GetName()}
			if seen[key] {
				traceAdmissionPhase(ctx, admissionPhaseRowAddress, -1)
				return zero, fixtures, ErrFixtures
			}
			seen[key], observed[m.GetUID()] = true, object
			if slot, ok := addresses[key]; ok {
				entry := f.document.Entries[slot]
				if entry.State != fixtureOriginal || !nativeFixtureUID(string(entry.OriginalUID)) || m.GetUID() != entry.OriginalUID {
					// Present DELETE-attempted objects are a no-effect wait, not
					// a relaxed deletion shape or replay authorization.
					traceAdmissionPhase(ctx, admissionPhaseRowFixtureIdentity, -1)
					return zero, fixtures, ErrFixtures
				}
				fixtures[slot] = object
				continue
			}
			if _, ok := leaders[key]; ok {
				lease, ok := object.(*coordinationv1.Lease)
				if !ok {
					traceAdmissionPhase(ctx, admissionPhaseRowLeaderShape, -1)
					return zero, fixtures, ErrFixtures
				}
				leases[key] = lease
				continue
			}
			if collection.kind == "ServiceAccount" {
				continue // separately sealed whole rows, including signed Public
			}
			row, err := phaseRow(key, m.GetUID(), m.GetResourceVersion(), object)
			if err != nil {
				traceAdmissionPhase(ctx, admissionPhaseRowShape, -1)
				return zero, fixtures, ErrFixtures
			}
			phase.Rows = append(phase.Rows, row)
		}
	}
	for slot, entry := range f.document.Entries {
		if entry.State == fixtureOriginal && fixtures[slot] == nil || entry.State == fixtureCreateAttempted {
			traceAdmissionPhase(ctx, admissionPhaseRowFixtureMissing, -1)
			return zero, fixtures, ErrFixtures
		}
	}
	for _, original := range floor.Leaders {
		parent, parentOK := observed[original.ParentUID].(*appsv1.Deployment)
		set, setOK := observed[original.SetUID].(*appsv1.ReplicaSet)
		pod, podOK := observed[original.PodUID].(*corev1.Pod)
		if !parentOK || !setOK || !podOK || len(set.OwnerReferences) != 1 || set.OwnerReferences[0].UID != parent.UID || leases[original.Row.Key] == nil {
			traceAdmissionPhase(ctx, admissionPhaseRowLeaderChain, -1)
			return zero, fixtures, ErrFixtures
		}
		state := admissionControllerState{Name: parent.Name, Executing: true, Deployment: parent, Sets: []*appsv1.ReplicaSet{set}, Pods: []*corev1.Pod{pod}}
		leader, err := capturePhaseLeader(original.Row.Key.Namespace, leases[original.Row.Key], state, now)
		if err != nil {
			traceAdmissionPhase(ctx, admissionPhaseRowLeaderShape, -1)
			return zero, fixtures, ErrFixtures
		}
		phase.Leaders = append(phase.Leaders, leader)
	}
	sortFixtureWorlds(phase.Rows)
	if phase.validate(o.Journal().Anchor().Namespace) != nil || !samePhaseBaseline(floor, phase) {
		traceAdmissionPhase(ctx, admissionPhaseRowFloor, -1)
		return zero, fixtures, ErrFixtures
	}
	return phase, fixtures, nil
}
