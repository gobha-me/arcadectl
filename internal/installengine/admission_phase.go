// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Baseline values contain only original addresses/UIDs and public hashes, not
// world settings, Secret data, raw storage sources or a caller-selected permit.
// Attachment and arbitrary-GVR GC safety remain FRESH obligations throughout
// fixture execution; hashing public builtin rows cannot inherit those facts.
type fixturePhaseBaseline struct {
	Version  string                  `json:"version"`
	Rows     []fixtureWorldRow       `json:"rows"`
	Leaders  []fixturePhaseLeader    `json:"leaders"`
	Public   []fixtureWorldRow       `json:"public,omitempty"`
	Accounts *fixtureAccountBaseline `json:"accounts,omitempty"`
}

// Present only in the v3 companion. Empty rows still encode an explicit
// complete floor; absence never means that the collection was observed empty.
type fixtureAccountBaseline struct {
	Version string            `json:"version"`
	Rows    []fixtureWorldRow `json:"rows"`
}

type fixturePhaseLeader struct {
	Row          fixtureWorldRow `json:"row"`
	ParentUID    types.UID       `json:"parentUid"`
	SetUID       types.UID       `json:"setUid"`
	PodUID       types.UID       `json:"podUid"`
	RenewTime    string          `json:"renewTime"`
	ManagedTimes []string        `json:"managedTimes"`
}

type initialAdmissionPhase struct {
	journal  *installstate.Snapshot
	worlds   *coldWorldTuple
	baseline fixturePhaseBaseline
}

// Only the original pre-fixture initializer can add a phase to the immutable
// companion. A resumed world-only legacy companion cannot be promoted using
// current survivors, and ordinary WAL/ACK/publication protections stay intact.
func (initial *initialAdmissionPhase) seal(f *fixtureLedger) error {
	if initial == nil || initial.journal == nil || initial.worlds == nil || f == nil || f.engine == nil || f.lock == nil || initial.journal.ResourceVersion() != f.document.JournalResourceVersion || !bytes.Equal(initial.journal.Bytes(), f.document.Journal) || initial.baseline.validate(initial.journal.Anchor().Namespace) != nil {
		return ErrFixtures
	}
	rows, err := initial.worlds.fixtureWorldRows()
	if err != nil {
		return ErrFixtures
	}
	if !fixtureAccountsRecipeMatches(f.document, &initial.baseline) {
		return ErrFixtures
	}
	d := fixtureWorldsDocument{Version: "original-worlds-v1", RunID: f.document.RunID, Journal: bytes.Clone(f.document.Journal), JournalResourceVersion: f.document.JournalResourceVersion, Rows: rows, Phase: &initial.baseline}
	return f.sealWorldsDocument(d)
}

func (b *fixturePhaseBaseline) validate(namespace string) error {
	if b == nil || b.Version != "admission-phase-v1" || b.Rows == nil || b.Leaders == nil || len(b.Rows) > 19*installsafety.MaxObjectsPerList || len(b.Leaders) > 2 {
		return ErrFixtures
	}
	uids := map[types.UID]fixtureWorldRow{}
	addresses := map[installstate.Key]bool{}
	counts := map[string]int{}
	previous := ""
	rowValid := func(row fixtureWorldRow) bool {
		return addressPart(row.Key.Name) && receiptUID.MatchString(string(row.UID)) && fixtureRV(row.ResourceVersion) && fixtureWorldsDigest.MatchString(row.SHA256)
	}
	for _, row := range b.Rows {
		order := fixtureWorldOrder(row.Key)
		if !rowValid(row) || uids[row.UID].UID != "" || addresses[row.Key] || order <= previous {
			return ErrFixtures
		}
		cluster := false
		switch row.Key.APIVersion + "/" + row.Key.Kind {
		case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy", "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding":
			cluster = true
		case "arcade.gobha.me/v1alpha1/GameServer", "arcade.gobha.me/v1alpha1/GameBackup", "arcade.gobha.me/v1alpha1/GameRestore", "arcade.gobha.me/v1alpha1/GameDestroy", "arcade.gobha.me/v1alpha1/ArcadeOperation", "batch/v1/Job", "v1/Pod", "coordination.k8s.io/v1/Lease", "v1/PersistentVolumeClaim", "v1/Secret", "apps/v1/Deployment", "apps/v1/ReplicaSet", "apps/v1/StatefulSet", "apps/v1/DaemonSet", "v1/ReplicationController", "batch/v1/CronJob", "discovery.k8s.io/v1/EndpointSlice":
		default:
			return ErrFixtures
		}
		if cluster && row.Key.Namespace != "" || !cluster && row.Key.Namespace != namespace {
			return ErrFixtures
		}
		counts[row.Key.APIVersion+"/"+row.Key.Kind]++
		if counts[row.Key.APIVersion+"/"+row.Key.Kind] > installsafety.MaxObjectsPerList {
			return ErrFixtures
		}
		uids[row.UID], previous = row, order
		addresses[row.Key] = true
	}
	previous = ""
	publicUIDs := map[types.UID]bool{}
	for _, row := range b.Public {
		if len(b.Public) > installstate.MaxResources || !rowValid(row) || publicUIDs[row.UID] || uids[row.UID].UID != "" || addresses[row.Key] || fixtureWorldOrder(row.Key) <= previous || row.Key.Kind == "Secret" || phaseCollectionKey(row.Key) {
			return ErrFixtures
		}
		if _, err := publicPermission(row.Key, "get"); err != nil || row.Key.Namespace != "" && row.Key.Namespace != namespace {
			return ErrFixtures
		}
		publicUIDs[row.UID], previous = true, fixtureWorldOrder(row.Key)
		addresses[row.Key] = true
	}
	previous = ""
	if b.Accounts != nil {
		if b.Accounts.Version != "service-accounts-v1" || b.Accounts.Rows == nil || len(b.Accounts.Rows) > installsafety.MaxObjectsPerList {
			return ErrFixtures
		}
		for _, row := range b.Accounts.Rows {
			if !rowValid(row) || row.Key.APIVersion != "v1" || row.Key.Kind != "ServiceAccount" || row.Key.Namespace != namespace || uids[row.UID].UID != "" || publicUIDs[row.UID] || addresses[row.Key] || fixtureWorldOrder(row.Key) <= previous {
				return ErrFixtures
			}
			previous, uids[row.UID], addresses[row.Key] = fixtureWorldOrder(row.Key), row, true
		}
	}
	previous = ""
	for _, leader := range b.Leaders {
		row := leader.Row
		order := fixtureWorldOrder(row.Key)
		family := "arcadectl-controller"
		if row.Key.Name == "destroy-controller.arcade.gobha.me" {
			family = "arcadectl-destroy-controller"
		} else if row.Key.Name != "controller.arcade.gobha.me" {
			return ErrFixtures
		}
		if !rowValid(row) || !nativeFixtureUID(string(row.UID)) || publicUIDs[row.UID] || uids[row.UID].UID != "" || addresses[row.Key] || row.Key.APIVersion != "coordination.k8s.io/v1" || row.Key.Kind != "Lease" || row.Key.Namespace != namespace || order <= previous || leader.ManagedTimes == nil || len(leader.ManagedTimes) > 128 {
			return ErrFixtures
		}
		parent, set, pod := uids[leader.ParentUID], uids[leader.SetUID], uids[leader.PodUID]
		if parent.Key != deploymentKey(namespace, family) || set.Key.APIVersion != "apps/v1" || set.Key.Kind != "ReplicaSet" || set.Key.Namespace != namespace || !strings.HasPrefix(set.Key.Name, family+"-") || pod.Key.APIVersion != "v1" || pod.Key.Kind != "Pod" || pod.Key.Namespace != namespace {
			return ErrFixtures
		}
		validTime := func(raw string) bool {
			t, err := time.Parse(time.RFC3339Nano, raw)
			return err == nil && !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && raw == t.UTC().Format(time.RFC3339Nano)
		}
		if !validTime(leader.RenewTime) {
			return ErrFixtures
		}
		for _, raw := range leader.ManagedTimes {
			if !validTime(raw) {
				return ErrFixtures
			}
		}
		uids[row.UID], previous = row, order
		addresses[row.Key] = true
	}
	return nil
}

// Capture before WAL intent. Every row comes from the SAME complete snapshot
// that independently passed ValidateCold. Repeat both worlds and the entire
// normalized nonfixture membership inside original policy/journal barriers.
// This private initializer is not full AdmissionEffective, a lock or a drain.
func (a *ClusterAdmission) captureInitialPhase(ctx context.Context, request LifecycleCheck) (*initialAdmissionPhase, error) {
	if a == nil || a.prerequisites == nil || ctx == nil || request.Checkpoint != AdmissionEffective || request.Snapshot == nil || request.Options.Now.IsZero() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cold, err := NewClusterCold(a.prerequisites)
	if err != nil {
		return nil, ErrAdmission
	}
	traceAdmissionPhase(ctx, admissionPhaseConfigured, -1)
	before, err := a.configured(ctx, request)
	if err != nil {
		return nil, ErrAdmission
	}
	coldRequest := request
	coldRequest.Checkpoint = ColdSafety
	var lastAccounts *phaseServiceAccounts
	collect := func() (*coldWorldTuple, [32]byte, fixturePhaseBaseline, error) {
		traceAdmissionPhase(ctx, admissionPhaseInitialCold, -1)
		tuple, observation, _, hash, err := cold.collectEvidence(ctx, coldRequest)
		if err != nil {
			return nil, [32]byte{}, fixturePhaseBaseline{}, ErrAdmission
		}
		traceAdmissionPhase(ctx, admissionPhaseInitialControllers, -1)
		families, err := a.prerequisites.engine.admissionControllers(ctx, request, observation)
		if err != nil {
			return nil, [32]byte{}, fixturePhaseBaseline{}, ErrAdmission
		}
		traceAdmissionPhase(ctx, admissionPhaseInitialRows, -1)
		baseline, err := capturePhaseBaseline(observation, families, time.Now().UTC())
		if err == nil {
			traceAdmissionPhase(ctx, admissionPhaseInitialPublic, -1)
			baseline.Public, err = a.phasePublicInventory(ctx, request)
		}
		if err == nil && a.prerequisites.engine.baseline != nil {
			traceAdmissionPhase(ctx, admissionPhaseInitialAccounts, -1)
			accounts, readErr := a.collectPhaseServiceAccounts(ctx, request)
			if readErr != nil {
				err = ErrFixtures
			} else {
				baseline.Accounts, err = accounts.baseline(baseline.Public, nil)
				lastAccounts = accounts
			}
		}
		return tuple, hash, baseline, err
	}
	worlds, firstHash, first, err := collect()
	if err != nil {
		return nil, ErrAdmission
	}
	_, secondHash, second, err := collect()
	if err != nil {
		return nil, ErrAdmission
	}
	traceAdmissionPhase(ctx, admissionPhaseInitialMembership, -1)
	if firstHash != secondHash || !samePhaseBaseline(first, second) {
		return nil, ErrAdmission
	}
	traceAdmissionPhase(ctx, admissionPhaseFinalConfigured, -1)
	after, err := a.configured(ctx, request)
	if err != nil || !sameAdmissionConfiguration(before, after) || a.prerequisites.original(ctx, request.Snapshot) != nil {
		return nil, ErrAdmission
	}
	if lastAccounts != nil {
		traceAdmissionPhase(ctx, admissionPhaseInitialAccounts, -1)
		closing, err := a.collectPhaseServiceAccounts(ctx, request)
		if err != nil || !samePhaseServiceAccounts(lastAccounts, closing) || a.prerequisites.original(ctx, request.Snapshot) != nil {
			return nil, ErrAdmission
		}
	}
	// The second read is the latest accepted renewal/RV/managed-field floor.
	// Sealing the first would permit regression to an already superseded read.
	traceAdmissionPhase(ctx, admissionPhaseComplete, -1)
	return &initialAdmissionPhase{request.Snapshot, worlds, second}, nil
}

type phaseCollection struct {
	version, kind string
	list          runtime.Object
}

func phaseCollections(o *installobserve.Observation) []phaseCollection {
	if o == nil || o.Snapshot() == nil || o.Runtime() == nil {
		return nil
	}
	s, r := o.Snapshot(), o.Runtime()
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

func phaseRow(key installstate.Key, uid types.UID, rv string, object any) (fixtureWorldRow, error) {
	body, err := json.Marshal(object)
	if err != nil || len(body) > 32*1024*1024 || !addressPart(key.Name) || !receiptUID.MatchString(string(uid)) || !fixtureRV(rv) {
		return fixtureWorldRow{}, ErrAdmission
	}
	return fixtureWorldRow{key, uid, rv, fixtureWorldDigest(body)}, nil
}

func capturePhaseBaseline(o *installobserve.Observation, families [2]admissionControllerState, now time.Time) (fixturePhaseBaseline, error) {
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
	for _, collection := range phaseCollections(o) {
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

func capturePhaseLeader(namespace string, lease *coordinationv1.Lease, state admissionControllerState, now time.Time) (fixturePhaseLeader, error) {
	var zero fixturePhaseLeader
	// client-go samples acquisition BEFORE requesting Lease GET/CREATE; the
	// server assigns creation afterward. These clocks have no valid ordering
	// constraint. Bookkeeping still requires acquire <= renew; acquisition and
	// server creation stay in the immutable whole-row hash across renewals.
	if !state.Executing || state.Deployment == nil || !installsafety.ControllerElectionBookkeeping(namespace, lease) || lease.CreationTimestamp.After(now.Add(time.Second)) || lease.Spec.RenewTime.After(now.Add(time.Second)) || now.Sub(lease.Spec.RenewTime.Time) > 15*time.Second {
		return zero, ErrAdmission
	}
	var podUID, setUID types.UID
	for _, pod := range state.Pods {
		if !strings.HasPrefix(*lease.Spec.HolderIdentity, pod.Name+"_") {
			continue
		}
		for _, set := range state.Sets {
			if len(pod.OwnerReferences) == 1 && pod.OwnerReferences[0].UID == set.UID && validOriginalPodTemplate(pod, set, true) && readyNamedPod(pod, set.Spec.Template.Spec.Containers[0].Name) {
				if podUID != "" {
					return zero, ErrAdmission
				}
				podUID, setUID = pod.UID, set.UID
			}
		}
	}
	if podUID == "" {
		return zero, ErrAdmission
	}
	copy := lease.DeepCopy()
	copy.ResourceVersion, copy.Spec.RenewTime = "", nil
	times := make([]string, len(copy.ManagedFields))
	for index := range copy.ManagedFields {
		field := &copy.ManagedFields[index]
		// Native field management and REST creation stamp independent times;
		// creation is not a lower bound for the original managed-field stamp.
		if field.Time == nil || field.Time.IsZero() || field.Time.Year() < 1 || field.Time.Year() > 9999 || field.Time.Time.After(now.Add(time.Second)) || field.Manager == "" || field.Operation != metav1.ManagedFieldsOperationUpdate || field.APIVersion != "coordination.k8s.io/v1" || field.Subresource != "" || field.FieldsType != "FieldsV1" || field.FieldsV1 == nil {
			return zero, ErrAdmission
		}
		times[index] = field.Time.UTC().Format(time.RFC3339Nano)
		field.Time = nil
	}
	row, err := phaseRow(installstate.Key{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: namespace, Name: lease.Name}, lease.UID, lease.ResourceVersion, copy)
	if err != nil {
		return zero, ErrAdmission
	}
	return fixturePhaseLeader{row, state.Deployment.UID, setUID, podUID, lease.Spec.RenewTime.UTC().Format(time.RFC3339Nano), times}, nil
}

func samePhaseBaseline(before, after fixturePhaseBaseline) bool {
	if before.Version != "admission-phase-v1" || after.Version != before.Version || !reflect.DeepEqual(before.Rows, after.Rows) || !reflect.DeepEqual(before.Public, after.Public) || !reflect.DeepEqual(before.Accounts, after.Accounts) || len(before.Leaders) != len(after.Leaders) {
		return false
	}
	for index, original := range before.Leaders {
		fresh := after.Leaders[index]
		oldRV, oldErr := strconv.ParseUint(original.Row.ResourceVersion, 10, 64)
		newRV, newErr := strconv.ParseUint(fresh.Row.ResourceVersion, 10, 64)
		oldTime, oldTimeErr := time.Parse(time.RFC3339Nano, original.RenewTime)
		newTime, newTimeErr := time.Parse(time.RFC3339Nano, fresh.RenewTime)
		if oldErr != nil || newErr != nil || newRV < oldRV || oldTimeErr != nil || newTimeErr != nil || newTime.Before(oldTime) || len(original.ManagedTimes) != len(fresh.ManagedTimes) {
			return false
		}
		if newRV == oldRV && (original.RenewTime != fresh.RenewTime || !reflect.DeepEqual(original.ManagedTimes, fresh.ManagedTimes)) {
			return false
		}
		for field, old := range original.ManagedTimes {
			x, xErr := time.Parse(time.RFC3339Nano, old)
			y, yErr := time.Parse(time.RFC3339Nano, fresh.ManagedTimes[field])
			if xErr != nil || yErr != nil || y.Before(x) {
				return false
			}
		}
		fresh.Row.ResourceVersion, fresh.RenewTime, fresh.ManagedTimes = original.Row.ResourceVersion, original.RenewTime, original.ManagedTimes
		if !reflect.DeepEqual(original, fresh) {
			return false
		}
	}
	return true
}
