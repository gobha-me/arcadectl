// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Private read-only evidence for the finite admission provider. It is NOT an
// ordinary cold checkpoint, an effect capability, adoption, or WAL retirement.
// The raw complete snapshot is never projected into ValidateCold: exact inert
// WAL fixtures and exact original rows are accounted for separately, while
// physical storage and retained ancestor safety consume the UNFILTERED lists.
type fixturePhaseObservation struct {
	objects [fixtureMaxSlots]*unstructured.Unstructured
	gc      *installobserve.GCObservation
	phase   fixturePhaseBaseline
}

// The typed complete collections already seal their original whole objects.
// Seal the rest of the public signed inventory too: metadata-only GC cannot
// prove a Service spec, ConfigMap data, CRD or access object's unchanged shape.
// Exact original recorded templates apply during mixed-package transitions;
// no readiness requirement, target-only replacement, or Secret GET is added.
func (a *ClusterAdmission) phasePublicInventory(ctx context.Context, request LifecycleCheck) ([]fixtureWorldRow, error) {
	return a.phasePublicInventoryAgainstGC(ctx, request, nil)
}

func (a *ClusterAdmission) phasePublicInventoryAgainstGC(ctx context.Context, request LifecycleCheck, gcRows []installobserve.GCObject) ([]fixtureWorldRow, error) {
	if a == nil || a.prerequisites == nil || request.Snapshot == nil {
		return nil, ErrFixtures
	}
	e := a.prerequisites.engine
	d := request.Snapshot.Document()
	rows := []fixtureWorldRow{}
	for _, original := range d.Resources {
		key := original.Key
		if key.Kind == "Secret" {
			continue
		}
		if phaseCollectionKey(key) {
			continue
		}
		entry, template := e.inventory(d, key)
		live, err := e.access.Get(ctx, key)
		if entry == nil || template == nil || err != nil {
			return nil, ErrFixtures
		}
		if key.Kind == "Namespace" {
			err = template.MatchNamespace(live, request.Snapshot)
		} else if key.Kind == "CustomResourceDefinition" {
			target, targetErr := e.contracts[d.TargetPackage].Template(key, false)
			if targetErr != nil {
				return nil, ErrFixtures
			}
			err = template.CheckCRD(live, entry.UID, target)
		} else {
			err = template.MatchLive(live, entry.UID)
		}
		if err != nil {
			return nil, ErrFixtures
		}
		if gcRows != nil && key.Namespace != "" {
			path, err := resourcePath(key, true)
			if err != nil {
				return nil, ErrFixtures
			}
			plural := path[strings.LastIndex(path, "/")+1:]
			matches := 0
			for _, observed := range gcRows {
				if observed.Metadata.UID == live.GetUID() || observed.Source.Kind == key.Kind && observed.Source.GVR.GroupVersion().String() == key.APIVersion && observed.Metadata.Namespace == key.Namespace && observed.Metadata.Name == key.Name {
					if observed.Source.Kind != key.Kind || observed.Source.GVR.GroupVersion().String() != key.APIVersion || observed.Source.GVR.Resource != plural || !reflect.DeepEqual(observed.Metadata, fixtureGCMetadata(live)) {
						return nil, ErrFixtures
					}
					matches++
				}
			}
			if matches != 1 {
				return nil, ErrFixtures
			}
		}
		row, err := phaseRow(key, live.GetUID(), live.GetResourceVersion(), live)
		if err != nil {
			return nil, ErrFixtures
		}
		rows = append(rows, row)
	}
	sortFixtureWorlds(rows)
	return rows, nil
}

func phaseCollectionKey(key installstate.Key) bool {
	for _, c := range proofCollections {
		if key.APIVersion == c.gv && key.Kind == c.kind {
			return true
		}
	}
	return false
}

func (w *fixtureWire) observePhase(ctx context.Context) (*fixturePhaseObservation, error) {
	if w == nil || w.ledger == nil || ctx == nil {
		return nil, ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	return w.observePhaseLocked(ctx)
}

// Caller serializes the entire closed provider operation on wireMu.
func (w *fixtureWire) observePhaseLocked(ctx context.Context) (*fixturePhaseObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	f := w.ledger
	traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
	if !w.phaseReadable() || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	traceAdmissionPhase(ctx, admissionPhaseWorlds, -1)
	worlds, err := f.readOriginalWorlds(false)
	if err != nil || worlds.Phase == nil || worlds.Phase.Public == nil || !fixtureAccountsRecipeMatches(f.document, worlds.Phase) {
		return nil, ErrFixtures // never promote a legacy world-only companion
	}
	body, identity := bytes.Clone(f.body), f.identity
	reads := &fixturePhaseRead{wire: w, body: body, identity: identity}
	current := func() bool { return reads.current(ctx) == nil }
	local := func() bool { return reads.local(ctx, w) == nil }
	a, request := w.actors.admission, w.actors.request
	traceAdmissionPhase(ctx, admissionPhaseConfigured, -1)
	before, err := a.configured(ctx, request)
	if err != nil || !current() {
		return nil, ErrFixtures
	}
	floor := *worlds.Phase
	if f.phaseFloor != nil {
		if !samePhaseBaseline(floor, *f.phaseFloor) {
			return nil, ErrFixtures
		}
		floor = *f.phaseFloor
	}
	var accepted *fixturePhaseObservation
	var acceptedAccounts *phaseServiceAccounts
	for pass := 0; pass < 2; pass++ {
		// FULL remote original witnesses bracket each complete pass. Within
		// this closed GET/LIST-only interval every old boundary still checks
		// pinned durable local evidence; no observation is accepted early.
		traceAdmissionPhase(ctx, admissionPhaseOpening, -1)
		if !current() {
			return nil, ErrFixtures
		}
		traceAdmissionPhase(ctx, admissionPhaseTyped, -1)
		o, err := a.prerequisites.observe(ctx, request)
		if err != nil || !local() {
			return nil, ErrFixtures
		}
		traceAdmissionPhase(ctx, admissionPhaseRows, -1)
		var accounts *phaseServiceAccounts
		if f.document.Recipe == fixtureRecipeV3 {
			accounts, err = a.collectPhaseServiceAccounts(ctx, request)
			if err != nil || !local() {
				return nil, ErrFixtures
			}
		}
		phase, objects, err := f.accountPhaseWithAccounts(ctx, o, floor, time.Now().UTC(), accounts)
		if err == nil {
			traceAdmissionPhase(ctx, admissionPhasePublicBefore, -1)
			phase.Public, err = a.phasePublicInventory(ctx, request)
			if err == nil && !samePhaseBaseline(floor, phase) {
				err = ErrFixtures
			}
		}
		if err != nil || !local() {
			return nil, ErrFixtures
		}
		// Exact GET/complete LIST correlation for EVERY slot, including planned
		// and deleted slots. Neither a missing GET alone nor a matching label is
		// original-identity evidence; unknown CREATE acknowledgements refuse.
		var live [fixtureMaxSlots]*unstructured.Unstructured
		for slot := range f.document.Entries {
			listed := objects[slot]
			traceAdmissionPhase(ctx, admissionPhaseNamedGet, slot)
			object, absent, err := w.getPhaseLocked(ctx, slot)
			if err != nil || absent != (listed == nil) || identity != f.identity || !bytes.Equal(body, f.body) || !w.phaseReadable() || w.localCurrent() != nil {
				return nil, ErrFixtures
			}
			if absent {
				continue
			}
			traceAdmissionPhase(ctx, admissionPhaseWholeFixture, slot)
			if f.validatePhaseFixture(slot, object, &phase, time.Now().UTC()) != nil {
				return nil, ErrFixtures
			}
			decoded := listed.DeepCopyObject()
			if decodeServing(object, decoded) != nil || !reflect.DeepEqual(listed, decoded) {
				return nil, ErrFixtures
			}
			live[slot] = object
		}
		// Named GETs keep live discovery/SSAR and whole-object correlation.
		// The complete pass's remote closure below must succeed before any
		// phase floor advances; UID+RV rejects change-and-restore.
		if !local() {
			return nil, ErrFixtures
		}
		traceAdmissionPhase(ctx, admissionPhaseStorage, -1)
		s, r := o.Snapshot(), o.Runtime()
		volumes, err := a.prerequisites.coldVolumes(ctx, s, r)
		if err != nil || installsafety.ValidateCSIDetachment(s.Claims, r.Attachments, volumes) != nil || installsafety.ValidateRetainedOwnerClosure(request.Target, s, request.Snapshot.Document().Resources) != nil || !local() {
			return nil, ErrFixtures
		}
		if phaseVolumesMatch(worlds, phase, live, volumes) != nil {
			return nil, ErrFixtures
		}
		traceAdmissionPhase(ctx, admissionPhaseGC, -1)
		gc, phase, err := w.phaseGCWithAccountRenewals(ctx, o, phase, live, reads, accounts)
		if err != nil || !local() {
			return nil, ErrFixtures
		}
		// Running original controller Leases may renew after the typed LIST.
		// A paired whole LIST must exactly correlate the later metadata read and
		// advance only that same sealed controller chain's bookkeeping floor.
		traceAdmissionPhase(ctx, admissionPhaseLeaders, -1)
		phase, refreshed, err := w.refreshPhaseLeadersRead(ctx, o, phase, gc, reads)
		if err != nil {
			return nil, ErrFixtures
		}
		traceAdmissionPhase(ctx, admissionPhaseOwners, -1)
		if f.phaseGCRowsWithAccounts(o, live, gc, refreshed, accounts) != nil || !local() {
			return nil, ErrFixtures
		}
		traceAdmissionPhase(ctx, admissionPhasePublicAfter, -1)
		publicAfter, err := a.phasePublicInventory(ctx, request)
		if err != nil || !reflect.DeepEqual(phase.Public, publicAfter) || !current() {
			return nil, ErrFixtures
		}
		if accounts != nil {
			closing, err := a.collectPhaseServiceAccounts(ctx, request)
			if err != nil || !samePhaseServiceAccounts(accounts, closing) || !current() {
				return nil, ErrFixtures
			}
		}
		// A second complete pass must correlate every live fixture's WHOLE
		// object, not just its UID. Normal controller transitions are observed
		// on a later invocation, never silently waived within this interval.
		traceAdmissionPhase(ctx, admissionPhaseFixtureCorrelation, -1)
		if accepted != nil {
			for slot, old := range accepted.objects {
				if !reflect.DeepEqual(old, live[slot]) {
					return nil, ErrFixtures
				}
			}
		}
		accepted = &fixturePhaseObservation{live, gc, phase}
		acceptedAccounts = accounts
		floor = phase
		// This full pass has accepted the policy/journal/actor barriers and
		// all storage/ancestor/GC/whole-object obligations. Even if the second
		// pass later refuses, never accept regression behind this read.
		copy := phase
		copy.Rows = append([]fixtureWorldRow{}, phase.Rows...)
		copy.Public = append([]fixtureWorldRow{}, phase.Public...)
		if phase.Accounts != nil {
			copy.Accounts = &fixtureAccountBaseline{Version: phase.Accounts.Version, Rows: append([]fixtureWorldRow{}, phase.Accounts.Rows...)}
		}
		copy.Leaders = append([]fixturePhaseLeader{}, phase.Leaders...)
		for index := range copy.Leaders {
			copy.Leaders[index].ManagedTimes = append([]string{}, phase.Leaders[index].ManagedTimes...)
		}
		f.phaseFloor = &copy
	}
	traceAdmissionPhase(ctx, admissionPhaseFinalConfigured, -1)
	after, err := a.configured(ctx, request)
	if err != nil || !sameAdmissionConfiguration(before, after) || !current() {
		return nil, ErrFixtures
	}
	traceAdmissionPhase(ctx, admissionPhaseFinalPublic, -1)
	publicAfter, err := a.phasePublicInventory(ctx, request)
	if err != nil || !reflect.DeepEqual(accepted.phase.Public, publicAfter) || !current() {
		return nil, ErrFixtures
	}
	if acceptedAccounts != nil {
		closing, err := a.collectPhaseServiceAccounts(ctx, request)
		if err != nil || !samePhaseServiceAccounts(acceptedAccounts, closing) || !current() {
			return nil, ErrFixtures
		}
	}
	traceAdmissionPhase(ctx, admissionPhaseComplete, -1)
	return accepted, nil
}

func (w *fixtureWire) phaseReadable() bool {
	if w == nil || w.ledger == nil || w.actors == nil {
		return false
	}
	f := w.ledger
	if !validFixtureRecipe(f.document) || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.behaviorCompletion != nil || f.document.DestroySeed != nil && f.document.DestroySeed.State != fixtureDestroySeedAcknowledged || f.document.RetainedMarker != nil && f.document.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		return false
	}
	for _, entry := range f.document.Entries {
		switch entry.State {
		case fixturePlanned, fixtureOriginal, fixtureDeleteAttempted, fixtureAbsent:
		default:
			return false // unknown CREATE cannot be repaired even by absence
		}
	}
	return true
}

// Account directly for every complete observed row. This is not a filtered
// safety snapshot or a general exemption callback. Fixture addresses come ONLY
// from the fixed durable ledger, and surviving fixtures still need whole GETs.
func (f *fixtureLedger) accountPhase(o *installobserve.Observation, floor fixturePhaseBaseline, now time.Time) (fixturePhaseBaseline, [fixtureMaxSlots]runtime.Object, error) {
	return f.accountPhaseTraced(nil, o, floor, now)
}

// Refusal diagnostics are closed labels from this SAME read attempt, never
// object/error content or proof. No classification rebases rows or retries an
// effect; all original acceptance predicates remain mandatory.
func (f *fixtureLedger) accountPhaseTraced(ctx context.Context, o *installobserve.Observation, floor fixturePhaseBaseline, now time.Time) (fixturePhaseBaseline, [fixtureMaxSlots]runtime.Object, error) {
	return f.accountPhaseWithAccounts(ctx, o, floor, now, nil)
}

func (f *fixtureLedger) accountPhaseWithAccounts(ctx context.Context, o *installobserve.Observation, floor fixturePhaseBaseline, now time.Time, accounts *phaseServiceAccounts) (fixturePhaseBaseline, [fixtureMaxSlots]runtime.Object, error) {
	var fixtures [fixtureMaxSlots]runtime.Object
	zero := fixturePhaseBaseline{}
	if f == nil || o == nil || o.Journal() == nil || !bytes.Equal(o.Journal().Bytes(), f.document.Journal) || o.Journal().ResourceVersion() != f.document.JournalResourceVersion {
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
		if accounts.observation == nil || accounts.observation.Journal() == nil || accounts.observation.Journal().ResourceVersion() != f.document.JournalResourceVersion || !bytes.Equal(accounts.observation.Journal().Bytes(), f.document.Journal) {
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
	for _, collection := range phaseCollectionsWithAccounts(o, accounts) {
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

func (f *fixtureLedger) validatePhaseFixture(slot int, object *unstructured.Unstructured, phase *fixturePhaseBaseline, now time.Time) error {
	if f == nil || object == nil || phase == nil || slot < 0 || slot >= len(fixtureCatalogFor(f.document)) {
		return ErrFixtures
	}
	if slot == fixtureRetainedPVC && f.document.RetainedMarker != nil {
		return f.validateRetainedMarkerResult(object, now)
	}
	if slot == fixtureCancelledDestroy || slot == fixtureVerifiedCancelledDestroy {
		warm := false
		for _, leader := range phase.Leaders {
			warm = warm || leader.Row.Key.Name == "destroy-controller.arcade.gobha.me"
		}
		if seed := f.document.DestroySeed; slot == fixtureCancelledDestroy && seed != nil {
			if warm != (seed.Mode == fixtureDestroySeedWarmCancelled) || seed.State != fixtureDestroySeedAcknowledged || object.GetResourceVersion() != seed.AcknowledgedResourceVersion {
				return ErrFixtures
			}
			if warm {
				return f.validateWarmDestroySeedResult(object, now)
			}
			return f.validateDestroySeedResult(object, now)
		}
		if warm {
			return f.validateWarmCancelledDestroySlotResult(slot, object, now)
		}
	}
	if f.validateResult(slot, fixtureStableResult, object, now) == nil {
		return nil
	}
	return f.validateResult(slot, fixtureAcknowledgedResult, object, now)
}

func phaseVolumesMatch(worlds fixtureWorldsDocument, phase fixturePhaseBaseline, fixtures [fixtureMaxSlots]*unstructured.Unstructured, volumes []*corev1.PersistentVolume) error {
	want := map[string]fixtureWorldRow{}
	uids := map[types.UID]bool{}
	for _, row := range phase.Rows {
		uids[row.UID] = true
	}
	for _, row := range phase.Public {
		uids[row.UID] = true
	}
	if phase.Accounts != nil {
		for _, row := range phase.Accounts.Rows {
			uids[row.UID] = true
		}
	}
	for _, leader := range phase.Leaders {
		uids[leader.Row.UID] = true
	}
	for _, object := range fixtures {
		if object != nil {
			uids[object.GetUID()] = true
		}
	}
	for _, row := range worlds.Rows {
		if row.Key.Kind == "PersistentVolume" {
			want[row.Key.Name] = row
		}
	}
	for _, volume := range volumes {
		if volume == nil || uids[volume.UID] {
			return ErrFixtures
		}
		uids[volume.UID] = true
		if original, protected := want[volume.Name]; protected {
			row, err := phaseRow(original.Key, volume.UID, volume.ResourceVersion, volume)
			if err != nil || original != row {
				return ErrFixtures
			}
			delete(want, volume.Name)
		}
	}
	if len(want) != 0 {
		return ErrFixtures
	}
	return nil
}

func (f *fixtureLedger) phaseGC(o *installobserve.Observation, objects [fixtureMaxSlots]*unstructured.Unstructured, gc *installobserve.GCObservation, refreshed map[installstate.Key]*coordinationv1.Lease) error {
	return f.phaseGCRows(o, objects, gc, refreshed)
}

// Pure inventory/owner validation also checks an unsealed refusal projection.
// Passing it never supplies a GCObservation, phase floor or effect authority.
type fixtureGCRows interface {
	Journal() *installstate.Snapshot
	Objects() []installobserve.GCObject
	Descendants([]types.UID) ([]installobserve.GCObject, error)
}

func (f *fixtureLedger) phaseGCRows(o *installobserve.Observation, objects [fixtureMaxSlots]*unstructured.Unstructured, gc fixtureGCRows, refreshed map[installstate.Key]*coordinationv1.Lease) error {
	return f.phaseGCRowsWithAccounts(o, objects, gc, refreshed, nil)
}

func (f *fixtureLedger) phaseGCRowsWithAccounts(o *installobserve.Observation, objects [fixtureMaxSlots]*unstructured.Unstructured, gc fixtureGCRows, refreshed map[installstate.Key]*coordinationv1.Lease, accounts *phaseServiceAccounts) error {
	if f == nil || !validFixtureRecipe(f.document) || gc == nil || gc.Journal() == nil || !bytes.Equal(gc.Journal().Bytes(), f.document.Journal) || gc.Journal().ResourceVersion() != f.document.JournalResourceVersion {
		return ErrFixtures
	}
	if (f.document.Recipe == fixtureRecipeV3) != (accounts != nil) || accounts != nil && (accounts.observation == nil || accounts.observation.Journal() == nil || accounts.observation.Journal().ResourceVersion() != f.document.JournalResourceVersion || !bytes.Equal(accounts.observation.Journal().Bytes(), f.document.Journal)) {
		return ErrFixtures
	}
	for slot := len(f.document.Entries); slot < len(objects); slot++ {
		if objects[slot] != nil {
			return ErrFixtures // unused v1 tail is never an exempted object
		}
	}
	rows := gc.Objects()
	byUID := map[types.UID][]installobserve.GCObject{}
	for _, row := range rows {
		byUID[row.Metadata.UID] = append(byUID[row.Metadata.UID], row)
	}
	known := map[schema.GroupResource]bool{}
	typed := map[types.UID]bool{}
	// Correlate the complete typed namespace inventory, not just fixture rows.
	for _, collection := range phaseCollectionsWithAccounts(o, accounts) {
		gv, err := schema.ParseGroupVersion(collection.version)
		if err != nil {
			return ErrFixtures
		}
		plural := ""
		if collection.version == "v1" && collection.kind == "ServiceAccount" {
			plural = "serviceaccounts"
		}
		for _, fixed := range proofCollections {
			if fixed.gv == collection.version && fixed.kind == collection.kind {
				plural = fixed.plural
			}
		}
		if plural == "" {
			return ErrFixtures
		}
		known[schema.GroupResource{Group: gv.Group, Resource: plural}] = true
		items, err := meta.ExtractList(collection.list)
		if err != nil {
			return ErrFixtures
		}
		for _, object := range items {
			m, err := meta.Accessor(object)
			if err != nil {
				return ErrFixtures
			}
			if m.GetNamespace() == "" {
				continue
			}
			key := installstate.Key{APIVersion: collection.version, Kind: collection.kind, Namespace: m.GetNamespace(), Name: m.GetName()}
			if lease := refreshed[key]; lease != nil {
				if collection.kind != "Lease" || lease.UID != m.GetUID() {
					return ErrFixtures
				}
				m = lease // only independently whole-validated original leaders
			}
			typed[m.GetUID()] = true
			matches := byUID[m.GetUID()]
			// Fresh discovery examines ALL served versions and the metadata
			// reader selects one exact version per GroupResource. Correlate its
			// canonical resource and public metadata; do not invent a second
			// source from the typed object's Kind or accept duplicate identities.
			if len(matches) != 1 || matches[0].Source.Kind != collection.kind || matches[0].Source.GVR.GroupResource() != (schema.GroupResource{Group: gv.Group, Resource: plural}) || !reflect.DeepEqual(matches[0].Metadata, fixtureGCMetadata(m)) {
				return ErrFixtures
			}
		}
	}
	for _, row := range rows {
		if known[row.Source.GVR.GroupResource()] && !typed[row.Metadata.UID] {
			return ErrFixtures // a GC-only typed object is not complete-list absence
		}
	}
	for slot, entry := range f.document.Entries {
		source, err := fixtureGCSource(entry)
		if err != nil {
			return ErrFixtures
		}
		for _, row := range rows {
			if row.Source.GVR.GroupResource() == source.GVR.GroupResource() && row.Metadata.Namespace == entry.Key.Namespace && row.Metadata.Name == entry.Key.Name {
				if objects[slot] == nil || !reflect.DeepEqual(row.Metadata, fixtureGCMetadata(objects[slot])) {
					return ErrFixtures
				}
			}
		}
		if objects[slot] == nil && len(byUID[entry.OriginalUID]) != 0 {
			return ErrFixtures
		}
		if entry.OriginalUID == "" {
			continue
		}
		children, err := gc.Descendants([]types.UID{entry.OriginalUID})
		if err != nil {
			return ErrFixtures
		}
		worker := -1
		for candidate, recipe := range fixtureCatalogFor(f.document) {
			if recipe.owner == slot && objects[candidate] != nil {
				worker = candidate
			}
		}
		if worker == -1 {
			if len(children) != 0 {
				return ErrFixtures
			}
		} else {
			source, err := fixtureGCSource(f.document.Entries[worker])
			if err != nil || objects[slot] == nil || len(children) != 1 || children[0].Source != source || !reflect.DeepEqual(children[0].Metadata, fixtureGCMetadata(objects[worker])) {
				return ErrFixtures
			}
		}
	}
	return nil
}
