//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/rest"
)

// Failure-only CURRENT classifier of a LATER observation against the sealed
// INITIAL floor. This cannot reconstruct the historical child's collection or
// its later in-memory phaseFloor. In particular, a match cannot cure its refusal.
// No effect, ledger recovery, phase-floor update or historical binary hook exists.
type historicalPhaseFailureObservation struct {
	status, stage, family                            string
	floorBound, collected, accounted, closingStable  bool
	membership, identity, rv, hash                   bool
	leaders                                          int
	leaderTimesPresent, acquireBefore, managedBefore bool
	renewStale, futureTime                           bool
}

func (o historicalPhaseFailureObservation) String() string {
	return fmt.Sprintf("classifier=current scope=post-exit-initial-floor status=%s stage=%s family=%s floor-bound=%t collected=%t accounted=%t closing-stable=%t row-membership-change=%t row-identity-change=%t row-rv-change=%t row-hash-change=%t leaders=%d leader-times-present=%t acquire-before-creation=%t managed-before-creation=%t renew-stale=%t future-time=%t", o.status, o.stage, o.family, o.floorBound, o.collected, o.accounted, o.closingStable, o.membership, o.identity, o.rv, o.hash, o.leaders, o.leaderTimesPresent, o.acquireBefore, o.managedBefore, o.renewStale, o.futureTime)
}

func unavailableHistoricalPhaseFailure() historicalPhaseFailureObservation {
	return historicalPhaseFailureObservation{status: "unavailable", stage: "unknown", family: "unknown"}
}

func observeHistoricalInstallerPhaseFailure(ctx context.Context, config *rest.Config, state string, original *installrender.Plan) historicalPhaseFailureObservation {
	o := unavailableHistoricalPhaseFailure()
	if ctx == nil || ctx.Err() != nil || config == nil || !original.IsTrusted() {
		return o
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		return o
	}
	files, err := privatefs.Open(state, false)
	if err != nil {
		return o
	}
	defer files.Close()
	receipt, err := installstate.LoadBootstrap(files, "bootstrap.json", original)
	if err != nil {
		return o
	}
	anchor, err := receipt.PinnedAnchor(ctx)
	if err != nil {
		return o
	}
	store, err := installstate.New(access.Namespaces(), original)
	if err != nil {
		return o
	}
	snapshot, err := store.Load(ctx, anchor)
	if err != nil {
		return o
	}
	engine, err := NewWithAccess(access, store, files, original)
	if err != nil {
		return o
	}
	observer, err := installobserve.New(access.readConfig(), store, original)
	if err != nil {
		return o
	}
	return collectHistoricalInstallerPhaseFailure(ctx, engine, snapshot, func(ctx context.Context) (*installobserve.Observation, error) {
		return observer.Collect(ctx, anchor)
	})
}

func collectHistoricalInstallerPhaseFailure(ctx context.Context, engine *Engine, snapshot *installstate.Snapshot, collect func(context.Context) (*installobserve.Observation, error)) historicalPhaseFailureObservation {
	o := unavailableHistoricalPhaseFailure()
	if ctx == nil || ctx.Err() != nil || engine == nil || engine.files == nil || snapshot == nil || collect == nil {
		return o
	}
	name := fixtureLedgerName(snapshot)
	body, _, walPin, err := engine.files.Pin(name, fixtureLedgerMaxBytes)
	if err != nil {
		return o
	}
	defer walPin.Close()
	document, err := engine.decodeFixtureLedger(body)
	if err != nil || document.Recipe != fixtureRecipeV2 || !bytes.Equal(document.Journal, snapshot.Bytes()) || document.JournalResourceVersion != snapshot.ResourceVersion() {
		return o
	}
	// Derive the companion address from the authenticated original journal/run,
	// never a directory scan or a path learned from a returned cluster object.
	worldName := "admission-worlds-" + snapshot.Document().InstallationID + "-" + document.RunID + ".json"
	worldBody, _, worldPin, err := engine.files.PinEvidence(worldName, privatefs.MaxEvidenceFileBytes)
	if err != nil {
		return o
	}
	defer worldPin.Close()
	worlds, err := decodeFixtureWorldsShape(worldBody, snapshot.Anchor().Namespace)
	if err != nil || worlds.Version != "original-worlds-v1" || worlds.RunID != document.RunID || !bytes.Equal(worlds.Journal, document.Journal) || worlds.JournalResourceVersion != document.JournalResourceVersion || fixtureWorldDigest(worldBody) != document.OriginalWorldsSHA256 || worlds.Phase == nil || !fixtureAccountsRecipeMatches(document, worlds.Phase) || walPin.Confirm() != nil || worldPin.Confirm() != nil {
		return o
	}
	o.floorBound = true
	observation, err := collect(ctx)
	if err != nil || observation == nil || observation.Journal() == nil || observation.Journal().Anchor() != snapshot.Anchor() || !bytes.Equal(observation.Journal().Bytes(), snapshot.Bytes()) || observation.Journal().ResourceVersion() != snapshot.ResourceVersion() {
		if ctx.Err() != nil {
			o.status = "context-ended"
		}
		return o
	}
	o.status, o.collected = "observed", true
	traceCtx, trace := WithLifecycleDiagnostic(ctx)
	traceAdmissionPhase(traceCtx, admissionPhaseRows, -1)
	// Deliberately no lock/wire/actors/capability: only the pure current account
	// classifier can consume this in-memory document, never a production send.
	ledger := &fixtureLedger{document: document}
	observedAt := time.Now().UTC()
	_, _, accountErr := ledger.accountPhaseTraced(traceCtx, observation, *worlds.Phase, observedAt)
	o.accounted = accountErr == nil
	o.stage, _ = trace.admission.phaseSnapshot()
	if o.accounted {
		o.stage = "complete"
	}
	if completeStoppedLists(observation.Snapshot(), observation.Runtime()) {
		observeHistoricalPhaseRows(&o, document, *worlds.Phase, observation)
		observeHistoricalPhaseLeaderTimes(&o, *worlds.Phase, observation, observedAt)
	}
	fresh, journalErr := engine.journal.Load(ctx, snapshot.Anchor())
	o.closingStable = journalErr == nil && fresh.ResourceVersion() == snapshot.ResourceVersion() && bytes.Equal(fresh.Bytes(), snapshot.Bytes()) && walPin.Confirm() == nil && worldPin.Confirm() == nil
	if !o.closingStable {
		// Preserve transient facets, but explicitly invalidate their original
		// evidence interval. They never become a completed stable observation.
		o.status = "changed"
	}
	if ctx.Err() != nil {
		o.status = "context-ended"
	}
	return o
}

// Fixed collection order chooses the first changed family. Hash change means
// whole typed row bytes changed (which includes RV); it does NOT identify a
// spec/status change. No address, UID, RV, digest or provider text is projected.
func observeHistoricalPhaseRows(report *historicalPhaseFailureObservation, document fixtureLedgerDocument, floor fixturePhaseBaseline, observation *installobserve.Observation) {
	fixtures := map[installstate.Key]bool{}
	for _, entry := range document.Entries {
		fixtures[entry.Key] = true
	}
	for _, leader := range floor.Leaders {
		fixtures[leader.Row.Key] = true
	}
	for _, collection := range phaseCollections(observation) {
		want := map[installstate.Key]fixtureWorldRow{}
		for _, row := range floor.Rows {
			if row.Key.APIVersion == collection.version && row.Key.Kind == collection.kind {
				want[row.Key] = row
			}
		}
		items, err := meta.ExtractList(collection.list)
		if err != nil || len(items) > installsafety.MaxObjectsPerList {
			return
		}
		for _, item := range items {
			object, err := meta.Accessor(item)
			if err != nil {
				return
			}
			key := installstate.Key{APIVersion: collection.version, Kind: collection.kind, Namespace: object.GetNamespace(), Name: object.GetName()}
			if fixtures[key] {
				continue
			}
			row, err := phaseRow(key, object.GetUID(), object.GetResourceVersion(), item)
			if err != nil {
				return
			}
			original, present := want[key]
			report.membership = report.membership || !present
			if present {
				report.identity = report.identity || original.UID != row.UID
				report.rv = report.rv || original.ResourceVersion != row.ResourceVersion
				report.hash = report.hash || original.SHA256 != row.SHA256
			}
			delete(want, key)
		}
		report.membership = report.membership || len(want) != 0
		if report.membership || report.identity || report.rv || report.hash {
			report.family = collection.kind // literal closed phaseCollections kind
			return
		}
	}
}

func observeHistoricalPhaseLeaderTimes(report *historicalPhaseFailureObservation, floor fixturePhaseBaseline, observation *installobserve.Observation, now time.Time) {
	report.leaders, report.leaderTimesPresent = len(floor.Leaders), true
	snapshot := observation.Snapshot()
	for _, original := range floor.Leaders {
		found := false
		for _, lease := range snapshot.Leases.Items {
			if lease.Namespace != original.Row.Key.Namespace || lease.Name != original.Row.Key.Name || lease.UID != original.Row.UID {
				continue
			}
			found = true
			present := !lease.CreationTimestamp.IsZero() && lease.Spec.AcquireTime != nil && !lease.Spec.AcquireTime.IsZero() && lease.Spec.RenewTime != nil && !lease.Spec.RenewTime.IsZero() && len(lease.ManagedFields) != 0
			if present {
				report.acquireBefore = report.acquireBefore || lease.Spec.AcquireTime.Time.Before(lease.CreationTimestamp.Time)
				report.renewStale = report.renewStale || now.Sub(lease.Spec.RenewTime.Time) > 15*time.Second
				report.futureTime = report.futureTime || lease.CreationTimestamp.After(now.Add(time.Second)) || lease.Spec.RenewTime.After(now.Add(time.Second))
			}
			for _, field := range lease.ManagedFields {
				if field.Time == nil || field.Time.IsZero() {
					present = false
					continue
				}
				report.managedBefore = report.managedBefore || field.Time.Before(&lease.CreationTimestamp)
				report.futureTime = report.futureTime || field.Time.After(now.Add(time.Second))
			}
			report.leaderTimesPresent = report.leaderTimesPresent && present
		}
		report.leaderTimesPresent = report.leaderTimesPresent && found
	}
}
