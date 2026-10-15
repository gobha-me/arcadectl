//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestInstallerBinaryHistoricalPhaseFailureDiagnostic(t *testing.T) {
	testHistoricalInstallerPhaseFailureObservation(t)
}

func testHistoricalInstallerPhaseFailureObservation(t *testing.T) {
	t.Helper()
	newPhase := unmarkedRecoveryPhaseFactory(t)
	for _, fault := range []string{"match", "fixture-replaced", "fixture-missing", "row-extra", "row-rv", "row-status", "row-identity", "row-missing", "bad-companion", "wrong-version", "replaced-companion", "replaced-wal", "changed-journal", "collection-refused", "context-ended", "late-context-ended"} {
		t.Run("historical-phase-"+fault, func(t *testing.T) {
			h := newPhase(t)
			f, ledger := h.f, h.f.wire.ledger
			engine, snapshot := ledger.engine, f.actor.request.Snapshot
			worldName, err := ledger.originalWorldsName()
			if err != nil {
				t.Fatal("original companion address unavailable")
			}
			worldBody, worldID, err := engine.files.ReadEvidence(worldName, privatefs.MaxEvidenceFileBytes)
			if err != nil || ledger.close() != nil {
				t.Fatal("original phase fixture unavailable")
			}
			walName := fixtureLedgerName(snapshot)
			walBody, walID, err := engine.files.Read(walName, fixtureLedgerMaxBytes)
			if err != nil {
				t.Fatal("original WAL unavailable")
			}
			if fault == "fixture-replaced" {
				f.objects[fixturePlainPod].SetUID("b0000000-0000-4000-8000-000000000001")
			}
			if fault == "fixture-missing" {
				h.hide[fixturePlainPod] = true
			}
			if fault == "row-extra" {
				extra := f.objects[fixturePlainPod].DeepCopy()
				extra.SetName("private-phase-canary")
				extra.SetUID("b0000000-0000-4000-8000-000000000002")
				h.extra = append(h.extra, extra)
			}
			if fault == "row-rv" || fault == "row-status" || fault == "row-identity" || fault == "row-missing" {
				// Policies are ordinary sealed rows, never fixture exemptions.
				for key, object := range f.actor.v.f.access.objects {
					if key.Kind == "ValidatingAdmissionPolicy" {
						if fault == "row-rv" {
							object.SetResourceVersion("991")
						} else if fault == "row-status" {
							object.Object["status"] = map[string]any{"observedGeneration": object.GetGeneration() + 1}
						} else if fault == "row-identity" {
							object.SetUID("b0000000-0000-4000-8000-000000000004")
						} else {
							delete(f.actor.v.f.access.objects, key)
						}
						break
					}
				}
			}
			if fault == "bad-companion" {
				if engine.files.RemoveEvidence(worldName, worldID) != nil {
					t.Fatal("test companion removal refused")
				}
				if _, err := engine.files.CreateEvidenceExclusive(worldName, []byte("private-phase-canary")); err != nil {
					t.Fatal("test invalid companion unavailable")
				}
			}
			if fault == "wrong-version" {
				worlds, err := decodeFixtureWorldsShape(worldBody, snapshot.Anchor().Namespace)
				if err != nil {
					t.Fatal("canonical companion fixture unavailable")
				}
				worlds.Version = "foreign-version"
				foreign, err := fixtureWorldsShapeBody(worlds, snapshot.Anchor().Namespace)
				if err != nil || engine.files.RemoveEvidence(worldName, worldID) != nil {
					t.Fatal("test foreign-version companion unavailable")
				}
				if _, err := engine.files.CreateEvidenceExclusive(worldName, foreign); err != nil {
					t.Fatal("test foreign-version companion publication refused")
				}
				document, err := engine.decodeFixtureLedger(walBody)
				if err != nil {
					t.Fatal("test WAL binding unavailable")
				}
				document.OriginalWorldsSHA256 = fixtureWorldDigest(foreign)
				matchedWAL, err := engine.fixtureLedgerBody(document)
				if err != nil {
					t.Fatal("test canonical WAL digest binding refused")
				}
				if _, err := engine.files.AtomicWrite(walName, matchedWAL, &walID); err != nil {
					t.Fatal("test coordinated WAL publication refused")
				}
			}
			base := f.actor.fixtureHandler
			requests, secretMetadata := 0, 0
			f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				requests++
				if r.Method != http.MethodGet {
					t.Error("post-exit observer attempted a mutation or review")
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				if strings.Contains(r.URL.Path, "/secrets") {
					if !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
						t.Error("post-exit observer requested Secret payloads")
						w.WriteHeader(http.StatusForbidden)
						return true
					}
					secretMetadata++
				}
				return base(w, r)
			}
			observer, err := installobserve.New(f.actor.admission.prerequisites.access.readConfig(), engine.journal, f.actor.request.Target)
			if err != nil {
				t.Fatal("read-only observer unavailable")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			collects := 0
			report := collectHistoricalInstallerPhaseFailure(ctx, engine, snapshot, func(ctx context.Context) (*installobserve.Observation, error) {
				collects++
				if fault == "collection-refused" || fault == "context-ended" {
					if fault == "context-ended" {
						cancel()
					}
					return nil, installobserve.ErrRead
				}
				observation, err := observer.Collect(ctx, snapshot.Anchor())
				switch fault {
				case "late-context-ended":
					cancel()
				case "replaced-companion":
					if engine.files.RemoveEvidence(worldName, worldID) != nil {
						t.Fatal("test replacement removal refused")
					}
					if _, err := engine.files.CreateEvidenceExclusive(worldName, worldBody); err != nil {
						t.Fatal("test same-byte companion replacement unavailable")
					}
				case "replaced-wal":
					if _, err := engine.files.AtomicWrite(walName, walBody, &walID); err != nil {
						t.Fatal("test same-byte WAL replacement unavailable")
					}
				case "changed-journal":
					namespace, _ := f.actor.v.f.access.client.CoreV1().Namespaces().Get(ctx, snapshot.Anchor().Namespace, metav1.GetOptions{})
					namespace.ResourceVersion = "991"
					if f.actor.v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
						t.Fatal("test changed journal unavailable")
					}
				}
				return observation, err
			})
			text := report.String()
			for _, private := range []string{"private-phase-canary", snapshot.Anchor().Namespace, string(f.objects[fixturePlainPod].GetUID()), worldName, string(walBody), string(worldBody)} {
				if private != "" && strings.Contains(text, private) {
					t.Fatal("post-exit phase diagnostic leaked private evidence")
				}
			}
			if f.creates != 0 || f.deletes != 0 || f.previews != 0 || f.seeds != 0 || ledger.behaviorCompletion != nil || ledger.phaseFloor != nil {
				t.Fatal("failure classifier gained effect or floor authority")
			}
			if fault == "bad-companion" || fault == "wrong-version" {
				if report.floorBound || collects != 0 || requests != 0 {
					t.Fatal("unbound companion authorized observation")
				}
				return
			}
			if !report.floorBound || collects != 1 {
				t.Fatal("original floor binding or single observation lost")
			}
			if fault == "collection-refused" || fault == "context-ended" {
				if report.collected || report.accounted || report.closingStable || requests != 0 || (report.status == "context-ended") != (fault == "context-ended") {
					t.Fatal("incomplete later collection became evidence")
				}
				return
			}
			if fault == "row-identity" || fault == "row-missing" {
				// The real sealed collector already refuses a changed/missing
				// signed original. Never weaken it to obtain a finer diagnostic.
				if report.collected || report.accounted || report.closingStable || report.status != "unavailable" || report.stage != "unknown" || requests == 0 {
					t.Fatal("collector original-identity refusal became later evidence")
				}
				closing, closingID, _ := engine.files.Read(walName, fixtureLedgerMaxBytes)
				if !bytes.Equal(closing, walBody) || closingID != walID {
					t.Fatal("collector refusal changed the original WAL")
				}
				return
			}
			wantStatus := "observed"
			if fault == "replaced-companion" || fault == "replaced-wal" || fault == "changed-journal" {
				wantStatus = "changed"
			}
			if fault == "late-context-ended" {
				wantStatus = "context-ended"
			}
			if !report.collected || secretMetadata == 0 || report.status != wantStatus {
				t.Fatal("complete bounded metadata-only observation unavailable", report.String())
			}
			if report.closingStable == (fault == "replaced-companion" || fault == "replaced-wal" || fault == "changed-journal" || fault == "late-context-ended") {
				t.Fatal("closing protected evidence drift lost")
			}
			wantStage := "complete"
			switch fault {
			case "fixture-replaced":
				wantStage = "original-row-fixture-identity"
			case "fixture-missing":
				wantStage = "original-row-missing-fixture"
			case "row-extra", "row-rv", "row-status":
				wantStage = "original-row-floor"
			}
			if report.stage != wantStage || report.accounted != (wantStage == "complete") {
				t.Fatal("current later classifier reported the wrong stage", report.String())
			}
			if fault == "row-extra" && (report.family != "Pod" || !report.membership) || fault == "row-rv" && (report.family != "ValidatingAdmissionPolicy" || !report.rv || !report.hash) || fault == "row-status" && (report.family != "ValidatingAdmissionPolicy" || report.rv || !report.hash) {
				t.Fatal("initial-floor row difference was lost or over-attributed", report.String())
			}
			if fault != "replaced-wal" {
				closing, closingID, _ := engine.files.Read(walName, fixtureLedgerMaxBytes)
				if !bytes.Equal(closing, walBody) || closingID != walID {
					t.Fatal("read-only classifier changed the original WAL")
				}
			}
		})
	}
	testHistoricalPhaseLeaderTimes(t)
}

func testHistoricalPhaseLeaderTimes(t *testing.T) {
	t.Helper()
	newPhase := fixtureWarmPhaseFactory(t)
	for _, fault := range []string{"match", "earlier-acquire", "earlier-managed", "stale-renew", "future-managed", "missing-managed", "replaced-leader"} {
		t.Run("historical-phase-leader-"+fault, func(t *testing.T) {
			h := newPhase(t)
			ledger := h.f.wire.ledger
			worlds, err := ledger.readOriginalWorlds(false)
			if err != nil || worlds.Phase == nil || len(worlds.Phase.Leaders) != 2 {
				t.Fatal("warm original floor unavailable")
			}
			observer, err := installobserve.New(h.f.actor.admission.prerequisites.access.readConfig(), ledger.engine.journal, h.f.actor.request.Target)
			if err != nil {
				t.Fatal("warm read-only observer unavailable")
			}
			changed := false
			for i, object := range h.extra {
				if object.GetKind() != "Lease" {
					continue
				}
				var lease coordinationv1.Lease
				if decodeServing(object, &lease) != nil {
					t.Fatal("original warm Lease unavailable")
				}
				switch fault {
				case "earlier-acquire":
					stamp := metav1.NewMicroTime(lease.CreationTimestamp.Add(-time.Second))
					lease.Spec.AcquireTime = &stamp
				case "earlier-managed":
					stamp := metav1.NewTime(lease.CreationTimestamp.Add(-time.Second))
					lease.ManagedFields[0].Time = &stamp
				case "stale-renew":
					stamp := metav1.NewMicroTime(time.Now().UTC().Add(-25 * time.Second))
					lease.Spec.RenewTime = &stamp
				case "future-managed":
					stamp := metav1.NewTime(time.Now().UTC().Add(20 * time.Second))
					lease.ManagedFields[0].Time = &stamp
				case "missing-managed":
					lease.ManagedFields[0].Time = nil
				case "replaced-leader":
					lease.UID = types.UID("b0000000-0000-4000-8000-000000000003")
				}
				h.extra[i] = servingObject(t, &lease)
				changed = true
				break
			}
			if !changed {
				t.Fatal("warm original Lease not found")
			}
			observation, err := observer.Collect(t.Context(), h.f.actor.request.Snapshot.Anchor())
			if err != nil {
				t.Fatal("warm complete observation unavailable")
			}
			report := unavailableHistoricalPhaseFailure()
			observeHistoricalPhaseLeaderTimes(&report, *worlds.Phase, observation, time.Now().UTC())
			if report.leaders != 2 || report.leaderTimesPresent != (fault != "missing-managed" && fault != "replaced-leader") || report.renewStale != (fault == "stale-renew") || report.futureTime != (fault == "future-managed") || report.acquireBefore != (fault == "earlier-acquire") || report.managedBefore != (fault == "earlier-managed") {
				t.Fatal("warm later leader facets unavailable")
			}
		})
	}
}
