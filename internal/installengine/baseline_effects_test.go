// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// These tests prove protected ownership/effect recovery, not admission health
// or native enforcement. No test-only guard is installed to bypass that gate.
func baselineFixturePlan(t *testing.T, namespace, profile string, source byte) *installbaseline.Plan {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat(string(source), 40), 1)
	if err != nil {
		t.Fatal("baseline fixture build failed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) // fake fixture key ONLY
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil {
		t.Fatal("baseline fixture signing failed")
	}
	verified, err := installbaseline.Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("baseline fixture authentication failed")
	}
	plan, err := installbaseline.Compile(verified, namespace, profile)
	if err != nil {
		t.Fatal("baseline fixture compilation failed")
	}
	return plan
}

type baselineFixtureAccess struct{ *fixtureAccess }

func (a *baselineFixtureAccess) Create(ctx context.Context, key installstate.Key, object *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	if dry {
		a.dryRuns++
		if a.dry != nil {
			return a.dry(object.DeepCopy()), nil
		}
		return object.DeepCopy(), nil
	}
	a.writes++
	namespace, err := a.client.CoreV1().Namespaces().Get(ctx, a.namespace, metav1.GetOptions{})
	if err != nil {
		a.t.Fatal("baseline intent observation unavailable")
	}
	var document installstate.Document
	if json.Unmarshal([]byte(namespace.Annotations[installstate.Annotation]), &document) != nil || document.Pending != nil || document.SecurityBaseline == nil {
		a.t.Fatal("baseline effect lacked separate durable intent")
	}
	pending := document.SecurityBaseline.Pending
	if pending == nil || pending.Action != installstate.Create || pending.Key != key || object.GetAnnotations()[installstate.MutationAnnotation] != pending.CreateNonce {
		a.t.Fatal("baseline effect differs from durable exact intent")
	}
	if a.write != nil {
		return a.write(installstate.Create, key, object)
	}
	result := object.DeepCopy()
	result.SetUID(types.UID("baseline-" + strconv.Itoa(a.writes)))
	result.SetResourceVersion(strconv.Itoa(a.writes + 100))
	a.objects[key] = result.DeepCopy()
	return result, nil
}

func newBaselineFixture(t *testing.T) *fixture {
	return newBaselineFixtureWithPlans(t, fixturePlan(t))
}

func newBaselineFixtureWithPlans(t *testing.T, plans ...*installrender.Plan) *fixture {
	return newBaselineFixtureAtStage(t, true, plans...)
}

func newPreparingBaselineFixture(t *testing.T) *fixture {
	return newBaselineFixtureAtStage(t, false, fixturePlan(t))
}

func newBaselineFixtureAtStage(t *testing.T, applying bool, plans ...*installrender.Plan) *fixture {
	t.Helper()
	f := newFixtureWithPlans(t, false, plans...)
	baseline := baselineFixturePlan(t, f.plan.Namespace(), f.plan.Profile().ID, 'd')
	document := f.snapshot.Document()
	if !applying {
		document.Stage = installstate.Preparing
	}
	var err error
	document.SecurityBaseline, err = installstate.PinnedSecurityBaseline(baseline)
	if err != nil {
		t.Fatal("baseline fixture pin failed")
	}
	body, err := installstate.EncodeWithBaseline(document, baseline, plans...)
	if err != nil {
		t.Fatal("baseline fixture journal encoding failed")
	}
	namespace, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal("baseline fixture namespace unavailable")
	}
	namespace.Annotations[installstate.Annotation] = string(body)
	if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
		t.Fatal("baseline fixture seed failed")
	}
	f.store, err = installstate.NewWithBaseline(f.access.client.CoreV1().Namespaces(), baseline, plans...)
	if err != nil {
		t.Fatal("baseline fixture store refused")
	}
	f.engine, err = NewWithBaselineAccess(&baselineFixtureAccess{f.access}, f.store, f.engine.files, baseline, plans...)
	if err != nil {
		t.Fatal("baseline fixture engine refused")
	}
	f.snapshot, err = f.store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("baseline fixture observation failed")
	}
	if !applying {
		return f
	}
	f.snapshot, err = f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
	if err != nil || f.snapshot.Document().SecurityBaseline.Stage != installstate.BaselineApplying || f.access.writes != 0 {
		t.Fatal("baseline preparing transition failed")
	}
	return f
}

func completeBaselineFixture(t *testing.T, f *fixture) {
	t.Helper()
	for i := 0; i <= installbaseline.ResourceCount; i++ {
		before := f.access.writes
		next, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
		if err != nil || f.access.writes-before > 1 {
			t.Fatal("baseline ownership step failed or emitted multiple effects")
		}
		f.snapshot = next
	}
	if f.snapshot.Document().SecurityBaseline.Stage != installstate.BaselineVerified || f.access.writes != installbaseline.ResourceCount {
		t.Fatal("closed original baseline ownership incomplete")
	}
}

func reloadBaselineFixture(t *testing.T, f *fixture) *installstate.Snapshot {
	t.Helper()
	// Restart the engine/store with only the same protected durable files and
	// authenticated sealed plans; no in-memory ACK capability survives.
	baseline, files := f.engine.baselinePlan(), f.engine.files
	var err error
	f.store, err = installstate.NewWithBaseline(f.access.client.CoreV1().Namespaces(), baseline, f.plan)
	if err != nil {
		t.Fatal("baseline recovery store reconstruction failed")
	}
	f.engine, err = NewWithBaselineAccess(&baselineFixtureAccess{f.access}, f.store, files, baseline, f.plan)
	if err != nil {
		t.Fatal("baseline recovery engine reconstruction failed")
	}
	snapshot, err := f.store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal("baseline recovery journal unavailable")
	}
	return snapshot
}

func TestBaselineDefinitiveRejectionCannotAdoptCopiedNonceAfterRestart(t *testing.T) {
	for index, rejection := range definitiveCreateErrors() {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			f := newBaselineFixture(t)
			f.access.write = func(_ installstate.Action, key installstate.Key, candidate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				foreign := candidate.DeepCopy()
				foreign.SetUID("foreign-copied-nonce")
				foreign.SetResourceVersion("101")
				f.access.objects[key] = foreign
				return nil, rejection
			}
			if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrOutcomeUnknown {
				t.Fatal("definitive rejection adopted copied nonce")
			}
			f.snapshot = reloadBaselineFixture(t, f)
			if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrOutcomeUnknown || f.access.writes != 1 || f.access.dryRuns != 1 {
				t.Fatal("restart adopted or replayed rejected effect")
			}
		})
	}
}

func TestBaselineInFlightFixtureFencePreservesAckButBlocksSettlement(t *testing.T) {
	f := newBaselineFixture(t)
	f.access.write = func(_ installstate.Action, key installstate.Key, candidate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		live := candidate.DeepCopy()
		live.SetUID("acknowledged-original")
		live.SetResourceVersion("101")
		f.access.objects[key] = live.DeepCopy()
		if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("new unresolved fixture evidence")); err != nil {
			t.Fatal("in-flight fixture fence seed failed")
		}
		return live, nil
	}
	if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrOutcomeUnknown {
		t.Fatal("in-flight fixture evidence permitted settlement")
	}
	f.snapshot = reloadBaselineFixture(t, f)
	if uid, err := f.engine.baseline.loadReceiptUID(f.snapshot.Document()); err != nil || uid != "acknowledged-original" {
		t.Fatal("known ACK identity was discarded while effect was in flight")
	}
	beforeUpdates := f.nsUpdates
	if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrFixtures || f.access.writes != 1 || f.access.dryRuns != 1 || f.nsUpdates != beforeUpdates || f.snapshot.Document().SecurityBaseline.Pending == nil {
		t.Fatal("unresolved fixture allowed follow-on baseline effects or erased pending intent")
	}
}

func TestBaselineOwnershipSeparateInventoryAndRuntimeFence(t *testing.T) {
	f := newBaselineFixture(t)
	runtimeInventory := f.snapshot.Document().Resources
	if _, err := f.engine.Apply(t.Context(), f.snapshot, f.key, f.plan.Digest(), false); err != ErrSecurityBaseline || f.access.writes != 0 || f.access.dryRuns != 0 {
		t.Fatal("unproved baseline allowed runtime effect")
	}
	completeBaselineFixture(t, f)
	document := f.snapshot.Document()
	if !reflect.DeepEqual(runtimeInventory, document.Resources) || document.Pending != nil || document.SecurityBaseline.Pending != nil || len(document.SecurityBaseline.Resources) != installbaseline.ResourceCount || f.access.dryRuns != installbaseline.ResourceCount {
		t.Fatal("baseline creation contaminated runtime inventory")
	}
	beforeWrites, beforeUpdates := f.access.writes, f.nsUpdates
	if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != nil || f.access.writes != beforeWrites || f.nsUpdates != beforeUpdates {
		t.Fatal("verified ownership was rewritten or replayed")
	}
	if _, err := f.engine.Apply(t.Context(), f.snapshot, f.key, f.plan.Digest(), false); err != ErrSecurityBaseline || f.access.writes != beforeWrites {
		t.Fatal("ownership alone became admission health proof")
	}
	if _, err := NewWithAccess(f.access, f.store, f.engine.files, f.plan); err != ErrInvalid {
		t.Fatal("baseline-aware journal accepted unguarded constructor")
	}
	resource := document.SecurityBaseline.Resources[0]
	f.access.objects[resource.Key].SetUID("replacement-baseline")
	if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrSecurityBaseline || f.access.writes != beforeWrites {
		t.Fatal("original baseline replacement was adopted or overwritten")
	}
}

func TestBaselineCreateAcknowledgementAndRecoveryMatrix(t *testing.T) {
	for _, mode := range []string{"lost-ack", "definite-rejection", "empty-ack", "malformed-ack", "unobservable-effect", "absent-effect", "replacement-before-readback"} {
		t.Run(mode, func(t *testing.T) {
			f := newBaselineFixture(t)
			f.access.write = func(_ installstate.Action, key installstate.Key, candidate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				live := candidate.DeepCopy()
				live.SetUID("baseline-original")
				live.SetResourceVersion("101")
				if mode != "absent-effect" {
					f.access.objects[key] = live.DeepCopy()
				}
				switch mode {
				case "lost-ack", "absent-effect":
					return nil, errors.New("fixture transport response lost")
				case "definite-rejection":
					return nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: key.Kind}, key.Name)
				case "empty-ack":
					return nil, nil
				case "malformed-ack":
					live.SetName("malformed-ack")
					return live, nil
				case "unobservable-effect":
					f.access.get = func(installstate.Key) error { return errors.New("fixture observation unavailable") }
					return live, nil
				case "replacement-before-readback":
					f.access.objects[key].SetUID("baseline-replacement")
					return live, nil
				}
				panic("unhandled fixture")
			}
			snapshot, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
			if mode == "lost-ack" {
				if err != nil || snapshot.Document().SecurityBaseline.Pending != nil || len(snapshot.Document().SecurityBaseline.Resources) != 1 {
					t.Fatal("original immediate ambiguous readback was not correlated")
				}
				return
			}
			if err != ErrOutcomeUnknown || snapshot.Document().SecurityBaseline.Pending == nil || f.access.writes != 1 {
				t.Fatal("unknown outcome erased intent or repeated effect")
			}
			f.snapshot = reloadBaselineFixture(t, f)
			pending := f.snapshot.Document().SecurityBaseline.Pending
			if mode == "absent-effect" {
				template, _ := f.engine.baseline.contract.Template(pending.Key, false)
				late, _ := template.Candidate(pending.CreateNonce)
				late.SetUID("late-unacknowledged-effect")
				late.SetResourceVersion("102")
				f.access.objects[pending.Key] = late
			}
			f.access.get = nil
			beforeDry := f.access.dryRuns
			for i := 0; i < 2; i++ {
				next, resumeErr := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
				if mode == "malformed-ack" || mode == "unobservable-effect" {
					if resumeErr != nil || next.Document().SecurityBaseline.Pending != nil || f.access.writes != 1 || f.access.dryRuns != beforeDry {
						t.Fatal("protected ACK recovery retried effect or lost original UID")
					}
					return
				}
				if resumeErr != ErrOutcomeUnknown || next.Document().SecurityBaseline.Pending == nil || f.access.writes != 1 || f.access.dryRuns != beforeDry {
					t.Fatal("resume adopted public nonce or replayed CREATE")
				}
			}
		})
	}
}

func TestBaselineRecoveryPinsUIDBeforeAcceptingMalformedAck(t *testing.T) {
	f := newBaselineFixture(t)
	f.access.write = func(_ installstate.Action, key installstate.Key, candidate *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		live := candidate.DeepCopy()
		live.SetUID("baseline-original")
		live.SetResourceVersion("101")
		f.access.objects[key] = live.DeepCopy()
		ack := live.DeepCopy()
		ack.SetName("malformed-ack")
		return ack, nil
	}
	_, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
	if err != ErrOutcomeUnknown {
		t.Fatal("malformed ACK was accepted")
	}
	f.snapshot = reloadBaselineFixture(t, f)
	pending := f.snapshot.Document().SecurityBaseline.Pending
	if uid, err := f.engine.baseline.loadReceiptUID(f.snapshot.Document()); err != nil || uid != "baseline-original" {
		t.Fatal("known ACK identity was not durable before shape acceptance")
	}
	f.access.objects[pending.Key].SetUID("copied-nonce-replacement")
	if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrOutcomeUnknown || f.access.writes != 1 {
		t.Fatal("copied nonce replacement was adopted")
	}
}

func TestBaselineSettlementLostResponseResumesWithoutEffect(t *testing.T) {
	f := newBaselineFixture(t)
	f.nsUpdate = func(candidate *corev1.Namespace) error {
		var document installstate.Document
		if json.Unmarshal([]byte(candidate.Annotations[installstate.Annotation]), &document) != nil {
			t.Fatal("fixture settlement malformed")
		}
		if len(document.SecurityBaseline.Resources) == 1 {
			return errors.New("fixture settlement response unavailable")
		}
		return nil
	}
	_, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
	if err != ErrOutcomeUnknown || f.access.writes != 1 {
		t.Fatal("settlement uncertainty was lost")
	}
	f.snapshot = reloadBaselineFixture(t, f)
	f.nsUpdate = nil
	snapshot, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot)
	if err != nil || snapshot.Document().SecurityBaseline.Pending != nil || len(snapshot.Document().SecurityBaseline.Resources) != 1 || f.access.writes != 1 || f.access.dryRuns != 1 {
		t.Fatal("lost settlement recovery repeated CREATE or failed original observation")
	}
}

func TestBaselineCreatePreEffectBarriers(t *testing.T) {
	for _, mode := range []string{"existing", "dryrun-mutation", "intent-rejection", "fixture-before", "fixture-during-dryrun", "namespace-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newBaselineFixture(t)
			resource := f.engine.baseline.plan.Resources()[0]
			key := installstate.Key{APIVersion: resource.Object.GetAPIVersion(), Kind: resource.Object.GetKind(), Name: resource.Object.GetName()}
			switch mode {
			case "existing":
				f.access.objects[key] = resource.Object.DeepCopy()
			case "dryrun-mutation":
				f.access.dry = func(o *unstructured.Unstructured) *unstructured.Unstructured { o.SetName("foreign"); return o }
			case "intent-rejection":
				f.nsUpdate = func(*corev1.Namespace) error {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, f.plan.Namespace(), errors.New("fixture intent rejected"))
				}
			case "fixture-before":
				if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("malformed active evidence")); err != nil {
					t.Fatal("fixture fence seed failed")
				}
			case "fixture-during-dryrun":
				f.access.dry = func(o *unstructured.Unstructured) *unstructured.Unstructured {
					if _, err := f.engine.files.CreateExclusive(fixtureLedgerName(f.snapshot), []byte("active evidence")); err != nil {
						t.Fatal("fixture fence seed failed")
					}
					return o
				}
			case "namespace-drift":
				namespace, _ := f.access.client.CoreV1().Namespaces().Get(t.Context(), f.plan.Namespace(), metav1.GetOptions{})
				namespace.ResourceVersion = "999"
				if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
					t.Fatal("namespace drift seed failed")
				}
			}
			if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err == nil || f.access.writes != 0 {
				t.Fatal("pre-effect barrier allowed CREATE")
			}
		})
	}
}

func TestBaselineReceiptRejectsForeignEvidenceAndEmptyUID(t *testing.T) {
	f := newBaselineFixture(t)
	f.access.write = func(installstate.Action, installstate.Key, *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		return nil, nil
	}
	if _, err := f.engine.EstablishBaselineOwnership(t.Context(), f.snapshot); err != ErrOutcomeUnknown {
		t.Fatal("empty ACK was accepted")
	}
	f.snapshot = reloadBaselineFixture(t, f)
	document := f.snapshot.Document()
	if _, err := f.engine.baseline.loadReceiptUID(document); err != ErrOwnership {
		t.Fatal("empty protected receipt became original identity")
	}
	for _, mutate := range []func(*installstate.Document){
		func(d *installstate.Document) { d.SecurityBaseline.ArtifactDigest = strings.Repeat("e", 64) },
		func(d *installstate.Document) { d.SecurityBaseline.Version = "foreign" },
		func(d *installstate.Document) { d.NamespaceUID = "foreign-namespace" },
		func(d *installstate.Document) { d.SecurityBaseline.Pending.AfterSHA256 = strings.Repeat("e", 64) },
		func(d *installstate.Document) { d.SecurityBaseline.Pending.Action = installstate.Update },
	} {
		foreign := f.snapshot.Document()
		mutate(&foreign)
		if f.engine.baseline.pinReceiptUID(foreign, "foreign-uid") == nil {
			t.Fatal("foreign evidence populated protected receipt")
		}
	}
	if f.engine.baseline.pinReceiptUID(document, "baseline-original") != nil {
		t.Fatal("original pin failed")
	}
	if f.engine.baseline.pinReceiptUID(document, "different-uid") != ErrOwnership {
		t.Fatal("pinned original UID was replaced")
	}
	if uid, err := f.engine.baseline.loadReceiptUID(document); err != nil || uid != "baseline-original" {
		t.Fatal("original receipt changed")
	}
}
