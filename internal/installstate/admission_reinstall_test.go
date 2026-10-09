// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

// Independent pre-provenance wire schema: explicit historical fields, never
// marshal the new Document and delete fields to manufacture an expectation.
func historicalJournalEncoding(t *testing.T, d Document) []byte {
	t.Helper()
	fields := map[string]any{
		"version": d.Version, "installationId": d.InstallationID, "namespace": d.Namespace,
		"namespaceUid": d.NamespaceUID, "profileId": d.ProfileID, "revision": d.Revision,
		"mode": d.Mode, "stage": d.Stage, "activePackage": d.ActivePackage,
		"previousPackage": d.PreviousPackage, "targetPackage": d.TargetPackage,
		"installed": d.Installed, "resources": d.Resources, "pending": d.Pending,
	}
	if d.AdmissionRetirementRevision != 0 {
		fields["admissionRetirementRevision"] = d.AdmissionRetirementRevision
	}
	if d.SecurityBaseline != nil {
		fields["securityBaseline"] = d.SecurityBaseline
	}
	body, err := json.Marshal(fields)
	if err == nil {
		body, err = canonicaljson.CanonicalJSON(body)
	}
	if err != nil {
		t.Fatal("independent historical schema encoding failed")
	}
	return body
}

// State-only fixtures exercise actual Namespace CAS and transition contracts.
// Synthetic recorded inventories are not engine effect or reinstall proof.
func reinstallSourceFixture(t *testing.T) (*installrender.Plan, *installbaseline.Plan, Document) {
	t.Helper()
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	d := initialDocument(plan)
	d.Mode, d.Stage, d.ActivePackage = Uninstall, Complete, plan.Digest()
	d.Revision, d.AdmissionRetirementRevision = 100, 90
	d.Resources = lifecycleResources(t, plan, true)
	d.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	d.SecurityBaseline.Stage = BaselineVerified
	for index := range installbaseline.ResourceCount {
		d.SecurityBaseline.Resources = append(d.SecurityBaseline.Resources, baselineResource(t, baseline, index))
	}
	SortBaselineResources(d.SecurityBaseline.Resources)
	if _, err := EncodeWithBaseline(d, baseline, plan); err != nil {
		t.Fatal("completed-retirement state fixture invalid")
	}
	return plan, baseline, d
}

func reinstallIntent(t *testing.T, source Document, baseline *installbaseline.Plan, plan *installrender.Plan) Document {
	t.Helper()
	body, err := EncodeWithBaseline(source, baseline, plan)
	if err != nil {
		t.Fatal("source canonical journal unavailable")
	}
	next := lifecycleCopy(t, source)
	next.Revision++
	next.Mode, next.Stage, next.AdmissionRetirementRevision = Install, Preparing, 0
	next.AdmissionReinstall = &ReinstallProvenance{SourceRevision: source.Revision, SourceJournalSHA256: journalSHA256(body)}
	return next
}

func TestAdmissionReinstallCanonicalAndContextConstraints(t *testing.T) {
	plan, baseline, source := reinstallSourceFixture(t)
	legacy := initialDocument(plan)
	old, err := Encode(legacy, plan)
	withContext, contextErr := EncodeWithBaseline(legacy, baseline, plan)
	if err != nil || contextErr != nil || !bytes.Equal(old, withContext) || !bytes.Equal(old, historicalJournalEncoding(t, legacy)) || bytes.Contains(old, []byte("admissionReinstall")) {
		t.Fatal("optional reinstall provenance changed authentic historical bytes")
	}
	baselineHistory, err := EncodeWithBaseline(source, baseline, plan)
	if err != nil || !bytes.Equal(baselineHistory, historicalJournalEncoding(t, source)) || bytes.Contains(baselineHistory, []byte("admissionReinstall")) {
		t.Fatal("nil provenance changed prior baseline-present journal encoding")
	}
	d := reinstallIntent(t, source, baseline, plan)
	body, err := EncodeWithBaseline(d, baseline, plan)
	decoded, decodeErr := DecodeWithBaseline(body, baseline, plan)
	if err != nil || decodeErr != nil || !reflect.DeepEqual(d, decoded) {
		t.Fatal("bounded reinstall provenance failed canonical roundtrip")
	}
	if _, err := Encode(d, plan); err != ErrInvalid {
		t.Fatal("runtime-only encoder accepted reinstall baseline provenance")
	}
	if _, err := Decode(body, plan); err != ErrInvalid {
		t.Fatal("runtime-only decoder accepted reinstall baseline provenance")
	}
	for _, scenario := range []string{"zero-revision", "current-revision", "future-revision", "uppercase-hash", "invalid-hash", "nil-baseline", "incomplete-baseline", "retirement-latch", "empty-active", "uninstall", "upgrade", "rollback"} {
		t.Run(scenario, func(t *testing.T) {
			bad := lifecycleCopy(t, d)
			switch scenario {
			case "zero-revision":
				bad.AdmissionReinstall.SourceRevision = 0
			case "current-revision":
				bad.AdmissionReinstall.SourceRevision = bad.Revision
			case "future-revision":
				bad.AdmissionReinstall.SourceRevision = bad.Revision + 1
			case "uppercase-hash":
				bad.AdmissionReinstall.SourceJournalSHA256 = strings.Repeat("A", 64)
			case "invalid-hash":
				bad.AdmissionReinstall.SourceJournalSHA256 = "PRIVATE-INVALID-DIGEST"
			case "nil-baseline":
				bad.SecurityBaseline = nil
			case "incomplete-baseline":
				bad.SecurityBaseline.Stage = BaselineApplying
			case "retirement-latch":
				bad.AdmissionRetirementRevision = source.AdmissionRetirementRevision
			case "empty-active":
				bad.ActivePackage = ""
			default:
				bad.Mode = Mode(scenario)
			}
			if _, err := EncodeWithBaseline(bad, baseline, plan); err != ErrInvalid {
				t.Fatal("invalid reinstall context encoded")
			}
		})
	}
}

func TestAdmissionReinstallCASPinsSealedSourceBeforeAnyWrite(t *testing.T) {
	plan, baseline, source := reinstallSourceFixture(t)
	body, _ := EncodeWithBaseline(source, baseline, plan)
	server := &namespaceServer{live: testNamespace(plan, source)}
	server.live.Annotations[Annotation] = string(body)
	store, err := NewWithBaseline(server.client().CoreV1().Namespaces(), baseline, plan)
	if err != nil {
		t.Fatal("reinstall store unavailable")
	}
	snapshot, err := store.Load(t.Context(), Anchor{source.Namespace, source.NamespaceUID, source.InstallationID})
	if err != nil {
		t.Fatal("completed source observation unavailable")
	}
	intent := reinstallIntent(t, source, baseline, plan)
	for _, scenario := range []string{"missing-pin", "wrong-revision", "wrong-hash", "invented-body", "retained-replacement", "baseline-piggyback"} {
		t.Run(scenario, func(t *testing.T) {
			bad := lifecycleCopy(t, intent)
			observed := *snapshot
			switch scenario {
			case "missing-pin":
				bad.AdmissionReinstall = nil
			case "wrong-revision":
				bad.AdmissionReinstall.SourceRevision--
			case "wrong-hash":
				bad.AdmissionReinstall.SourceJournalSHA256 = strings.Repeat("f", 64)
			case "invented-body":
				observed.body = append(snapshot.Bytes(), '\n')
			case "retained-replacement":
				bad.Resources[0].UID = "replacement"
			case "baseline-piggyback":
				bad.SecurityBaseline.Resources[0].UID = "replacement"
			}
			if _, err := store.Commit(t.Context(), &observed, bad); err != ErrInvalid || server.updates != 0 {
				t.Fatal("unbound reinstall source attempted namespace mutation")
			}
		})
	}
	bound, err := store.Commit(t.Context(), snapshot, intent)
	if err != nil || server.updates != 1 || bound.Document().AdmissionReinstall == nil || !reflect.DeepEqual(bound.Document().AdmissionReinstall, intent.AdmissionReinstall) {
		t.Fatal("exact completed source failed one namespace CAS")
	}
	copy := bound.Document()
	copy.AdmissionReinstall.SourceRevision = 1
	if bound.Document().AdmissionReinstall.SourceRevision != source.Revision {
		t.Fatal("snapshot accessor exposed mutable provenance")
	}
	initial := initialDocument(plan)
	initial.AdmissionReinstall = intent.AdmissionReinstall
	if _, err := store.Bind(t.Context(), bound.Anchor(), initial); err != ErrInvalid || server.updates != 1 {
		t.Fatal("fresh bootstrap accepted reinstall provenance")
	}
}

func TestAdmissionReinstallSourceSurvivesActualJournalTransitions(t *testing.T) {
	plan, baseline, source := reinstallSourceFixture(t)
	body, _ := EncodeWithBaseline(source, baseline, plan)
	server := &namespaceServer{live: testNamespace(plan, source)}
	server.live.Annotations[Annotation] = string(body)
	store, _ := NewWithBaseline(server.client().CoreV1().Namespaces(), baseline, plan)
	snapshot, err := store.Load(t.Context(), Anchor{source.Namespace, source.NamespaceUID, source.InstallationID})
	if err != nil {
		t.Fatal("source observation unavailable")
	}
	snapshot, err = store.Commit(t.Context(), snapshot, reinstallIntent(t, source, baseline, plan))
	if err != nil {
		t.Fatal("reinstall begin CAS failed")
	}
	pin := snapshot.Document().AdmissionReinstall
	commit := func(next Document) {
		t.Helper()
		next.Revision = snapshot.Document().Revision + 1
		for _, mutate := range []func(*Document){
			func(d *Document) { d.AdmissionReinstall = nil },
			func(d *Document) { d.AdmissionReinstall.SourceRevision-- },
			func(d *Document) { d.AdmissionReinstall.SourceJournalSHA256 = strings.Repeat("e", 64) },
		} {
			bad := lifecycleCopy(t, next)
			mutate(&bad)
			writes := server.updates
			if _, err := store.Commit(t.Context(), snapshot, bad); err != ErrInvalid || server.updates != writes {
				t.Fatal("stage/intent/settlement/completion changed source provenance")
			}
		}
		var commitErr error
		snapshot, commitErr = store.Commit(t.Context(), snapshot, next)
		if commitErr != nil || !reflect.DeepEqual(snapshot.Document().AdmissionReinstall, pin) {
			t.Fatal("original source did not survive legal journal transition")
		}
	}
	d := snapshot.Document()
	d.Stage = Applying
	commit(d)
	// Pending runtime effects, every settlement, recovery/resume and completion
	// are real Store CAS, but the acknowledged inventory here is synthetic.
	d = snapshot.Document()
	d.Stage = RecoveryRequired
	commit(d)
	d = snapshot.Document()
	d.Stage = Applying
	commit(d)
	for index, resource := range lifecycleResources(t, plan, false) {
		if resource.Retained {
			continue
		}
		d = snapshot.Document()
		d.Pending = &Pending{Action: Create, Key: resource.Key, CreateNonce: fmt.Sprintf("%032x", index+1), AfterSHA256: resource.TemplateSHA256}
		commit(d)
		d = snapshot.Document()
		d.Pending = nil
		d.Resources = append(d.Resources, resource)
		SortResources(d.Resources)
		commit(d)
	}
	d = snapshot.Document()
	d.Stage = Verifying
	commit(d)
	d = snapshot.Document()
	d.Stage, d.Installed = Complete, true
	commit(d)
	if len(snapshot.Document().Resources) != MaxResources {
		t.Fatal("completed reinstall fixture lost original retained inventory")
	}
	d = snapshot.Document()
	d.Revision++
	d.Mode, d.Stage, d.AdmissionReinstall = Uninstall, Preparing, nil
	cleared, err := store.Commit(t.Context(), snapshot, d)
	if err != nil || cleared.Document().AdmissionReinstall != nil {
		t.Fatal("subsequent operation could not clear completed reinstall provenance")
	}
	// Clearing cannot piggyback an unrelated baseline transition or ordinary
	// stage transition, even when its caller supplies a valid-looking pin.
	bad := cleared.Document()
	bad.Revision++
	bad.AdmissionReinstall = pin
	bad.Stage = Quiescing
	if _, err := store.Commit(t.Context(), cleared, bad); err != ErrInvalid {
		t.Fatal("retired source was resurrected into a later operation")
	}
}
