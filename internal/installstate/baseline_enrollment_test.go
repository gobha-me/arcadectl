// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

// Synthetic state/CAS fixtures, not native legacy installation or enrollment
// certification. Historical bytes use the independent original wire schema.
func enrollmentSourceFixture(t *testing.T) (*installrender.Plan, *installbaseline.Plan, Document, []byte) {
	t.Helper()
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	d := initialDocument(plan)
	d.Revision, d.Stage, d.Installed, d.ActivePackage = 100, Complete, true, plan.Digest()
	d.Resources = lifecycleResources(t, plan, false)
	body := historicalJournalEncoding(t, d)
	decoded, err := DecodeWithBaseline(body, baseline, plan)
	if err != nil || !reflect.DeepEqual(decoded, d) || decoded.SecurityBaseline != nil {
		t.Fatal("independent omitted-baseline source schema refused")
	}
	return plan, baseline, d, body
}

func enrollmentIntent(t *testing.T, d Document, source []byte, baseline *installbaseline.Plan) Document {
	t.Helper()
	next := lifecycleCopy(t, d)
	next.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	// Independent state-only seal fixture; actual protected source/world
	// envelope authentication belongs to the engine's closed protocol.
	next.SecurityBaseline.Enrollment = &BaselineEnrollmentProvenance{SourceRevision: d.Revision, SourceJournalSHA256: journalSHA256(source), SourceEvidenceSHA256: strings.Repeat("b", 64)}
	next.Revision++
	return next
}

func originalBaselineWire(t *testing.T, d Document) []byte {
	t.Helper()
	b := d.SecurityBaseline
	d.SecurityBaseline = nil
	var fields map[string]any
	if err := json.Unmarshal(historicalJournalEncoding(t, d), &fields); err != nil {
		t.Fatal("original runtime wire unavailable")
	}
	// Freeze the original nested schema; do not marshal today's baseline type
	// and delete its new field to manufacture a compatibility expectation.
	fields["securityBaseline"] = map[string]any{
		"version": b.Version, "artifactDigest": b.ArtifactDigest, "stage": b.Stage,
		"resources": b.Resources, "pending": b.Pending,
	}
	body, err := json.Marshal(fields)
	if err == nil {
		body, err = canonicaljson.CanonicalJSON(body)
	}
	if err != nil {
		t.Fatal("original nested baseline wire unavailable")
	}
	return body
}

func TestBaselineEnrollmentHistoricalEncodingAndBoundedContext(t *testing.T) {
	plan, baseline, d, old := enrollmentSourceFixture(t)
	encoded, err := EncodeWithBaseline(d, baseline, plan)
	if err != nil || !bytes.Equal(old, encoded) || bytes.Contains(encoded, []byte("enrollment")) {
		t.Fatal("nil enrollment rewrote omitted-baseline historical bytes")
	}
	fresh := initialDocument(plan)
	fresh.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	freshBody, err := EncodeWithBaseline(fresh, baseline, plan)
	if err != nil || bytes.Contains(freshBody, []byte("enrollment")) || !bytes.Equal(freshBody, originalBaselineWire(t, fresh)) {
		t.Fatal("nil enrollment rewrote previous baseline-present schema")
	}
	intent := enrollmentIntent(t, d, old, baseline)
	body, err := EncodeWithBaseline(intent, baseline, plan)
	decoded, readErr := DecodeWithBaseline(body, baseline, plan)
	if err != nil || readErr != nil || !reflect.DeepEqual(intent, decoded) || !validTransition(d, intent) {
		t.Fatal("exact installed source failed canonical enrollment introduction")
	}
	for name, mutate := range map[string]func(*Document){
		"zero-revision":          func(d *Document) { d.SecurityBaseline.Enrollment.SourceRevision = 0 },
		"future-revision":        func(d *Document) { d.SecurityBaseline.Enrollment.SourceRevision = d.Revision },
		"upper-hash":             func(d *Document) { d.SecurityBaseline.Enrollment.SourceJournalSHA256 = strings.Repeat("A", 64) },
		"missing-evidence-seal":  func(d *Document) { d.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = "" },
		"upper-evidence-seal":    func(d *Document) { d.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = strings.Repeat("A", 64) },
		"wrong-mode":             func(d *Document) { d.Mode = Uninstall },
		"not-installed":          func(d *Document) { d.Installed = false },
		"runtime-stage":          func(d *Document) { d.Stage = Preparing },
		"retired":                func(d *Document) { d.AdmissionRetirementRevision = 90 },
		"active-target-mismatch": func(d *Document) { d.ActivePackage = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := lifecycleCopy(t, intent)
			mutate(&bad)
			if _, err := EncodeWithBaseline(bad, baseline, plan); err != ErrInvalid {
				t.Fatal("invalid incomplete enrollment context encoded")
			}
		})
	}
}

func TestBaselineEnrollmentImmutableAcrossDistinctPackageTransitions(t *testing.T) {
	plan, baseline, source, old := enrollmentSourceFixture(t)
	other := lifecyclePlan(t, 2)
	if plan.Digest() == other.Digest() {
		t.Fatal("package transition fixture reused identical signed package")
	}
	// Pure completed-ownership fixture. All native effects and supported
	// predecessor proofs belong to engine/executable tests, not this state test.
	d := enrollmentIntent(t, source, old, baseline)
	d.SecurityBaseline.Stage = BaselineVerified
	for index := range installbaseline.ResourceCount {
		d.SecurityBaseline.Resources = append(d.SecurityBaseline.Resources, baselineResource(t, baseline, index))
	}
	SortBaselineResources(d.SecurityBaseline.Resources)
	for _, mode := range []Mode{Upgrade, Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			next := lifecycleCopy(t, d)
			next.Revision++
			next.Mode, next.Stage, next.TargetPackage = mode, Preparing, other.Digest()
			if !validTransition(d, next) {
				t.Fatal("distinct package operation could not preserve provenance")
			}
			if _, err := EncodeWithBaseline(next, baseline, plan, other); err != nil {
				t.Fatal("distinct signed package operation did not encode")
			}
			for _, mutate := range []func(*Document){
				func(d *Document) { d.SecurityBaseline.Enrollment = nil },
				func(d *Document) { d.SecurityBaseline.Enrollment.SourceRevision-- },
				func(d *Document) { d.SecurityBaseline.Enrollment.SourceJournalSHA256 = strings.Repeat("f", 64) },
				func(d *Document) { d.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = strings.Repeat("f", 64) },
			} {
				bad := lifecycleCopy(t, next)
				mutate(&bad)
				if validTransition(d, bad) {
					t.Fatal("distinct package operation erased or repinned source")
				}
			}
		})
	}
}

func TestBaselineEnrollmentIntroductionPinsLiteralSnapshotBeforeCAS(t *testing.T) {
	plan, baseline, d, old := enrollmentSourceFixture(t)
	server := &namespaceServer{live: testNamespace(plan, d)}
	server.live.Annotations[Annotation] = string(old)
	store, err := NewWithBaseline(server.client().CoreV1().Namespaces(), baseline, plan)
	if err != nil {
		t.Fatal("historical enrollment journal unavailable")
	}
	snapshot, err := store.Load(t.Context(), Anchor{d.Namespace, d.NamespaceUID, d.InstallationID})
	if err != nil {
		t.Fatal("original historical snapshot unavailable")
	}
	intent := enrollmentIntent(t, d, old, baseline)
	for _, name := range []string{"missing-pin", "missing-evidence-seal", "wrong-revision", "wrong-hash", "invented-body", "runtime-mode", "inventory", "history"} {
		t.Run(name, func(t *testing.T) {
			bad := lifecycleCopy(t, intent)
			observed := *snapshot
			switch name {
			case "missing-pin":
				bad.SecurityBaseline.Enrollment = nil
			case "missing-evidence-seal":
				bad.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = ""
			case "wrong-revision":
				bad.SecurityBaseline.Enrollment.SourceRevision--
			case "wrong-hash":
				bad.SecurityBaseline.Enrollment.SourceJournalSHA256 = strings.Repeat("e", 64)
			case "invented-body":
				observed.body = append(snapshot.Bytes(), '\n')
			case "runtime-mode":
				bad.Mode = Uninstall
			case "inventory":
				bad.Resources[0].UID = "replacement"
			case "history":
				bad.PreviousPackage = plan.Digest()
			}
			if _, err := store.Commit(t.Context(), &observed, bad); err != ErrInvalid || server.updates != 0 {
				t.Fatal("unbound or piggyback enrollment attempted namespace mutation")
			}
		})
	}
	bound, err := store.Commit(t.Context(), snapshot, intent)
	if err != nil || server.updates != 1 || !reflect.DeepEqual(bound.Document(), intent) {
		t.Fatal("bound historical enrollment failed single original CAS")
	}
	copy := bound.Document()
	copy.SecurityBaseline.Enrollment.SourceRevision = 1
	if bound.Document().SecurityBaseline.Enrollment.SourceRevision != d.Revision {
		t.Fatal("snapshot accessor exposed mutable enrollment pin")
	}
	initial := initialDocument(plan)
	initial.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	initial.SecurityBaseline.Enrollment = intent.SecurityBaseline.Enrollment
	if _, err := store.Bind(t.Context(), bound.Anchor(), initial); err != ErrInvalid || server.updates != 1 {
		t.Fatal("fresh bootstrap manufactured enrollment provenance")
	}
}

func TestBaselineEnrollmentPinSurvivesOwnershipAndOrdinaryTransitions(t *testing.T) {
	plan, baseline, source, old := enrollmentSourceFixture(t)
	d := enrollmentIntent(t, source, old, baseline)
	assertTransition := func(next Document) {
		t.Helper()
		next.Revision = d.Revision + 1
		if !validTransition(d, next) {
			t.Fatal("legitimate enrollment transition refused")
		}
		if _, err := EncodeWithBaseline(next, baseline, plan); err != nil {
			t.Fatal("legitimate enrollment transition cannot encode")
		}
		for _, change := range []func(*Document){
			func(d *Document) { d.SecurityBaseline.Enrollment = nil },
			func(d *Document) { d.SecurityBaseline.Enrollment.SourceRevision-- },
			func(d *Document) { d.SecurityBaseline.Enrollment.SourceJournalSHA256 = strings.Repeat("f", 64) },
			func(d *Document) { d.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = strings.Repeat("f", 64) },
		} {
			bad := lifecycleCopy(t, next)
			change(&bad)
			if validTransition(d, bad) {
				t.Fatal("settlement/recovery/runtime transition changed enrollment pin")
			}
		}
		d = next
	}
	next := lifecycleCopy(t, d)
	next.SecurityBaseline.Stage = BaselineApplying
	assertTransition(next)
	for index := range installbaseline.ResourceCount {
		row := baselineResource(t, baseline, index)
		intent := lifecycleCopy(t, d)
		intent.SecurityBaseline.Pending = &Pending{Action: Create, Key: row.Key, AfterSHA256: row.TemplateSHA256, CreateNonce: strings.Repeat("b", 32)}
		assertTransition(intent)
		recovery := lifecycleCopy(t, d)
		recovery.SecurityBaseline.Stage = BaselineRecovery
		assertTransition(recovery)
		resume := lifecycleCopy(t, d)
		resume.SecurityBaseline.Stage = BaselineApplying
		assertTransition(resume)
		settled := lifecycleCopy(t, d)
		settled.SecurityBaseline.Pending = nil
		settled.SecurityBaseline.Resources = append(settled.SecurityBaseline.Resources, row)
		SortBaselineResources(settled.SecurityBaseline.Resources)
		assertTransition(settled)
	}
	verified := lifecycleCopy(t, d)
	verified.SecurityBaseline.Stage = BaselineVerified
	assertTransition(verified)
	// Provenance does not freeze the original runtime Mode after ownership.
	uninstall := lifecycleCopy(t, d)
	uninstall.Mode, uninstall.Stage = Uninstall, Preparing
	assertTransition(uninstall)
	quiescing := lifecycleCopy(t, d)
	quiescing.Stage = Quiescing
	assertTransition(quiescing)
}
