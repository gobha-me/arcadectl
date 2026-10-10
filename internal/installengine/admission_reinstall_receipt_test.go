// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Genuine legacy lifecycle-completed uninstall, then explicitly synthetic
// baseline enrollment in recorded journals/receipt. No live guard, native
// health, access recreation, world execution or full reinstall is claimed.
func reinstallReceiptFixture(t *testing.T) (*fixture, *installstate.Snapshot) {
	t.Helper()
	v, snapshot := reinstallReceiptLifecycleFixture(t)
	return v.f, snapshot
}

func reinstallReceiptLifecycleFixture(t *testing.T) (*lifecycleFixture, *installstate.Snapshot) {
	t.Helper()
	v, snapshot := retirementFixture(t)
	snapshot = v.finish(t, snapshot)
	f := v.f
	d := snapshot.Document()
	baseline := baselineFixturePlan(t, d.Namespace, d.ProfileID, 'd')
	name := retirementName(d, d.AdmissionRetirementRevision)
	body, identity, err := f.engine.files.Read(name, retirementMaxBytes)
	if err != nil {
		t.Fatal("genuine original retirement receipt unavailable")
	}
	var receipt retirementReceipt
	if json.Unmarshal(body, &receipt) != nil {
		t.Fatal("original retirement receipt malformed")
	}
	original, err := installstate.Decode(receipt.Journal, f.plan)
	if err != nil {
		t.Fatal("original pre-withdrawal journal unavailable")
	}
	security := &installstate.SecurityBaseline{Version: installbaseline.Version, ArtifactDigest: baseline.Digest(), Stage: installstate.BaselineVerified, Resources: []installstate.BaselineResource{}}
	for index, resource := range baseline.Resources() {
		object := resource.Object.DeepCopy()
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
		uid := types.UID(fmt.Sprintf("reinstall-source-baseline-%d", index))
		security.Resources = append(security.Resources, installstate.BaselineResource{Key: key, UID: uid, TemplateSHA256: resource.TemplateSHA256})
		object.SetUID(uid)
		object.SetResourceVersion("100")
		object.SetAnnotations(map[string]string{installstate.MutationAnnotation: strings.Repeat("a", 32)})
		if key.Kind == "ValidatingAdmissionPolicy" {
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
		f.access.objects[key] = object // Explicit synthetic health/read fixtures only.
	}
	installstate.SortBaselineResources(security.Resources)
	d.SecurityBaseline, original.SecurityBaseline = security, security
	receipt.Version = "v2"
	for _, row := range security.Resources {
		receipt.Baseline = append(receipt.Baseline, retirementPolicy{row.Key, admissionIdentity{row.UID, "100", row.TemplateSHA256}})
	}
	receipt.Journal, err = installstate.EncodeWithBaseline(original, baseline, f.plan)
	if err != nil {
		t.Fatal("synthetic baseline original journal invalid")
	}
	body, _ = json.Marshal(receipt)
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		t.Fatal("synthetic receipt invalid")
	}
	if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
		t.Fatal("synthetic protected baseline receipt seed failed")
	}
	journal, err := installstate.EncodeWithBaseline(d, baseline, f.plan)
	if err != nil {
		t.Fatal("synthetic baseline completed journal invalid")
	}
	namespace, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal("original Namespace unavailable")
	}
	namespace.Annotations[installstate.Annotation] = string(journal)
	if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
		t.Fatal("synthetic completed baseline journal seed failed")
	}
	f.store, err = installstate.NewWithBaseline(f.access.client.CoreV1().Namespaces(), baseline, f.plan)
	if err != nil {
		t.Fatal("source store unavailable")
	}
	f.engine, err = NewWithBaselineAccess(f.access, f.store, f.engine.files, baseline, f.plan)
	if err != nil {
		t.Fatal("source engine unavailable")
	}
	snapshot, err = f.store.Load(t.Context(), snapshot.Anchor())
	if err != nil {
		t.Fatal("source snapshot unavailable")
	}
	return v, snapshot
}

func TestAdmissionReinstallProtectedSourceSurvivesRestartAndClosesBothFiles(t *testing.T) {
	f, source := reinstallReceiptFixture(t)
	writes, namespaceWrites := f.access.writes, f.nsUpdates
	witness, err := f.engine.saveReinstallSource(source)
	if err != nil || f.engine.closeReinstallSource(witness) != nil || witness.provenance.SourceRevision != source.Document().Revision || witness.provenance.SourceJournalSHA256 != reinstallJournalSHA256(source.Bytes()) {
		t.Fatal("exact protected completed-source publication failed")
	}
	t.Cleanup(witness.release)
	if strings.HasPrefix(witness.name, "uninstall-admission-") || strings.HasPrefix(witness.name, "baseline-create-") {
		t.Fatal("source receipt reused another evidence domain")
	}
	again, err := f.engine.saveReinstallSource(source)
	if err != nil {
		t.Fatal("exclusive original publication could not be confirmed after restart boundary")
	}
	t.Cleanup(again.release)
	d := source.Document()
	d.Mode, d.Stage, d.AdmissionRetirementRevision = installstate.Install, installstate.Preparing, 0
	d.Revision++
	d.AdmissionReinstall = &witness.provenance
	current, err := f.store.Commit(t.Context(), source, d)
	if err != nil {
		t.Fatal("pinned source Begin state CAS failed")
	}
	// Reconstruct the actual engine/store over the same original Namespace and
	// protected files; no in-memory source or CREATE acknowledgement survives.
	store, err := installstate.NewWithBaseline(f.access.client.CoreV1().Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("restart source store failed")
	}
	engine, err := NewWithBaselineAccess(f.access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal("restart source engine failed")
	}
	current, err = store.Load(t.Context(), current.Anchor())
	if err != nil {
		t.Fatal("restart current journal unavailable")
	}
	opened, err := engine.openReinstallSource(current)
	if err != nil || engine.closeReinstallSource(opened) != nil || !bytes.Equal(opened.body, witness.body) || !bytes.Equal(current.Bytes(), mustReinstallJournal(t, engine, d)) {
		t.Fatal("durable source did not authenticate after engine restart")
	}
	t.Cleanup(opened.release)
	if engine.baseline.runtimeGuard != nil || f.access.writes != writes || f.nsUpdates != namespaceWrites+1 {
		t.Fatal("source evidence conferred runtime authority or recreated access")
	}
	for _, file := range []string{opened.name, opened.retirement.name} {
		fresh, err := engine.openReinstallSource(current)
		if err != nil {
			t.Fatal("fresh source bracket unavailable")
		}
		t.Cleanup(fresh.release)
		body, identity, err := engine.files.Read(file, retirementMaxBytes)
		if err != nil {
			t.Fatal("opening protected evidence unavailable")
		}
		if _, err := engine.files.AtomicWrite(file, body, &identity); err != nil {
			t.Fatal("test-only identical-body receipt replacement failed")
		}
		if engine.closeReinstallSource(fresh) != ErrSecurityBaseline {
			t.Fatal("identical-body replacement escaped original file identity closure")
		}
	}
}

func mustReinstallJournal(t *testing.T, e *Engine, d installstate.Document) []byte {
	t.Helper()
	body, err := installstate.EncodeWithBaseline(d, e.baselinePlan(), e.plans[d.TargetPackage])
	if err != nil {
		t.Fatal("exact reinstall test journal encoding failed")
	}
	return body
}

func TestAdmissionReinstallProtectedSourceRefusesForeignOrMalformedEvidence(t *testing.T) {
	f, source := reinstallReceiptFixture(t)
	witness, err := f.engine.saveReinstallSource(source)
	if err != nil {
		t.Fatal("source publication failed")
	}
	t.Cleanup(witness.release)
	d := source.Document()
	d.Mode, d.Stage, d.AdmissionRetirementRevision = installstate.Install, installstate.Preparing, 0
	d.Revision++
	d.AdmissionReinstall = &witness.provenance
	current, err := f.store.Commit(t.Context(), source, d)
	if err != nil {
		t.Fatal("source pin CAS failed")
	}
	for _, scenario := range []string{"noncanonical", "unknown-field", "wrong-domain", "changed-source-uid", "changed-source-revision", "truncated", "oversized", "unrelated-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			bad := bytes.Clone(witness.body)
			switch scenario {
			case "noncanonical":
				bad = append(bad, '\n')
			case "unknown-field":
				var fields map[string]any
				_ = json.Unmarshal(bad, &fields)
				fields["secret"] = "PRIVATE-UNKNOWN-RECEIPT-CANARY"
				bad, _ = json.Marshal(fields)
				bad, _ = canonicaljson.CanonicalJSON(bad)
			case "wrong-domain":
				bad = bytes.Replace(bad, []byte(reinstallReceiptVersion), []byte(baselineReceiptVersion), 1)
			case "changed-source-uid", "changed-source-revision":
				changed := source.Document()
				if scenario == "changed-source-uid" {
					changed.Resources[0].UID = "same-looking-retained-replacement"
				} else {
					changed.Revision++
				}
				bad, _ = reinstallSourceBody(mustReinstallJournal(t, f.engine, changed))
			case "truncated":
				bad = bad[:len(bad)/2]
			case "oversized":
				bad = bytes.Repeat([]byte("x"), reinstallReceiptMaxBytes+1)
			case "unrelated-receipt":
				bad = bytes.Clone(witness.retirement.body)
			}
			_, identity, err := f.engine.files.Read(witness.name, reinstallReceiptMaxBytes)
			if err != nil {
				t.Fatal("test evidence opening unavailable")
			}
			if _, err := f.engine.files.AtomicWrite(witness.name, bad, &identity); err != nil {
				t.Fatal("test malformed source seed failed")
			}
			if _, err := f.engine.openReinstallSource(current); err != ErrSecurityBaseline {
				t.Fatal("foreign/malformed protected source was accepted")
			}
			_, identity, err = f.engine.files.Read(witness.name, int64(len(bad)+1))
			if err != nil {
				t.Fatal("test malformed source recovery opening unavailable")
			}
			if _, err := f.engine.files.AtomicWrite(witness.name, witness.body, &identity); err != nil {
				t.Fatal("test-only source restoration failed")
			}
		})
	}
	// The reader itself cannot refresh a stale original journal or accept a
	// changed retained identity just because the source file still exists.
	if _, err := f.engine.openReinstallSource(source); err != ErrSecurityBaseline {
		t.Fatal("historical uninstall snapshot was relabelled as current Install")
	}
	if _, err := reinstallSourceName("../PRIVATE-PATH", source.Document().Revision); err != ErrSecurityBaseline {
		t.Fatal("source receipt accepted a caller-selected path")
	}
	restored, err := f.engine.openReinstallSource(current)
	if err != nil {
		t.Fatal("negative source tests damaged restored original evidence")
	}
	t.Cleanup(restored.release)
	for _, scenario := range []string{"runtime-omitted", "runtime-key", "runtime-uid", "runtime-hash", "runtime-rv", "runtime-duplicate", "runtime-reordered", "baseline-key", "baseline-uid", "baseline-hash", "baseline-rv", "baseline-duplicate", "baseline-reordered"} {
		t.Run(scenario, func(t *testing.T) {
			var receipt retirementReceipt
			if json.Unmarshal(witness.retirement.body, &receipt) != nil {
				t.Fatal("original retirement rows unavailable")
			}
			rows := receipt.Policies
			if strings.HasPrefix(scenario, "baseline-") {
				rows = receipt.Baseline
			}
			switch {
			case scenario == "runtime-omitted":
				receipt.Policies = nil
			case strings.HasSuffix(scenario, "-key"):
				rows[0].Key.Name = "same-count-foreign-policy"
			case strings.HasSuffix(scenario, "-uid"):
				rows[0].Identity.UID = "same-name-foreign-policy"
			case strings.HasSuffix(scenario, "-hash"):
				rows[0].Identity.TemplateSHA256 = strings.Repeat("e", 64)
			case strings.HasSuffix(scenario, "-rv"):
				rows[0].Identity.ResourceVersion = ""
			case strings.HasSuffix(scenario, "-duplicate"):
				rows[0] = rows[1]
			case strings.HasSuffix(scenario, "-reordered"):
				rows[0], rows[1] = rows[1], rows[0]
			}
			bad, _ := json.Marshal(receipt)
			bad, err := canonicaljson.CanonicalJSON(bad)
			if err != nil {
				t.Fatal("malformed static rows failed test encoding")
			}
			_, identity, err := f.engine.files.Read(witness.retirement.name, retirementMaxBytes)
			if err != nil {
				t.Fatal("original row evidence unavailable")
			}
			if _, err := f.engine.files.AtomicWrite(witness.retirement.name, bad, &identity); err != nil {
				t.Fatal("malformed static row seed failed")
			}
			if _, err := f.engine.openReinstallSource(current); err != ErrSecurityBaseline {
				t.Fatal("malformed retirement rows authenticated as source provenance")
			}
			if _, err := f.engine.saveReinstallSource(source); err != ErrSecurityBaseline {
				t.Fatal("malformed retirement rows reached source publication")
			}
			_, identity, err = f.engine.files.Read(witness.retirement.name, retirementMaxBytes)
			if err != nil {
				t.Fatal("malformed retirement row recovery opening unavailable")
			}
			if _, err := f.engine.files.AtomicWrite(witness.retirement.name, witness.retirement.body, &identity); err != nil {
				t.Fatal("test-only retirement restoration failed")
			}
		})
	}
}

func TestAdmissionReinstallReceiptDescriptorsReleaseOnRefusalAndClose(t *testing.T) {
	f, source := reinstallReceiptFixture(t)
	witness, err := f.engine.saveReinstallSource(source)
	if err != nil {
		t.Fatal("original source publication unavailable")
	}
	defer witness.release()
	d := source.Document()
	d.Mode, d.Stage, d.AdmissionRetirementRevision = installstate.Install, installstate.Preparing, 0
	d.Revision++
	d.AdmissionReinstall = &witness.provenance
	current, err := f.store.Commit(t.Context(), source, d)
	if err != nil {
		t.Fatal("source pin CAS unavailable")
	}
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal("descriptor accounting unavailable")
		}
		return len(entries)
	}
	before := count()
	for range 32 {
		opened, err := f.engine.openReinstallSource(current)
		if err != nil || f.engine.closeReinstallSource(opened) != nil {
			t.Fatal("healthy repeated source proof unavailable")
		}
		opened.release()
		opened.release()
		if f.engine.closeReinstallSource(opened) != ErrSecurityBaseline {
			t.Fatal("released source supplied proof authority")
		}
	}
	if count() != before {
		t.Fatal("successful source acquisition/release leaked descriptors")
	}
	// Source pin is acquired first; malformed retirement then refuses. Each
	// failed constructor must release BOTH the original source and retirement
	// descriptors, without relying on GC or Store.Close to reclaim them.
	name := witness.retirement.name
	body, identity, err := f.engine.files.Read(name, retirementMaxBytes)
	if err != nil {
		t.Fatal("original retirement receipt unavailable")
	}
	if _, err := f.engine.files.AtomicWrite(name, []byte("{}"), &identity); err != nil {
		t.Fatal("test-owned malformed retirement seed failed")
	}
	for range 32 {
		rejected, err := f.engine.openReinstallSource(current)
		if err != ErrSecurityBaseline || rejected != nil {
			rejected.release()
			t.Fatal("malformed retirement produced a source witness")
		}
	}
	if count() != before {
		t.Fatal("partial failed source construction leaked descriptors")
	}
	_, identity, err = f.engine.files.Read(name, retirementMaxBytes)
	if err != nil {
		t.Fatal("test-owned retirement restoration unavailable")
	}
	if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
		t.Fatal("test-owned retirement restoration failed")
	}
	// Refuse malformed source before a retirement pin can be acquired too.
	_, identity, err = f.engine.files.Read(witness.name, reinstallReceiptMaxBytes)
	if err != nil {
		t.Fatal("test-owned source opening unavailable")
	}
	if _, err := f.engine.files.AtomicWrite(witness.name, []byte("{}"), &identity); err != nil {
		t.Fatal("test-owned malformed source seed failed")
	}
	for range 32 {
		rejected, err := f.engine.openReinstallSource(current)
		if err != ErrSecurityBaseline || rejected != nil {
			rejected.release()
			t.Fatal("malformed source produced a witness")
		}
	}
	if count() != before {
		t.Fatal("failed source decode leaked descriptors")
	}
}

func TestAdmissionReinstallMalformedRetirementCannotPublishFirstSource(t *testing.T) {
	f, source := reinstallReceiptFixture(t)
	d := source.Document()
	name, err := reinstallSourceName(d.InstallationID, d.Revision)
	if err != nil {
		t.Fatal("fixed source receipt name unavailable")
	}
	if _, _, err := f.engine.files.Read(name, reinstallReceiptMaxBytes); err != privatefs.ErrNotFound {
		t.Fatal("unpublished source fixture already has evidence")
	}
	retirement := retirementName(d, d.AdmissionRetirementRevision)
	body, identity, err := f.engine.files.Read(retirement, retirementMaxBytes)
	if err != nil {
		t.Fatal("original retirement evidence unavailable")
	}
	var receipt retirementReceipt
	if json.Unmarshal(body, &receipt) != nil || len(receipt.Baseline) != 12 {
		t.Fatal("original static rows unavailable")
	}
	receipt.Baseline[0] = receipt.Baseline[1] // Valid JSON, right count, wrong identities.
	bad, _ := json.Marshal(receipt)
	bad, err = canonicaljson.CanonicalJSON(bad)
	if err != nil {
		t.Fatal("duplicate row encoding failed")
	}
	if _, err := f.engine.files.AtomicWrite(retirement, bad, &identity); err != nil {
		t.Fatal("duplicate row seeding failed")
	}
	if _, err := f.engine.saveReinstallSource(source); err != ErrSecurityBaseline {
		t.Fatal("unauthenticated retirement reached source publication")
	}
	if _, _, err := f.engine.files.Read(name, reinstallReceiptMaxBytes); err != privatefs.ErrNotFound {
		t.Fatal("source was published before retirement authentication")
	}
}
