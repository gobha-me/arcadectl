// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Actual legacy fixture lifecycle/Secret/journal machinery with synthetic proof
// providers and an explicitly synthetic historical bootstrap receipt. No cold
// worlds, baseline effects, native enrollment or old binary are certified here.
func baselineEnrollmentSourceFixture(t *testing.T, mode installstate.Mode) (*lifecycleFixture, *installstate.Snapshot, string, *coldWorldTuple) {
	t.Helper()
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	source := v.finish(t, v.f.snapshot)
	if mode == installstate.Upgrade || mode == installstate.Rollback {
		var err error
		source, err = v.l.Begin(t.Context(), source, installstate.Upgrade, target.Digest(), v.opts)
		if err != nil {
			t.Fatal("genuine fixture upgrade Begin unavailable")
		}
		source = v.finish(t, source)
		if mode == installstate.Rollback {
			source, err = v.l.Begin(t.Context(), source, installstate.Rollback, previous.Digest(), v.opts)
			if err != nil {
				t.Fatal("genuine fixture rollback Begin unavailable")
			}
			source = v.finish(t, source)
		}
	}
	d := source.Document()
	bootstrapName := "Bootstrap_Original.json"
	body, err := json.Marshal(map[string]any{
		"version": "v1", "installationId": d.InstallationID, "namespace": d.Namespace,
		"namespaceUid": d.NamespaceUID, "createAttempted": true,
		"packageSha256": previous.Digest(), "profileId": d.ProfileID,
	})
	if err == nil {
		body, err = canonicaljson.CanonicalJSON(body)
	}
	if err != nil {
		t.Fatal("independent historical bootstrap wire unavailable")
	}
	if _, err := v.f.engine.files.CreateExclusive(bootstrapName, body); err != nil {
		t.Fatal("protected synthetic historical bootstrap unavailable")
	}
	baseline := baselineFixturePlan(t, d.Namespace, d.ProfileID, 'e')
	store, err := installstate.NewWithBaseline(v.f.access.client.CoreV1().Namespaces(), baseline, previous, target)
	if err != nil {
		t.Fatal("baseline-aware historical store unavailable")
	}
	engine, err := NewWithBaselineAccess(v.f.access, store, v.f.engine.files, baseline, previous, target)
	if err != nil {
		t.Fatal("historical source engine unavailable")
	}
	v.f.store, v.f.engine = store, engine
	source, err = store.Load(t.Context(), source.Anchor())
	if err != nil || source.Document().Mode != mode || source.Document().SecurityBaseline != nil {
		t.Fatal("original completed historical mode was rewritten")
	}
	claim := corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "retained-world", Namespace: d.Namespace, UID: "original-world-claim", ResourceVersion: "20"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "retained-volume"}}
	volume := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "retained-volume", UID: "original-world-volume", ResourceVersion: "21"}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.example.test", VolumeHandle: "private-storage-source-marker"}}}}
	return v, source, bootstrapName, &coldWorldTuple{Claims: []corev1.PersistentVolumeClaim{claim}, Volumes: []*corev1.PersistentVolume{volume}}
}

func publishBaselineEnrollmentSource(t *testing.T, v *lifecycleFixture, source *installstate.Snapshot, name string, worlds *coldWorldTuple) *baselineEnrollmentSourceWitness {
	t.Helper()
	inputs, err := v.f.engine.openBaselineEnrollmentInputs(t.Context(), source, v.f.plan, name, v.opts.Activation.CAFile)
	if err != nil {
		t.Fatal("original historical bootstrap/CA input owner unavailable")
	}
	t.Cleanup(inputs.release)
	witness, err := v.f.engine.saveBaselineEnrollmentSource(t.Context(), source, inputs, worlds)
	if err != nil {
		t.Fatal("protected source publication unavailable", err)
	}
	t.Cleanup(witness.release)
	return witness
}

func introduceBaselineEnrollmentSource(t *testing.T, v *lifecycleFixture, source *installstate.Snapshot, witness *baselineEnrollmentSourceWitness) *installstate.Snapshot {
	t.Helper()
	d := source.Document()
	d.Revision++
	d.SecurityBaseline, _ = installstate.PinnedSecurityBaseline(v.f.engine.baselinePlan())
	provenance := witness.provenance
	d.SecurityBaseline.Enrollment = &provenance
	current, err := v.f.store.Commit(t.Context(), source, d)
	if err != nil {
		t.Fatal("literal source/envelope introduction CAS unavailable", err)
	}
	return current
}

func TestBaselineEnrollmentProtectedSourceModesAndRestart(t *testing.T) {
	for _, mode := range []installstate.Mode{installstate.Install, installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			v, source, name, worlds := baselineEnrollmentSourceFixture(t, mode)
			e := v.f.engine
			writes, nsWrites, secretWrites := v.f.access.writes, v.f.nsUpdates, v.private.writes
			w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
			if e.confirmBaselineEnrollmentSource(t.Context(), w, source) != nil || w.matchesWorlds(worlds) != nil || bytes.Contains(w.body, []byte("private-storage-source-marker")) || bytes.Contains(w.body, []byte(v.opts.Activation.CAFile)) {
				t.Fatal("source did not retain exact hash-only original evidence")
			}
			current := introduceBaselineEnrollmentSource(t, v, source, w)
			w.release()
			plans := make([]*installrender.Plan, 0, len(e.plans))
			for _, plan := range e.plans {
				plans = append(plans, plan)
			}
			store, err := installstate.NewWithBaseline(v.f.access.client.CoreV1().Namespaces(), e.baselinePlan(), plans...)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewWithBaselineAccess(v.f.access, store, e.files, e.baselinePlan(), plans...)
			if err != nil {
				t.Fatal(err)
			}
			current, err = store.Load(t.Context(), current.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			opened, err := restarted.openBaselineEnrollmentSource(t.Context(), current, v.f.plan, name, v.opts.Activation.CAFile)
			if err != nil {
				t.Fatal("sealed source did not survive real owner/store reconstruction")
			}
			defer opened.release()
			if restarted.confirmBaselineEnrollmentSource(t.Context(), opened, current) != nil || opened.matchesWorlds(worlds) != nil || !reflect.DeepEqual(opened.source, source.Document()) || !bytes.Equal(opened.body, w.body) || current.Document().Mode != mode || current.Document().Stage != installstate.Complete {
				t.Fatal("restart recaptured worlds or rewrote historical runtime/history")
			}
			if restarted.baseline.runtimeGuard != nil || v.f.access.writes != writes || v.private.writes != secretWrites || v.f.nsUpdates != nsWrites+1 {
				t.Fatal("source witness granted runtime authority or issued a target effect")
			}
		})
	}
}

func TestBaselineEnrollmentSourceNeverRecapturesSurvivingWorlds(t *testing.T) {
	v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
	w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
	original := bytes.Clone(w.body)
	w.release()
	inputs, err := v.f.engine.openBaselineEnrollmentInputs(t.Context(), source, v.f.plan, name, v.opts.Activation.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.release()
	if _, err := v.f.engine.saveBaselineEnrollmentSource(t.Context(), source, inputs, &coldWorldTuple{}); err != ErrOutcomeUnknown {
		t.Fatal("pre-introduction restart recaptured only surviving worlds")
	}
	body, _, err := v.f.engine.files.ReadEvidence(w.name, int64(len(original)))
	if err != nil || !bytes.Equal(body, original) {
		t.Fatal("failed restart changed original world floor")
	}
	current := introduceBaselineEnrollmentSource(t, v, source, w)
	forged := w.receipt
	forged.Worlds = []fixtureWorldRow{}
	forgedBody, _, err := v.f.engine.baselineEnrollmentSourceBody(forged)
	if err != nil {
		t.Fatal("structurally valid empty-world adversarial envelope unavailable")
	}
	_, identity, err := v.f.engine.files.ReadEvidence(w.name, privatefs.MaxEvidenceFileBytes)
	if err != nil || v.f.engine.files.RemoveEvidence(w.name, identity) != nil {
		t.Fatal("test-only original envelope unavailable")
	}
	if _, err := v.f.engine.files.CreateEvidenceExclusive(w.name, forgedBody); err != nil {
		t.Fatal("test-only forged envelope replacement unavailable")
	}
	if _, err := v.f.engine.openBaselineEnrollmentSource(t.Context(), current, v.f.plan, name, v.opts.Activation.CAFile); err != ErrSecurityBaseline {
		t.Fatal("journal-only seal admitted changed world evidence after introduction")
	}
}

func TestBaselineEnrollmentSourcePinsAllOriginalsThroughClose(t *testing.T) {
	for _, which := range []string{"source", "bootstrap", "ca", "released", "copied"} {
		t.Run(which, func(t *testing.T) {
			v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
			w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
			if which == "copied" {
				copy := *w
				copy.release()
				if v.f.engine.confirmBaselineEnrollmentSource(t.Context(), &copy, source) != ErrSecurityBaseline || v.f.engine.confirmBaselineEnrollmentSource(t.Context(), w, source) != nil {
					t.Fatal("copied source owner confirmed or released original pins")
				}
				return
			}
			if which == "released" {
				w.release()
			} else {
				if which == "ca" {
					path := v.opts.Activation.CAFile
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					for range 2 {
						if os.WriteFile(path+".replacement", body, 0600) != nil || os.Rename(path+".replacement", path) != nil {
							t.Fatal("identical CA replacement unavailable")
						}
					}
				} else {
					for range 2 {
						if which == "source" {
							body, identity, err := v.f.engine.files.ReadEvidence(w.name, privatefs.MaxEvidenceFileBytes)
							if err != nil || v.f.engine.files.RemoveEvidence(w.name, identity) != nil {
								t.Fatal("original source replacement fixture unavailable")
							}
							if _, err := v.f.engine.files.CreateEvidenceExclusive(w.name, body); err != nil {
								t.Fatal(err)
							}
						} else {
							body, identity, err := v.f.engine.files.Read(name, installstate.MaxBytes)
							if err != nil {
								t.Fatal(err)
							}
							if _, err := v.f.engine.files.AtomicWrite(name, body, &identity); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
			if v.f.engine.confirmBaselineEnrollmentSource(t.Context(), w, source) != ErrSecurityBaseline {
				t.Fatal("released or replaced original descriptor supplied source evidence")
			}
			w.release()
			for _, base := range []string{w.name, name, filepath.Base(v.opts.Activation.CAFile)} {
				if testBaselineReceiptDescriptors(t, base) != 0 {
					t.Fatal("source owner leaked an original descriptor")
				}
			}
		})
	}
}

func TestBaselineEnrollmentSourcePreCASRestartKeepsAuditRVAndFloor(t *testing.T) {
	v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
	w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
	originalBody, originalRV := bytes.Clone(w.body), w.receipt.JournalResourceVersion
	w.release()
	namespace, err := v.f.access.client.CoreV1().Namespaces().Get(t.Context(), source.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	namespace.Status.Phase = corev1.NamespaceActive
	if _, err := v.f.access.client.CoreV1().Namespaces().UpdateStatus(t.Context(), namespace, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	lifecycle := &Lifecycle{engine: v.f.engine}
	if _, err := lifecycle.original(t.Context(), source); err != ErrConcurrent {
		t.Fatal("same-invocation original Namespace RV fence was relaxed")
	}
	fresh, err := v.f.store.Load(t.Context(), source.Anchor())
	if err != nil || fresh.ResourceVersion() == source.ResourceVersion() || !bytes.Equal(fresh.Bytes(), source.Bytes()) {
		t.Fatal("benign metadata-only restart fixture unavailable")
	}
	if _, err := lifecycle.original(t.Context(), fresh); err != nil {
		t.Fatal("fresh observation rejected benign server-owned Namespace status", err)
	}
	reopened := publishBaselineEnrollmentSource(t, v, fresh, name, worlds)
	if reopened.receipt.JournalResourceVersion != originalRV || !bytes.Equal(reopened.body, originalBody) || reopened.provenance != w.provenance {
		t.Fatal("restart republished the initial source/world envelope")
	}
}

func TestBaselineEnrollmentSourceDecoderRejectsMalformedEvidence(t *testing.T) {
	v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
	w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
	if _, _, err := v.f.engine.decodeBaselineEnrollmentSource(w.body); err != nil {
		t.Fatal("known-good canonical historical source unavailable", err)
	}
	encode := func(t *testing.T, mutate func(*baselineEnrollmentSourceReceipt)) []byte {
		t.Helper()
		var receipt baselineEnrollmentSourceReceipt
		if err := json.Unmarshal(w.body, &receipt); err != nil {
			t.Fatal(err)
		}
		mutate(&receipt)
		body, err := json.Marshal(receipt)
		if err == nil {
			body, err = canonicaljson.CanonicalEvidenceJSON(body)
		}
		if err != nil {
			t.Fatal("malformed semantic envelope encoding unavailable", err)
		}
		return body
	}
	for _, tc := range []struct {
		name   string
		mutate func(*baselineEnrollmentSourceReceipt)
	}{
		{"wrong_version", func(r *baselineEnrollmentSourceReceipt) { r.Version = "v0" }},
		{"wrong_baseline", func(r *baselineEnrollmentSourceReceipt) { r.BaselineSHA256 = strings.Repeat("a", 64) }},
		{"invalid_audit_rv", func(r *baselineEnrollmentSourceReceipt) { r.JournalResourceVersion = "0" }},
		{"invalid_bootstrap_name", func(r *baselineEnrollmentSourceReceipt) { r.Bootstrap.ReceiptName = "../receipt" }},
		{"invalid_bootstrap_package", func(r *baselineEnrollmentSourceReceipt) { r.Bootstrap.PackageSHA256 = strings.Repeat("A", 64) }},
		{"invalid_bootstrap_digest", func(r *baselineEnrollmentSourceReceipt) { r.Bootstrap.SHA256 = "bad" }},
		{"invalid_ca_digest", func(r *baselineEnrollmentSourceReceipt) { r.CASHA256 = "bad" }},
		{"null_worlds", func(r *baselineEnrollmentSourceReceipt) { r.Worlds = nil }},
		{"unsorted_worlds", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[0], r.Worlds[1] = r.Worlds[1], r.Worlds[0] }},
		{"duplicate_uid", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[1].UID = r.Worlds[0].UID }},
		{"duplicate_key", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[1].Key = r.Worlds[0].Key }},
		{"invalid_uid", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[0].UID = "" }},
		{"wrong_kind", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[0].Key.Kind = "Secret" }},
		{"wrong_namespace", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[1].Key.Namespace = "other-namespace" }},
		{"namespaced_pv", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[0].Key.Namespace = source.Anchor().Namespace }},
		{"invalid_row_rv", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[0].ResourceVersion = "0" }},
		{"invalid_row_digest", func(r *baselineEnrollmentSourceReceipt) { r.Worlds[0].SHA256 = strings.Repeat("A", 64) }},
		{"noncomplete_journal", func(r *baselineEnrollmentSourceReceipt) {
			d := source.Document()
			d.Stage = installstate.Applying
			r.Journal, _ = json.Marshal(d)
		}},
		{"baseline_already_present", func(r *baselineEnrollmentSourceReceipt) {
			d := source.Document()
			d.SecurityBaseline, _ = installstate.PinnedSecurityBaseline(v.f.engine.baselinePlan())
			r.Journal, _ = json.Marshal(d)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := v.f.engine.decodeBaselineEnrollmentSource(encode(t, tc.mutate)); err != ErrSecurityBaseline {
				t.Fatal("malformed source semantics supplied an enrollment source", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"unknown_field", append([]byte(`{"unknown":true,`), w.body[1:]...)},
		{"duplicate_field", append([]byte(`{"version":"`+baselineEnrollmentSourceVersion+`",`), w.body[1:]...)},
		{"noncanonical", append([]byte(" "), w.body...)},
		{"trailing_whitespace", append(bytes.Clone(w.body), '\n')},
		{"trailing_value", append(bytes.Clone(w.body), []byte(" {}")...)},
		{"truncated", w.body[:len(w.body)-1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := v.f.engine.decodeBaselineEnrollmentSource(tc.body); err != ErrSecurityBaseline {
				t.Fatal("malformed source wire supplied an enrollment source", err)
			}
		})
	}
}

func TestBaselineEnrollmentSourcePartialOpenReleasesDescriptors(t *testing.T) {
	for _, which := range []string{"bootstrap_decode", "ca_missing", "ca_permissions", "source_decode"} {
		t.Run(which, func(t *testing.T) {
			v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
			w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
			w.release()
			caFile := v.opts.Activation.CAFile
			if which == "source_decode" {
				forged := w.receipt
				forged.Version = "malformed-source"
				body, err := json.Marshal(forged)
				if err == nil {
					body, err = canonicaljson.CanonicalEvidenceJSON(body)
				}
				_, identity, readErr := v.f.engine.files.ReadEvidence(w.name, privatefs.MaxEvidenceFileBytes)
				if err != nil || readErr != nil || v.f.engine.files.RemoveEvidence(w.name, identity) != nil {
					t.Fatal("sealed malformed source fixture unavailable")
				}
				if _, err := v.f.engine.files.CreateEvidenceExclusive(w.name, body); err != nil {
					t.Fatal(err)
				}
				// The public seal deliberately matches: this exercises decoding
				// and descriptor cleanup, not the separate digest rejection.
				w.provenance.SourceEvidenceSHA256 = fixtureWorldDigest(body)
			}
			current := introduceBaselineEnrollmentSource(t, v, source, w)
			switch which {
			case "bootstrap_decode":
				_, identity, err := v.f.engine.files.Read(name, installstate.MaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := v.f.engine.files.AtomicWrite(name, []byte(`{}`), &identity); err != nil {
					t.Fatal(err)
				}
			case "ca_missing":
				caFile += ".missing"
			case "ca_permissions":
				if err := os.Chmod(caFile, 0666); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := v.f.engine.openBaselineEnrollmentSource(t.Context(), current, v.f.plan, name, caFile)
			if err != ErrSecurityBaseline || opened != nil {
				t.Fatal("partial failed open supplied an enrollment owner", err)
			}
			for _, base := range []string{w.name, name, filepath.Base(v.opts.Activation.CAFile)} {
				if testBaselineReceiptDescriptors(t, base) != 0 {
					t.Fatal("partial failed open leaked a protected original descriptor")
				}
			}
		})
	}
}

func TestBaselineEnrollmentSourceLargeEvidenceKeepsCredentialLimit(t *testing.T) {
	v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
	w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
	w.release()
	receipt := w.receipt
	receipt.Worlds = make([]fixtureWorldRow, 6000)
	for i := range receipt.Worlds {
		receipt.Worlds[i] = fixtureWorldRow{
			Key: installstate.Key{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: source.Anchor().Namespace, Name: fmt.Sprintf("retained-world-%05d", i)},
			UID: types.UID(fmt.Sprintf("original-claim-%05d", i)), ResourceVersion: "25", SHA256: strings.Repeat("a", 64),
		}
	}
	body, _, err := v.f.engine.baselineEnrollmentSourceBody(receipt)
	if err != nil || int64(len(body)) <= privatefs.MaxFileBytes || int64(len(body)) > privatefs.MaxEvidenceFileBytes {
		t.Fatal("large bounded source envelope unavailable", err)
	}
	_, identity, err := v.f.engine.files.ReadEvidence(w.name, privatefs.MaxEvidenceFileBytes)
	if err != nil || v.f.engine.files.RemoveEvidence(w.name, identity) != nil {
		t.Fatal("test-only large source replacement unavailable")
	}
	if _, err := v.f.engine.files.CreateEvidenceExclusive(w.name, body); err != nil {
		t.Fatal(err)
	}
	w.provenance.SourceEvidenceSHA256 = fixtureWorldDigest(body)
	current := introduceBaselineEnrollmentSource(t, v, source, w)
	if _, _, pin, err := v.f.engine.files.Pin(w.name, int64(len(body))); err != privatefs.ErrUnsafe || pin != nil {
		t.Fatal("source evidence widened ordinary credential pin limits")
	}
	opened, err := v.f.engine.openBaselineEnrollmentSource(t.Context(), current, v.f.plan, name, v.opts.Activation.CAFile)
	if err != nil || opened == nil {
		t.Fatal("original large evidence could not be reconstructed", err)
	}
	defer opened.release()
	if len(opened.receipt.Worlds) != 6000 || !bytes.Equal(opened.body, body) || v.f.engine.confirmBaselineEnrollmentSource(t.Context(), opened, current) != nil {
		t.Fatal("large envelope lost its sealed original identity")
	}
	// Evidence byte limits do not widen the complete collection count limit.
	receipt.Worlds = append(receipt.Worlds, make([]fixtureWorldRow, installsafety.MaxObjectsPerList+1-len(receipt.Worlds))...)
	for i := 6000; i < len(receipt.Worlds); i++ {
		receipt.Worlds[i] = fixtureWorldRow{
			Key: installstate.Key{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: source.Anchor().Namespace, Name: fmt.Sprintf("retained-world-%05d", i)},
			UID: types.UID(fmt.Sprintf("original-claim-%05d", i)), ResourceVersion: "25", SHA256: strings.Repeat("a", 64),
		}
	}
	if _, _, err := v.f.engine.baselineEnrollmentSourceBody(receipt); err != ErrSecurityBaseline {
		t.Fatal("large evidence widened the per-kind original world limit")
	}
}

func TestBaselineEnrollmentSourceRejectsChangedParsedEvidence(t *testing.T) {
	for _, which := range []string{"worlds", "coordinated_worlds", "source", "journal", "audit_rv", "body", "provenance", "name", "identity", "coordinated_name"} {
		t.Run(which, func(t *testing.T) {
			v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Install)
			w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
			candidate := worlds
			switch which {
			case "worlds":
				w.receipt.Worlds = []fixtureWorldRow{}
				candidate = &coldWorldTuple{}
			case "coordinated_worlds":
				w.receipt.Worlds = []fixtureWorldRow{}
				var err error
				w.body, w.source, err = v.f.engine.baselineEnrollmentSourceBody(w.receipt)
				if err != nil {
					t.Fatal("coordinated in-memory floor mutation unavailable", err)
				}
				w.provenance.SourceEvidenceSHA256 = fixtureWorldDigest(w.body)
				candidate = &coldWorldTuple{}
			case "source":
				w.source.Installed = false
			case "journal":
				d := source.Document()
				d.Stage = installstate.Applying
				w.receipt.Journal, _ = json.Marshal(d)
			case "audit_rv":
				w.receipt.JournalResourceVersion = "987654"
			case "body":
				w.body = append(bytes.Clone(w.body), '\n')
			case "provenance":
				w.provenance.SourceEvidenceSHA256 = strings.Repeat("a", 64)
			case "name":
				w.name = "another-original-source.json"
			case "identity":
				w.identity = privatefs.FileIdentity{}
			case "coordinated_name":
				identity, err := v.f.engine.files.CreateEvidenceExclusive("alternate-evidence.json", bytes.Clone(w.body))
				if err != nil {
					t.Fatal("same-body alternative-file fixture unavailable", err)
				}
				w.name, w.identity = "alternate-evidence.json", identity
			}
			if v.f.engine.confirmBaselineEnrollmentSource(t.Context(), w, source) != ErrSecurityBaseline || w.matchesWorlds(candidate) != ErrSecurityBaseline {
				t.Fatal("parsed mutable evidence changed the original sealed world/source floor")
			}
		})
	}
}

func TestBaselineEnrollmentSourceRejectsPausedAndMixedTarget(t *testing.T) {
	for _, which := range []string{"paused", "predecessor"} {
		t.Run(which, func(t *testing.T) {
			v, source, name, worlds := baselineEnrollmentSourceFixture(t, installstate.Upgrade)
			w := publishBaselineEnrollmentSource(t, v, source, name, worlds)
			d := source.Document()
			changed := false
			for i := range d.Resources {
				row := &d.Resources[i]
				if row.Key.Kind != "Deployment" {
					continue
				}
				packageDigest := d.TargetPackage
				if which == "predecessor" {
					packageDigest = v.f.plan.Digest()
				}
				template, err := v.f.engine.contracts[packageDigest].Template(row.Key, which == "paused")
				if err == nil && template.Hash() != row.TemplateSHA256 {
					row.TemplateSHA256 = template.Hash()
					changed = true
					break
				}
			}
			if !changed {
				t.Fatal("distinct cached paused/predecessor template unavailable")
			}
			if v.f.engine.historicalEnrollmentSource(d) {
				t.Fatal("completed source admitted a non-target cached template")
			}
			receipt := w.receipt
			receipt.Journal, _ = json.Marshal(d)
			body, err := json.Marshal(receipt)
			if err == nil {
				body, err = canonicaljson.CanonicalEvidenceJSON(body)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := v.f.engine.decodeBaselineEnrollmentSource(body); err != ErrSecurityBaseline {
				t.Fatal("source decoder admitted paused/mixed target inventory")
			}
		})
	}
}
