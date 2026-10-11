// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"reflect"
	"slices"
	"testing"
)

// This exercises copying, not journal acceptance: the graph includes every
// mutable branch even where those branches cannot coexist in a valid stage.
func snapshotCopyDocument() Document {
	return Document{
		Version: Version, InstallationID: "installation", Namespace: "isolated",
		NamespaceUID: "namespace-uid", ProfileID: "profile", Revision: 123,
		Mode: Upgrade, Stage: Applying, ActivePackage: "active", PreviousPackage: "previous",
		TargetPackage: "target", Installed: true, AdmissionRetirementRevision: 98,
		Resources:          []Resource{{Key: Key{"v1", "Service", "isolated", "service"}, UID: "runtime-uid", TemplateSHA256: "runtime-hash", Retained: true}},
		Pending:            &Pending{Action: Update, Key: Key{"v1", "Service", "isolated", "service"}, CreateNonce: "nonce", BeforeUID: "runtime-uid", BeforeResourceVersion: "77", BeforeSHA256: "before", AfterSHA256: "after"},
		AdmissionReinstall: &ReinstallProvenance{SourceRevision: 97, SourceJournalSHA256: "reinstall-source"},
		SecurityBaseline: &SecurityBaseline{
			Version: "baseline-version", ArtifactDigest: "baseline-digest", Stage: BaselineApplying,
			Resources:  []BaselineResource{{Key: Key{"v1", "ServiceAccount", "isolated", "account"}, UID: "baseline-uid", TemplateSHA256: "baseline-hash"}},
			Pending:    &Pending{Action: Create, Key: Key{"v1", "ServiceAccount", "isolated", "account"}, CreateNonce: "baseline-nonce", AfterSHA256: "baseline-after"},
			Enrollment: &BaselineEnrollmentProvenance{SourceRevision: 96, SourceJournalSHA256: "enrollment-source", SourceEvidenceSHA256: "enrollment-evidence"},
		},
	}
}

func TestSnapshotDocumentCopyMatchesJSONShape(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Document)
	}{
		{"all-fields", func(*Document) {}},
		{"nil-resources", func(d *Document) { d.Resources = nil; d.SecurityBaseline.Resources = nil }},
		{"empty-resources", func(d *Document) { d.Resources = []Resource{}; d.SecurityBaseline.Resources = []BaselineResource{} }},
		{"nil-pointers", func(d *Document) { d.Pending = nil; d.AdmissionReinstall = nil; d.SecurityBaseline = nil }},
		{"nil-baseline-pointers", func(d *Document) { d.SecurityBaseline.Pending = nil; d.SecurityBaseline.Enrollment = nil }},
		{"zero-pointers", func(d *Document) {
			d.Pending = &Pending{}
			d.AdmissionReinstall = &ReinstallProvenance{}
			d.SecurityBaseline = &SecurityBaseline{Pending: &Pending{}, Enrollment: &BaselineEnrollmentProvenance{}}
		}},
		{"unicode", func(d *Document) {
			d.Namespace = "世界-é-🙂"
			d.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = "\"\\\n\t"
		}},
		{"zero-document", func(d *Document) { *d = Document{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := snapshotCopyDocument()
			test.edit(&d)
			var want Document
			if err := jsonCopy(d, &want); err != nil {
				t.Fatal(err)
			}
			s := &Snapshot{document: d}
			if got := s.Document(); !reflect.DeepEqual(got, want) {
				t.Fatal("defensive copy changed journal values or nil/empty shape")
			}
		})
	}
	var absent *Snapshot
	if !reflect.DeepEqual(absent.Document(), Document{}) {
		t.Fatal("nil snapshot manufactured a document")
	}
}

func TestSnapshotDocumentCopiesEveryMutableBranch(t *testing.T) {
	d := snapshotCopyDocument()
	var want Document
	if err := jsonCopy(d, &want); err != nil {
		t.Fatal(err)
	}
	s := &Snapshot{document: d}
	a, b := s.Document(), s.Document()
	a.Resources[0].UID = "changed-runtime"
	a.Pending.BeforeResourceVersion = "changed-runtime-pending"
	a.AdmissionReinstall.SourceRevision++
	a.SecurityBaseline.Resources[0].UID = "changed-baseline"
	a.SecurityBaseline.Pending.CreateNonce = "changed-baseline-pending"
	a.SecurityBaseline.Enrollment.SourceRevision++
	if !reflect.DeepEqual(s.Document(), want) || !reflect.DeepEqual(b, want) {
		t.Fatal("accessor output aliases its source or another accessor result")
	}
	// Isolation is bidirectional: subsequent source mutation cannot affect a
	// previously returned document either.
	d.Resources[0].UID = "source-runtime"
	d.Pending.BeforeResourceVersion = "source-runtime-pending"
	d.AdmissionReinstall.SourceRevision++
	d.SecurityBaseline.Resources[0].UID = "source-baseline"
	d.SecurityBaseline.Pending.CreateNonce = "source-baseline-pending"
	d.SecurityBaseline.Enrollment.SourceRevision++
	if !reflect.DeepEqual(b, want) {
		t.Fatal("source mutation reached an independent accessor result")
	}
}

func TestSnapshotDocumentMutableGraphIsExhaustive(t *testing.T) {
	// A future reference-valued field requires an explicit copy and test.
	// Scalar additions are already preserved by the initial value copy.
	var paths []string
	var inspect func(reflect.Type, string)
	inspect = func(typ reflect.Type, path string) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice:
			paths = append(paths, path)
			inspect(typ.Elem(), path)
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				inspect(field.Type, path+"."+field.Name)
			}
		case reflect.Map, reflect.Interface, reflect.Array, reflect.Chan, reflect.Func, reflect.UnsafePointer:
			t.Fatalf("unreviewed document field type at %s", path)
		}
	}
	inspect(reflect.TypeFor[Document](), "Document")
	want := []string{
		"Document.Resources", "Document.Pending", "Document.AdmissionReinstall",
		"Document.SecurityBaseline", "Document.SecurityBaseline.Resources",
		"Document.SecurityBaseline.Pending", "Document.SecurityBaseline.Enrollment",
	}
	slices.Sort(paths)
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Fatal("document mutable graph changed; review defensive copy coverage")
	}
}

func TestSnapshotDocumentConcurrentCopies(t *testing.T) {
	d := snapshotCopyDocument()
	s := &Snapshot{document: d, body: []byte("sealed-original")}
	anchor := s.Anchor()
	for range 8 {
		t.Run("independent-copy", func(t *testing.T) {
			t.Parallel()
			for range 20 {
				copy := s.Document()
				copy.Resources[0].UID = "mutated"
				copy.Pending.CreateNonce = "mutated"
				copy.AdmissionReinstall.SourceRevision++
				copy.SecurityBaseline.Resources[0].UID = "mutated"
				copy.SecurityBaseline.Pending.CreateNonce = "mutated"
				copy.SecurityBaseline.Enrollment.SourceRevision++
				if !reflect.DeepEqual(s.Document(), d) || s.Anchor() != anchor || s.ResourceVersion() != "" || string(s.Bytes()) != "sealed-original" {
					t.Fatal("independent mutation changed sealed observation")
				}
			}
		})
	}
}

var snapshotCopyBenchmarkSink Document

func BenchmarkSnapshotDocumentCopy(b *testing.B) {
	for _, scenario := range []string{"legacy", "full-baseline"} {
		b.Run(scenario, func(b *testing.B) {
			d := snapshotCopyDocument()
			if scenario == "legacy" {
				d.Pending, d.AdmissionReinstall, d.SecurityBaseline = nil, nil, nil
			} else {
				for len(d.Resources) < MaxResources {
					d.Resources = append(d.Resources, d.Resources[0])
				}
				for len(d.SecurityBaseline.Resources) < 12 {
					d.SecurityBaseline.Resources = append(d.SecurityBaseline.Resources, d.SecurityBaseline.Resources[0])
				}
			}
			b.Run("json-roundtrip", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var copy Document
					if err := jsonCopy(d, &copy); err != nil {
						b.Fatal(err)
					}
					snapshotCopyBenchmarkSink = copy
				}
			})
			b.Run("sealed-accessor", func(b *testing.B) {
				s := &Snapshot{document: d}
				b.ReportAllocs()
				for b.Loop() {
					snapshotCopyBenchmarkSink = s.Document()
				}
			})
		})
	}
}
