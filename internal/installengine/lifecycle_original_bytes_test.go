// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLifecycleOriginalJournalByteComparisonKeepsFreshBindingGuards(t *testing.T) {
	for _, scenario := range []string{"original", "same-body-new-rv", "new-journal-same-rv", "replaced-namespace", "namespace-shape-drift"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			ctx := t.Context()
			before := f.snapshot.Bytes()
			ns, err := f.access.client.CoreV1().Namespaces().Get(ctx, f.plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				t.Fatal("original namespace unavailable")
			}
			wantErr := error(nil)
			wantReads := 1
			switch scenario {
			case "original":
				wantReads = 2 // Fresh sealed journal, then complete Namespace GET.
			case "same-body-new-rv":
				ns.ResourceVersion = "2"
				wantErr = ErrConcurrent
			case "new-journal-same-rv":
				d := f.snapshot.Document()
				d.Revision++
				encoded, err := installstate.Encode(d, f.plan)
				if err != nil {
					t.Fatal("changed canonical journal unavailable")
				}
				ns.Annotations[installstate.Annotation] = string(encoded)
				wantErr = ErrConcurrent
			case "replaced-namespace":
				ns.UID = "replacement-namespace"
				wantErr = ErrOwnership
			case "namespace-shape-drift":
				ns.Labels["unreviewed-extra"] = "changed"
				wantErr, wantReads = ErrOwnership, 2
			}
			if err := f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
				t.Fatal("controlled namespace change unavailable")
			}
			if scenario == "same-body-new-rv" {
				fresh, err := f.store.Load(ctx, f.snapshot.Anchor())
				if err != nil || !fresh.SameJournalBytes(f.snapshot) || fresh.ResourceVersion() == f.snapshot.ResourceVersion() {
					t.Fatal("byte-only comparison swallowed the independent RV difference")
				}
			}
			f.access.client.ClearActions()
			got, err := (&Lifecycle{engine: f.engine}).original(ctx, f.snapshot)
			if !errors.Is(err, wantErr) || (wantErr == nil) != (got != nil) {
				t.Fatal("fresh namespace/journal/identity binding changed")
			}
			reads := 0
			for _, action := range f.access.client.Actions() {
				if action.GetVerb() != "get" || action.GetResource().Resource != "namespaces" {
					t.Fatal("original observation performed an unexpected request or mutation")
				}
				reads++
			}
			if reads != wantReads || f.access.writes != 0 || f.nsUpdates != 0 || !bytes.Equal(f.snapshot.Bytes(), before) {
				t.Fatal("fresh reads, no-effect behavior or immutable original changed")
			}
		})
	}
}
