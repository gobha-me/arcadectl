// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestJournalDecodeMemoStrictBytesAndContext(t *testing.T) {
	plan, next := testPlan(t), lifecyclePlan(t, 2)
	baseline := baselinePlan(t, plan, 1)
	anchor := Anchor{plan.Namespace(), "namespace-uid", strings.Repeat("a", 32)}
	for _, mode := range []string{"legacy", "baseline-context-only", "pinned", "verified", "install", "upgrade", "rollback", "uninstall"} {
		t.Run(mode, func(t *testing.T) {
			d := initialDocument(plan)
			var pinned *installbaseline.Plan
			if mode != "legacy" {
				pinned = baseline
			}
			if mode != "legacy" && mode != "baseline-context-only" {
				d.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
				if mode != "pinned" {
					d.SecurityBaseline.Stage = BaselineVerified
					for i := 0; i < installbaseline.ResourceCount; i++ {
						d.SecurityBaseline.Resources = append(d.SecurityBaseline.Resources, baselineResource(t, baseline, i))
					}
					slices.SortFunc(d.SecurityBaseline.Resources, func(a, b BaselineResource) int { return strings.Compare(a.Key.String(), b.Key.String()) })
				}
			}
			if mode == "install" || mode == "upgrade" || mode == "rollback" || mode == "uninstall" {
				d.Stage, d.ActivePackage, d.Installed = Complete, plan.Digest(), true
				d.Resources = lifecycleResources(t, plan, mode == "uninstall")
				switch mode {
				case "upgrade":
					d.Mode, d.ActivePackage, d.TargetPackage, d.PreviousPackage = Upgrade, next.Digest(), next.Digest(), plan.Digest()
				case "rollback":
					d.Mode, d.PreviousPackage = Rollback, next.Digest()
				case "uninstall":
					d.Mode, d.Installed = Uninstall, false
				}
			}
			plans := []*installrender.Plan{plan, next}
			body, err := EncodeWithBaseline(d, pinned, plans...)
			if err != nil {
				t.Fatal("valid memo control unavailable", err)
			}
			store := &Store{plans: plans, baseline: pinned}
			for pass := 0; pass < 3; pass++ {
				want, wantErr := DecodeWithBaseline(body, pinned, plans...)
				got, gotErr := store.decodeJournal(body, anchor)
				if wantErr != nil || gotErr != nil || !reflect.DeepEqual(want, got) {
					t.Fatal("pure memo differs from original strict decoder")
				}
				got.Resources[0].UID = "caller-mutation"
				if got.SecurityBaseline != nil {
					got.SecurityBaseline.ArtifactDigest = "caller-mutation"
				}
			}
			// Every invalid byte shape must miss and clear, not reuse a previous
			// successful decode. Duplicate keys include a nested resource key.
			for _, bad := range [][]byte{nil, append([]byte(" "), body...), append(bytes.Clone(body), '\n'), bytes.Replace(body, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1), bytes.Replace(body, []byte(`"kind":"Namespace"`), []byte(`"kind":"Namespace","kind":"Namespace"`), 1), bytes.Replace(body, []byte(`"version":"v1"`), []byte(`"version":"v1","unknown":1`), 1), bytes.Repeat([]byte("x"), MaxBytes+1)} {
				if _, err := store.decodeJournal(body, anchor); err != nil {
					t.Fatal(err)
				}
				if _, err := DecodeWithBaseline(bad, pinned, plans...); err == nil {
					t.Fatal("invalid control unexpectedly accepted by original decoder")
				}
				if _, err := store.decodeJournal(bad, anchor); err == nil || store.decoded.body != nil {
					t.Fatal("refused decode populated or retained memo")
				}
			}
			if _, err := store.decodeJournal(body, anchor); err != nil {
				t.Fatal(err)
			}
			store.plans = []*installrender.Plan{next, plan}
			if _, err := store.decodeJournal(body, anchor); err != nil || !slices.Equal(store.decoded.plans, store.plans) {
				t.Fatal("ordered registry change reused the previous context")
			}
			store.plans = []*installrender.Plan{plan, &installrender.Plan{}}
			if _, err := store.decodeJournal(body, anchor); err == nil || store.decoded.body != nil {
				t.Fatal("untrusted changed registry reused a prior decode")
			}
			store.plans = plans
			if _, err := store.decodeJournal(body, anchor); err != nil {
				t.Fatal(err)
			}
			wrong := anchor
			wrong.InstallationID = strings.Repeat("f", 32)
			if _, err := store.decodeJournal(body, wrong); err == nil || store.decoded.body != nil {
				t.Fatal("anchor refusal filled or retained memo")
			}
			if mode != "legacy" && mode != "baseline-context-only" {
				store.baseline = baselinePlan(t, plan, 2)
				if _, err := store.decodeJournal(body, anchor); err == nil || store.decoded.body != nil {
					t.Fatal("changed sealed baseline reused an old decode")
				}
				store.baseline = nil
				if _, err := store.decodeJournal(body, anchor); err == nil {
					t.Fatal("baseline omission reused pinned authority")
				}
			}
		})
	}
}

func TestJournalDecodeMemoPopulatedPointersAndInputOwnership(t *testing.T) {
	plan, baseline, source, historical := enrollmentSourceFixture(t)
	enrollment := enrollmentIntent(t, source, historical, baseline)
	reinstallPlan, reinstallBaseline, retired := reinstallSourceFixture(t)
	reinstall := reinstallIntent(t, retired, reinstallBaseline, reinstallPlan)
	runtimePending := initialDocument(plan)
	runtimePending.Stage = Applying
	for _, resource := range lifecycleResources(t, plan, false) {
		if resource.Key.Kind == "Deployment" {
			runtimePending.Pending = &Pending{Action: Create, Key: resource.Key, CreateNonce: strings.Repeat("e", 32), AfterSHA256: strings.Repeat("f", 64)}
			break
		}
	}
	baselinePending := initialDocument(plan)
	baselinePending.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	baselinePending.SecurityBaseline.Stage = BaselineApplying
	resource := baselineResource(t, baseline, 0)
	baselinePending.SecurityBaseline.Pending = &Pending{Action: Create, Key: resource.Key, CreateNonce: strings.Repeat("e", 32), AfterSHA256: resource.TemplateSHA256}
	for _, scenario := range []struct {
		name     string
		plan     *installrender.Plan
		baseline *installbaseline.Plan
		document Document
		mutate   func(*Document)
	}{
		{"runtime-pending", plan, nil, runtimePending, func(d *Document) { d.Pending.CreateNonce = "caller-mutation" }},
		{"baseline-pending", plan, baseline, baselinePending, func(d *Document) { d.SecurityBaseline.Pending.CreateNonce = "caller-mutation" }},
		{"enrollment", plan, baseline, enrollment, func(d *Document) { d.SecurityBaseline.Enrollment.SourceEvidenceSHA256 = "caller-mutation" }},
		{"reinstall", reinstallPlan, reinstallBaseline, reinstall, func(d *Document) { d.AdmissionReinstall.SourceRevision++ }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			body, err := EncodeWithBaseline(scenario.document, scenario.baseline, scenario.plan)
			if err != nil {
				t.Fatal("valid populated journal unavailable", err)
			}
			original := bytes.Clone(body)
			anchor := Anchor{scenario.document.Namespace, scenario.document.NamespaceUID, scenario.document.InstallationID}
			store := &Store{plans: []*installrender.Plan{scenario.plan}, baseline: scenario.baseline}
			for pass := 0; pass < 3; pass++ {
				want, wantErr := DecodeWithBaseline(original, scenario.baseline, scenario.plan)
				got, gotErr := store.decodeJournal(original, anchor)
				if wantErr != nil || gotErr != nil || !reflect.DeepEqual(want, got) {
					t.Fatal("populated miss/hit differs from strict decoder")
				}
				scenario.mutate(&got)
				if !reflect.DeepEqual(store.decoded.document, want) {
					t.Fatal("returned pointer aliases the retained pure document")
				}
			}
			// Use a distinct caller-owned input for the miss, then corrupt it.
			store = &Store{plans: []*installrender.Plan{scenario.plan}, baseline: scenario.baseline}
			if _, err := store.decodeJournal(body, anchor); err != nil {
				t.Fatal(err)
			}
			body[0] = 'x'
			if !bytes.Equal(store.decoded.body, original) {
				t.Fatal("caller-owned input changed retained bytes before reread")
			}
			got, err := store.decodeJournal(original, anchor)
			if err != nil || !bytes.Equal(store.decoded.body, original) || !reflect.DeepEqual(got, scenario.document) {
				t.Fatal("caller-owned input bytes alias the retained memo")
			}
		})
	}
}

func TestJournalDecodeMemoStillObservesFreshNamespace(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	body, err := Encode(d, plan)
	if err != nil {
		t.Fatal(err)
	}
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	server := &namespaceServer{live: testNamespace(plan, d)}
	server.live.Annotations[Annotation] = string(body)
	client := server.client()
	store, err := New(client.CoreV1().Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Load(t.Context(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	server.live.ResourceVersion = "fresh-rv"
	second, err := store.Load(t.Context(), anchor)
	if err != nil || second.ResourceVersion() != "fresh-rv" || first.ResourceVersion() == second.ResourceVersion() || len(client.Actions()) != 2 {
		t.Fatal("warm memo replaced a fresh GET/RV with old observation")
	}
	// The fake client's GET already copies its reply. Exercise the actual
	// observation boundary directly as well, so that copy cannot hide aliasing.
	reply := server.live.DeepCopy()
	direct, err := store.observe(reply, anchor)
	if err != nil {
		t.Fatal(err)
	}
	reply.Annotations[Annotation] = "reply-mutation"
	reply.Labels["reply-mutation"] = "changed"
	reply.ResourceVersion = "reply-rv-mutation"
	if !bytes.Equal(direct.Bytes(), body) || direct.namespace.Annotations[Annotation] != string(body) || direct.namespace.Labels["reply-mutation"] != "" || direct.ResourceVersion() != "fresh-rv" {
		t.Fatal("actual Namespace reply aliases sealed snapshot")
	}
	// Both the original reply and public accessor outputs remain independent
	// of prior sealed observations, including when subsequent reads hit.
	server.live.Annotations[Annotation] = "caller-mutation"
	server.live.Labels["caller-mutation"] = "changed"
	copy := second.Bytes()
	copy[0] = 'x'
	if !bytes.Equal(first.Bytes(), body) || !bytes.Equal(second.Bytes(), body) || second.namespace.Annotations[Annotation] != string(body) || second.namespace.Labels["caller-mutation"] != "" {
		t.Fatal("live Namespace or accessor output aliases sealed snapshot")
	}
	server.live = testNamespace(plan, d)
	server.live.Annotations[Annotation] = string(body)
	original := server.live.DeepCopy()
	for _, mutate := range []func(*corev1.Namespace){
		func(n *corev1.Namespace) { n.UID = "replacement" },
		func(n *corev1.Namespace) { n.ResourceVersion = "" },
		func(n *corev1.Namespace) { n.Labels["pod-security.kubernetes.io/enforce"] = "privileged" },
		func(n *corev1.Namespace) { n.OwnerReferences = []metav1.OwnerReference{{UID: "foreign"}} },
		func(n *corev1.Namespace) { n.Finalizers = []string{"foreign"} },
		func(n *corev1.Namespace) { n.Spec.Finalizers = []corev1.FinalizerName{"foreign"} },
		func(n *corev1.Namespace) { n.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time} },
		func(n *corev1.Namespace) { n.Annotations[Annotation] += " " },
	} {
		server.live = original.DeepCopy()
		if _, err := store.Load(t.Context(), anchor); err != nil {
			t.Fatal(err)
		}
		mutate(server.live)
		before := len(client.Actions())
		if _, err := store.Load(t.Context(), anchor); err != ErrOwnership || len(client.Actions()) != before+1 {
			t.Fatal("warm decode bypassed fresh unsafe Namespace rejection")
		}
	}
	server.live, server.failGet = original.DeepCopy(), true
	if _, err := store.Load(t.Context(), anchor); err != ErrOwnership {
		t.Fatal("warm memo bypassed GET failure")
	}
	if server.updates != 0 || server.creates != 0 {
		t.Fatal("memoized reads caused namespace writes")
	}
}

func TestJournalDecodeMemoSingleEntryConcurrentCopies(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	body, err := Encode(d, plan)
	if err != nil {
		t.Fatal(err)
	}
	store, other := &Store{plans: []*installrender.Plan{plan}}, &Store{plans: []*installrender.Plan{plan}}
	for _, current := range []*Store{store, other} {
		if _, err := current.decodeJournal(body, anchor); err != nil {
			t.Fatal(err)
		}
	}
	if &store.decoded.body[0] == &other.decoded.body[0] || &store.decoded.document.Resources[0] == &other.decoded.document.Resources[0] {
		t.Fatal("separate Stores share mutable decode state")
	}
	changed := d
	changed.Revision++
	secondBody, err := Encode(changed, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{body, secondBody, body} {
		if _, err := store.decodeJournal(input, anchor); err != nil || !bytes.Equal(store.decoded.body, input) || len(store.decoded.body) > MaxBytes {
			t.Fatal("memo did not retain only the current bounded exact body")
		}
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			for pass := 0; pass < 8; pass++ {
				got, err := store.decodeJournal(body, anchor)
				if err != nil || !reflect.DeepEqual(got, d) {
					t.Error("concurrent hit changed document")
					return
				}
				got.Resources[0].UID = "concurrent-caller"
			}
		})
	}
	group.Wait()
	if !reflect.DeepEqual(store.decoded.document, d) || !bytes.Equal(store.decoded.body, body) {
		t.Fatal("caller output aliases cached document or bytes")
	}
}

func TestJournalDecodeMemoAllocationControl(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	body, err := Encode(d, plan)
	if err != nil {
		t.Fatal(err)
	}
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	store := &Store{plans: []*installrender.Plan{plan}}
	if _, err := store.decodeJournal(body, anchor); err != nil {
		t.Fatal(err)
	}
	strict := testing.AllocsPerRun(3, func() {
		got, err := DecodeWithBaseline(body, nil, plan)
		if err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(got)
	})
	memo := testing.AllocsPerRun(3, func() {
		got, err := store.decodeJournal(body, anchor)
		if err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(got)
	})
	t.Logf("pure decode allocations strict=%.0f memo=%.0f", strict, memo)
	if strict == 0 || memo >= strict/4 {
		t.Fatal("memo did not remove repeated parsing allocation cost")
	}
}
