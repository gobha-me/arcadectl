// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func testPhaseFloorPodPair(t *testing.T, emptyTypeMeta bool, edit func(*corev1.Pod)) (fixturePhaseBaseline, fixturePhaseBaseline, map[types.UID]runtime.Object) {
	t.Helper()
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{
		Name: "original-pod", Namespace: "phase-pod-test", UID: "c0000000-0000-4000-8000-000000000002", ResourceVersion: "91",
	}, Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "api", Image: "example.invalid/inert:fixture"}}}}
	if emptyTypeMeta {
		pod.TypeMeta = metav1.TypeMeta{} // native typed LIST members may omit GVK
	}
	key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}
	original, err := phaseRow(key, pod.UID, pod.ResourceVersion, pod)
	if err != nil {
		t.Fatal("independent original typed Pod row unavailable")
	}
	fresh := pod.DeepCopy()
	fresh.ResourceVersion = "92"
	if edit != nil {
		edit(fresh)
	}
	current, err := phaseRow(key, fresh.UID, fresh.ResourceVersion, fresh)
	if err != nil {
		t.Fatal("independent current typed Pod row unavailable")
	}
	before := fixturePhaseBaseline{Version: "admission-phase-v1", Rows: []fixtureWorldRow{original}, Leaders: []fixturePhaseLeader{}}
	after := fixturePhaseBaseline{Version: before.Version, Rows: []fixtureWorldRow{current}, Leaders: []fixturePhaseLeader{}}
	return before, after, map[types.UID]runtime.Object{fresh.UID: fresh}
}

func testPhaseFloorObservedCopy(objects map[types.UID]runtime.Object) map[types.UID]runtime.Object {
	if objects == nil {
		return nil
	}
	copy := make(map[types.UID]runtime.Object, len(objects))
	for uid, object := range objects {
		if pod, ok := object.(*corev1.Pod); ok && pod == nil || object == nil {
			copy[uid] = object
		} else {
			copy[uid] = object.DeepCopyObject()
		}
	}
	return copy
}

func TestPhaseFloorPodDiagnosticWholeTypedRVClassification(t *testing.T) {
	for _, test := range []struct {
		name, want string
		emptyGVK   bool
		edit       func(*corev1.Pod)
	}{
		{"rv-only", "change=rv-only", false, nil},
		{"native-empty-gvk", "change=rv-only", true, nil},
		{"rv-and-status", "change=body-beyond-rv", false, func(p *corev1.Pod) { p.Status.Reason = "PRIVATE-POD-CANARY" }},
		{"rv-and-spec", "change=body-beyond-rv", false, func(p *corev1.Pod) { p.Spec.Containers[0].Image = "example.invalid/private-pod-canary:changed" }},
		{"rv-and-labels", "change=body-beyond-rv", false, func(p *corev1.Pod) { p.Labels = map[string]string{"source": "PRIVATE-POD-CANARY"} }},
		{"rv-and-annotations", "change=body-beyond-rv", false, func(p *corev1.Pod) { p.Annotations = map[string]string{"source": "PRIVATE-POD-CANARY"} }},
		{"rv-and-managed-fields", "change=body-beyond-rv", false, func(p *corev1.Pod) {
			p.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "PRIVATE-POD-CANARY", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: "v1", FieldsType: "FieldsV1", FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:status":{}}`)}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, after, observed := testPhaseFloorPodPair(t, test.emptyGVK, test.edit)
			floorBytes := phaseCopyJSON(t, []any{before, after})
			objects := testPhaseFloorObservedCopy(observed)
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			recorder := beginPhaseFloorDiagnostic(ctx)
			recorder.difference(before, after)
			oldSnapshot := diagnostic.PhaseFloorSnapshot()
			if samePhaseBaseline(before, after) || oldSnapshot != "category=rows kind=Pod membership=false identity=false resource-version=true hash=true other=false" {
				t.Fatal("typed Pod setup did not reach the original unchanged whole-row refusal")
			}
			recorder.recordPodDifference(before, after, observed)
			if diagnostic.PhaseFloorPodSnapshot() != test.want || diagnostic.PhaseFloorSnapshot() != oldSnapshot || strings.Contains(diagnostic.PhaseFloorPodSnapshot(), "CANARY") {
				t.Fatal("Pod diagnostic misclassified RV-only versus body change, or altered old output")
			}
			if !bytes.Equal(floorBytes, phaseCopyJSON(t, []any{before, after})) || !reflect.DeepEqual(objects, observed) || samePhaseBaseline(before, after) {
				t.Fatal("diagnostic changed the Pod/floor or rescued the original refusal")
			}
			for _, object := range observed {
				object.(*corev1.Pod).Status.Message = "PRIVATE-LATE-CANARY"
			}
			if diagnostic.PhaseFloorPodSnapshot() != test.want {
				t.Fatal("diagnostic retained caller-owned Pod state")
			}
		})
	}
}

func TestPhaseFloorPodDiagnosticRejectsUnboundCandidate(t *testing.T) {
	for _, fault := range []string{"nil-map", "missing-uid", "wrong-type", "nil-pod", "name", "namespace", "uid", "rv", "gv", "kind", "stale-body", "unhashable", "same-rv", "replaced-uid", "missing-row"} {
		t.Run(fault, func(t *testing.T) {
			before, after, observed := testPhaseFloorPodPair(t, false, nil)
			uid := after.Rows[0].UID
			pod := observed[uid].(*corev1.Pod)
			switch fault {
			case "nil-map":
				observed = nil
			case "missing-uid":
				delete(observed, uid)
			case "wrong-type":
				observed[uid] = &corev1.ConfigMap{ObjectMeta: pod.ObjectMeta}
			case "nil-pod":
				observed[uid] = (*corev1.Pod)(nil)
			case "name":
				pod.Name = "different"
			case "namespace":
				pod.Namespace = "different"
			case "uid":
				pod.UID = "c0000000-0000-4000-8000-000000000099"
			case "rv":
				pod.ResourceVersion = "93"
			case "gv":
				pod.APIVersion = "private.example/v1"
			case "kind":
				pod.Kind = "PRIVATE-POD-CANARY"
			case "stale-body":
				pod.Status.Reason = "PRIVATE-POD-CANARY"
			case "unhashable":
				pod.ManagedFields = []metav1.ManagedFieldsEntry{{FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"PRIVATE-POD-CANARY":`)}}}
			case "same-rv":
				after.Rows[0].ResourceVersion = before.Rows[0].ResourceVersion
			case "replaced-uid":
				before.Rows[0].UID = "c0000000-0000-4000-8000-000000000099"
			case "missing-row":
				after.Rows = nil
			}
			floors := phaseCopyJSON(t, []any{before, after})
			objects := testPhaseFloorObservedCopy(observed)
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			recorder := beginPhaseFloorDiagnostic(ctx)
			recorder.difference(before, after)
			old := diagnostic.PhaseFloorSnapshot()
			recorder.recordPodDifference(before, after, observed)
			if diagnostic.PhaseFloorPodSnapshot() != "change=unavailable" || diagnostic.PhaseFloorSnapshot() != old || !bytes.Equal(floors, phaseCopyJSON(t, []any{before, after})) || !reflect.DeepEqual(objects, observed) {
				t.Fatal("unbound/unhashable Pod acquired classification or mutated evidence")
			}
		})
	}
}

func TestPhaseFloorPodDiagnosticInvocationAndLateWriterIsolation(t *testing.T) {
	before, after, observed := testPhaseFloorPodPair(t, false, nil)
	for _, reset := range []string{"record", "invocation", "phase", "outer", "checkpoint", "fresh-step"} {
		t.Run(reset, func(t *testing.T) {
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			old := beginPhaseFloorDiagnostic(ctx)
			old.difference(before, after)
			old.recordPodDifference(before, after, observed)
			if diagnostic.PhaseFloorPodSnapshot() != "change=rv-only" {
				t.Fatal("initial optional Pod diagnostic unavailable")
			}
			switch reset {
			case "record":
				old.record(phaseFloorCandidate, 0, 0)
			case "invocation":
				beginPhaseFloorDiagnostic(ctx)
			case "phase":
				traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
			case "outer":
				traceAdmission(ctx, admissionCaseObservation, 5)
			case "checkpoint":
				traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
			case "fresh-step":
				ctx, diagnostic = WithLifecycleDiagnostic(ctx)
			}
			if diagnostic.PhaseFloorPodSnapshot() != "" {
				t.Fatal("Pod diagnostic survived reset or successful/new invocation")
			}
			current := beginPhaseFloorDiagnostic(ctx)
			b, a, objects := testPhaseFloorPodPair(t, false, func(p *corev1.Pod) { p.Status.Reason = "PRIVATE-POD-CANARY" })
			current.difference(b, a)
			current.recordPodDifference(b, a, objects)
			var joined sync.WaitGroup
			for range 3 {
				joined.Go(func() {
					for range 20 {
						old.recordPodDifference(before, after, observed)
						if diagnostic.PhaseFloorPodSnapshot() != "change=body-beyond-rv" {
							t.Error("late old writer replaced the current optional Pod diagnostic")
						}
					}
				})
			}
			joined.Wait()
		})
	}
	if (*LifecycleDiagnostic)(nil).PhaseFloorPodSnapshot() != "" {
		t.Fatal("nil lifecycle invented a Pod diagnostic")
	}
	var nilRecorder *phaseFloorDiagnostic
	nilRecorder.recordPodDifference(before, after, observed)
	ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
	recorder := beginPhaseFloorDiagnostic(ctx)
	for _, corrupt := range []uint32{0, 4, 255, 0xffffffff} {
		recorder.pod.Store(corrupt)
		if diagnostic.PhaseFloorPodSnapshot() != "" {
			t.Fatal("unreviewed numeric Pod state escaped its fixed output domain")
		}
	}
	// A preceding non-Pod difference must not be attributed to a later Pod.
	a, b := before, after
	first := before.Rows[0]
	first.Key.Kind, first.Key.Name = "Job", "first-job"
	a.Rows = append([]fixtureWorldRow{first}, a.Rows...)
	first.ResourceVersion = "99"
	b.Rows = append([]fixtureWorldRow{first}, b.Rows...)
	recorder.difference(a, b)
	recorder.recordPodDifference(a, b, observed)
	if diagnostic.PhaseFloorPodSnapshot() != "" {
		t.Fatal("later Pod stole a preceding non-Pod refusal")
	}
}

// Real sealed observers with an inert synthetic original Pod, matching the
// existing V3 floor-refusal fixture. No native owner-chain certificate is claimed.
func TestPhaseFloorPodDiagnosticHTTPSRefusalCustodyAndReadCensus(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV3(t, h.f.wire.ledger)
		ns := h.f.actor.request.Snapshot.Anchor().Namespace
		h.extra = append(h.extra,
			&unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "default", "namespace": ns, "uid": "c0000000-0000-4000-8000-000000000001", "resourceVersion": "91"}, "automountServiceAccountToken": false}},
			&unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "original-api-row", "namespace": ns, "uid": "c0000000-0000-4000-8000-000000000002", "resourceVersion": "91"}, "spec": map[string]any{"serviceAccountName": "arcadectl-api", "containers": []any{map[string]any{"name": "api", "image": "example.invalid/inert:fixture"}}}}},
		)
	})
	for _, fault := range []string{"healthy", "rv-only", "rv-status", "rv-spec", "rv-labels", "rv-managed-fields"} {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			unchanged := fixturePreviewUnchanged(t, h.f)
			worldName, err := f.originalWorldsName()
			if err != nil {
				t.Fatal("original worlds name unavailable")
			}
			worldBody, worldID, err := f.engine.files.ReadEvidence(worldName, privatefs.MaxEvidenceFileBytes)
			if err != nil {
				t.Fatal("original immutable worlds unavailable")
			}
			client := h.f.actor.v.f.access.client
			nsName := h.f.actor.request.Snapshot.Anchor().Namespace
			originalNamespace, err := client.CoreV1().Namespaces().Get(t.Context(), nsName, metav1.GetOptions{})
			if err != nil {
				t.Fatal("original Namespace unavailable")
			}
			actionsBefore := len(client.Actions())
			want := ""
			h.f.actor.withState(func() {
				pod := h.extra[1]
				if fault != "healthy" {
					pod.SetResourceVersion("92")
					want = "change=body-beyond-rv"
				}
				switch fault {
				case "rv-only":
					want = "change=rv-only"
				case "rv-status":
					pod.Object["status"] = map[string]any{"reason": "PRIVATE-POD-CANARY"}
				case "rv-spec":
					_ = unstructured.SetNestedField(pod.Object, "different-node", "spec", "nodeName")
				case "rv-labels":
					pod.SetLabels(map[string]string{"source": "PRIVATE-POD-CANARY"})
				case "rv-managed-fields":
					pod.Object["metadata"].(map[string]any)["managedFields"] = []any{map[string]any{"manager": "PRIVATE-POD-CANARY", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:status": map[string]any{}}}}
				}
			})
			requests := map[string]int{}
			persistent := 0
			var prior func(http.ResponseWriter, *http.Request) bool
			h.f.actor.withState(func() {
				prior = h.f.actor.fixtureHandler
				h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
					requests[r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Accept")]++
					review := r.Method == http.MethodPost && (r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews")
					if r.Method != http.MethodGet && !review {
						persistent++
					}
					return prior(w, r)
				}
			})
			defer h.f.actor.withState(func() { h.f.actor.fixtureHandler = prior })
			take := func() map[string]int {
				var counts map[string]int
				h.f.actor.withState(func() { counts = requests; requests = map[string]int{} })
				return counts
			}
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			before, after, objects := testPhaseFloorPodPair(t, false, nil)
			stale := beginPhaseFloorDiagnostic(ctx)
			stale.difference(before, after)
			stale.recordPodDifference(before, after, objects)
			observation, gotErr := h.f.wire.observePhase(ctx)
			firstReads := take()
			if fault == "healthy" {
				if gotErr != nil || observation == nil || f.phaseFloor == nil || diagnostic.PhaseFloorPodSnapshot() != "" || diagnostic.PhaseFloorSnapshot() != "" {
					t.Fatal("successful complete observation retained stale refusal diagnostics")
				}
			} else {
				if gotErr != ErrFixtures || observation != nil || f.phaseFloor != nil || diagnostic.PhaseFloorPodSnapshot() != want || diagnostic.PhaseFloorSnapshot() != "category=rows kind=Pod membership=false identity=false resource-version=true hash=true other=false" {
					t.Fatal("actual Pod diagnostic changed whole-row refusal, old output or floor")
				}
				if phase, slot := diagnostic.admission.phaseSnapshot(); phase != "original-row-floor" || slot != -1 {
					t.Fatal("Pod classification came from the wrong refusal boundary")
				}
			}
			// Same remote state and complete reader, with NO recorder at all.
			second, secondErr := h.f.wire.observePhase(t.Context())
			secondReads := take()
			if (secondErr == nil) != (fault == "healthy") || (second != nil) != (fault == "healthy") || fault != "healthy" && secondErr != ErrFixtures || len(firstReads) == 0 || !reflect.DeepEqual(firstReads, secondReads) {
				t.Fatal("optional diagnostic altered refusal/success or the exact HTTP read census")
			}
			unchanged()
			currentWorldBody, currentWorldID, err := f.engine.files.ReadEvidence(worldName, privatefs.MaxEvidenceFileBytes)
			currentNamespace, nsErr := client.CoreV1().Namespaces().Get(t.Context(), nsName, metav1.GetOptions{})
			if err != nil || !bytes.Equal(worldBody, currentWorldBody) || worldID != currentWorldID || nsErr != nil || !reflect.DeepEqual(originalNamespace, currentNamespace) || h.f.creates != 0 || h.f.deletes != 0 || h.f.previews != 0 || h.f.seeds != 0 || f.behaviorCompletion != nil || persistent != 0 {
				t.Fatal("diagnostic changed immutable worlds/journal or published an effect")
			}
			for _, action := range client.Actions()[actionsBefore:] {
				if action.GetResource().Resource == "namespaces" && action.GetVerb() != "get" && action.GetVerb() != "list" && action.GetVerb() != "watch" {
					t.Fatal("diagnostic issued a Namespace intent mutation")
				}
			}
		})
	}
}
