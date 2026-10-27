// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Independent literals: no production scope-selection helper participates in
// the expected schedule. Existing All55ClosedRequests remains authoritative
// for the full request/body schedule; native matrices still run all 55 cases.
func testAdmissionCaseRemovedPairs(number int) int {
	if number == 39 || number == 45 {
		return 0
	}
	actor := map[int]bool{16: true, 17: true, 24: true, 25: true, 32: true, 33: true, 38: true, 42: true, 44: true, 46: true, 49: true, 50: true, 51: true, 52: true, 53: true, 54: true}
	counterpart := number >= 0 && number <= 11 || number == 38 || number == 49 || number == 50
	want := 1
	if actor[number] {
		want += 3
	}
	if counterpart {
		want += 6
	}
	return want
}

func TestAdmissionCaseScopeLiteral191PairCoverage(t *testing.T) {
	wantCounts := map[int]int{0: 2, 1: 25, 4: 13, 7: 12, 10: 3}
	wantActors := map[int]admissionActor{16: ordinaryControllerActor, 17: destroyControllerActor, 24: ordinaryControllerActor, 25: destroyControllerActor, 32: destroyControllerActor, 33: ordinaryControllerActor, 38: ordinaryControllerActor, 42: ordinaryControllerActor, 44: destroyControllerActor, 46: ordinaryControllerActor, 49: destroyAdministratorActor, 50: destroyAdministratorActor, 51: destroyControllerActor, 52: destroyControllerActor, 53: destroyAdministratorActor, 54: destroyAdministratorActor}
	// Three explicitly synthetic prefixes represent no setup, acknowledged
	// seed, and acknowledged seed+marker. Each owns real sealed HTTPS phase,
	// WAL and world evidence. The loop constructs requests/scopes only; it
	// neither executes55HTTPcases nor fabricates a behavior completion receipt.
	prefixes := [3]*testAdmissionCaseProtocol{testAdmissionCaseProtocolFixture(t, 1), testAdmissionCaseProtocolFixture(t, 39), testAdmissionCaseProtocolFixture(t, 45)}
	// 38,49,50 combine actor and counterpart reductions; all other CREATE
	// counterparts have parent actor. 39 and45 retain their entire full path.
	gotCounts, total := map[int]int{}, 0
	for number := 0; number < 55; number++ {
		prefix := prefixes[0]
		if number >= 45 {
			prefix = prefixes[2]
		} else if number >= 39 {
			prefix = prefixes[1]
		}
		prefix.d.next, prefix.d.completed = fixtureAdmissionCase(number), (uint64(1)<<number)-1
		r, err := prefix.h.f.wire.admissionRequest(fixtureAdmissionCase(number), prefix.before)
		wantSlot := -1
		switch {
		case number >= 12 && number <= 19:
			wantSlot = 1
		case number >= 20 && number <= 27:
			wantSlot = 3
		case number >= 28 && number <= 35:
			wantSlot = 5
		case number == 36 || number == 37:
			wantSlot = 6
		case number >= 39 && number <= 46:
			wantSlot = 7
		case number == 47:
			wantSlot = 8
		case number == 48:
			wantSlot = 10
		case number >= 51:
			wantSlot = 9
		}
		if err != nil || r.object == nil || r.actor != wantActors[number] || r.slot != wantSlot {
			t.Fatal("actual closed case changed independent literal actor/slot schedule", number)
		}
		caseCtx, scope, scopeErr := newAdmissionCaseScope(t.Context(), prefix.d, fixtureAdmissionCase(number), prefix.seal, prefix.before)
		eligible := number != 39 && number != 45
		removed := 0
		if !eligible {
			if caseCtx != nil || scope != nil || scopeErr != ErrFixtures {
				t.Fatal("excluded entire seed/marker case acquired scope", number)
			}
		} else {
			if caseCtx == nil || scope == nil || scopeErr != nil {
				t.Fatal("eligible actual case failed exact scope construction", number)
			}
			removed = 1
			if r.actor != 0 {
				removed += 3
			}
			if r.slot == -1 {
				removed += 6
			}
			if scope.close() != nil {
				t.Fatal("fresh unused case scope failed to revoke", number)
			}
		}
		if removed != testAdmissionCaseRemovedPairs(number) {
			t.Fatal("actual request/scope eligibility changed literal per-case reduction", number)
		}
		gotCounts[removed]++
		total += removed
	}
	if total != 191 || !reflect.DeepEqual(gotCounts, wantCounts) || testAdmissionCaseRemovedPairs(47) != 1 || fixtureAdmissionCaseCount != 55 || fixtureAdmissionAllCases != (uint64(1)<<55)-1 {
		t.Fatal("literal reduction changed exclusions, parent case47, or complete55case coverage")
	}
	for _, prefix := range prefixes {
		prefix.assertCustody(t)
	}
}

type testAdmissionCaseProtocol struct {
	accessPath                                                                                string
	accessGets                                                                                int
	h                                                                                         *fixturePhaseTest
	d                                                                                         *fixtureAdmissionDriver
	seal                                                                                      fixtureDriverSeal
	before                                                                                    *fixturePhaseObservation
	number                                                                                    fixtureAdmissionCase
	policies, bindings, exactReviews, counterpartReviews, counterpartGets, probes, persistent int
	probePhaseLists, postPhaseLists                                                           int
	fault                                                                                     string
	injected                                                                                  bool
	onExact, onProbe                                                                          func()
	originalWAL                                                                               []byte
	originalJournal                                                                           *installstate.Snapshot
}

// Synthesized predecessor bits are TEST instrumentation only. They authorize
// one actual runCaseLocked seam after a full sealed phase; no prefix execution,
// all55 completion, native serving or persistent setup is claimed.
func testAdmissionCaseProtocolFixture(t *testing.T, number fixtureAdmissionCase) *testAdmissionCaseProtocol {
	t.Helper()
	return testAdmissionCaseProtocolFixtureOn(t, number, unmarkedRecoveryPhaseFactory(t)(t))
}

// testAdmissionCaseProtocolFixtureOn is the unchanged protocol fixture body over
// a caller-supplied unmarked phase (adversarial #100: Upgrade/Rollback/Uninstall
// transition phases reuse the identical real runCaseLocked boundary).
func testAdmissionCaseProtocolFixtureOn(t *testing.T, number fixtureAdmissionCase, h *fixturePhaseTest) *testAdmissionCaseProtocol {
	t.Helper()
	f := h.f.wire.ledger
	if number >= 39 {
		if f.advance(fixtureSeedIntent(t, f)) != nil {
			t.Fatal("synthetic case-prefix seed intent unavailable")
		}
		f.seedEffect = false
		if f.advance(fixtureSeedAcknowledgement(t, f)) != nil {
			t.Fatal("synthetic case-prefix seed ACK unavailable")
		}
		created := time.Now().UTC().Truncate(time.Second).Add(-40 * time.Second)
		h.f.objects[fixtureCancelledDestroy] = fixtureDestroySeedExample(t, f, created)
		h.f.objects[fixtureCancelledDestroy].SetResourceVersion(f.document.DestroySeed.AcknowledgedResourceVersion)
		if number >= 45 {
			if f.advance(fixtureMarkerIntent(t, f)) != nil {
				t.Fatal("synthetic case-prefix marker intent unavailable")
			}
			f.markerEffect = false
			if f.advance(fixtureMarkerAcknowledgement(t, f)) != nil {
				t.Fatal("synthetic case-prefix marker ACK unavailable")
			}
			h.f.objects[fixtureRetainedPVC] = fixtureMarkedRetainedExample(t, f, created)
		}
	}
	before, err := h.f.wire.observePhase(t.Context())
	if err != nil || before == nil {
		t.Fatal("single-case complete original phase unavailable")
	}
	d := &fixtureAdmissionDriver{wire: h.f.wire, previous: before, next: number, completed: (uint64(1) << number) - 1}
	seal, err := d.sealLocked()
	if err != nil {
		t.Fatal("single-case original seal unavailable")
	}
	p := &testAdmissionCaseProtocol{h: h, d: d, before: before, seal: seal, number: number, originalWAL: bytes.Clone(f.body), originalJournal: h.f.actor.request.Snapshot}
	for _, resource := range h.f.actor.request.Target.ResourceMetadata() {
		if resource.Kind == "ClusterRole" && resource.APIVersion == "rbac.authorization.k8s.io/v1" {
			path := "/apis/rbac.authorization.k8s.io/v1/clusterroles/" + resource.Name
			if p.accessPath == "" || path < p.accessPath {
				p.accessPath = path
			}
		}
	}
	if p.accessPath == "" {
		t.Fatal("literal signed ClusterRole request census target unavailable")
	}
	p.install(t)
	return p
}

func (p *testAdmissionCaseProtocol) install(t *testing.T) {
	t.Helper()
	h, number := p.h, int(p.number)
	namespace := h.f.actor.request.Snapshot.Anchor().Namespace
	var verb, resource, name, method, path, user string
	group, version, prefix := "", "v1", "/api/v1"
	counterpart := number == 1 || number == 50
	slot, policyIndex, policyStem := -1, -1, "arcadectl-backup-worker-gate"
	switch number {
	case 1:
		verb, resource, method, policyIndex = "create", "pods", http.MethodPost, 1
		name = "arcadectl-probe-" + h.f.wire.ledger.document.RunID + "-case-01"
	case 13, 17:
		verb, resource, method, slot = "update", "pods", http.MethodPut, fixtureBackupPod
		policyIndex = 2
		if number == 17 {
			policyIndex = 3
			user = "system:serviceaccount:" + namespace + ":arcadectl-destroy-controller"
		}
		name = h.f.wire.ledger.document.Entries[slot].Key.Name
	case 39, 45:
		verb, resource, method, slot, policyStem = "update", "persistentvolumeclaims", http.MethodPut, fixtureRetainedPVC, "arcadectl-retained-world-pvc-delete"
		name = h.f.wire.ledger.document.Entries[slot].Key.Name
		if number == 45 {
			policyIndex = 1
		}
	case 47:
		verb, resource, method, slot = "delete", "persistentvolumeclaims", http.MethodDelete, fixturePlainPVC
		name = h.f.wire.ledger.document.Entries[slot].Key.Name
	case 50:
		verb, resource, method, policyIndex, policyStem = "create", "gamedestroys", http.MethodPost, 1, "arcadectl-destroy-unsafe-admin"
		group, version, prefix = "arcade.gobha.me", "v1alpha1", "/apis/arcade.gobha.me/v1alpha1"
		user = "system:serviceaccount:" + namespace + ":arcadectl-destroy-admin"
		name = "arcadectl-probe-" + h.f.wire.ledger.document.RunID + "-case-50"
	default:
		t.Fatal("single-case protocol fixture has no independent literal oracle")
	}
	path = prefix + "/namespaces/" + namespace + "/" + resource
	if method != http.MethodPost {
		path += "/" + name
	}
	exactName := name
	if method == http.MethodPost {
		exactName = ""
	}
	exact := authv1.ResourceAttributes{Group: group, Version: version, Resource: resource, Namespace: namespace, Name: exactName, Verb: verb}
	qualified := resource
	if group != "" {
		qualified += "." + group
	}
	policy := probePolicyName(t, h.f.actor.request.Target, policyStem)
	validation := ""
	if policyIndex >= 0 {
		validation = h.f.wire.actors.policies.policies[policy].Spec.Validations[policyIndex].Message
	}
	base := h.f.actor.fixtureHandler
	h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		review := r.Method == http.MethodPost && (r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews")
		if r.Method != http.MethodGet && !review && r.URL.Query().Get("dryRun") != "All" {
			p.persistent++
			t.Error("single read-only case attempted persistent target or Namespace intent write")
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		if r.Method == http.MethodGet && r.URL.Path == p.accessPath {
			p.accessGets++
		}
		if testRuntimeConfigurationRequest(r) {
			if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") {
				p.policies++
			} else if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings") {
				p.bindings++
			}
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("limit") == "128" && !testRuntimeConfigurationRequest(r) && p.probes > 0 {
			p.postPhaseLists++
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			r.Body = io.NopCloser(bytes.NewReader(body))
			var review authv1.SelfSubjectAccessReview
			if err != nil || json.Unmarshal(body, &review) != nil {
				t.Error("case review unavailable")
				return base(w, r)
			}
			if a := review.Spec.ResourceAttributes; a != nil && review.Spec.NonResourceAttributes == nil {
				isExact := reflect.DeepEqual(*a, exact) && r.Header.Get("Impersonate-User") == user
				isCounterpart := counterpart && reflect.DeepEqual(*a, authv1.ResourceAttributes{Group: group, Version: version, Resource: resource, Namespace: namespace, Name: name, Verb: "get"}) && r.Header.Get("Impersonate-User") == ""
				if isExact || isCounterpart {
					if isExact {
						p.exactReviews++
						if p.onExact != nil {
							p.onExact()
						}
					} else {
						p.counterpartReviews++
					}
					review.Status.Allowed = true
					_ = json.NewEncoder(w).Encode(review)
					return true
				}
			}
		}
		if counterpart && r.Method == http.MethodGet && r.URL.Path == path+"/"+name {
			p.counterpartGets++
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: 404, Message: fmt.Sprintf("%s %q not found", qualified, name), Details: &metav1.StatusDetails{Group: group, Name: name, Kind: resource}})
			return true
		}
		if r.URL.Path != path || r.Method == http.MethodGet {
			return base(w, r)
		}
		if r.Method != method || r.Header.Get("Impersonate-User") != user || r.URL.Query().Get("dryRun") != "All" {
			p.persistent++
			t.Error("case probe escaped independent method/identity/dryrun oracle")
			w.WriteHeader(500)
			return true
		}
		p.probes++
		p.probePhaseLists = h.lists
		if p.onProbe != nil {
			p.onProbe()
		}
		if p.fault == "probe-error" {
			w.WriteHeader(http.StatusForbidden)
			return true
		}
		if policyIndex >= 0 {
			cause := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", policy, policy, validation)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: metav1.StatusReasonInvalid, Code: 422, Message: fmt.Sprintf("%s %q is forbidden: %s", qualified, name, cause), Details: &metav1.StatusDetails{Group: group, Name: name, Kind: resource, Causes: []metav1.StatusCause{{Message: cause}}}})
		} else {
			reply := h.f.objects[slot].DeepCopy()
			if number == 47 {
				meta := reply.Object["metadata"].(map[string]any)
				meta["deletionTimestamp"] = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
				meta["deletionGracePeriodSeconds"] = int64(0)
			}
			_ = json.NewEncoder(w).Encode(reply.Object)
		}
		return true
	}
}

func (p *testAdmissionCaseProtocol) run(ctx context.Context) error {
	f := p.h.f.wire.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	return p.d.runCaseLocked(ctx, p.number)
}

func (p *testAdmissionCaseProtocol) assertCustody(t *testing.T) {
	t.Helper()
	f := p.h.f.wire.ledger
	if !bytes.Equal(p.originalWAL, f.body) || f.identity != p.seal.identity || f.document.Revision != p.seal.revision || f.behaviorCompletion != nil || f.ackSlot != -1 || f.effectSlot != -1 || f.markerAck || f.markerEffect || f.seedAck || f.seedEffect || p.h.f.creates != 0 || p.h.f.deletes != 0 || p.h.f.seeds != 0 || p.persistent != 0 {
		t.Fatal("read-only case changed WAL/effect/publication capability")
	}
	// Namespace UID/RV fault tests deliberately change only custody metadata;
	// every case still leaves the live journal annotation's bytes untouched.
	ns, err := p.h.f.actor.v.f.access.client.CoreV1().Namespaces().Get(t.Context(), p.originalJournal.Anchor().Namespace, metav1.GetOptions{})
	if err != nil || ns.Annotations[installstate.Annotation] != string(p.originalJournal.Bytes()) {
		t.Fatal("read-only case changed live journal bytes")
	}
}

func testAdmissionCaseCensus(t *testing.T, number fixtureAdmissionCase) {
	t.Helper()
	p := testAdmissionCaseProtocolFixture(t, number)
	if err := p.run(t.Context()); err != nil || p.d.failed || p.d.next != number+1 || p.d.completed != (uint64(1)<<(number+1))-1 {
		t.Fatal("single actual case refused or advanced wrong bit", err)
	}
	// Each full phase retains six configuration observations. The two outer
	// unchanged fences add one each. Only excluded39/45 keep the middle pair.
	want := 14
	if number == 39 || number == 45 {
		want = 15
	}
	wantReviews := 1
	wantAccessGets := 20
	if number == 39 || number == 45 {
		wantAccessGets = 21
	}
	if number == 17 || number == 50 {
		wantReviews = 2
	} // Driver review AND actor-probe review.
	if p.policies != want || p.bindings != want || p.accessGets != wantAccessGets || p.exactReviews != wantReviews || p.probes != 1 || p.h.lists <= p.probePhaseLists || p.postPhaseLists == 0 {
		t.Fatal("case changed independent configuration/review/probe/post-observation census", p.policies, p.bindings, p.exactReviews, p.probes)
	}
	if (number == 1 || number == 50) && (p.counterpartReviews != 2 || p.counterpartGets != 2) {
		t.Fatal("counterpart lost its two fresh exact reviews and named absence reads")
	}
	p.assertCustody(t)
}

// Separate roots let complete-union CI distribute each actual composed case.
func TestAdmissionCaseScopeCounterpartHTTPSCensus(t *testing.T)      { testAdmissionCaseCensus(t, 1) }
func TestAdmissionCaseScopeParentNamedHTTPSCensus(t *testing.T)      { testAdmissionCaseCensus(t, 13) }
func TestAdmissionCaseScopeActorHTTPSCensus(t *testing.T)            { testAdmissionCaseCensus(t, 17) }
func TestAdmissionCaseScopeEntireSeedCaseRemainsFull(t *testing.T)   { testAdmissionCaseCensus(t, 39) }
func TestAdmissionCaseScopeEntireMarkerCaseRemainsFull(t *testing.T) { testAdmissionCaseCensus(t, 45) }
func TestAdmissionCaseScopeParent47HasNoActorProbe(t *testing.T)     { testAdmissionCaseCensus(t, 47) }
func TestAdmissionCaseScopeActorCounterpartHTTPSCensus(t *testing.T) { testAdmissionCaseCensus(t, 50) }

func TestAdmissionCaseScopeProbeErrorStillReadsCompletePostPhaseAndCounterpart(t *testing.T) {
	p := testAdmissionCaseProtocolFixture(t, 1)
	p.fault = "probe-error"
	if p.run(t.Context()) != ErrFixtures || !p.d.failed || p.d.next != 1 || p.d.completed != 1 || p.probes != 1 || p.h.lists <= p.probePhaseLists || p.postPhaseLists == 0 || p.counterpartGets != 2 || p.counterpartReviews != 2 {
		t.Fatal("poisoned case skipped mandatory parent-context post-observations or published its bit")
	}
	p.assertCustody(t)
}

func testAdmissionCaseDeferredDrift(t *testing.T, fault string) {
	t.Helper()
	p := testAdmissionCaseProtocolFixture(t, 17)
	objects := p.h.f.actor.v.f.access.objects
	var selected installstate.Key
	for key := range objects {
		kind := "ClusterRole"
		if strings.HasPrefix(fault, "policy-") {
			kind = "ValidatingAdmissionPolicy"
		}
		if key.Kind == kind && (selected == (installstate.Key{}) || key.String() < selected.String()) {
			selected = key
		}
	}
	if selected == (installstate.Key{}) {
		t.Fatal("drift has no original signed target")
	}
	original := objects[selected].DeepCopy()
	p.onExact = func() {
		if p.injected {
			return
		}
		p.injected = true
		o := objects[selected]
		switch fault {
		case "access-uid", "policy-uid":
			o.SetUID("b0000000-0000-4000-8000-000000000001")
		case "access-rv", "policy-rv":
			o.SetResourceVersion("999")
		case "policy-shape":
			_ = unstructured.SetNestedField(o.Object, "Ignore", "spec", "failurePolicy")
		case "policy-status":
			_ = unstructured.SetNestedField(o.Object, int64(0), "status", "observedGeneration")
		case "policy-edit-restore":
			_ = unstructured.SetNestedField(o.Object, "Ignore", "spec", "failurePolicy")
			p.onProbe = func() {
				restored := original.DeepCopy()
				restored.SetResourceVersion("1000")
				objects[selected] = restored
			}
		case "namespace-uid", "journal-rv":
			s := p.h.f.actor.request.Snapshot
			ns, err := p.h.f.actor.v.f.access.client.CoreV1().Namespaces().Get(t.Context(), s.Anchor().Namespace, metav1.GetOptions{})
			if err != nil {
				t.Error("namespace drift unavailable")
				return
			}
			if fault == "namespace-uid" {
				ns.UID = "b0000000-0000-4000-8000-000000000001"
			} else {
				ns.ResourceVersion = "999"
			}
			if p.h.f.actor.v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, "") != nil {
				t.Error("external namespace drift refused")
			}
		case "wal", "worlds":
			f := p.h.f.wire.ledger
			name, body, id := f.name, bytes.Clone(f.body), f.identity
			if fault == "worlds" {
				name, _ = f.originalWorldsName()
				var err error
				body, id, err = f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
				if err != nil {
					t.Error("world evidence unavailable")
					return
				}
			}
			if _, err := f.engine.files.AtomicWrite(name, body, &id); err != nil {
				t.Error("identical original file replacement unavailable")
			}
		default:
			t.Error("unknown case drift")
		}
	}
	if p.run(t.Context()) != ErrFixtures || !p.injected || !p.d.failed || p.d.completed != (uint64(1)<<17)-1 || p.d.next != 17 {
		t.Fatal("deferred original drift escaped case closure or published bit")
	}
	if fault == "policy-edit-restore" && p.probes != 1 {
		t.Fatal("edit-restore did not cross actual dryrun before final refusal")
	}
	p.assertCustody(t)
}

func TestAdmissionCaseScopeAccessUIDDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "access-uid")
}
func TestAdmissionCaseScopeAccessRVDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "access-rv")
}
func TestAdmissionCaseScopePolicyUIDDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "policy-uid")
}
func TestAdmissionCaseScopePolicyRVDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "policy-rv")
}
func TestAdmissionCaseScopePolicyShapeDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "policy-shape")
}
func TestAdmissionCaseScopePolicyStatusDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "policy-status")
}
func TestAdmissionCaseScopePolicyRestoredWithNewRVHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "policy-edit-restore")
}
func TestAdmissionCaseScopeNamespaceUIDDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "namespace-uid")
}
func TestAdmissionCaseScopeJournalRVDriftHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "journal-rv")
}
func TestAdmissionCaseScopeWALReplacementHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "wal")
}
func TestAdmissionCaseScopeWorldReplacementHTTPS(t *testing.T) {
	testAdmissionCaseDeferredDrift(t, "worlds")
}
