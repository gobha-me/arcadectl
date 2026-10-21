// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func phaseFloorWant(category, kind string, flags uint32) string {
	return fmt.Sprintf("category=%s kind=%s membership=%t identity=%t resource-version=%t hash=%t other=%t", category, kind, flags&phaseFloorMembership != 0, flags&phaseFloorIdentity != 0, flags&phaseFloorRV != 0, flags&phaseFloorHash != 0, flags&phaseFloorOther != 0)
}

func TestPhaseFloorDiagnosticClosedProjection(t *testing.T) {
	row := fixtureWorldRow{Key: installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "PRIVATE-CANARY", Name: "PRIVATE-CANARY"}, UID: "PRIVATE-CANARY", ResourceVersion: "91", SHA256: "PRIVATE-CANARY"}
	base := fixturePhaseBaseline{Version: "admission-phase-v1", Rows: []fixtureWorldRow{row}, Leaders: []fixturePhaseLeader{}}
	for _, test := range []struct {
		name, category, kind string
		flags                uint32
		edit                 func(*fixturePhaseBaseline)
	}{
		{"version", "version", "unknown", phaseFloorOther, func(b *fixturePhaseBaseline) { b.Version = "PRIVATE-CANARY" }},
		{"membership", "rows", "Pod", phaseFloorMembership, func(b *fixturePhaseBaseline) { b.Rows = b.Rows[:0] }},
		{"key", "rows", "Pod", phaseFloorMembership, func(b *fixturePhaseBaseline) { b.Rows[0].Key.Name = "different" }},
		{"uid", "rows", "Pod", phaseFloorIdentity, func(b *fixturePhaseBaseline) { b.Rows[0].UID = "different" }},
		{"rv", "rows", "Pod", phaseFloorRV, func(b *fixturePhaseBaseline) { b.Rows[0].ResourceVersion = "92" }},
		{"hash", "rows", "Pod", phaseFloorHash, func(b *fixturePhaseBaseline) { b.Rows[0].SHA256 = "different" }},
		{"rv-and-hash", "rows", "Pod", phaseFloorRV | phaseFloorHash, func(b *fixturePhaseBaseline) { b.Rows[0].ResourceVersion, b.Rows[0].SHA256 = "92", "different" }},
		{"public", "public", "Service", phaseFloorMembership, func(b *fixturePhaseBaseline) { r := row; r.Key.Kind = "Service"; b.Public = []fixtureWorldRow{r} }},
		{"public-empty-representation", "public", "unknown", phaseFloorOther, func(b *fixturePhaseBaseline) { b.Public = []fixtureWorldRow{} }},
		{"account-presence", "accounts", "ServiceAccount", phaseFloorOther, func(b *fixturePhaseBaseline) {
			b.Accounts = &fixtureAccountBaseline{Version: "service-accounts-v1", Rows: []fixtureWorldRow{}}
		}},
		{"leader-membership", "leaders", "Lease", phaseFloorMembership, func(b *fixturePhaseBaseline) { b.Leaders = []fixturePhaseLeader{{}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := phaseCopyJSON(t, base)
			fresh := base
			fresh.Rows = append([]fixtureWorldRow(nil), base.Rows...)
			test.edit(&fresh)
			ctx, d := WithLifecycleDiagnostic(t.Context())
			beginPhaseFloorDiagnostic(ctx).difference(base, fresh)
			if samePhaseBaseline(base, fresh) || d.PhaseFloorSnapshot() != phaseFloorWant(test.category, test.kind, test.flags) || strings.Contains(d.PhaseFloorSnapshot(), "CANARY") || len(d.PhaseFloorSnapshot()) > 192 {
				t.Fatal("closed projection missing or values escaped", d.PhaseFloorSnapshot())
			}
			if !bytes.Equal(before, phaseCopyJSON(t, base)) {
				t.Fatal("diagnostic mutated its floor")
			}
		})
	}
	// Pure classifier coverage, not a claim that accounting rereads Public.
	for _, family := range []string{"public", "accounts"} {
		a, b := base, base
		r := row
		r.Key.Kind = "Service"
		if family == "accounts" {
			r.Key.Kind = "ServiceAccount"
		}
		a.Public, b.Public = []fixtureWorldRow{r}, []fixtureWorldRow{r}
		b.Public[0].SHA256 = "different"
		if family == "accounts" {
			a.Accounts = &fixtureAccountBaseline{Version: "service-accounts-v1", Rows: a.Public}
			b.Accounts = &fixtureAccountBaseline{Version: "service-accounts-v1", Rows: b.Public}
			a.Public, b.Public = nil, nil
		}
		ctx, d := WithLifecycleDiagnostic(t.Context())
		beginPhaseFloorDiagnostic(ctx).difference(a, b)
		if d.PhaseFloorSnapshot() != phaseFloorWant(family, r.Key.Kind, phaseFloorHash) {
			t.Fatal("whole-row hash difference missing")
		}
	}
	wantKinds := []string{"unknown", "GameServer", "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation", "Job", "Pod", "Lease", "PersistentVolumeClaim", "Secret", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "EndpointSlice", "ServiceAccount", "Namespace", "CustomResourceDefinition", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Service"}
	if !reflect.DeepEqual(phaseFloorKinds[:], wantKinds) {
		t.Fatal("reviewed closed kinds changed")
	}
	for _, kind := range append(wantKinds, "PRIVATE-CANARY", "Pod\nPRIVATE-CANARY") {
		id := phaseFloorKind(kind)
		if int(id) >= len(wantKinds) || phaseFloorKinds[id] != kind && id != 0 {
			t.Fatal("unreviewed kind escaped")
		}
	}
	for _, value := range []uint32{0, 255, 0xffffffff, 1 << 24, phaseFloorRows | uint32(len(phaseFloorKinds))<<8, uint32(len(phaseFloorCategories))} {
		trace, recorder := &admissionTrace{}, &phaseFloorDiagnostic{}
		trace.phaseFloor.Store(recorder)
		recorder.value.Store(value)
		if trace.phaseFloorSnapshot() != "" {
			t.Fatal("corrupt recorder escaped")
		}
	}
	if (*LifecycleDiagnostic)(nil).PhaseFloorSnapshot() != "" || (*admissionTrace)(nil).phaseFloorSnapshot() != "" {
		t.Fatal("nil recorder invented evidence")
	}
}

func TestPhaseFloorDiagnosticLeaderRenewalIsNotTheRefusedLeader(t *testing.T) {
	leader := fixturePhaseLeader{
		Row:       fixtureWorldRow{Key: installstate.Key{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Namespace: "PRIVATE-CANARY", Name: "first"}, UID: "PRIVATE-CANARY", ResourceVersion: "91", SHA256: "PRIVATE-CANARY"},
		ParentUID: "PRIVATE-CANARY", SetUID: "PRIVATE-CANARY", PodUID: "PRIVATE-CANARY",
		RenewTime: "2026-10-21T00:00:00Z", ManagedTimes: []string{"2026-10-21T00:00:00Z"},
	}
	other := leader
	other.Row.Key.Name = "second"
	before := fixturePhaseBaseline{Version: "admission-phase-v1", Leaders: []fixturePhaseLeader{leader, other}}
	for _, scenario := range []string{"allowed", "second-rv-regression", "second-hash", "second-chain", "second-time-regression"} {
		t.Run(scenario, func(t *testing.T) {
			after := before
			after.Leaders = append([]fixturePhaseLeader(nil), before.Leaders...)
			after.Leaders[0].Row.ResourceVersion = "92"
			after.Leaders[0].RenewTime = "2026-10-21T00:00:01Z"
			after.Leaders[0].ManagedTimes = []string{"2026-10-21T00:00:01Z"}
			var flags uint32
			switch scenario {
			case "second-rv-regression":
				after.Leaders[1].Row.ResourceVersion = "90"
				flags = phaseFloorRV
			case "second-hash":
				after.Leaders[1].Row.SHA256 = "different"
				flags = phaseFloorHash
			case "second-chain":
				after.Leaders[1].PodUID = "different"
				flags = phaseFloorOther
			case "second-time-regression":
				after.Leaders[1].RenewTime = "2026-10-20T23:59:59Z"
				flags = phaseFloorOther
			}
			ctx, d := WithLifecycleDiagnostic(t.Context())
			beginPhaseFloorDiagnostic(ctx).difference(before, after)
			if scenario == "allowed" {
				if !samePhaseBaseline(before, after) || d.PhaseFloorSnapshot() != "" {
					t.Fatal("allowed monotonic renewal became a refusal")
				}
			} else if samePhaseBaseline(before, after) || d.PhaseFloorSnapshot() != phaseFloorWant("leaders", "Lease", flags) {
				t.Fatal("allowed first renewal obscured refused second leader", d.PhaseFloorSnapshot())
			}
		})
	}
}

// Invalid durable companion floors are refused before accounting. These are
// deliberately direct calculator negatives over a genuinely sealed read, not
// a claim that a malformed durable companion reaches the full wire's guard.
func TestPhaseFloorDiagnosticActualInputGuardPreservesCalculation(t *testing.T) {
	h := fixtureV3PhaseFactory(t)(t)
	f := h.f.wire.ledger
	worlds, err := f.readOriginalWorlds(false)
	if err != nil || worlds.Phase == nil {
		t.Fatal("sealed floor unavailable", err)
	}
	a, request := h.f.actor.admission, h.f.actor.request
	o, err := a.prerequisites.observe(t.Context(), request)
	if err != nil {
		t.Fatal("sealed observation unavailable", err)
	}
	accounts, err := a.collectPhaseServiceAccounts(t.Context(), request)
	if err != nil {
		t.Fatal("sealed account collection unavailable", err)
	}
	body, identity := bytes.Clone(f.body), f.identity
	reads := [3]int{h.lists, h.gets, h.publicGets}
	floorBytes := phaseCopyJSON(t, worlds.Phase)
	for _, scenario := range []string{"valid", "floor-version", "floor-accounts", "absent-account-input"} {
		t.Run(scenario, func(t *testing.T) {
			floor, accountInput := *worlds.Phase, accounts
			switch scenario {
			case "floor-version":
				floor.Version = "PRIVATE-CANARY"
			case "floor-accounts":
				floor.Accounts = nil
			case "absent-account-input":
				accountInput = nil
			}
			now := time.Now().UTC()
			want, wantFixtures, wantErr := f.phaseCopyLegacyAccount(t.Context(), o, floor, now, accountInput)
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			got, gotFixtures, gotErr := f.accountPhaseWithAccounts(ctx, o, floor, now, accountInput)
			if wantErr != gotErr || !bytes.Equal(phaseCopyJSON(t, []any{want, wantFixtures}), phaseCopyJSON(t, []any{got, gotFixtures})) {
				t.Fatal("diagnostic changed the frozen calculator result")
			}
			if scenario == "valid" {
				if gotErr != nil || diagnostic.PhaseFloorSnapshot() != "" {
					t.Fatal("valid calculation refused")
				}
			} else if gotErr != ErrFixtures || diagnostic.PhaseFloorSnapshot() != phaseFloorWant("input-floor-or-recipe", "unknown", 0) {
				t.Fatal("actual first guard not identified", diagnostic.PhaseFloorSnapshot())
			}
		})
	}
	if !bytes.Equal(floorBytes, phaseCopyJSON(t, worlds.Phase)) || !bytes.Equal(body, f.body) || identity != f.identity || f.phaseFloor != nil || reads != [3]int{h.lists, h.gets, h.publicGets} || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
		t.Fatal("accounting diagnostic changed input, WAL, floor, effects or reads")
	}
}

func TestPhaseFloorDiagnosticResetAndInvocationIsolation(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context(), context.WithValue(t.Context(), admissionTraceKey{}, "PRIVATE-CANARY"), context.WithValue(t.Context(), admissionTraceKey{}, (*admissionTrace)(nil))} {
		beginPhaseFloorDiagnostic(ctx).record(phaseFloorInput, 0, 0)
	}
	for _, reset := range []string{"invocation", "phase", "outer", "checkpoint", "fresh-step"} {
		t.Run(reset, func(t *testing.T) {
			ctx, d := WithLifecycleDiagnostic(t.Context())
			old := beginPhaseFloorDiagnostic(ctx)
			old.record(phaseFloorInput, 0, 0)
			if d.PhaseFloorSnapshot() != phaseFloorWant("input-floor-or-recipe", "unknown", 0) {
				t.Fatal("initial guard diagnostic missing")
			}
			switch reset {
			case "invocation":
				beginPhaseFloorDiagnostic(ctx)
			case "phase":
				traceAdmissionPhase(ctx, admissionPhaseOriginal, -1)
			case "outer":
				traceAdmission(ctx, admissionCaseObservation, 22)
			case "checkpoint":
				traceLifecycleCheckpoint(ctx, AdmissionEffective, lifecycleDiagnosticEntered)
			case "fresh-step":
				ctx, d = WithLifecycleDiagnostic(ctx)
			}
			old.record(phaseFloorCandidate, 0, 0)
			if d.PhaseFloorSnapshot() != "" {
				t.Fatal("old writer survived reset")
			}
			current := beginPhaseFloorDiagnostic(ctx)
			current.record(phaseFloorRows, phaseFloorKind("Pod"), phaseFloorHash)
			var joined sync.WaitGroup
			for range 4 {
				joined.Go(func() {
					for range 100 {
						old.record(phaseFloorInput, 0, 0)
						if d.PhaseFloorSnapshot() != phaseFloorWant("rows", "Pod", phaseFloorHash) {
							t.Error("late writer replaced current refusal")
						}
					}
				})
			}
			joined.Wait()
			before := d.PhaseFloorSnapshot()
			traceAdmission(ctx, admissionStep(255), 99999)
			traceAdmissionPhase(ctx, admissionPhaseStep(255), 99999)
			if d.PhaseFloorSnapshot() != before || len(d.Snapshot()) > 256 {
				t.Fatal("invalid reset or enlarged original snapshot")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ctx, d := WithLifecycleDiagnostic(ctx)
	beginPhaseFloorDiagnostic(ctx).record(phaseFloorInput, 0, 0)
	if ctx.Err() != context.Canceled || d.PhaseFloorSnapshot() != phaseFloorWant("input-floor-or-recipe", "unknown", 0) {
		t.Fatal("diagnostic changed cancellation")
	}
}

// Real sealed reader/WAL transport with synthetic rows. The API-account Pod
// below is inert and unowned; this is NOT native API owner-chain certification.
func TestPhaseFloorDiagnosticV3ActualRefusalsRemainNoEffect(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV3(t, h.f.wire.ledger)
		ns := h.f.actor.request.Snapshot.Anchor().Namespace
		h.extra = append(h.extra,
			&unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "default", "namespace": ns, "uid": "c0000000-0000-4000-8000-000000000001", "resourceVersion": "91"}, "automountServiceAccountToken": false}},
			&unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "arcadectl-api-status-row", "namespace": ns, "uid": "c0000000-0000-4000-8000-000000000002", "resourceVersion": "91"}, "spec": map[string]any{"serviceAccountName": "arcadectl-api", "containers": []any{map[string]any{"name": "api", "image": "example.invalid/inert:fixture"}}}}},
		)
	})
	for _, scenario := range []string{"valid", "pod-status", "pod-status-rv", "policy-status", "default-missing", "extra-account"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			f := h.f.wire.ledger
			body, identity := bytes.Clone(f.body), f.identity
			want := ""
			switch scenario {
			case "pod-status", "pod-status-rv":
				h.extra[1].Object["status"] = map[string]any{"reason": "PRIVATE-CANARY"}
				flags := phaseFloorHash
				if scenario == "pod-status-rv" {
					h.extra[1].SetResourceVersion("92")
					flags |= phaseFloorRV
				}
				want = phaseFloorWant("rows", "Pod", flags)
			case "policy-status":
				found := false
				for key, object := range h.f.actor.v.f.access.objects {
					if key.Kind == "ValidatingAdmissionPolicy" {
						found = true
						status, _, _ := unstructured.NestedMap(object.Object, "status")
						status["conditions"] = []any{map[string]any{"type": "FixtureReady", "status": "True", "observedGeneration": object.GetGeneration(), "lastTransitionTime": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), "reason": "FixtureReady", "message": "PRIVATE-CANARY"}}
						object.Object["status"] = status
						break
					}
				}
				if !found {
					t.Fatal("original policy control absent")
				}
				want = phaseFloorWant("rows", "ValidatingAdmissionPolicy", phaseFloorHash)
			case "default-missing":
				h.extra = h.extra[1:]
				want = phaseFloorWant("accounts", "ServiceAccount", phaseFloorMembership)
			case "extra-account":
				extra := h.extra[0].DeepCopy()
				extra.SetName("foreign")
				extra.SetUID("c0000000-0000-4000-8000-000000000003")
				h.extra = append(h.extra, extra)
				want = phaseFloorWant("accounts", "ServiceAccount", phaseFloorMembership)
			}
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			observation, err := h.f.wire.observePhase(ctx)
			if scenario == "valid" {
				if err != nil || observation == nil || f.phaseFloor == nil || diagnostic.PhaseFloorSnapshot() != "" {
					t.Fatal("unchanged complete evidence refused", err)
				}
			} else {
				if err != ErrFixtures || observation != nil || f.phaseFloor != nil || diagnostic.PhaseFloorSnapshot() != want {
					t.Fatal("actual refusal changed boundary or lacked exact diagnostic", diagnostic.PhaseFloorSnapshot())
				}
				if phase, slot := diagnostic.admission.phaseSnapshot(); phase != "original-row-floor" || slot != -1 {
					t.Fatal("refusal was intercepted before the intended floor guard", phase, slot)
				}
				// A diagnostic is not required to refuse, and must not alter
				// the floor, WAL or effects when the same drift remains.
				if observation, err := h.f.wire.observePhase(t.Context()); err != ErrFixtures || observation != nil || f.phaseFloor != nil {
					t.Fatal("absent diagnostic changed refusal")
				}
			}
			if !bytes.Equal(body, f.body) || f.identity != identity || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || f.behaviorCompletion != nil || diagnostic.TypedMetadataSnapshot() != "" {
				t.Fatal("diagnostic changed WAL/effects or invented unrelated metadata mismatch")
			}
		})
	}
}
