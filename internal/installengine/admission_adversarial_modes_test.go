// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Adversarial #100 proofs over REAL genuine Upgrade, Rollback and Uninstall
// checkpoints: the sealed journal, signed inventory, actor factory, whole-phase
// observer and protected WAL are production code over synthetic HTTPS replies.
// They are NOT native admission evidence; native all-55 proof stays Atlas-gated.

// uninstallQuiesced is the first Uninstall checkpoint whose next Step owes the
// full AdmissionEffective proof over an already stopped, original runtime: no
// API Deployment and both controllers at their signed paused templates.
func uninstallQuiesced(v *lifecycleFixture, d installstate.Document) bool {
	if d.Mode != installstate.Uninstall || d.Stage != installstate.Quiescing || d.Pending != nil {
		return false
	}
	if r, _ := v.f.engine.inventory(d, deploymentKey(d.Namespace, apiFamily)); r != nil {
		return false
	}
	for _, family := range controllerFamilies {
		key := deploymentKey(d.Namespace, family)
		r, _ := v.f.engine.inventory(d, key)
		paused, err := v.f.engine.contracts[d.ActivePackage].Template(key, true)
		if r == nil || err != nil || r.TemplateSHA256 != paused.Hash() {
			return false
		}
	}
	return true
}

type adversarialModePhase struct {
	h                *fixturePhaseTest
	previous, target *installrender.Plan
}

// newAdversarialModePhase reaches the genuine checkpoint at which the lifecycle
// owes AdmissionEffective for mode, then builds the unmarked whole-phase fixture
// exactly like unmarkedRecoveryPhaseFactory does for Install.
func newAdversarialModePhase(t *testing.T, mode installstate.Mode) *adversarialModePhase {
	t.Helper()
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	snapshot := v.finish(t, v.f.snapshot)
	begin := func(next installstate.Mode, digest string) {
		t.Helper()
		var err error
		if snapshot, err = v.l.Begin(t.Context(), snapshot, next, digest, v.opts); err != nil {
			t.Fatal("genuine transition could not begin", next, err)
		}
	}
	reached := func(d installstate.Document) bool {
		if mode == installstate.Uninstall {
			return uninstallQuiesced(v, d)
		}
		return d.Mode == mode && d.Stage == installstate.Applying && d.Pending == nil
	}
	switch mode {
	case installstate.Upgrade:
		begin(installstate.Upgrade, target.Digest())
	case installstate.Rollback:
		begin(installstate.Upgrade, target.Digest())
		snapshot = v.finish(t, snapshot)
		begin(installstate.Rollback, previous.Digest())
	case installstate.Uninstall:
		begin(installstate.Uninstall, previous.Digest())
	default:
		t.Fatal("no genuine admission checkpoint for mode", mode)
	}
	for i := 0; i < 100 && !reached(snapshot.Document()); i++ {
		snapshot = v.step(t, snapshot)
	}
	if !reached(snapshot.Document()) {
		t.Fatal("genuine admission checkpoint not reached for", mode)
	}
	for _, secret := range v.private.objects {
		metadata := secret.DeepCopy()
		metadata.Data, metadata.StringData = nil, nil
		metadata.APIVersion, metadata.Kind = "v1", "Secret"
		v.f.access.objects[secretKey(metadata.Namespace, metadata.Name)] = servingObject(t, metadata)
	}
	actor := newActorFixtureAtCheckpointPlans(t, v, snapshot, previous, target)
	actor.request.Options.Now = time.Now().UTC()
	if actor.request.Mode != mode || actor.request.Snapshot.Document().Mode != mode {
		t.Fatal("transition request lost its genuine lifecycle mode", mode)
	}
	setup := func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger)
		base := h.f.actor.fixtureHandler
		h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			for key, object := range h.f.actor.v.f.access.objects {
				if key.Kind != "Secret" {
					continue
				}
				path, err := privateSecretPath(key, false)
				if err != nil || path != r.URL.Path {
					continue
				}
				if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
					t.Error("fixture requested private Secret data")
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				encodeStoppedObject(t, w, r, object)
				return true
			}
			return base(w, r)
		}
	}
	h := fixturePhaseFactoryFromWireFactory(t, func(t *testing.T) *fixtureWireTest { return newFixtureWireTestAtActor(t, actor) }, setup)(t)
	f := h.f.wire.ledger
	acknowledgeAllRecipeFixtures(t, f)
	created := time.Now().UTC().Truncate(time.Second).Add(-40 * time.Second)
	for slot := range f.document.Entries {
		h.f.objects[slot] = fixtureResultExample(t, f, slot, fixtureStableResult, created)
	}
	return &adversarialModePhase{h: h, previous: previous, target: target}
}

func smallestKey(objects map[installstate.Key]*unstructured.Unstructured, kind string) installstate.Key {
	var selected installstate.Key
	for key := range objects {
		if key.Kind == kind && (selected == (installstate.Key{}) || key.String() < selected.String()) {
			selected = key
		}
	}
	return selected
}

func setFirstValidationExpression(t *testing.T, o *unstructured.Unstructured, expression string) {
	t.Helper()
	validations, found, err := unstructured.NestedSlice(o.Object, "spec", "validations")
	if err != nil || !found || len(validations) == 0 {
		t.Fatal("policy fixture has no validation to forge")
	}
	validations[0].(map[string]any)["expression"] = expression
	if unstructured.SetNestedSlice(o.Object, validations, "spec", "validations") != nil {
		t.Fatal("forged validation unavailable")
	}
}

// A forged, missing or duplicated policy/binding object must make the
// configuration observation behind AdmissionEffective (and the configured and
// CREATE-probe entry points built on it) fail in EVERY mode, with the genuine
// configuration restored and re-accepted after each forgery.
func testAdmissionAdversarialForgedConfiguration(t *testing.T, mode installstate.Mode) {
	t.Helper()
	phase := newAdversarialModePhase(t, mode)
	actor := phase.h.f.actor
	a, request := actor.admission, actor.request
	objects := actor.v.f.access.objects
	requests, posts := 0, 0
	base := actor.fixtureHandler
	actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		requests++
		if r.Method == http.MethodPost {
			posts++
		}
		return base(w, r)
	}
	observed := func() (int, int) {
		var n, p int
		actor.withState(func() { n, p = requests, posts })
		return n, p
	}
	ctx := t.Context()
	first, err := a.configured(ctx, request)
	if err != nil || len(first.policies) != 6 || len(first.bindings) != 6 || len(first.objects) != 12 {
		t.Fatal("genuine transition configuration positive control unavailable", err)
	}
	policyKey, bindingKey := smallestKey(objects, "ValidatingAdmissionPolicy"), smallestKey(objects, "ValidatingAdmissionPolicyBinding")
	if policyKey == (installstate.Key{}) || bindingKey == (installstate.Key{}) {
		t.Fatal("transition fixture has no signed policy/binding")
	}
	condition := func(generation int64) map[string]any {
		return map[string]any{"type": "Accepted", "status": "True", "observedGeneration": generation, "lastTransitionTime": "2026-10-05T21:00:00Z", "reason": "Accepted", "message": "public fixture"}
	}
	forgeries := []struct {
		name string
		key  installstate.Key
		edit func(o *unstructured.Unstructured)
	}{
		{"policy-uid", policyKey, func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000001") }},
		{"policy-failure-policy", policyKey, func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "Ignore", "spec", "failurePolicy")
		}},
		{"policy-weakened-expression", policyKey, func(o *unstructured.Unstructured) { setFirstValidationExpression(t, o, "true") }},
		{"policy-stale-generation", policyKey, func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, int64(0), "status", "observedGeneration")
		}},
		{"policy-no-typechecking", policyKey, func(o *unstructured.Unstructured) {
			unstructured.RemoveNestedField(o.Object, "status", "typeChecking")
		}},
		{"policy-warnings", policyKey, func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedSlice(o.Object, []any{map[string]any{"fieldRef": "spec.validations[0].expression", "warning": "forged"}}, "status", "typeChecking", "expressionWarnings")
		}},
		{"policy-false-condition", policyKey, func(o *unstructured.Unstructured) {
			c := condition(o.GetGeneration())
			c["status"] = "False"
			_ = unstructured.SetNestedSlice(o.Object, []any{c}, "status", "conditions")
		}},
		{"policy-duplicate-condition", policyKey, func(o *unstructured.Unstructured) {
			c := condition(o.GetGeneration())
			_ = unstructured.SetNestedSlice(o.Object, []any{c, c}, "status", "conditions")
		}},
		{"binding-uid", bindingKey, func(o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000002") }},
		{"binding-policy-name", bindingKey, func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "foreign", "spec", "policyName")
		}},
		{"binding-audit-only", bindingKey, func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedSlice(o.Object, []any{"Audit"}, "spec", "validationActions")
		}},
		{"binding-param-ref", bindingKey, func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, map[string]any{"name": "foreign", "parameterNotFoundAction": "Allow"}, "spec", "paramRef")
		}},
	}
	for _, forgery := range forgeries {
		original := objects[forgery.key].DeepCopy()
		forgery.edit(objects[forgery.key])
		before, beforePosts := observed()
		witness, err := a.configured(ctx, request)
		if witness != nil || err != ErrAdmission {
			t.Fatalf("%s: forged %s accepted by %s configuration: %v", mode, forgery.name, mode, err)
		}
		configured := request
		configured.Checkpoint = AdmissionConfigured
		if a.VerifyConfigured(ctx, configured) != ErrAdmission || a.VerifyCreateProbes(ctx, request) != ErrAdmission {
			t.Fatalf("%s: forged %s accepted by configured/probe verification", mode, forgery.name)
		}
		if after, afterPosts := observed(); after <= before || afterPosts != beforePosts {
			t.Fatalf("%s: forged %s was not observed, or probes were sent over a forged configuration", mode, forgery.name)
		}
		objects[forgery.key] = original
		if _, err := a.configured(ctx, request); err != nil {
			t.Fatalf("%s: restoring %s did not restore the genuine configuration: %v", mode, forgery.name, err)
		}
	}
	// Missing members and a forged duplicate identity are forgeries of the
	// whole signed set. (Unrelated extra members of the label-selected
	// LIST are intentionally ignored by production: the signed expected
	// keys, not the LIST, are authority, so no such case is asserted.)
	for _, key := range []installstate.Key{policyKey, bindingKey} {
		original := objects[key]
		delete(objects, key)
		if witness, err := a.configured(ctx, request); witness != nil || err != ErrAdmission {
			t.Fatalf("%s: configuration missing %s accepted", mode, key.Kind)
		}
		objects[key] = original
	}
	for _, key := range []installstate.Key{policyKey, bindingKey} {
		duplicate := installstate.Key{APIVersion: key.APIVersion, Kind: key.Kind, Name: "forged-duplicate-identity"}
		forged := objects[key].DeepCopy()
		forged.SetName(duplicate.Name) // same labels and UID as a signed original
		objects[duplicate] = forged
		if witness, err := a.configured(ctx, request); witness != nil || err != ErrAdmission {
			t.Fatalf("%s: a forged %s duplicating an original UID was accepted", mode, key.Kind)
		}
		delete(objects, duplicate)
		if _, err := a.configured(ctx, request); err != nil {
			t.Fatalf("%s: removing the forged duplicate did not restore the genuine configuration", mode)
		}
	}
	// A bare resourceVersion change is still observed as drift.
	for _, key := range []installstate.Key{policyKey, bindingKey} {
		original := objects[key].DeepCopy()
		objects[key].SetResourceVersion("changed-after-first-witness")
		changed, err := a.configured(ctx, request)
		if err != nil || sameAdmissionConfiguration(first, changed) {
			t.Fatalf("%s: %s resourceVersion change not detected", mode, key.Kind)
		}
		objects[key] = original
	}
	if again, err := a.configured(ctx, request); err != nil || !sameAdmissionConfiguration(first, again) {
		t.Fatalf("%s: genuine configuration not stable after forgeries", mode)
	}
}

// The matched live objects are transferred (not copied) into each request's
// witness. Two live witnesses must stay disjoint, and mutating one must reach
// neither a concurrent witness, a later match, the template memo nor the live
// cluster object. A shared pointer would let a mutation forge later proof.
func testAdmissionAdversarialWitnessMutation(t *testing.T, mode installstate.Mode) {
	t.Helper()
	phase := newAdversarialModePhase(t, mode)
	actor := phase.h.f.actor
	a, request := actor.admission, actor.request
	objects := actor.v.f.access.objects
	ctx := t.Context()
	first, err := a.configured(ctx, request)
	if err != nil {
		t.Fatal("first genuine witness unavailable", err)
	}
	second, err := a.configured(ctx, request)
	if err != nil {
		t.Fatal("second genuine witness unavailable", err)
	}
	for name, policy := range first.policies {
		if policy == second.policies[name] || policy.Spec.Validations == nil || len(policy.Spec.Validations) == 0 {
			t.Fatal("concurrent witnesses share a policy object or the fixture lacks validations", name)
		}
	}
	for name, binding := range first.bindings {
		if binding == second.bindings[name] || len(binding.Spec.ValidationActions) == 0 {
			t.Fatal("concurrent witnesses share a binding object or the fixture lacks actions", name)
		}
	}
	encode := func(c *admissionConfiguration) string {
		body, err := json.Marshal([]any{c.policies, c.bindings})
		if err != nil {
			t.Fatal("witness encoding unavailable")
		}
		return string(body)
	}
	live := func() string {
		var keys []installstate.Key
		for key := range objects {
			if key.Kind == "ValidatingAdmissionPolicy" || key.Kind == "ValidatingAdmissionPolicyBinding" {
				keys = append(keys, key)
			}
		}
		slices.SortFunc(keys, func(a, b installstate.Key) int { return strings.Compare(a.String(), b.String()) })
		var all []map[string]any
		for _, key := range keys {
			all = append(all, objects[key].Object)
		}
		body, err := json.Marshal(all)
		if err != nil {
			t.Fatal("live encoding unavailable")
		}
		return string(body)
	}
	pristine, liveBefore, identities := encode(second), live(), maps.Clone(second.objects)
	if pristine != encode(first) || !reflect.DeepEqual(first.objects, second.objects) {
		t.Fatal("independent genuine witnesses differ before any mutation")
	}
	for _, policy := range first.policies {
		policy.Spec.Validations[0].Expression = "true"
		policy.Spec.Validations = append(policy.Spec.Validations, policy.Spec.Validations[0])
		policy.SetResourceVersion("foreign")
		policy.SetLabels(map[string]string{"forged": "true"})
		if policy.Status.TypeChecking != nil {
			policy.Status.TypeChecking.ExpressionWarnings = append(policy.Status.TypeChecking.ExpressionWarnings, policy.Status.TypeChecking.ExpressionWarnings...)
		}
	}
	for _, binding := range first.bindings {
		binding.Spec.PolicyName = "foreign"
		binding.Spec.ValidationActions[0] = "Audit"
		binding.SetUID("forged-uid")
	}
	for key := range first.objects {
		first.objects[key] = admissionIdentity{UID: "forged-uid", ResourceVersion: "foreign", TemplateSHA256: "foreign"}
	}
	if encode(second) != pristine || !reflect.DeepEqual(second.objects, identities) {
		t.Fatalf("%s: mutating one witness changed a concurrent witness", mode)
	}
	if live() != liveBefore {
		t.Fatalf("%s: mutating a witness wrote through to the live cluster object", mode)
	}
	third, err := a.configured(ctx, request)
	if err != nil || encode(third) != pristine || !reflect.DeepEqual(third.objects, identities) || !sameAdmissionConfiguration(second, third) {
		t.Fatalf("%s: mutated witness poisoned a later genuine match: %v", mode, err)
	}
	if sameAdmissionConfiguration(first, third) {
		t.Fatalf("%s: mutated witness still equals the genuine configuration", mode)
	}
}

// Requests whose (mode, target, snapshot) do not describe the genuine lifecycle
// transition must be refused before ANY cluster observation, probe, journal or
// WAL change, through every public admission entry point.
func testAdmissionAdversarialTamperedRequest(t *testing.T, mode installstate.Mode) {
	t.Helper()
	phase := newAdversarialModePhase(t, mode)
	actor, ledger := phase.h.f.actor, phase.h.f.wire.ledger
	a, request := actor.admission, actor.request
	previous, target := phase.previous, phase.target
	requests := 0
	base := actor.fixtureHandler
	actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		requests++
		return base(w, r)
	}
	ctx := t.Context()
	if _, err := a.configured(ctx, request); err != nil {
		t.Fatal("genuine request positive control unavailable", err)
	}
	wrong := map[installstate.Mode][]struct {
		mode   installstate.Mode
		target *installrender.Plan
	}{
		installstate.Upgrade:   {{installstate.Upgrade, previous}, {installstate.Rollback, previous}, {installstate.Rollback, target}, {installstate.Uninstall, target}, {installstate.Install, target}},
		installstate.Rollback:  {{installstate.Rollback, target}, {installstate.Upgrade, target}, {installstate.Upgrade, previous}, {installstate.Uninstall, previous}, {installstate.Install, previous}},
		installstate.Uninstall: {{installstate.Uninstall, target}, {installstate.Upgrade, previous}, {installstate.Rollback, previous}, {installstate.Rollback, target}, {installstate.Install, target}},
	}[mode]
	type tampered struct {
		name          string
		request       LifecycleCheck
		wantEffective error
	}
	var cases []tampered
	label := map[*installrender.Plan]string{previous: "previous", target: "target"}
	for _, w := range wrong {
		bad := request
		bad.Mode, bad.Target = w.mode, w.target
		cases = append(cases, tampered{string(w.mode) + "-" + label[w.target], bad, ErrFixtures})
	}
	for name, edit := range map[string]func(*LifecycleCheck){
		"unknown-mode":     func(r *LifecycleCheck) { r.Mode = installstate.Mode("forged") },
		"empty-mode":       func(r *LifecycleCheck) { r.Mode = "" },
		"zero-plan":        func(r *LifecycleCheck) { r.Target = &installrender.Plan{} },
		"nil-plan":         func(r *LifecycleCheck) { r.Target = nil },
		"uncataloged-plan": func(r *LifecycleCheck) { r.Target = fixturePlan(t) },
	} {
		bad := request
		edit(&bad)
		cases = append(cases, tampered{name, bad, ErrFixtures})
	}
	noSnapshot := request
	noSnapshot.Snapshot = nil
	cases = append(cases, tampered{"nil-snapshot", noSnapshot, ErrInvalid})
	walBefore, revision := slices.Clone(ledger.body), ledger.document.Revision
	writes, updates := actor.v.f.access.writes, actor.v.f.nsUpdates
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := requests
			if witness, err := a.configured(ctx, c.request); witness != nil || err != ErrInvalid {
				t.Fatal("tampered request produced a configuration witness", err)
			}
			if phaseResult, err := a.waitInitialPhase(ctx, c.request); phaseResult != nil || err != ErrInvalid {
				t.Fatal("tampered request waited for or captured an initial phase", err)
			}
			if err := a.VerifyEffective(ctx, c.request); err != c.wantEffective {
				t.Fatal("tampered request accepted by VerifyEffective", err)
			}
			if err := a.VerifyCreateProbes(ctx, c.request); err != ErrInvalid {
				t.Fatal("tampered request reached the CREATE probes", err)
			}
			configured := c.request
			configured.Checkpoint = AdmissionConfigured
			if err := a.VerifyConfigured(ctx, configured); err != ErrInvalid {
				t.Fatal("tampered request accepted by VerifyConfigured", err)
			}
			if requests != before || actor.v.f.access.writes != writes || actor.v.f.nsUpdates != updates {
				t.Fatal("tampered request observed or changed the cluster before refusal")
			}
			if !slices.Equal(walBefore, ledger.body) || ledger.document.Revision != revision {
				t.Fatal("tampered request changed the protected WAL")
			}
		})
	}
}

type adversarialLateFault struct {
	kind string
	// atProbe mutates at the actual dry-run probe request (onProbe); otherwise at
	// the exact authorization review immediately before it (onExact).
	atProbe bool
	// restore returns the ORIGINAL object, with a new resourceVersion, at the probe.
	restore bool
	edit    func(t *testing.T, o *unstructured.Unstructured)
}

// adversarialLateMutation injects one late mutation through the existing
// onExact/onProbe hooks around the real runCaseLocked boundary and requires the
// case to FAIL, publish no behavior bit and leave the WAL/journal untouched.
func adversarialLateMutation(t *testing.T, p *testAdmissionCaseProtocol, fault adversarialLateFault) {
	t.Helper()
	objects := p.h.f.actor.v.f.access.objects
	selected := smallestKey(objects, fault.kind)
	if selected == (installstate.Key{}) {
		t.Fatal("late mutation has no original signed target", fault.kind)
	}
	original := objects[selected].DeepCopy()
	inject := func() {
		if p.injected {
			return
		}
		p.injected = true
		fault.edit(t, objects[selected])
		if fault.restore {
			p.onProbe = func() {
				restored := original.DeepCopy()
				restored.SetResourceVersion("1000")
				objects[selected] = restored
			}
		}
	}
	if fault.atProbe {
		p.onProbe = inject
	} else {
		p.onExact = inject
	}
	if p.run(t.Context()) != ErrFixtures || !p.injected || !p.d.failed || p.d.completed != (uint64(1)<<17)-1 || p.d.next != 17 {
		t.Fatal("late mutation was silently accepted, never fired, or published a case bit")
	}
	if fault.restore && p.probes != 1 {
		t.Fatal("edit-restore did not cross the actual dry-run probe before final refusal")
	}
	p.assertCustody(t)
}

// The actors' request-owned policy/binding witnesses (the objects #105 now
// transfers from MatchLiveAdmissionObject instead of copying) supply the
// expected denial message and binding for the real case. Mutating them at the
// exact-review boundary, as an aliasing bug would, must fail the case.
func adversarialWitnessMutation(t *testing.T, p *testAdmissionCaseProtocol, edit func(*admissionConfiguration)) {
	t.Helper()
	witness := p.h.f.wire.actors.policies
	if witness == nil || len(witness.policies) != 6 || len(witness.bindings) != 6 {
		t.Fatal("actor witness fixture unavailable")
	}
	p.onExact = func() {
		if p.injected {
			return
		}
		p.injected = true
		edit(witness)
	}
	if p.run(t.Context()) != ErrFixtures || !p.injected || !p.d.failed || p.d.completed != (uint64(1)<<17)-1 || p.d.next != 17 {
		t.Fatal("witness mutation was silently accepted, never fired, or published a case bit")
	}
	p.assertCustody(t)
}

func testAdmissionAdversarialActorWitness(t *testing.T, mode installstate.Mode) {
	t.Helper()
	phase := newAdversarialModePhase(t, mode)
	adversarialWitnessMutation(t, testAdmissionCaseProtocolFixtureOn(t, 17, phase.h), func(w *admissionConfiguration) {
		for _, policy := range w.policies {
			for i := range policy.Spec.Validations {
				policy.Spec.Validations[i].Message += " (forged)"
			}
		}
	})
}

// One representative per hook placement keeps the heavy per-mode whole-phase
// cost bounded: exact-time policy forgery, probe-time policy weakening, and a
// binding edit restored with a new version at the probe.
func adversarialLateFaults() map[string]adversarialLateFault {
	policy, binding := "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"
	return map[string]adversarialLateFault{
		"policy-uid-at-exact-review": {kind: policy, edit: func(t *testing.T, o *unstructured.Unstructured) { o.SetUID("b0000000-0000-4000-8000-000000000001") }},
		"policy-weakened-expression-at-probe": {kind: policy, atProbe: true, edit: func(t *testing.T, o *unstructured.Unstructured) {
			setFirstValidationExpression(t, o, "true")
		}},
		"binding-audit-edit-restored-at-probe": {kind: binding, restore: true, edit: func(t *testing.T, o *unstructured.Unstructured) {
			_ = unstructured.SetNestedSlice(o.Object, []any{"Audit"}, "spec", "validationActions")
		}},
	}
}

func testAdmissionAdversarialLate(t *testing.T, mode installstate.Mode, fault string) {
	t.Helper()
	selected, ok := adversarialLateFaults()[fault]
	if !ok {
		t.Fatal("unknown late mutation", fault)
	}
	phase := newAdversarialModePhase(t, mode)
	adversarialLateMutation(t, testAdmissionCaseProtocolFixtureOn(t, 17, phase.h), selected)
}

// Separate roots per mode (and per late fault) let complete-union CI distribute
// each heavy whole-phase case instead of serializing them in one process.
func TestAdmissionAdversarialForgedConfigurationUpgrade(t *testing.T) {
	testAdmissionAdversarialForgedConfiguration(t, installstate.Upgrade)
}
func TestAdmissionAdversarialForgedConfigurationRollback(t *testing.T) {
	testAdmissionAdversarialForgedConfiguration(t, installstate.Rollback)
}
func TestAdmissionAdversarialForgedConfigurationUninstall(t *testing.T) {
	testAdmissionAdversarialForgedConfiguration(t, installstate.Uninstall)
}
func TestAdmissionAdversarialWitnessMutationUpgrade(t *testing.T) {
	testAdmissionAdversarialWitnessMutation(t, installstate.Upgrade)
}
func TestAdmissionAdversarialWitnessMutationRollback(t *testing.T) {
	testAdmissionAdversarialWitnessMutation(t, installstate.Rollback)
}
func TestAdmissionAdversarialWitnessMutationUninstall(t *testing.T) {
	testAdmissionAdversarialWitnessMutation(t, installstate.Uninstall)
}
func TestAdmissionAdversarialTamperedRequestUpgrade(t *testing.T) {
	testAdmissionAdversarialTamperedRequest(t, installstate.Upgrade)
}
func TestAdmissionAdversarialTamperedRequestRollback(t *testing.T) {
	testAdmissionAdversarialTamperedRequest(t, installstate.Rollback)
}
func TestAdmissionAdversarialTamperedRequestUninstall(t *testing.T) {
	testAdmissionAdversarialTamperedRequest(t, installstate.Uninstall)
}
func TestAdmissionAdversarialActorWitnessUpgrade(t *testing.T) {
	testAdmissionAdversarialActorWitness(t, installstate.Upgrade)
}
func TestAdmissionAdversarialActorWitnessRollback(t *testing.T) {
	testAdmissionAdversarialActorWitness(t, installstate.Rollback)
}
func TestAdmissionAdversarialActorWitnessUninstall(t *testing.T) {
	testAdmissionAdversarialActorWitness(t, installstate.Uninstall)
}
func TestAdmissionAdversarialLateUpgradePolicyUIDAtExactReview(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Upgrade, "policy-uid-at-exact-review")
}
func TestAdmissionAdversarialLateRollbackPolicyUIDAtExactReview(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Rollback, "policy-uid-at-exact-review")
}
func TestAdmissionAdversarialLateUninstallPolicyUIDAtExactReview(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Uninstall, "policy-uid-at-exact-review")
}
func TestAdmissionAdversarialLateUpgradePolicyWeakenedAtProbe(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Upgrade, "policy-weakened-expression-at-probe")
}
func TestAdmissionAdversarialLateRollbackPolicyWeakenedAtProbe(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Rollback, "policy-weakened-expression-at-probe")
}
func TestAdmissionAdversarialLateUninstallPolicyWeakenedAtProbe(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Uninstall, "policy-weakened-expression-at-probe")
}
func TestAdmissionAdversarialLateUpgradeBindingEditRestoredAtProbe(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Upgrade, "binding-audit-edit-restored-at-probe")
}
func TestAdmissionAdversarialLateRollbackBindingEditRestoredAtProbe(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Rollback, "binding-audit-edit-restored-at-probe")
}
func TestAdmissionAdversarialLateUninstallBindingEditRestoredAtProbe(t *testing.T) {
	testAdmissionAdversarialLate(t, installstate.Uninstall, "binding-audit-edit-restored-at-probe")
}
