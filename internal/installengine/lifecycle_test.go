// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// These tests exercise actual journal CAS/effects/private-file/Secret machinery
// with fixture Kubernetes and explicitly trusted fixture proof providers. They
// are not production admission, kubelet, auth or full binary certification.
type lifecycleFixture struct {
	f       *fixture
	l       *Lifecycle
	private *fakePrivateSecrets
	opts    LifecycleOptions
	checks  []Checkpoint
	effects []installstate.Key
	fail    Checkpoint
	probe   func(LifecycleCheck) error
}

func (v *lifecycleFixture) Check(ctx context.Context, request LifecycleCheck) error {
	kind, s := request.Checkpoint, request.Snapshot
	v.checks = append(v.checks, kind)
	if kind == v.fail {
		return errors.New("private fixture detail must never be reflected")
	}
	if v.probe != nil {
		if err := v.probe(request); err != nil {
			return err
		}
	}
	d := s.Document()
	for _, key := range v.l.ordered(d) {
		rank := installRank(key)
		r, tmpl := v.f.engine.inventory(d, key)
		switch kind {
		case CRDsAvailable:
			if rank == 0 && (r == nil || tmpl.CheckCRD(v.f.access.objects[key], r.UID, tmpl) != nil) {
				return ErrLifecycle
			}
		case AdmissionConfigured, AdmissionEffective:
			if (rank == 1 || rank == 2) && r == nil {
				return ErrLifecycle
			}
		case APIStopped, RuntimeStopped:
			if rank == 5 && v.f.access.objects[key] != nil {
				return ErrLifecycle
			}
			if kind == RuntimeStopped && rank == 4 && v.f.access.objects[key] != nil {
				n, found, _ := unstructured.NestedInt64(v.f.access.objects[key].Object, "spec", "replicas")
				if !found || n != 0 {
					return ErrLifecycle
				}
			}
		case ControllersAvailable, TargetAuthenticated:
			if rank == 4 || kind == TargetAuthenticated && rank == 5 {
				var dep appsv1.Deployment
				if r == nil || decodeServing(v.f.access.objects[key], &dep) != nil || !availableInstallationDeployment(&dep) {
					return ErrLifecycle
				}
			}
		}
	}
	return ctx.Err()
}

func TestLifecycleSignedServiceAccountsPrecedeBehavioralAdmission(t *testing.T) {
	for _, gate := range []Checkpoint{AdmissionConfigured, AdmissionEffective} {
		t.Run(fmt.Sprint(gate), func(t *testing.T) {
			v := newLifecycleFixture(t)
			v.fail = gate
			s := v.f.snapshot
			refused := false
			for i := 0; i < 100; i++ {
				next, err := v.l.Step(context.Background(), s, v.opts)
				s = next
				if err != nil {
					if !errors.Is(err, ErrLifecycle) {
						t.Fatal(err)
					}
					refused = true
					break
				}
			}
			if !refused || s.Document().Pending != nil {
				t.Fatal("admission barrier did not stop before an effect")
			}
			accounts := 0
			for _, r := range s.Document().Resources {
				if r.Key.Kind == "ServiceAccount" {
					accounts++
				} else if r.Key.Kind != "Namespace" && installRank(r.Key) >= 3 {
					t.Fatal("RBAC/service/workload authority preceded behavioral proof")
				}
			}
			wanted := 0
			if gate == AdmissionEffective {
				for _, resource := range v.f.plan.Resources() {
					if resource.Object.GetKind() == "ServiceAccount" {
						wanted++
					}
				}
			}
			if accounts != wanted {
				t.Fatal("configured/effective barriers did not bound identity-only effects")
			}
		})
	}
}

func TestLifecycleServiceAccountResumeDoesNotSkipBehavioralBarrier(t *testing.T) {
	v := newLifecycleFixture(t)
	v.probe = func(request LifecycleCheck) error {
		if request.Checkpoint == AdmissionEffective {
			for _, resource := range request.Target.Resources() {
				if resource.Object.GetKind() == "ServiceAccount" {
					if r, _ := v.f.engine.inventory(request.Snapshot.Document(), resourceKey(resource)); r == nil {
						return ErrLifecycle
					}
				}
			}
		}
		return nil
	}
	s := v.f.snapshot
	for i := 0; i < 100; i++ {
		s = v.step(t, s)
		accounts := 0
		for _, r := range s.Document().Resources {
			if r.Key.Kind == "ServiceAccount" {
				accounts++
			}
		}
		if accounts == 1 {
			break
		}
	}
	// A new coordinator over the same original sealed journal resumes the
	// partially created identities; it neither recreates one nor bypasses proof.
	l, err := NewLifecycleWithChecks(v.f.engine, v.l.secrets, v)
	if err != nil {
		t.Fatal(err)
	}
	v.l = l
	s = v.finish(t, s)
	if !s.Document().Installed || !slices.Contains(v.checks, AdmissionConfigured) || !slices.Contains(v.checks, AdmissionEffective) {
		t.Fatal("resumed install skipped one admission obligation")
	}
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	return newLifecycleFixturePlans(t, fixturePlan(t))
}

func newLifecycleFixturePlans(t *testing.T, plans ...*installrender.Plan) *lifecycleFixture {
	t.Helper()
	f := newFixtureWithPlans(t, false, plans...)
	now := time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)
	credentials := fixtureTLS(t, f.plan.Namespace(), now)
	v := &lifecycleFixture{f: f, private: &fakePrivateSecrets{f: f, objects: map[string]*corev1.Secret{}}, opts: LifecycleOptions{Now: now, Credentials: credentials, Activation: ActivationOptions{CAFile: credentials.CAFile}}}
	w, err := NewSecretWorkflow(f.engine, v.private)
	if err != nil {
		t.Fatal(err)
	}
	v.l, err = NewLifecycleWithChecks(f.engine, w, v)
	if err != nil {
		t.Fatal(err)
	}
	f.access.dry = func(o *unstructured.Unstructured) *unstructured.Unstructured { return v.admit(t, o) }
	f.access.write = func(action installstate.Action, key installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		v.effects = append(v.effects, key)
		if action == installstate.Delete {
			delete(f.access.objects, key)
			return nil, nil
		}
		result := v.admit(t, o)
		if action == installstate.Create {
			result.SetUID(types.UID(fmt.Sprintf("original-%s-%d", key.Name, f.access.writes)))
			result.SetGeneration(1)
		} else {
			before := f.access.objects[key]
			if before == nil || before.GetUID() != o.GetUID() || before.GetResourceVersion() != o.GetResourceVersion() {
				return nil, ErrConcurrent
			}
			result.SetGeneration(before.GetGeneration() + 1)
		}
		result.SetResourceVersion(strconv.Itoa(f.access.writes + 100))
		if key.Kind == "CustomResourceDefinition" {
			names, _, _ := unstructured.NestedMap(result.Object, "spec", "names")
			result.Object["status"] = map[string]any{"acceptedNames": names, "storedVersions": []any{"v1alpha1"}, "conditions": []any{map[string]any{"type": "Established", "status": "True"}, map[string]any{"type": "NamesAccepted", "status": "True"}}}
		}
		if key.Kind == "Deployment" {
			replicas, _, _ := unstructured.NestedInt64(result.Object, "spec", "replicas")
			result.Object["status"] = map[string]any{"observedGeneration": result.GetGeneration(), "replicas": replicas, "updatedReplicas": replicas, "readyReplicas": replicas, "availableReplicas": replicas}
		}
		f.access.objects[key] = result.DeepCopy()
		return result, nil
	}
	return v
}

func TestLifecycleCompletionRechecksAdmissionAndControllerProofs(t *testing.T) {
	for _, gate := range []Checkpoint{CRDsAvailable, AdmissionEffective, ControllersAvailable} {
		t.Run(fmt.Sprint(gate), func(t *testing.T) {
			v := newLifecycleFixture(t)
			v.probe = func(request LifecycleCheck) error {
				if request.Checkpoint == gate && request.Snapshot.Document().Stage == installstate.Verifying {
					return ErrLifecycle
				}
				return nil
			}
			s := v.f.snapshot
			for s.Document().Stage != installstate.Verifying {
				s = v.step(t, s)
			}
			before := v.f.nsUpdates
			if _, err := v.l.Step(context.Background(), s, v.opts); !errors.Is(err, ErrLifecycle) || before != v.f.nsUpdates {
				t.Fatal("completion used stale admission/controller evidence")
			}
		})
	}
}

func TestLifecycleBeginPreflightsRequestedOperationNotOldJournal(t *testing.T) {
	v := newLifecycleFixture(t)
	s := v.finish(t, v.f.snapshot)
	checked := false
	v.probe = func(request LifecycleCheck) error {
		if request.Checkpoint == Prerequisites {
			checked = true
			if request.Mode != installstate.Uninstall || request.Target.Digest() != v.f.plan.Digest() || request.Snapshot.Document().Mode != installstate.Install || request.Snapshot.Document().Stage != installstate.Complete {
				return ErrLifecycle
			}
		}
		return nil
	}
	if _, err := v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts); err != nil || !checked {
		t.Fatal("requested operation preflight was not separate from original evidence")
	}
}

func TestLifecycleKnownUIDPendingRecoveryIsOnlyObservation(t *testing.T) {
	v := newLifecycleFixture(t)
	baseWrite := v.f.access.write
	failNext := false
	v.f.access.write = func(action installstate.Action, key installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		ack, err := baseWrite(action, key, o)
		failNext = true
		return ack, err
	}
	v.f.access.get = func(installstate.Key) error {
		if failNext {
			failNext = false
			return ErrRead
		}
		return nil
	}
	s, err := v.l.Step(context.Background(), v.f.snapshot, v.opts)
	if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
		t.Fatal("effect/readback interruption missing")
	}
	writes, dry, checks := v.f.access.writes, v.f.access.dryRuns, len(v.checks)
	next, err := v.l.Step(context.Background(), s, v.opts)
	if err != nil || next.Document().Pending != nil || len(next.Document().Resources) != 2 || writes != v.f.access.writes || dry != v.f.access.dryRuns || checks != len(v.checks) {
		t.Fatal("settled pending recovery executed another workflow step")
	}
}

func lifecycleTransitionPlans(t *testing.T) (*installrender.Plan, *installrender.Plan) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32)) // fake fixture ONLY
	build := func(legacy bool, predecessors []installpackage.Predecessor) *installrender.Plan {
		letter, source := "d", strings.Repeat("e", 40)
		if legacy {
			letter, source = "a", installrender.LegacySourceSHA
		}
		images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat(letter, 64), API: "registry.example/api@sha256:" + strings.Repeat(letter, 64)}
		payloads, crds, err := installrender.RenderPayloads(images, legacy)
		if err != nil {
			t.Fatal(err)
		}
		body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: source, SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(legacy), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds, Predecessors: predecessors}, payloads)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := installpackage.Sign(body, key)
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := installpackage.Verify(body, sig, payloads, key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		plan, err := installrender.Compile(pkg, installrender.DefaultNamespace, installrender.Profile137)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	previous := build(true, nil)
	target := build(false, []installpackage.Predecessor{{ID: "issue-26", PackageSHA256: previous.Digest(), SourceSHA: previous.Manifest().SourceSHA, Images: previous.Manifest().Images, Namespace: previous.Namespace(), ProfileIDs: []string{previous.Profile().ID}}})
	return previous, target
}

func TestLifecycleSupportedUpgradeAndExactPredecessorRollback(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	v := newLifecycleFixturePlans(t, previous, target)
	s := v.finish(t, v.f.snapshot)
	original := s.Document().Resources
	initialAPI, _ := v.f.engine.inventory(s.Document(), installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: previous.Namespace(), Name: "arcadectl-api"})
	var err error
	s, err = v.l.Begin(context.Background(), s, installstate.Upgrade, target.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	for s.Document().Stage != installstate.Complete {
		before := s.Document()
		s = v.step(t, s)
		if s.Document().Stage != installstate.Complete && (s.Document().ActivePackage != previous.Digest() || s.Document().PreviousPackage != before.PreviousPackage) {
			t.Fatal("active package changed before completion")
		}
	}
	if s.Document().ActivePackage != target.Digest() || s.Document().PreviousPackage != previous.Digest() {
		t.Fatal("upgrade did not record exact predecessor")
	}
	upgradedAPI, _ := v.f.engine.inventory(s.Document(), initialAPI.Key)
	if upgradedAPI.UID == initialAPI.UID {
		t.Fatal("API recreation reused original deleted UID")
	}
	s, err = v.l.Begin(context.Background(), s, installstate.Rollback, previous.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	s = v.finish(t, s)
	if s.Document().ActivePackage != previous.Digest() || s.Document().PreviousPackage != target.Digest() {
		t.Fatal("rollback did not switch to exact authenticated predecessor")
	}
	for _, r := range s.Document().Resources {
		old := original[slices.IndexFunc(original, func(old installstate.Resource) bool { return old.Key == r.Key })]
		if r.TemplateSHA256 != old.TemplateSHA256 || r.Key != initialAPI.Key && r.UID != old.UID {
			t.Fatal("rollback failed whole old template/retained identity restoration")
		}
	}
}

func TestLifecycleFreshPreparingFailsPrerequisitesBeforeAnyEffects(t *testing.T) {
	v := newLifecycleFixture(t)
	d := v.f.snapshot.Document()
	d.Stage = installstate.Preparing
	body, err := installstate.Encode(d, v.f.plan)
	if err != nil {
		t.Fatal(err)
	}
	n, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n.Annotations[installstate.Annotation] = string(body)
	if err := v.f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), n, ""); err != nil {
		t.Fatal(err)
	}
	s, err := v.f.store.Load(context.Background(), v.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	v.fail = Prerequisites
	if _, err := v.l.Step(context.Background(), s, v.opts); !errors.Is(err, ErrLifecycle) || v.f.access.writes != 0 || v.f.nsUpdates != 0 {
		t.Fatal("fresh operation mutated before prerequisites")
	}
	v.fail = 0
	v.finish(t, s)
}

func TestLifecycleUninstallRecoveryAfterAuthorityRemoval(t *testing.T) {
	for _, point := range []string{"one-controller", "both-controllers", "retained-only"} {
		t.Run(point, func(t *testing.T) {
			v := newLifecycleFixture(t)
			s := v.finish(t, v.f.snapshot)
			s, err := v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts)
			if err != nil {
				t.Fatal(err)
			}
			var removed installstate.Key
			for i := 0; i < 100; i++ {
				s = v.step(t, s)
				missing := 0
				for _, key := range v.l.ordered(s.Document()) {
					if installRank(key) == 4 {
						if r, _ := v.f.engine.inventory(s.Document(), key); r == nil {
							missing++
							removed = key
						}
					}
				}
				if point == "one-controller" && missing == 1 || point == "both-controllers" && missing == 2 || point == "retained-only" && s.Document().Stage == installstate.Verifying {
					break
				}
			}
			d := s.Document()
			if d.Stage != installstate.Applying && d.Stage != installstate.Verifying || removed.Name == "" {
				t.Fatal("did not reach exact interruption point")
			}
			d.Stage, d.Revision = installstate.RecoveryRequired, d.Revision+1
			s, err = v.f.store.Commit(context.Background(), s, d)
			if err != nil {
				t.Fatal(err)
			}
			s = v.step(t, s) // RecoveryRequired -> Quiescing
			// A replacement cannot turn absence into a safe recovery decision.
			tmpl, _ := v.f.engine.contracts[d.TargetPackage].Template(removed, false)
			replacement, _ := tmpl.Candidate(strings.Repeat("f", 32))
			replacement.SetUID("foreign-controller")
			replacement.SetResourceVersion("999")
			v.f.access.objects[removed] = replacement
			writes := v.f.access.writes
			if _, err := v.l.Step(context.Background(), s, v.opts); !errors.Is(err, ErrOwnership) || v.f.access.writes != writes {
				t.Fatal("uninstall recovery adopted/recreated a deleted controller")
			}
			delete(v.f.access.objects, removed) // fixture only; no cluster mutation
			beforeEffects := len(v.effects)
			s = v.finish(t, s)
			if s.Document().Installed || len(s.Document().Resources) != 20 || v.private.writes != 2 {
				t.Fatal("uninstall recovery did not preserve the retained installation")
			}
			for _, key := range v.effects[beforeEffects:] {
				if key == removed {
					t.Fatal("recovery replayed already settled controller removal")
				}
			}
		})
	}
}

func (v *lifecycleFixture) admit(t *testing.T, o *unstructured.Unstructured) *unstructured.Unstructured {
	t.Helper()
	o = o.DeepCopy()
	switch o.GetKind() {
	case "CustomResourceDefinition":
		if _, found, _ := unstructured.NestedMap(o.Object, "spec", "conversion"); !found {
			_ = unstructured.SetNestedMap(o.Object, map[string]any{"strategy": "None"}, "spec", "conversion")
		}
	case "Deployment":
		var d appsv1.Deployment
		if decodeServing(o, &d) != nil {
			t.Fatal("fixture deployment decode")
		}
		s, err := v.f.store.Load(context.Background(), v.f.snapshot.Anchor())
		if err != nil {
			t.Fatal(err)
		}
		doc := s.Document()
		digest, paused := doc.TargetPackage, d.Spec.Replicas != nil && *d.Spec.Replicas == 0
		if paused {
			digest = doc.ActivePackage
		}
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
		tmpl, err := v.f.engine.contracts[digest].Template(key, paused)
		if err != nil {
			t.Fatal(err)
		}
		pod, err := tmpl.PodTemplate()
		if err != nil {
			t.Fatal(err)
		}
		d.Spec.Template = *pod
		d.Spec.RevisionHistoryLimit = ptr.To[int32](10)
		d.Spec.ProgressDeadlineSeconds = ptr.To[int32](600)
		if d.Spec.Strategy.Type == "" {
			d.Spec.Strategy.Type = appsv1.RollingUpdateDeploymentStrategyType
		}
		if d.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType {
			d.Spec.Strategy.RollingUpdate = &appsv1.RollingUpdateDeployment{MaxSurge: ptr.To(intstr.FromString("25%")), MaxUnavailable: ptr.To(intstr.FromString("25%"))}
		}
		o = servingObject(t, &d)
	case "Service":
		var service corev1.Service
		if decodeServing(o, &service) != nil {
			t.Fatal("fixture service decode")
		}
		service.Spec.SessionAffinity = corev1.ServiceAffinityNone
		service.Spec.InternalTrafficPolicy = ptr.To(corev1.ServiceInternalTrafficPolicyCluster)
		service.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicySingleStack)
		service.Spec.ClusterIP = "10.96.0.10"
		service.Spec.ClusterIPs = []string{service.Spec.ClusterIP}
		service.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
		o = servingObject(t, &service)
	}
	return o
}

func (v *lifecycleFixture) step(t *testing.T, s *installstate.Snapshot) *installstate.Snapshot {
	t.Helper()
	writes := v.f.access.writes + v.private.writes
	next, err := v.l.Step(context.Background(), s, v.opts)
	if err != nil {
		t.Fatalf("step %s/%s (%d resources): %v", s.Document().Mode, s.Document().Stage, len(s.Document().Resources), err)
	}
	if v.f.access.writes+v.private.writes-writes > 1 || next.Document().Pending != nil {
		t.Fatal("step was not a single settled effect/stage")
	}
	return next
}

func (v *lifecycleFixture) finish(t *testing.T, s *installstate.Snapshot) *installstate.Snapshot {
	t.Helper()
	for i := 0; i < 100 && s.Document().Stage != installstate.Complete; i++ {
		s = v.step(t, s)
	}
	if s.Document().Stage != installstate.Complete {
		t.Fatal("lifecycle did not finish")
	}
	return s
}

func TestLifecycleFreshRetainUninstallAndSamePackageReinstall(t *testing.T) {
	v := newLifecycleFixture(t)
	s := v.finish(t, v.f.snapshot)
	if !s.Document().Installed || len(s.Document().Resources) != 40 || v.private.writes != 2 {
		t.Fatal("fresh completion inventory")
	}
	var lastRank int
	for i, key := range v.effects {
		rank := installRank(key)
		if i > 0 && rank < lastRank {
			t.Fatal("workload or binding started before dependency barrier")
		}
		lastRank = rank
	}
	if v.effects[len(v.effects)-1].Name != "arcadectl-api" || !slices.Contains(v.checks, TargetAuthenticated) {
		t.Fatal("API was not last/authentication barrier missing")
	}
	original := s.Document().Resources
	privateOriginal := map[string]types.UID{}
	for name, obj := range v.private.objects {
		privateOriginal[name] = obj.UID
	}
	start := len(v.effects)
	var err error
	s, err = v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	s = v.finish(t, s)
	if s.Document().Installed || len(s.Document().Resources) != 20 || v.private.writes != 2 {
		t.Fatal("uninstall did not retain exact anchors/credentials")
	}
	if v.effects[start].Kind != "Deployment" || v.effects[start].Name != "arcadectl-api" {
		t.Fatal("API admission was not removed first")
	}
	for _, r := range s.Document().Resources {
		if !r.Retained || !slices.ContainsFunc(original, func(old installstate.Resource) bool { return old.Key == r.Key && old.UID == r.UID }) {
			t.Fatal("retained identity changed")
		}
	}
	s, err = v.l.Begin(context.Background(), s, installstate.Install, v.f.plan.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	s = v.finish(t, s)
	if !s.Document().Installed || len(s.Document().Resources) != 40 || v.private.writes != 2 {
		t.Fatal("reinstall regenerated private credentials")
	}
	for name, uid := range privateOriginal {
		if v.private.objects[name].UID != uid {
			t.Fatal("private original UID changed")
		}
	}
}

func TestLifecycleBarrierFailureHasNoEffectAndRedactsDetail(t *testing.T) {
	for _, gate := range []Checkpoint{CRDsAvailable, AdmissionEffective, ControllersAvailable, TargetAuthenticated} {
		t.Run(fmt.Sprint(gate), func(t *testing.T) {
			v := newLifecycleFixture(t)
			v.fail = gate
			s := v.f.snapshot
			for i := 0; i < 100; i++ {
				writes, nsWrites := v.f.access.writes+v.private.writes, v.f.nsUpdates
				next, err := v.l.Step(context.Background(), s, v.opts)
				if err != nil {
					if !errors.Is(err, ErrLifecycle) || strings.Contains(err.Error(), "private fixture") || v.f.access.writes+v.private.writes != writes || v.f.nsUpdates != nsWrites {
						t.Fatal("barrier failure leaked details or changed authority")
					}
					if s.Document().Installed || s.Document().Stage == installstate.Complete {
						t.Fatal("failure marked installation complete")
					}
					v.fail = 0
					v.finish(t, s)
					return
				}
				s = next
			}
			t.Fatal("required barrier never checked")
		})
	}
}

func TestLifecycleUninstallRepeatsSafetyAndWillNotRemoveRetained(t *testing.T) {
	v := newLifecycleFixture(t)
	s := v.finish(t, v.f.snapshot)
	s, err := v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts)
	if err != nil {
		t.Fatal(err)
	}
	s = v.step(t, s) // Preparing -> Quiescing
	for s.Document().Stage == installstate.Quiescing {
		s = v.step(t, s)
	}
	v.fail = RuntimeStopped
	writes, journalWrites := v.f.access.writes, v.f.nsUpdates
	if _, err := v.l.Step(context.Background(), s, v.opts); !errors.Is(err, ErrLifecycle) || v.f.access.writes != writes || v.f.nsUpdates != journalWrites {
		t.Fatal("authority removed before runtime absence proof")
	}
	v.fail = 0
	s = v.step(t, s)
	v.fail = ColdSafety
	writes = v.f.access.writes
	if _, err := v.l.Step(context.Background(), s, v.opts); !errors.Is(err, ErrLifecycle) || v.f.access.writes != writes {
		t.Fatal("cold proof was not repeated between deletions")
	}
	v.fail = 0
	v.finish(t, s)
}

func TestLifecyclePendingRecoveryDoesNotReplayOrFallThrough(t *testing.T) {
	v := newLifecycleFixture(t)
	baseWrite := v.f.access.write
	v.f.access.write = func(action installstate.Action, key installstate.Key, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
		_, err := baseWrite(action, key, obj)
		if err != nil {
			return nil, err
		}
		// An invalid acknowledgement lacks durable original UID evidence.
		return nil, nil
	}
	pending, err := v.l.Step(context.Background(), v.f.snapshot, v.opts)
	if !errors.Is(err, ErrOutcomeUnknown) || pending.Document().Pending == nil {
		t.Fatal("fixture did not create an interrupted effect")
	}
	writes, dryRuns := v.f.access.writes, v.f.access.dryRuns
	for i := 0; i < 3; i++ {
		if _, err := v.l.Step(context.Background(), pending, v.opts); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("unidentified create was adopted")
		}
	}
	if v.f.access.writes != writes || v.f.access.dryRuns != dryRuns {
		t.Fatal("pending recovery replayed effect/dry-run")
	}
	if _, err := v.l.Begin(context.Background(), pending, installstate.Rollback, v.f.plan.Digest(), v.opts); !errors.Is(err, ErrInvalid) {
		t.Fatal("pending operation switched mode/target")
	}
}

func TestLifecyclePrerequisitesFailBeforeNewJournalOperation(t *testing.T) {
	v := newLifecycleFixture(t)
	s := v.finish(t, v.f.snapshot)
	v.fail = Prerequisites
	before, writes := v.f.nsUpdates, v.f.access.writes
	if _, err := v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts); !errors.Is(err, ErrLifecycle) || v.f.nsUpdates != before || v.f.access.writes != writes {
		t.Fatal("new operation started before prerequisites")
	}
}

func TestLifecycleCompleteRequiresLiveCRDAndAllOriginalTargetShapes(t *testing.T) {
	for _, corrupt := range []string{"crd-status", "public-uid", "controller-ready", "private-uid"} {
		t.Run(corrupt, func(t *testing.T) {
			v := newLifecycleFixture(t)
			s := v.f.snapshot
			for s.Document().Stage != installstate.Verifying {
				s = v.step(t, s)
			}
			for key, obj := range v.f.access.objects {
				if corrupt == "crd-status" && key.Kind == "CustomResourceDefinition" {
					delete(obj.Object, "status")
					break
				}
				if corrupt == "public-uid" && key.Kind == "ServiceAccount" {
					obj.SetUID("replacement-uid")
					break
				}
				if corrupt == "controller-ready" && installRank(key) == 4 {
					_ = unstructured.SetNestedField(obj.Object, int64(0), "status", "readyReplicas")
					break
				}
			}
			if corrupt == "private-uid" {
				v.private.objects[adminauth.CredentialSecretName].UID = "replacement-uid"
			}
			before := v.f.nsUpdates
			if _, err := v.l.Step(context.Background(), s, v.opts); err == nil || v.f.nsUpdates != before {
				t.Fatal("unproved live target was marked complete")
			}
		})
	}
}
