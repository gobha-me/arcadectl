// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

type baselineDescendantsFixture struct {
	f       *fixture
	d       installstate.Document
	parents map[string]*baselineParent
	access  map[installstate.Key]admissionIdentity
	objects *installobserve.ExecutableCollections
}

// Synthetic whole signed chains deliberately have no Ready condition, node,
// observed generation or minimum count. Native admission is a separate gate.
func newBaselineDescendantsFixture(t *testing.T) *baselineDescendantsFixture {
	return newBaselineDescendantsFixtureWithPlans(t, fixturePlan(t))
}

func newBaselineDescendantsFixtureWithPlans(t *testing.T, plans ...*installrender.Plan) *baselineDescendantsFixture {
	t.Helper()
	f := newFixtureWithPlans(t, false, plans...)
	v := &baselineDescendantsFixture{f: f, d: f.snapshot.Document(), parents: map[string]*baselineParent{}, access: map[installstate.Key]admissionIdentity{}, objects: &installobserve.ExecutableCollections{
		Pods: &corev1.PodList{}, Jobs: &batchv1.JobList{}, Deployments: &appsv1.DeploymentList{}, ReplicaSets: &appsv1.ReplicaSetList{},
		StatefulSets: &appsv1.StatefulSetList{}, DaemonSets: &appsv1.DaemonSetList{}, ReplicationControllers: &corev1.ReplicationControllerList{}, CronJobs: &batchv1.CronJobList{},
	}}
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
		v.access[installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: v.d.Namespace, Name: name}] = admissionIdentity{UID: types.UID("original-" + name + "-account")}
	}
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
		key := deploymentKey(v.d.Namespace, name)
		template, err := f.engine.contracts[v.d.TargetPackage].Template(key, false)
		if err != nil {
			t.Fatal("signed parent fixture unavailable")
		}
		live := testBaselineParentLive(t, template, strings.Repeat("b", 32))
		live.SetUID(types.UID("original-" + name + "-parent"))
		live.SetResourceVersion("17")
		live.SetGeneration(1)
		v.d.Resources = append(v.d.Resources, installstate.Resource{Key: key, UID: live.GetUID(), TemplateSHA256: template.Hash(), Phase: template.Phase()})
		parent, err := f.engine.originalBaselineParent(v.d, key, live)
		t.Cleanup(parent.release)
		if err != nil {
			t.Fatal("original parent fixture unavailable")
		}
		v.parents[name] = parent
		v.objects.Deployments.Items = append(v.objects.Deployments.Items, *parent.parent.DeepCopy())
		set := inertFixture(parent.parent, "bcdfg23456", 1)
		set.CreationTimestamp = metav1.NewTime(time.Unix(100, 0).UTC())
		set.Spec.Template = *parent.parent.Spec.Template.DeepCopy()
		set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg23456"
		set.Labels = maps.Clone(set.Spec.Template.Labels)
		set.Spec.Replicas = ptr.To[int32](1)
		set.Status = appsv1.ReplicaSetStatus{}
		v.objects.ReplicaSets.Items = append(v.objects.ReplicaSets.Items, *set)
		v.objects.Pods.Items = append(v.objects.Pods.Items, *baselineDescendantPod(set, "bcdfg"))
	}
	return v
}

func TestBaselineDescendantsMixedSignedUpgradeAndRollback(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	for _, mode := range []installstate.Mode{installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			v := newBaselineDescendantsFixtureWithPlans(t, previous, target)
			v.d.Mode, v.d.ActivePackage, v.d.TargetPackage, v.d.Installed = mode, previous.Digest(), target.Digest(), true
			if mode == installstate.Rollback {
				v.d.ActivePackage, v.d.TargetPackage, v.d.PreviousPackage = target.Digest(), previous.Digest(), previous.Digest()
			}
			for i := range v.objects.ReplicaSets.Items {
				old := &v.objects.ReplicaSets.Items[i]
				old.Spec.Replicas = ptr.To[int32](0)
				pod := &v.objects.Pods.Items[i]
				stamp := metav1.NewTime(time.Unix(2000000000, 0).UTC())
				pod.DeletionTimestamp, pod.DeletionGracePeriodSeconds = &stamp, ptr.To[int64](30)
				parent := v.parents[old.OwnerReferences[0].Name]
				template, err := v.f.engine.contracts[target.Digest()].Template(deploymentKey(v.d.Namespace, parent.parent.Name), false)
				if err != nil {
					t.Fatal("signed target unavailable")
				}
				targetPod, err := template.PodTemplate()
				if err != nil || reflect.DeepEqual(targetPod.Spec, old.Spec.Template.Spec) {
					t.Fatal("transition does not have genuinely distinct signed payloads")
				}
				set := inertFixture(parent.parent, "cdfgh23456", 2)
				set.CreationTimestamp = metav1.NewTime(time.Unix(102, 0).UTC())
				set.Spec.Template = *targetPod
				set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "cdfgh23456"
				set.Labels = maps.Clone(set.Spec.Template.Labels)
				set.Spec.Replicas = ptr.To[int32](1)
				set.Status = appsv1.ReplicaSetStatus{}
				v.objects.ReplicaSets.Items = append(v.objects.ReplicaSets.Items, *set)
				v.objects.Pods.Items = append(v.objects.Pods.Items, *baselineDescendantPod(set, "cdfgh"))
				// Only mutate the three original entries, not newly appended ones.
				if i == 2 {
					break
				}
			}
			before := v.objects.DeepCopy()
			w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects)
			if err != nil || w == nil || len(w.sets) != 6 || len(w.pods) != 6 || !reflect.DeepEqual(before, v.objects) {
				t.Fatal("mixed signed predecessor/target identity refused or original evidence changed")
			}
			// LIST ordering has no authority significance.
			for i, j := 0, len(v.objects.ReplicaSets.Items)-1; i < j; i, j = i+1, j-1 {
				v.objects.ReplicaSets.Items[i], v.objects.ReplicaSets.Items[j] = v.objects.ReplicaSets.Items[j], v.objects.ReplicaSets.Items[i]
			}
			for i, j := 0, len(v.objects.Pods.Items)-1; i < j; i, j = i+1, j-1 {
				v.objects.Pods.Items[i], v.objects.Pods.Items[j] = v.objects.Pods.Items[j], v.objects.Pods.Items[i]
			}
			reordered, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects)
			if err != nil || !reflect.DeepEqual(w, reordered) {
				t.Fatal("LIST order changed original descendant closure")
			}
			// A stalled rollout may still have both distinct signed revisions
			// at replicas one. Neither availability nor the new parent wins
			// identity authority over its authenticated predecessor.
			for i := range v.objects.ReplicaSets.Items {
				v.objects.ReplicaSets.Items[i].Spec.Replicas = ptr.To[int32](1)
			}
			if coexist, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects); err != nil || !reflect.DeepEqual(w, coexist) {
				t.Fatal("distinct signed predecessor and target executors cannot coexist")
			}
		})
	}
}

func TestBaselineDescendantsUnreferencedSignedPackageIsNotAuthority(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	unused := fixturePlanImages(t, previous.Namespace(), previous.Profile().ID, installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("f", 64), API: "registry.example/api@sha256:" + strings.Repeat("e", 64)})
	if unused.Digest() == previous.Digest() || unused.Digest() == target.Digest() {
		t.Fatal("unused package fixture is not independent")
	}
	v := newBaselineDescendantsFixtureWithPlans(t, previous, target, unused)
	v.d.Mode, v.d.ActivePackage, v.d.TargetPackage, v.d.Installed = installstate.Upgrade, previous.Digest(), target.Digest(), true
	set := &v.objects.ReplicaSets.Items[0]
	template, err := v.f.engine.contracts[unused.Digest()].Template(deploymentKey(v.d.Namespace, set.OwnerReferences[0].Name), false)
	if err != nil {
		t.Fatal("unused authenticated package template unavailable")
	}
	pod, err := template.PodTemplate()
	if err != nil {
		t.Fatal("unused authenticated template unavailable")
	}
	set.Spec.Template = *pod
	set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg23456"
	set.Labels = maps.Clone(set.Spec.Template.Labels)
	v.objects.Pods.Items[0] = *baselineDescendantPod(set, "bcdfg")
	if w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects); err == nil || w != nil {
		t.Fatal("authenticated but unreferenced package acquired executor authority")
	}
}

func baselineDescendantPod(set *appsv1.ReplicaSet, suffix string) *corev1.Pod {
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{
		Name: set.Name + "-" + suffix, GenerateName: set.Name + "-", Namespace: set.Namespace, UID: types.UID(string(set.UID) + "-" + suffix), ResourceVersion: "19", CreationTimestamp: metav1.NewTime(time.Unix(101, 0).UTC()),
		Labels: maps.Clone(set.Spec.Template.Labels), Annotations: maps.Clone(set.Spec.Template.Annotations), OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", set.Name, set.UID),
	}, Spec: *set.Spec.Template.Spec.DeepCopy()}
	pod.Spec.EnableServiceLinks = ptr.To(true)
	pod.Spec.Tolerations = []corev1.Toleration{
		{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](300)},
		{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](300)},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, fixtureTokenVolume("kube-api-access-bcdfg"))
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "kube-api-access-bcdfg", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true})
	return pod
}

func TestBaselineDescendantsOriginalIdentityWithoutReadiness(t *testing.T) {
	for _, scenario := range []string{"unscheduled", "no-pods", "no-sets", "native-list-omission", "draining", "zero-grace", "foreground-set-live-parent", "foreground-pod", "multiple-drains", "inert-history", "shared-repository-fixture", "no-parents"} {
		t.Run(scenario, func(t *testing.T) {
			v := newBaselineDescendantsFixture(t)
			wantSets, wantPods := 3, 3
			switch scenario {
			case "no-pods":
				v.objects.Pods.Items = nil
				wantPods = 0
			case "no-sets":
				v.objects.Pods.Items = nil
				v.objects.ReplicaSets.Items = nil
				wantPods, wantSets = 0, 0
			case "no-parents":
				v.parents = map[string]*baselineParent{}
				v.objects.Deployments.Items = nil
				v.objects.Pods.Items = nil
				v.objects.ReplicaSets.Items = nil
				wantPods, wantSets = 0, 0
			case "native-list-omission":
				for i := range v.objects.Deployments.Items {
					v.objects.Deployments.Items[i].TypeMeta = metav1.TypeMeta{}
				}
				for i := range v.objects.ReplicaSets.Items {
					v.objects.ReplicaSets.Items[i].TypeMeta = metav1.TypeMeta{}
				}
				for i := range v.objects.Pods.Items {
					v.objects.Pods.Items[i].TypeMeta = metav1.TypeMeta{}
				}
			case "draining", "zero-grace", "multiple-drains":
				for i := range v.objects.ReplicaSets.Items {
					v.objects.ReplicaSets.Items[i].Spec.Replicas = ptr.To[int32](0)
				}
				for i := range v.objects.Pods.Items {
					p := &v.objects.Pods.Items[i]
					stamp := metav1.NewTime(time.Unix(2000000000, 0).UTC())
					p.DeletionTimestamp = &stamp
					p.DeletionGracePeriodSeconds = ptr.To[int64](30)
					if scenario == "zero-grace" {
						p.DeletionGracePeriodSeconds = ptr.To[int64](0)
					}
				}
				if scenario == "multiple-drains" {
					for _, suffix := range []string{"cdfgh", "dfghj", "fghjk"} {
						p := v.objects.Pods.Items[0].DeepCopy()
						p.Name = p.GenerateName + suffix
						p.UID = types.UID("original-draining-" + suffix)
						v.objects.Pods.Items = append(v.objects.Pods.Items, *p)
					}
					wantPods = 6
				}
			case "foreground-set-live-parent", "foreground-pod":
				stamp := metav1.NewTime(time.Unix(200, 0).UTC())
				s := &v.objects.ReplicaSets.Items[0]
				s.DeletionTimestamp = &stamp
				s.DeletionGracePeriodSeconds = ptr.To[int64](0)
				s.Finalizers = []string{metav1.FinalizerDeleteDependents}
				if scenario == "foreground-pod" {
					p := &v.objects.Pods.Items[0]
					p.DeletionTimestamp = &stamp
					p.DeletionGracePeriodSeconds = ptr.To[int64](0)
					p.Finalizers = []string{metav1.FinalizerDeleteDependents}
				}
			case "inert-history":
				s := inertFixture(v.parents["arcadectl-api"].parent, "cdfgh23456", 2)
				s.CreationTimestamp = metav1.NewTime(time.Unix(50, 0).UTC())
				v.objects.ReplicaSets.Items = append(v.objects.ReplicaSets.Items, *s)
				wantSets = 4
			case "shared-repository-fixture":
				v.objects.Jobs.Items = append(v.objects.Jobs.Items, batchv1.Job{TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: metav1.ObjectMeta{Name: "proof-fixture", Namespace: v.d.Namespace, UID: "original-tokenless-fixture", ResourceVersion: "21"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "proof-tokenless", AutomountServiceAccountToken: ptr.To(false), Containers: []corev1.Container{{Name: "fixture", Image: v.f.plan.Manifest().Images.Controller}}}}}})
			}
			before := v.objects.DeepCopy()
			writes := v.f.access.writes
			w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects)
			if err != nil || w == nil || len(w.sets) != wantSets || len(w.pods) != wantPods {
				t.Fatal("original process identity incorrectly required Ready, minimum count, or stoppedness")
			}
			if !reflect.DeepEqual(before, v.objects) || v.f.access.writes != writes {
				t.Fatal("identity classifier mutated source evidence or performed an effect")
			}
		})
	}
}

func TestBaselineDescendantsRefusesForeignAndMalformedClosure(t *testing.T) {
	for _, scenario := range []string{"missing-parent", "parent-replacement", "missing-set", "set-owner-uid", "set-owner-kind", "set-owner-flags", "set-extra-owner", "pod-owner-uid", "pod-owner-kind", "pod-owner-flags", "pod-extra-owner", "alias", "image", "token", "pod-finalizer", "pod-duplicate-finalizer", "pod-zero-timestamp", "pod-negative-grace", "pod-oversized-grace", "pod-grace-without-delete", "set-positive-grace", "set-finalizer", "historical-executor", "duplicate-uid", "duplicate-key", "nonnumeric-rv", "nil-collection", "reserved-admin-job", "nested-unsupported-owner", "missing-account", "partial-typemeta", "api-orphan"} {
		t.Run(scenario, func(t *testing.T) {
			v := newBaselineDescendantsFixture(t)
			s := &v.objects.ReplicaSets.Items[0]
			p := &v.objects.Pods.Items[0]
			stamp := metav1.NewTime(time.Unix(200, 0).UTC())
			switch scenario {
			case "missing-parent":
				delete(v.parents, "arcadectl-controller")
				v.objects.Deployments.Items = v.objects.Deployments.Items[1:]
			case "parent-replacement":
				v.objects.Deployments.Items[0].UID = "replacement-parent"
			case "missing-set":
				v.objects.ReplicaSets.Items = v.objects.ReplicaSets.Items[1:]
			case "set-owner-uid":
				s.OwnerReferences[0].UID = "foreign-parent"
			case "set-owner-kind":
				s.OwnerReferences[0].Kind = "Job"
			case "set-owner-flags":
				s.OwnerReferences[0].Controller = ptr.To(false)
			case "set-extra-owner":
				s.OwnerReferences = append(s.OwnerReferences, s.OwnerReferences[0])
			case "pod-owner-uid":
				p.OwnerReferences[0].UID = "foreign-set"
			case "pod-owner-kind":
				p.OwnerReferences[0].Kind = "Deployment"
			case "pod-owner-flags":
				p.OwnerReferences[0].BlockOwnerDeletion = ptr.To(false)
			case "pod-extra-owner":
				p.OwnerReferences = append(p.OwnerReferences, p.OwnerReferences[0])
			case "alias":
				p.Spec.DeprecatedServiceAccount = "arcadectl-destroy-admin"
			case "image":
				p.Spec.Containers[0].Image = "foreign.example/image:latest"
			case "token":
				p.Spec.Volumes[len(p.Spec.Volumes)-1].Projected.Sources[0].ServiceAccountToken.ExpirationSeconds = ptr.To[int64](3600)
			case "pod-finalizer", "pod-duplicate-finalizer":
				p.DeletionTimestamp = &stamp
				p.DeletionGracePeriodSeconds = ptr.To[int64](0)
				p.Finalizers = []string{"foreign.example/hold"}
				if scenario == "pod-duplicate-finalizer" {
					s.DeletionTimestamp = &stamp
					p.Finalizers = []string{metav1.FinalizerDeleteDependents, metav1.FinalizerDeleteDependents}
				}
			case "pod-zero-timestamp":
				p.DeletionTimestamp = &metav1.Time{}
			case "pod-negative-grace":
				p.DeletionTimestamp = &stamp
				p.DeletionGracePeriodSeconds = ptr.To[int64](-1)
			case "pod-oversized-grace":
				p.DeletionTimestamp = &stamp
				p.DeletionGracePeriodSeconds = ptr.To[int64](31)
			case "pod-grace-without-delete":
				p.DeletionGracePeriodSeconds = ptr.To[int64](0)
			case "set-positive-grace":
				s.DeletionTimestamp = &stamp
				s.DeletionGracePeriodSeconds = ptr.To[int64](1)
			case "set-finalizer":
				s.DeletionTimestamp = &stamp
				s.Finalizers = []string{"foreign.example/hold"}
			case "historical-executor":
				s.Spec.Replicas = ptr.To[int32](0)
				s.Spec.Template.Spec.Containers[0].Image = "obsolete.example/image:latest"
				s.Status = appsv1.ReplicaSetStatus{ObservedGeneration: s.Generation}
				p.Spec.Containers[0].Image = s.Spec.Template.Spec.Containers[0].Image
			case "duplicate-uid":
				p.UID = s.UID
			case "duplicate-key":
				copy := p.DeepCopy()
				copy.UID = "duplicate-key-new-uid"
				v.objects.Pods.Items = append(v.objects.Pods.Items, *copy)
			case "nonnumeric-rv":
				p.ResourceVersion = "opaque"
			case "nil-collection":
				v.objects.CronJobs = nil
			case "reserved-admin-job", "nested-unsupported-owner":
				job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "foreign-job", Namespace: v.d.Namespace, UID: "foreign-job-uid", ResourceVersion: "22"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "arcadectl-destroy-admin"}}}}
				if scenario == "nested-unsupported-owner" {
					job.Spec.Template.Spec.ServiceAccountName = "unreserved"
					job.OwnerReferences = fixtureOwner("apps/v1", "ReplicaSet", s.Name, s.UID)
				}
				v.objects.Jobs.Items = append(v.objects.Jobs.Items, job)
			case "missing-account":
				delete(v.access, installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: v.d.Namespace, Name: "arcadectl-destroy-admin"})
			case "partial-typemeta":
				p.TypeMeta = metav1.TypeMeta{Kind: "Pod"}
			case "api-orphan":
				p = &v.objects.Pods.Items[2]
				p.OwnerReferences = nil
			}
			var before *installobserve.ExecutableCollections
			if completeBaselineExecutableCollections(v.objects) {
				before = v.objects.DeepCopy()
			}
			if w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects); err == nil || w != nil {
				t.Fatal("foreign or malformed process acquired original installation identity")
			}
			if before != nil && !reflect.DeepEqual(before, v.objects) {
				t.Fatal("refusal mutated source evidence")
			}
		})
	}
}

func TestBaselineExecutableNodeRefusesTypedNilAndMismatchedCollection(t *testing.T) {
	var nilPod *corev1.Pod
	for _, item := range []runtime.Object{nil, nilPod, &batchv1.Job{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "test", UID: "foreign", ResourceVersion: "1"}}, &batchv1.Job{}} {
		if node, err := baselineExecutableNodeFor(item, baselineExecutableCollections[0], "test"); err == nil || node != nil {
			t.Fatal("nil or mismatched typed object acquired native collection identity")
		}
	}
}

func TestBaselineDescendantsCompleteCollectionAndUIDOnlyClosure(t *testing.T) {
	for index := 0; index < 8; index++ {
		t.Run(baselineExecutableCollections[index].kind, func(t *testing.T) {
			v := newBaselineDescendantsFixture(t)
			reflect.ValueOf(v.objects).Elem().Field(index).SetZero()
			if w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects); err == nil || w != nil {
				t.Fatal("incomplete native collection supplied identity proof")
			}
		})
	}
	for _, seed := range []string{"parent", "access", "nested"} {
		t.Run(seed, func(t *testing.T) {
			v := newBaselineDescendantsFixture(t)
			uid := v.parents["arcadectl-api"].parent.UID
			if seed == "access" {
				uid = v.access[installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: v.d.Namespace, Name: "arcadectl-api"}].UID
			}
			job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-parent", Namespace: v.d.Namespace, UID: "unrelated-producer", ResourceVersion: "31", OwnerReferences: []metav1.OwnerReference{{APIVersion: "foreign.example/v1", Kind: "Unrelated", Name: "unrelated-owner", UID: uid, Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)}}}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "nonreserved"}}}}
			for _, family := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
				if v.f.engine.familyIdentitySignal(family, job.ObjectMeta, &job.Spec.Template.Spec) || v.f.engine.familyIdentitySignal(family, job.Spec.Template.ObjectMeta, &job.Spec.Template.Spec) {
					t.Fatal("UID-only control unexpectedly has a family identity signal")
				}
			}
			v.objects.Jobs.Items = append(v.objects.Jobs.Items, job)
			if seed == "nested" {
				v.objects.Pods.Items = append(v.objects.Pods.Items, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-child", Namespace: v.d.Namespace, UID: "unrelated-child-uid", ResourceVersion: "32", OwnerReferences: []metav1.OwnerReference{{APIVersion: "foreign.example/v1", Kind: "Unrelated", Name: "unrelated", UID: job.UID}}}, Spec: corev1.PodSpec{ServiceAccountName: "nonreserved"}})
			}
			if w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects); err == nil || w != nil {
				t.Fatal("malformed UID-only owner edge escaped original family closure")
			}
		})
	}
}

func TestBaselineDescendantsOriginalParentForegroundAndExecutorBound(t *testing.T) {
	t.Run("original-parent-deleting", func(t *testing.T) {
		v := newBaselineDescendantsFixture(t)
		parent := v.parents["arcadectl-controller"]
		v.d.Mode, v.d.ActivePackage, v.d.Installed = installstate.Uninstall, v.d.TargetPackage, true
		v.d.Pending = &installstate.Pending{Action: installstate.Delete, Key: deploymentKey(v.d.Namespace, parent.parent.Name), BeforeUID: parent.parent.UID, BeforeResourceVersion: parent.parent.ResourceVersion, BeforeSHA256: parent.template.Hash(), CreateNonce: strings.Repeat("c", 32)}
		live := parent.whole.DeepCopy()
		stamp := metav1.NewTime(time.Unix(200, 0).UTC())
		live.SetDeletionTimestamp(&stamp)
		live.SetFinalizers([]string{metav1.FinalizerDeleteDependents})
		live.SetDeletionGracePeriodSeconds(ptr.To[int64](0))
		live.SetResourceVersion("18")
		original, err := v.f.engine.originalBaselineParent(v.d, v.d.Pending.Key, live)
		t.Cleanup(original.release)
		if err != nil || original == nil {
			t.Fatal("original foreground parent fixture refused")
		}
		v.parents[original.parent.Name] = original
		v.objects.Deployments.Items[0] = *original.parent.DeepCopy()
		p := &v.objects.Pods.Items[0]
		p.DeletionTimestamp = &stamp
		p.DeletionGracePeriodSeconds = ptr.To[int64](30)
		if w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects); err != nil || w == nil || len(w.pods) != 3 {
			t.Fatal("original foreground parent lost signed draining descendants")
		}
	})
	t.Run("third-replicas-one-set", func(t *testing.T) {
		v := newBaselineDescendantsFixture(t)
		for index, hash := range []string{"cdfgh23456", "dfghj23456"} {
			set := v.objects.ReplicaSets.Items[0].DeepCopy()
			set.Name = "arcadectl-controller-" + hash
			set.UID = types.UID("original-additional-set-" + hash)
			set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
			set.Labels = maps.Clone(set.Spec.Template.Labels)
			set.Spec.Selector.MatchLabels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
			v.objects.ReplicaSets.Items = append(v.objects.ReplicaSets.Items, *set)
			w, err := v.f.engine.baselineDescendants(v.d, v.parents, v.access, v.objects)
			if index == 0 && (err != nil || w == nil) {
				t.Fatal("two bounded signed sets refused")
			}
			if index == 1 && (err == nil || w != nil) {
				t.Fatal("third executing set escaped signed replica bound")
			}
		}
	})
}
