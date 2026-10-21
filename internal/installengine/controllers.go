// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

var ErrControllers = errors.New("original target controller readiness is unproved")

// ClusterControllers implements only ControllersAvailable. Availability is not
// namespace-wide runtime absence, exclusive credential authority, leadership,
// reconciliation progress or authenticated API activation. In particular, a
// shared image repository does not make an API/worker a controller descendant.
type ClusterControllers struct{ prerequisites *ClusterPrerequisites }

func NewClusterControllers(p *ClusterPrerequisites) (*ClusterControllers, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil {
		return nil, ErrInvalid
	}
	return &ClusterControllers{p}, nil
}

func (c *ClusterControllers) Verify(ctx context.Context, request LifecycleCheck) error {
	if c == nil || c.prerequisites == nil || ctx == nil || request.Snapshot == nil || request.Options.Now.IsZero() || request.Checkpoint != ControllersAvailable {
		return ErrInvalid
	}
	d := request.Snapshot.Document()
	if d.Pending != nil || request.Mode != d.Mode || request.Mode == installstate.Uninstall || request.Target == nil || request.Target.Digest() != d.TargetPackage || (d.Stage != installstate.Applying && d.Stage != installstate.Verifying) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	first, err := c.collect(ctx, request)
	if err != nil {
		return ErrControllers
	}
	second, err := c.collect(ctx, request)
	if err != nil || first != second || c.prerequisites.original(ctx, request.Snapshot) != nil {
		return ErrControllers
	}
	return nil
}

type controllerWitness struct {
	Accounts    []corev1.ServiceAccount
	Deployments []appsv1.Deployment
	ReplicaSets []appsv1.ReplicaSet
	Pods        []corev1.Pod
}

func (c *ClusterControllers) collect(ctx context.Context, request LifecycleCheck) ([32]byte, error) {
	var zero [32]byte
	p := c.prerequisites
	o, err := p.observe(ctx, request)
	if err != nil {
		return zero, ErrControllers
	}
	w, err := p.engine.availableControllers(ctx, request, o)
	if err != nil || p.original(ctx, request.Snapshot) != nil {
		return zero, ErrControllers
	}
	slices.SortFunc(w.Accounts, func(a, b corev1.ServiceAccount) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(w.Deployments, func(a, b appsv1.Deployment) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(w.ReplicaSets, func(a, b appsv1.ReplicaSet) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(w.Pods, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	body, err := json.Marshal(w)
	if err != nil || len(body) > 32*1024*1024 {
		return zero, ErrControllers
	}
	return sha256.Sum256(body), nil
}

func (e *Engine) availableControllers(ctx context.Context, request LifecycleCheck, o *installobserve.Observation) (*controllerWitness, error) {
	if o == nil || o.Snapshot() == nil || o.Runtime() == nil {
		return nil, ErrControllers
	}
	s, r := o.Snapshot(), o.Runtime()
	if !completeStoppedLists(s, r) {
		return nil, ErrControllers
	}
	d := request.Snapshot.Document()
	c := e.contracts[d.TargetPackage]
	if c == nil {
		return nil, ErrControllers
	}
	w := &controllerWitness{}
	parents := map[string]*appsv1.Deployment{}
	uids := map[types.UID]bool{}
	for _, name := range controllerFamilies {
		for _, kind := range []string{"ServiceAccount", "Deployment"} {
			key := installstate.Key{APIVersion: "v1", Kind: kind, Namespace: d.Namespace, Name: name}
			if kind == "Deployment" {
				key.APIVersion = "apps/v1"
			}
			recorded, template := e.inventory(d, key)
			target, err := c.Template(key, false)
			if recorded == nil || template == nil || err != nil || recorded.TemplateSHA256 != target.Hash() {
				return nil, ErrControllers
			}
			live, err := e.access.Get(ctx, key)
			if err != nil || target.MatchLive(live, recorded.UID) != nil {
				return nil, ErrControllers
			}
			if kind == "ServiceAccount" {
				var account corev1.ServiceAccount
				if decodeServing(live, &account) != nil {
					return nil, ErrControllers
				}
				w.Accounts = append(w.Accounts, account)
				uids[account.UID] = true
			} else {
				var deployment appsv1.Deployment
				if decodeServing(live, &deployment) != nil || deployment.Spec.Paused || !availableInstallationDeployment(&deployment) {
					return nil, ErrControllers
				}
				parents[name] = &deployment
				uids[deployment.UID] = true
				w.Deployments = append(w.Deployments, deployment)
			}
		}
	}
	// Role-scoped redundant signals and original UID closure identify every
	// descendant even with damaged ownership. Repository-only process absence
	// belongs to shutdown/cold checks, not availability after the API is serving.
	related := func(meta metav1.ObjectMeta, spec *corev1.PodSpec) bool {
		if uids[meta.UID] {
			return true
		}
		for _, owner := range meta.OwnerReferences {
			if uids[owner.UID] {
				return true
			}
		}
		for _, name := range controllerFamilies {
			if e.familyIdentitySignal(name, meta, spec) {
				return true
			}
			selector, err := metav1.LabelSelectorAsSelector(parents[name].Spec.Selector)
			if err != nil || selector.Matches(labels.Set(meta.Labels)) {
				return true
			}
		}
		return false
	}
	// Seed every role-related set before following ownership edges, so a
	// renamed nested descendant cannot evade closure by preceding its parent.
	for i := range r.ReplicaSets.Items {
		item := &r.ReplicaSets.Items[i]
		if related(item.ObjectMeta, &item.Spec.Template.Spec) || related(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			uids[item.UID] = true
		}
	}
	if closeDescendantUIDs(s, r, uids) != nil {
		return nil, ErrControllers
	}
	seen := map[string]bool{}
	for i := range r.Deployments.Items {
		item := &r.Deployments.Items[i]
		if !related(item.ObjectMeta, &item.Spec.Template.Spec) && !related(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			continue
		}
		parent := parents[item.Name]
		if parent == nil || !reflect.DeepEqual(item, parent) {
			return nil, ErrControllers
		}
		seen[item.Name] = true
	}
	if len(seen) != len(parents) {
		return nil, ErrControllers
	}
	sets := map[string][]*appsv1.ReplicaSet{}
	for i := range r.ReplicaSets.Items {
		item := &r.ReplicaSets.Items[i]
		if !related(item.ObjectMeta, &item.Spec.Template.Spec) && !related(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			continue
		}
		if len(item.OwnerReferences) != 1 {
			return nil, ErrControllers
		}
		parent := parents[item.OwnerReferences[0].Name]
		if parent == nil || !controllerSetIdentity(item, parent) || item.CreationTimestamp.IsZero() {
			return nil, ErrControllers
		}
		sets[parent.Name] = append(sets[parent.Name], item)
		uids[item.UID] = true
		w.ReplicaSets = append(w.ReplicaSets, *item.DeepCopy())
	}
	selected := map[types.UID]*appsv1.ReplicaSet{}
	for name, parent := range parents {
		var current *appsv1.ReplicaSet
		for _, set := range sets[name] {
			if controllerTargetTemplate(set, parent) && (current == nil || set.CreationTimestamp.Before(&current.CreationTimestamp) || set.CreationTimestamp.Equal(&current.CreationTimestamp) && set.Name < current.Name) {
				current = set
			}
		}
		if current == nil || !availableControllerSet(current, parent) {
			return nil, ErrControllers
		}
		selected[current.UID] = current
		for _, set := range sets[name] {
			if set.UID != current.UID && !inertReplicaSet(set, parent) {
				return nil, ErrControllers
			}
		}
	}
	podCounts := map[types.UID]int{}
	for i := range s.Pods.Items {
		pod := &s.Pods.Items[i]
		if !related(pod.ObjectMeta, &pod.Spec) {
			continue
		}
		if len(pod.OwnerReferences) != 1 {
			return nil, ErrControllers
		}
		set := selected[pod.OwnerReferences[0].UID]
		if set == nil || !servingMetadata(pod.ObjectMeta, d.Namespace) || !originalOwner(pod.ObjectMeta, "apps/v1", "ReplicaSet", set.Name, set.UID) || !validOriginalPodTemplate(pod, set, true) || !readyNamedPod(pod, set.Spec.Template.Spec.Containers[0].Name) {
			return nil, ErrControllers
		}
		podCounts[set.UID]++
		w.Pods = append(w.Pods, *pod.DeepCopy())
	}
	for uid := range selected {
		if podCounts[uid] != 1 {
			return nil, ErrControllers
		}
	}
	for _, job := range s.Jobs.Items {
		if related(job.ObjectMeta, &job.Spec.Template.Spec) || related(job.Spec.Template.ObjectMeta, &job.Spec.Template.Spec) {
			return nil, ErrControllers
		}
	}
	for _, item := range r.StatefulSets.Items {
		if related(item.ObjectMeta, &item.Spec.Template.Spec) || related(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrControllers
		}
	}
	for _, item := range r.DaemonSets.Items {
		if related(item.ObjectMeta, &item.Spec.Template.Spec) || related(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrControllers
		}
	}
	for _, item := range r.ReplicationControllers.Items {
		if related(item.ObjectMeta, nil) || item.Spec.Template != nil && related(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrControllers
		}
	}
	for _, item := range r.CronJobs.Items {
		t := item.Spec.JobTemplate.Spec.Template
		if related(item.ObjectMeta, &t.Spec) || related(item.Spec.JobTemplate.ObjectMeta, &t.Spec) || related(t.ObjectMeta, &t.Spec) {
			return nil, ErrControllers
		}
	}
	return w, nil
}

// Only common native identity/shape is checked on the defensive copy. Actual
// execution/status must separately satisfy inertReplicaSet or availableControllerSet;
// this normalization is never a readiness or stoppedness proof.
func controllerSetIdentity(rs *appsv1.ReplicaSet, parent *appsv1.Deployment) bool {
	copy := rs.DeepCopy()
	copy.Spec.Replicas = ptr.To[int32](0)
	copy.Status = appsv1.ReplicaSetStatus{ObservedGeneration: copy.Generation}
	return inertReplicaSet(copy, parent)
}

func controllerTargetTemplate(rs *appsv1.ReplicaSet, parent *appsv1.Deployment) bool {
	want, actual := parent.Spec.Template.DeepCopy(), rs.Spec.Template.DeepCopy()
	delete(actual.Labels, appsv1.DefaultDeploymentUniqueLabelKey)
	return normalizeSAAlias(&want.Spec) && normalizeSAAlias(&actual.Spec) && apiequality.Semantic.DeepEqual(want, actual)
}

func availableControllerSet(rs *appsv1.ReplicaSet, parent *appsv1.Deployment) bool {
	return controllerSetIdentity(rs, parent) && controllerTargetTemplate(rs, parent) && rs.Spec.Replicas != nil && *rs.Spec.Replicas == 1 && rs.Status.ObservedGeneration == rs.Generation && rs.Status.Replicas == 1 && rs.Status.FullyLabeledReplicas == 1 && rs.Status.ReadyReplicas == 1 && rs.Status.AvailableReplicas == 1 && (rs.Status.TerminatingReplicas == nil || *rs.Status.TerminatingReplicas == 0) && nativePositiveRevision(parent.Annotations["deployment.kubernetes.io/revision"]) && rs.Annotations["deployment.kubernetes.io/revision"] == parent.Annotations["deployment.kubernetes.io/revision"] && rs.Annotations[installstate.MutationAnnotation] == parent.Annotations[installstate.MutationAnnotation] && rs.Annotations["deployment.kubernetes.io/desired-replicas"] == "1" && rs.Annotations["deployment.kubernetes.io/max-replicas"] == "2"
}
