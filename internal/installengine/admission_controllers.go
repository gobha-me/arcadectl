// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type admissionControllerState struct {
	Name       string
	Executing  bool
	Available  bool
	Deployment *appsv1.Deployment
	Sets       []*appsv1.ReplicaSet
	Pods       []*corev1.Pod
}

// Classify the two original signed families independently BEFORE fixtures.
// Use recorded templates, not only the target: quiescence can still execute a
// supported predecessor. Signed execution is deliberately not readiness: a
// failed rollout may retain its original predecessor executor before rollback
// can pause it. This consumes complete unfiltered observations; a paused
// family with ANY executable descendant is not stopped. The caller
// brackets it with ordinary cold safety and repeats the owned baseline before
// sealing. It is not a standalone admission or effect certificate.
func (e *Engine) admissionControllers(ctx context.Context, request LifecycleCheck, o *installobserve.Observation) ([2]admissionControllerState, error) {
	var result [2]admissionControllerState
	if e == nil || ctx == nil || request.Snapshot == nil || o == nil || o.Snapshot() == nil || o.Runtime() == nil {
		return result, ErrAdmission
	}
	s, r := o.Snapshot(), o.Runtime()
	if !completeStoppedLists(s, r) {
		return result, ErrAdmission
	}
	d := request.Snapshot.Document()
	parents := map[string]*appsv1.Deployment{}
	uids := map[types.UID]bool{}
	for index, name := range controllerFamilies {
		state := &result[index]
		state.Name = name
		accountKey := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: name}
		account, template := e.inventory(d, accountKey)
		liveAccount, err := e.access.Get(ctx, accountKey)
		if account == nil || template == nil || err != nil || template.MatchLive(liveAccount, account.UID) != nil {
			return [2]admissionControllerState{}, ErrAdmission
		}
		uids[account.UID] = true
		key := deploymentKey(d.Namespace, name)
		recorded, template := e.inventory(d, key)
		live, err := e.access.Get(ctx, key)
		if recorded == nil {
			if !apierrors.IsNotFound(err) {
				return [2]admissionControllerState{}, ErrAdmission
			}
			continue
		}
		if template == nil || err != nil || template.MatchLive(live, recorded.UID) != nil {
			return [2]admissionControllerState{}, ErrAdmission
		}
		parent := &appsv1.Deployment{}
		if decodeServing(live, parent) != nil || parent.Spec.Paused {
			return [2]admissionControllerState{}, ErrAdmission
		}
		if stoppedDeployment(parent) {
			state.Executing = false
		} else if parent.Spec.Replicas != nil && *parent.Spec.Replicas == 1 {
			state.Executing = true
		} else {
			return [2]admissionControllerState{}, ErrAdmission
		}
		state.Deployment, parents[name] = parent, parent
		uids[parent.UID] = true
	}
	// Repository-only signals are not identity: the API can share a registry
	// repository with both managers. Exact roles, selectors and original UID
	// closure still identify malformed or renamed descendants.
	related := func(metadata metav1.ObjectMeta, spec *corev1.PodSpec) bool {
		if uids[metadata.UID] {
			return true
		}
		for _, owner := range metadata.OwnerReferences {
			if uids[owner.UID] {
				return true
			}
		}
		for _, name := range controllerFamilies {
			if e.familyIdentitySignal(name, metadata, spec) {
				return true
			}
			if parent := parents[name]; parent != nil {
				selector, err := metav1.LabelSelectorAsSelector(parent.Spec.Selector)
				if err != nil || selector.Matches(labels.Set(metadata.Labels)) {
					return true
				}
			}
		}
		return false
	}
	for index := range r.ReplicaSets.Items {
		set := &r.ReplicaSets.Items[index]
		if related(set.ObjectMeta, &set.Spec.Template.Spec) || related(set.Spec.Template.ObjectMeta, &set.Spec.Template.Spec) {
			uids[set.UID] = true
		}
	}
	if closeDescendantUIDs(s, r, uids) != nil {
		return [2]admissionControllerState{}, ErrAdmission
	}
	seen := map[string]bool{}
	for index := range r.Deployments.Items {
		parent := &r.Deployments.Items[index]
		if !related(parent.ObjectMeta, &parent.Spec.Template.Spec) && !related(parent.Spec.Template.ObjectMeta, &parent.Spec.Template.Spec) {
			continue
		}
		if parents[parent.Name] == nil || !reflect.DeepEqual(parent, parents[parent.Name]) || seen[parent.Name] {
			return [2]admissionControllerState{}, ErrAdmission
		}
		seen[parent.Name] = true
	}
	if len(seen) != len(parents) {
		return [2]admissionControllerState{}, ErrAdmission
	}
	for index := range r.ReplicaSets.Items {
		set := &r.ReplicaSets.Items[index]
		if !related(set.ObjectMeta, &set.Spec.Template.Spec) && !related(set.Spec.Template.ObjectMeta, &set.Spec.Template.Spec) {
			continue
		}
		if len(set.OwnerReferences) != 1 {
			return [2]admissionControllerState{}, ErrAdmission
		}
		parent := parents[set.OwnerReferences[0].Name]
		if parent == nil || !controllerSetIdentity(set, parent) || set.CreationTimestamp.IsZero() {
			return [2]admissionControllerState{}, ErrAdmission
		}
		for family := range result {
			if result[family].Name == parent.Name {
				result[family].Sets = append(result[family].Sets, set.DeepCopy())
			}
		}
	}
	selected := map[types.UID]*appsv1.ReplicaSet{}
	for family := range result {
		state := &result[family]
		if !state.Executing {
			for _, set := range state.Sets {
				if !inertReplicaSet(set, state.Deployment) {
					return [2]admissionControllerState{}, ErrAdmission
				}
			}
			continue
		}
		var current *appsv1.ReplicaSet
		executors := 0
		for _, set := range state.Sets {
			if set.Spec.Replicas != nil && *set.Spec.Replicas == 1 {
				executors++
				// The signed replicas-one RollingUpdate has one surge slot.
				// Both predecessor and target chains can execute in a stalled
				// rollout; neither unknown history nor a third executor may.
				if executors > 2 || !e.controllerRuntimeSet(set, state.Deployment, d) {
					return [2]admissionControllerState{}, ErrAdmission
				}
				selected[set.UID] = set
				if controllerTargetTemplate(set, state.Deployment) {
					current = set
				}
			} else if !inertReplicaSet(set, state.Deployment) {
				return [2]admissionControllerState{}, ErrAdmission
			}
		}
		if executors == 0 {
			return [2]admissionControllerState{}, ErrAdmission
		}
		state.Available = executors == 1 && current != nil && availableInstallationDeployment(state.Deployment) && availableControllerSet(current, state.Deployment)
	}
	counts := map[types.UID]int{}
	for index := range s.Pods.Items {
		pod := &s.Pods.Items[index]
		if !related(pod.ObjectMeta, &pod.Spec) {
			continue
		}
		if len(pod.OwnerReferences) != 1 {
			return [2]admissionControllerState{}, ErrAdmission
		}
		set := selected[pod.OwnerReferences[0].UID]
		if set == nil || !servingMetadata(pod.ObjectMeta, d.Namespace) || !originalOwner(pod.ObjectMeta, "apps/v1", "ReplicaSet", set.Name, set.UID) || !validOriginalPodTemplate(pod, set, false) {
			return [2]admissionControllerState{}, ErrAdmission
		}
		counts[set.UID]++
		for family := range result {
			if result[family].Name == set.OwnerReferences[0].Name {
				result[family].Pods = append(result[family].Pods, pod.DeepCopy())
				result[family].Available = result[family].Available && validOriginalPodTemplate(pod, set, true) && readyNamedPod(pod, set.Spec.Template.Spec.Containers[0].Name)
			}
		}
	}
	for uid := range selected {
		if counts[uid] != 1 {
			return [2]admissionControllerState{}, ErrAdmission
		}
	}
	for _, job := range s.Jobs.Items {
		if related(job.ObjectMeta, &job.Spec.Template.Spec) || related(job.Spec.Template.ObjectMeta, &job.Spec.Template.Spec) {
			return [2]admissionControllerState{}, ErrAdmission
		}
	}
	for _, set := range r.StatefulSets.Items {
		if related(set.ObjectMeta, &set.Spec.Template.Spec) || related(set.Spec.Template.ObjectMeta, &set.Spec.Template.Spec) {
			return [2]admissionControllerState{}, ErrAdmission
		}
	}
	for _, set := range r.DaemonSets.Items {
		if related(set.ObjectMeta, &set.Spec.Template.Spec) || related(set.Spec.Template.ObjectMeta, &set.Spec.Template.Spec) {
			return [2]admissionControllerState{}, ErrAdmission
		}
	}
	for _, controller := range r.ReplicationControllers.Items {
		if related(controller.ObjectMeta, nil) || controller.Spec.Template != nil && related(controller.Spec.Template.ObjectMeta, &controller.Spec.Template.Spec) {
			return [2]admissionControllerState{}, ErrAdmission
		}
	}
	for _, job := range r.CronJobs.Items {
		template := job.Spec.JobTemplate.Spec.Template
		if related(job.ObjectMeta, &template.Spec) || related(job.Spec.JobTemplate.ObjectMeta, &template.Spec) || related(template.ObjectMeta, &template.Spec) {
			return [2]admissionControllerState{}, ErrAdmission
		}
	}
	return result, nil
}
