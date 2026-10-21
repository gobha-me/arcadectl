// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Process identity, not installer ownership, readiness, stoppedness, coldness
// or cleanup authority. The caller still owes actual behavioral proof and
// unchanged whole opening/closing observations. Draining Pods remain present.
type baselineFamilyWitness struct {
	sets map[installstate.Key]types.UID
	pods map[installstate.Key]types.UID
}

type baselineExecutableNode struct {
	key      installstate.Key
	object   runtime.Object
	metadata metav1.ObjectMeta
	template *corev1.PodTemplateSpec
	spec     *corev1.PodSpec
}

// Pure three-family closure over ALL eight complete native collections. Names,
// identities, selectors and even malformed owner references select
// suspects; only the exact original Deployment -> ReplicaSet -> admitted Pod
// chain can classify a process. Missing parents are never inferred from a
// descendant UID. No availability or minimum Pod/cardinality gate is applied.
func (e *Engine) baselineDescendants(d installstate.Document, parents map[string]*baselineParent, access map[installstate.Key]admissionIdentity, objects *installobserve.ExecutableCollections) (*baselineFamilyWitness, error) {
	if e == nil || !e.baselineObservable(d) || parents == nil || access == nil || !completeBaselineExecutableCollections(objects) {
		return nil, ErrSecurityBaseline
	}
	objects = objects.DeepCopy()
	nodes := map[types.UID]*baselineExecutableNode{}
	keys := map[installstate.Key]bool{}
	selected := map[types.UID]bool{}
	children := map[types.UID][]types.UID{}
	selectors := map[string]labels.Selector{}
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api", "arcadectl-destroy-admin"} {
		key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: name}
		identity := access[key]
		if !receiptUID.MatchString(string(identity.UID)) {
			return nil, ErrSecurityBaseline
		}
	}
	for key, identity := range access {
		if !accessRetirementKey(key) || key.Namespace != "" && key.Namespace != d.Namespace || !receiptUID.MatchString(string(identity.UID)) {
			return nil, ErrSecurityBaseline
		}
		selected[identity.UID] = true
	}
	for name, original := range parents {
		if original == nil || original.whole == nil || original.parent == nil || original.template == nil || name != "arcadectl-controller" && name != "arcadectl-destroy-controller" && name != "arcadectl-api" || name != original.parent.Name || original.parent.Namespace != d.Namespace || original.parent.UID != original.whole.GetUID() || original.parent.Spec.Selector == nil || len(original.parent.Spec.Selector.MatchLabels) == 0 {
			return nil, ErrSecurityBaseline
		}
		selector, err := metav1.LabelSelectorAsSelector(original.parent.Spec.Selector)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		selectors[name] = selector
		selected[original.parent.UID] = true
	}
	for index, list := range []runtime.Object{objects.Pods, objects.Jobs, objects.Deployments, objects.ReplicaSets, objects.StatefulSets, objects.DaemonSets, objects.ReplicationControllers, objects.CronJobs} {
		items, err := meta.ExtractList(list)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		collection := baselineExecutableCollections[index]
		for _, item := range items {
			node, err := baselineExecutableNodeFor(item, collection, d.Namespace)
			if err != nil || nodes[node.metadata.UID] != nil || keys[node.key] {
				return nil, ErrSecurityBaseline
			}
			nodes[node.metadata.UID], keys[node.key] = node, true
			for _, owner := range node.metadata.OwnerReferences {
				children[owner.UID] = append(children[owner.UID], node.metadata.UID)
			}
			if baselineReservedAccount(node.key.Name) || baselineReservedAccount(node.spec.ServiceAccountName) || baselineReservedAccount(node.spec.DeprecatedServiceAccount) {
				selected[node.metadata.UID] = true
			}
			for _, family := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
				// Repository sharing is not process identity. Tokenless installer
				// fixtures may use the same image; cold/stop checks retain their
				// separate repository-wide absence obligations.
				if e.familyIdentitySignal(family, node.metadata, node.spec) || node.template != nil && e.familyIdentitySignal(family, node.template.ObjectMeta, node.spec) || selectors[family] != nil && selectors[family].Matches(labels.Set(node.metadata.Labels)) {
					selected[node.metadata.UID] = true
				}
			}
		}
	}
	// Close every owner edge before classifying, including wrong owner kinds
	// or controller flags. Selection is order-independent; those malformed
	// edges must then fail the strict original chain rather than hide a child.
	queue := make([]types.UID, 0, len(selected))
	for uid := range selected {
		queue = append(queue, uid)
	}
	for index := 0; index < len(queue); index++ {
		for _, child := range children[queue[index]] {
			if !selected[child] {
				selected[child] = true
				queue = append(queue, child)
			}
		}
	}
	witness := &baselineFamilyWitness{sets: map[installstate.Key]types.UID{}, pods: map[installstate.Key]types.UID{}}
	seenParents := map[string]bool{}
	signedSets := map[types.UID]*appsv1.ReplicaSet{}
	executingSets := map[string]int{}
	for uid, node := range nodes {
		if !selected[uid] {
			continue
		}
		switch object := node.object.(type) {
		case *appsv1.Deployment:
			original := parents[object.Name]
			if original == nil || !reflect.DeepEqual(object, original.parent) || seenParents[object.Name] {
				return nil, ErrSecurityBaseline
			}
			seenParents[object.Name] = true
		case *appsv1.ReplicaSet:
			if len(object.OwnerReferences) != 1 {
				return nil, ErrSecurityBaseline
			}
			original := parents[object.OwnerReferences[0].Name]
			if original == nil || !originalOwner(object.ObjectMeta, "apps/v1", "Deployment", original.parent.Name, original.parent.UID) || object.CreationTimestamp.IsZero() {
				return nil, ErrSecurityBaseline
			}
			comparison := object.DeepCopy()
			// An original old ReplicaSet can be foreground-deleted while its
			// Deployment remains live. This validates metadata, not DELETE
			// authority or completion; the original owner chain is unchanged.
			metadata, err := baselineDescendantMetadata(object.ObjectMeta, d.Namespace, "ReplicaSet", nil, true)
			if err != nil {
				return nil, ErrSecurityBaseline
			}
			comparison.ObjectMeta = metadata
			if e.controllerRuntimeSet(comparison, original.parent, d) {
				if *object.Spec.Replicas == 1 {
					executingSets[original.parent.Name]++
					if executingSets[original.parent.Name] > 2 {
						return nil, ErrSecurityBaseline
					}
				}
				signedSets[uid] = object
			} else if !inertReplicaSet(comparison, original.parent) {
				return nil, ErrSecurityBaseline
			}
			witness.sets[node.key] = uid
		case *corev1.Pod:
			// Classified in a separate pass, independently of LIST order.
		default:
			// Alternate producers, foreign originals and arbitrary descendants
			// remain observable negative-proof subjects, never original process
			// identity or cleanup authority. Their presence refuses this proof.
			return nil, ErrSecurityBaseline
		}
	}
	if len(seenParents) != len(parents) {
		return nil, ErrSecurityBaseline
	}
	for uid, node := range nodes {
		pod, ok := node.object.(*corev1.Pod)
		if !ok || !selected[uid] {
			continue
		}
		if len(pod.OwnerReferences) != 1 {
			return nil, ErrSecurityBaseline
		}
		set := signedSets[pod.OwnerReferences[0].UID]
		if set == nil || !originalOwner(pod.ObjectMeta, "apps/v1", "ReplicaSet", set.Name, set.UID) || !validOriginalPodTemplate(pod, set, false) || pod.CreationTimestamp.IsZero() {
			return nil, ErrSecurityBaseline
		}
		parent := parents[set.OwnerReferences[0].Name]
		foreground := set.DeletionTimestamp != nil || parent.parent.DeletionTimestamp != nil
		if _, err := baselineDescendantMetadata(pod.ObjectMeta, d.Namespace, "Pod", set.Spec.Template.Spec.TerminationGracePeriodSeconds, foreground); err != nil {
			return nil, ErrSecurityBaseline
		}
		witness.pods[node.key] = uid
	}
	return witness, nil
}

func completeBaselineExecutableCollections(c *installobserve.ExecutableCollections) bool {
	return c != nil && c.Pods != nil && c.Jobs != nil && c.Deployments != nil && c.ReplicaSets != nil && c.StatefulSets != nil && c.DaemonSets != nil && c.ReplicationControllers != nil && c.CronJobs != nil
}

func baselineExecutableNodeFor(item runtime.Object, collection proofCollection, namespace string) (*baselineExecutableNode, error) {
	if item == nil || reflect.ValueOf(item).Kind() == reflect.Pointer && reflect.ValueOf(item).IsNil() {
		return nil, ErrSecurityBaseline
	}
	item = item.DeepCopyObject()
	if item == nil {
		return nil, ErrSecurityBaseline
	}
	// Only native LIST's literal omission of BOTH item envelope fields is
	// supported; the strict whole observer has already certified that omission.
	gvk := item.GetObjectKind().GroupVersionKind()
	want := schema.FromAPIVersionAndKind(collection.gv, collection.kind)
	if gvk.Kind == "" && gvk.GroupVersion().String() == "" {
		item.GetObjectKind().SetGroupVersionKind(want)
	} else if gvk != want {
		return nil, ErrSecurityBaseline
	}
	node := &baselineExecutableNode{object: item}
	kind := ""
	switch o := item.(type) {
	case *corev1.Pod:
		kind = "Pod"
		node.metadata, node.spec = o.ObjectMeta, &o.Spec
	case *batchv1.Job:
		kind = "Job"
		node.metadata, node.template = o.ObjectMeta, &o.Spec.Template
	case *appsv1.Deployment:
		kind = "Deployment"
		node.metadata, node.template = o.ObjectMeta, &o.Spec.Template
	case *appsv1.ReplicaSet:
		kind = "ReplicaSet"
		node.metadata, node.template = o.ObjectMeta, &o.Spec.Template
	case *appsv1.StatefulSet:
		kind = "StatefulSet"
		node.metadata, node.template = o.ObjectMeta, &o.Spec.Template
	case *appsv1.DaemonSet:
		kind = "DaemonSet"
		node.metadata, node.template = o.ObjectMeta, &o.Spec.Template
	case *corev1.ReplicationController:
		kind = "ReplicationController"
		node.metadata, node.template = o.ObjectMeta, o.Spec.Template
	case *batchv1.CronJob:
		kind = "CronJob"
		node.metadata, node.template = o.ObjectMeta, &o.Spec.JobTemplate.Spec.Template
	default:
		return nil, ErrSecurityBaseline
	}
	if node.template != nil {
		node.spec = &node.template.Spec
	}
	if kind != collection.kind || node.spec == nil || node.metadata.Namespace != namespace || !addressPart(node.metadata.Name) || !receiptUID.MatchString(string(node.metadata.UID)) || !baselineParentRV(node.metadata.ResourceVersion) || node.metadata.Generation < 0 {
		return nil, ErrSecurityBaseline
	}
	node.key = installstate.Key{APIVersion: collection.gv, Kind: collection.kind, Namespace: namespace, Name: node.metadata.Name}
	return node, nil
}

// Validate only reviewed native termination metadata before removing it from
// a disposable static comparison. This is NEVER a stoppedness/coldness proof.
func baselineDescendantMetadata(metadata metav1.ObjectMeta, namespace, kind string, signedGrace *int64, foreground bool) (metav1.ObjectMeta, error) {
	comparison := metadata.DeepCopy()
	if metadata.DeletionTimestamp == nil {
		if metadata.DeletionGracePeriodSeconds != nil || len(metadata.Finalizers) != 0 {
			return metav1.ObjectMeta{}, ErrSecurityBaseline
		}
	} else {
		if metadata.DeletionTimestamp.IsZero() || kind != "Pod" && kind != "ReplicaSet" {
			return metav1.ObjectMeta{}, ErrSecurityBaseline
		}
		grace := int64(0)
		if metadata.DeletionGracePeriodSeconds != nil {
			grace = *metadata.DeletionGracePeriodSeconds
		}
		if kind == "Pod" {
			if signedGrace == nil || *signedGrace < 0 || grace < 0 || grace > *signedGrace {
				return metav1.ObjectMeta{}, ErrSecurityBaseline
			}
		} else if grace != 0 {
			return metav1.ObjectMeta{}, ErrSecurityBaseline
		}
		if len(metadata.Finalizers) != 0 && (len(metadata.Finalizers) != 1 || metadata.Finalizers[0] != metav1.FinalizerDeleteDependents || !foreground) {
			return metav1.ObjectMeta{}, ErrSecurityBaseline
		}
		comparison.DeletionTimestamp, comparison.DeletionGracePeriodSeconds, comparison.Finalizers = nil, nil, nil
	}
	if !servingMetadata(*comparison, namespace) || !baselineParentRV(metadata.ResourceVersion) {
		return metav1.ObjectMeta{}, ErrSecurityBaseline
	}
	return *comparison, nil
}
