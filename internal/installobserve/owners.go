// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

type mapping struct {
	gvr        schema.GroupVersionResource
	namespaced bool
}

type ownerGraph struct {
	observer *Observer
	nodes    map[installstate.Key]metav1.ObjectMeta
	uids     map[types.UID]installstate.Key
	roots    map[installstate.Key]bool
	retained map[installstate.Key]types.UID
	scopes   map[string]bool
	names    map[string]string
	mappings map[string]mapping
	groups   map[string]*metav1.APIResourceList
	gets     map[installstate.Key]bool
	colors   map[installstate.Key]uint8
	heights  map[installstate.Key]int
	owners   []installsafety.OwnerNode
	bytes    int
}

func newOwnerGraph(o *Observer, inventory []installstate.Resource, cs []collection) *ownerGraph {
	g := &ownerGraph{observer: o, nodes: map[installstate.Key]metav1.ObjectMeta{}, uids: map[types.UID]installstate.Key{}, roots: map[installstate.Key]bool{}, retained: map[installstate.Key]types.UID{}, scopes: map[string]bool{}, names: map[string]string{}, mappings: map[string]mapping{}, groups: map[string]*metav1.APIResourceList{}, gets: map[installstate.Key]bool{}, colors: map[installstate.Key]uint8{}, heights: map[installstate.Key]int{}}
	for _, c := range cs {
		g.scopes[c.gv+"/"+c.kind], g.names[c.gv+"/"+c.kind] = c.namespaced, c.resource
	}
	for _, r := range o.plan.Resources() {
		g.scopes[r.Object.GetAPIVersion()+"/"+r.Object.GetKind()] = r.Object.GetNamespace() != ""
	}
	for _, known := range []struct{ gv, kind, name string }{
		{"v1", "Namespace", "namespaces"}, {"v1", "ConfigMap", "configmaps"},
		{"v1", "ServiceAccount", "serviceaccounts"}, {"v1", "Service", "services"},
		{"apps/v1", "Deployment", "deployments"}, {"apps/v1", "ReplicaSet", "replicasets"},
		{"rbac.authorization.k8s.io/v1", "Role", "roles"}, {"rbac.authorization.k8s.io/v1", "RoleBinding", "rolebindings"},
		{"rbac.authorization.k8s.io/v1", "ClusterRole", "clusterroles"}, {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "clusterrolebindings"},
		{"apiextensions.k8s.io/v1", "CustomResourceDefinition", "customresourcedefinitions"},
	} {
		key := known.gv + "/" + known.kind
		g.names[key] = known.name
		if _, ok := g.scopes[key]; !ok {
			g.scopes[key] = known.kind != "Namespace" && known.kind != "CustomResourceDefinition" && known.kind != "ClusterRole" && known.kind != "ClusterRoleBinding"
		}
	}
	for _, r := range inventory {
		if r.Retained {
			g.retained[r.Key], g.roots[r.Key] = r.UID, true
		}
	}
	return g
}

// Metadata observations deliberately discard labels, annotations, managed
// fields and arbitrary payload. Secret values can appear even in annotations;
// only fields required for identity and the GC closure leave the read boundary.
func publicMetadata(m metav1.Object) metav1.ObjectMeta {
	result := metav1.ObjectMeta{Name: m.GetName(), Namespace: m.GetNamespace(), UID: m.GetUID(), ResourceVersion: m.GetResourceVersion(), Generation: m.GetGeneration(), OwnerReferences: m.GetOwnerReferences()}
	if timestamp := m.GetDeletionTimestamp(); timestamp != nil {
		result.DeletionTimestamp = timestamp.DeepCopy()
	}
	return *result.DeepCopy()
}

func (g *ownerGraph) seed(key installstate.Key, m metav1.Object) error {
	if !validKey(key, g.observer.plan.Namespace()) || m.GetName() != key.Name || m.GetNamespace() != key.Namespace || !validIdentity(string(m.GetUID())) || !validIdentity(m.GetResourceVersion()) || len(m.GetOwnerReferences()) > installsafety.MaxOwnerReferences {
		return ErrOwnership
	}
	if scoped, known := g.scopes[key.APIVersion+"/"+key.Kind]; known && scoped != (key.Namespace != "") {
		return ErrOwnership
	}
	for _, ref := range m.GetOwnerReferences() {
		if !validIdentity(string(ref.UID)) || !validKey(installstate.Key{APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: key.Namespace, Name: ref.Name}, g.observer.plan.Namespace()) {
			return ErrOwnership
		}
	}
	value := publicMetadata(m)
	if previous, exists := g.nodes[key]; exists {
		if !reflect.DeepEqual(previous, value) {
			return ErrOwnership
		}
	} else {
		if len(g.nodes) >= installsafety.MaxOwnerGraphNodes {
			return ErrRead
		}
		if previous, exists := g.uids[value.UID]; exists && previous != key {
			return ErrOwnership
		}
		if err := g.charge(value); err != nil {
			return err
		}
		g.nodes[key], g.uids[value.UID] = value, key
	}
	// All world/domain records, PVCs, and Secrets are retained independently of
	// inventory. Jobs/Pods/Leases and unrelated cluster policies are not roots.
	if key.Kind == "Secret" && key.APIVersion == "v1" || key.Kind == "PersistentVolumeClaim" && key.APIVersion == "v1" || key.APIVersion == "arcade.gobha.me/v1alpha1" {
		g.roots[key] = true
	}
	return nil
}

// Bound aggregate recursive evidence as well as individual HTTP responses.
// This prevents many distinct API groups or large owner-reference arrays from
// accumulating unbounded memory in the shared installer/CI environment.
func (g *ownerGraph) charge(value any) error {
	body, err := json.Marshal(value)
	if err != nil || g.bytes+len(body) > 32*1024*1024 {
		return ErrRead
	}
	g.bytes += len(body)
	return nil
}

func validKey(key installstate.Key, namespace string) bool {
	gv, err := schema.ParseGroupVersion(key.APIVersion)
	if err != nil || len(validation.IsDNS1035Label(gv.Version)) != 0 || gv.Group != "" && len(validation.IsDNS1123Subdomain(gv.Group)) != 0 || gv.String() != key.APIVersion || len(key.APIVersion) > 253 || len(key.Kind) == 0 || len(key.Kind) > 128 || len(validation.IsDNS1123Subdomain(key.Name)) != 0 || key.Namespace != "" && key.Namespace != namespace {
		return false
	}
	for _, c := range key.Kind {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func (g *ownerGraph) resolve(ctx context.Context, apiVersion, kind string) (mapping, error) {
	key := apiVersion + "/" + kind
	if m, ok := g.mappings[key]; ok {
		return m, nil
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil || gv.Version == "" || gv.String() != apiVersion || !validKey(installstate.Key{APIVersion: apiVersion, Kind: kind, Name: "validation"}, g.observer.plan.Namespace()) {
		return mapping{}, ErrOwnership
	}
	list, exists := g.groups[apiVersion]
	if !exists {
		list, err = g.observer.clients.Discovery(ctx, apiVersion)
		if err != nil || list == nil || list.GroupVersion != apiVersion || len(list.APIResources) > installsafety.MaxOwnerGraphNodes {
			return mapping{}, ErrOwnership
		}
		if err := g.charge(list); err != nil {
			return mapping{}, err
		}
		g.groups[apiVersion] = list.DeepCopy()
	}
	var found *metav1.APIResource
	for i := range list.APIResources {
		r := &list.APIResources[i]
		if r.Kind != kind || strings.Contains(r.Name, "/") {
			continue
		}
		if found != nil || len(validation.IsDNS1035Label(r.Name)) != 0 || r.Group != "" && r.Group != gv.Group || r.Version != "" && r.Version != gv.Version || !slices.Contains(r.Verbs, "get") {
			return mapping{}, ErrOwnership
		}
		found = r
	}
	if found == nil {
		return mapping{}, ErrOwnership
	}
	if scoped, known := g.scopes[key]; known && scoped != found.Namespaced {
		return mapping{}, ErrOwnership
	}
	if name, known := g.names[key]; known && name != found.Name {
		return mapping{}, ErrOwnership
	}
	m := mapping{gvr: gv.WithResource(found.Name), namespaced: found.Namespaced}
	g.mappings[key] = m
	return m, nil
}

func (g *ownerGraph) get(ctx context.Context, key installstate.Key, uid types.UID) error {
	if ctx.Err() != nil {
		return ErrRead
	}
	if g.gets[key] {
		if g.nodes[key].UID != uid {
			return ErrOwnership
		}
		return nil
	}
	m, err := g.resolve(ctx, key.APIVersion, key.Kind)
	if err != nil || m.namespaced != (key.Namespace != "") || key.Namespace == "" && g.retained[key] != uid {
		return ErrOwnership
	}
	var object *metav1.PartialObjectMetadata
	if m.namespaced {
		object, err = g.observer.clients.Metadata.Resource(m.gvr).Namespace(key.Namespace).Get(ctx, key.Name, metav1.GetOptions{})
	} else {
		object, err = g.observer.clients.Metadata.Resource(m.gvr).Get(ctx, key.Name, metav1.GetOptions{})
	}
	if err != nil || object == nil || object.UID != uid || object.DeletionTimestamp != nil {
		return ErrOwnership
	}
	if err := g.seed(key, object); err != nil {
		return err
	}
	g.gets[key] = true
	g.owners = append(g.owners, installsafety.OwnerNode{Key: key, Metadata: publicMetadata(object)})
	return nil
}

func (g *ownerGraph) collect(ctx context.Context) ([]installsafety.OwnerNode, error) {
	// Sort roots to make diagnostics/GET ordering stable. Scope resolution stays
	// local to this observation; no discovery result survives the read barrier.
	roots := make([]installstate.Key, 0, len(g.roots))
	for key := range g.roots {
		roots = append(roots, key)
	}
	slices.SortFunc(roots, func(a, b installstate.Key) int { return strings.Compare(a.String(), b.String()) })
	for _, key := range roots {
		if uid, pinned := g.retained[key]; pinned {
			if err := g.get(ctx, key, uid); err != nil {
				return nil, err
			}
		}
		if err := g.walk(ctx, key, 0); err != nil {
			return nil, err
		}
	}
	return g.owners, nil
}

func (g *ownerGraph) walk(ctx context.Context, key installstate.Key, depth int) error {
	if ctx.Err() != nil {
		return ErrRead
	}
	if depth > installsafety.MaxOwnerDepth || g.colors[key] == 1 || g.colors[key] == 2 && depth+g.heights[key] > installsafety.MaxOwnerDepth {
		return ErrOwnership
	}
	if g.colors[key] == 2 {
		return nil
	}
	node, exists := g.nodes[key]
	if !exists || node.DeletionTimestamp != nil {
		return ErrOwnership
	}
	g.colors[key] = 1
	height := 0
	for _, owner := range node.OwnerReferences {
		m, err := g.resolve(ctx, owner.APIVersion, owner.Kind)
		if err != nil || !validIdentity(string(owner.UID)) {
			return ErrOwnership
		}
		parent := installstate.Key{APIVersion: owner.APIVersion, Kind: owner.Kind, Name: owner.Name}
		if m.namespaced {
			// Kubernetes forbids cluster children with namespaced owners.
			if key.Namespace == "" {
				return ErrOwnership
			}
			parent.Namespace = key.Namespace
		}
		if !validKey(parent, g.observer.plan.Namespace()) || g.get(ctx, parent, owner.UID) != nil {
			return ErrOwnership
		}
		if err := g.walk(ctx, parent, depth+1); err != nil {
			return err
		}
		if nextHeight := g.heights[parent] + 1; nextHeight > height {
			height = nextHeight
		}
	}
	g.heights[key], g.colors[key] = height, 2
	return nil
}
