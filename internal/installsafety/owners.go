// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"reflect"
	"strings"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const (
	MaxOwnerGraphNodes = 10000
	MaxOwnerDepth      = 64
	MaxOwnerReferences = 128
)

// OwnerNode is evidence from an uncached metadata GET of the exact owner
// address. The engine must establish actual REST scope and collection
// provenance; this pure value cannot authenticate its provider. Namespace is
// the installation namespace or empty for a cluster object. Secret data and
// arbitrary raw specs are deliberately excluded.
type OwnerNode struct {
	Key      installstate.Key
	Metadata metav1.ObjectMeta
}

type ownerObservation struct {
	key      installstate.Key
	uid      types.UID
	rv       string
	owners   []metav1.OwnerReference
	deleting bool
}

// ValidateRetainedOwnerClosure is only the pure retention/ancestor portion of
// safety, shared by the full admission phase over its COMPLETE observation.
// It grants no fixture exemption, mutation, domain/worker settlement or cold
// checkpoint. The inventory must remain the original signed journal inventory.
func ValidateRetainedOwnerClosure(plan *installrender.Plan, s *Snapshot, inventory []installstate.Resource) error {
	if !plan.IsTrusted() || !complete(s) {
		return ErrInvalid
	}
	owned, removable, err := inventoryContract(plan, inventory)
	if err != nil {
		return err
	}
	return validateOwnerClosure(plan, s, inventory, owned, removable)
}

func validateOwnerClosure(plan *installrender.Plan, s *Snapshot, inventory []installstate.Resource, owned map[installstate.Key]types.UID, removable map[types.UID]bool) error {
	if len(s.Owners) > MaxOwnerGraphNodes {
		return ErrInvalid
	}
	nodes := map[installstate.Key]ownerObservation{}
	uids := map[types.UID]installstate.Key{}
	roots := map[installstate.Key]bool{}
	retainedInventory := map[installstate.Key]types.UID{}
	// Scope is fixed for reviewed and typed kinds. Recursive observations cannot
	// disguise a known cluster kind as a namespaced object (or the reverse).
	scopes := map[string]bool{"v1/ConfigMap": true, "apps/v1/ReplicaSet": true}
	for _, r := range plan.Resources() {
		scopes[r.Object.GetAPIVersion()+"/"+r.Object.GetKind()] = r.Object.GetNamespace() != ""
	}
	for _, kind := range []string{"GameServer", "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation"} {
		scopes[arcade.GroupVersion.String()+"/"+kind] = true
	}
	for _, pair := range []string{"batch/v1/Job", "v1/Pod", "coordination.k8s.io/v1/Lease", "v1/PersistentVolumeClaim", "v1/Secret"} {
		scopes[pair] = true
	}
	for _, r := range inventory {
		if r.Retained {
			retainedInventory[r.Key] = r.UID
		}
	}
	add := func(key installstate.Key, metadata metav1.Object, retained bool) error {
		if !validOwnerKey(key, plan.Namespace()) || metadata.GetName() != key.Name || metadata.GetNamespace() != key.Namespace || !boundedIdentity(string(metadata.GetUID())) || !boundedIdentity(metadata.GetResourceVersion()) || len(metadata.GetOwnerReferences()) > MaxOwnerReferences {
			return ErrOwnership
		}
		if namespaced, known := scopes[key.APIVersion+"/"+key.Kind]; known && namespaced != (key.Namespace != "") {
			return ErrOwnership
		}
		node := ownerObservation{key: key, uid: metadata.GetUID(), rv: metadata.GetResourceVersion(), owners: metadata.GetOwnerReferences(), deleting: metadata.GetDeletionTimestamp() != nil}
		if old, ok := nodes[key]; ok {
			if old.uid != node.uid || old.rv != node.rv || old.deleting != node.deleting || !reflect.DeepEqual(old.owners, node.owners) {
				return ErrOwnership
			}
		} else {
			if len(nodes) >= MaxOwnerGraphNodes {
				return ErrInvalid
			}
			if old, ok := uids[node.uid]; ok && old != key {
				return ErrOwnership
			}
			nodes[key], uids[node.uid] = node, key
		}
		if retained {
			roots[key] = true
		}
		return nil
	}
	seed := func(apiVersion, kind string, metadata metav1.Object, retained bool) error {
		return add(installstate.Key{APIVersion: apiVersion, Kind: kind, Namespace: metadata.GetNamespace(), Name: metadata.GetName()}, metadata, retained)
	}
	for i := range s.GameServers.Items {
		if err := seed(arcade.GroupVersion.String(), "GameServer", &s.GameServers.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Backups.Items {
		if err := seed(arcade.GroupVersion.String(), "GameBackup", &s.Backups.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Restores.Items {
		if err := seed(arcade.GroupVersion.String(), "GameRestore", &s.Restores.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Destroys.Items {
		if err := seed(arcade.GroupVersion.String(), "GameDestroy", &s.Destroys.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Operations.Items {
		if err := seed(arcade.GroupVersion.String(), "ArcadeOperation", &s.Operations.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Jobs.Items {
		if err := seed("batch/v1", "Job", &s.Jobs.Items[i], false); err != nil {
			return err
		}
	}
	for i := range s.Pods.Items {
		if err := seed("v1", "Pod", &s.Pods.Items[i], false); err != nil {
			return err
		}
	}
	for i := range s.Leases.Items {
		if err := seed("coordination.k8s.io/v1", "Lease", &s.Leases.Items[i], false); err != nil {
			return err
		}
	}
	for i := range s.Claims.Items {
		if err := seed("v1", "PersistentVolumeClaim", &s.Claims.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Secrets.Items {
		if err := seed("v1", "Secret", &s.Secrets.Items[i], true); err != nil {
			return err
		}
	}
	for i := range s.Policies.Items {
		o := &s.Policies.Items[i]
		key := installstate.Key{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy", Name: o.Name}
		if err := add(key, o, retainedInventory[key] != ""); err != nil {
			return err
		}
	}
	for i := range s.Bindings.Items {
		o := &s.Bindings.Items[i]
		key := installstate.Key{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding", Name: o.Name}
		if err := add(key, o, retainedInventory[key] != ""); err != nil {
			return err
		}
	}
	for i := range s.Owners {
		if err := add(s.Owners[i].Key, &s.Owners[i].Metadata, retainedInventory[s.Owners[i].Key] != ""); err != nil {
			return err
		}
	}
	// Every retained inventoried object participates in the closure, including
	// Namespace/CRD anchors that are not part of a namespaced domain list.
	for key, uid := range retainedInventory {
		if node, ok := nodes[key]; !ok || node.uid != uid {
			return ErrOwnership
		}
		roots[key] = true
	}
	colors := map[installstate.Key]uint8{}
	heights := map[installstate.Key]int{}
	var walk func(installstate.Key, int) error
	walk = func(key installstate.Key, depth int) error {
		if depth > MaxOwnerDepth {
			return ErrOwnership
		}
		if colors[key] == 1 {
			return ErrOwnership
		}
		if colors[key] == 2 {
			if depth+heights[key] > MaxOwnerDepth {
				return ErrOwnership
			}
			return nil
		}
		node, ok := nodes[key]
		if !ok {
			return ErrOwnership
		}
		if removable[node.uid] {
			return ErrRetention
		}
		if node.deleting {
			return ErrRetention
		}
		if key.Namespace == "" && (retainedInventory[key] == "" || owned[key] != node.uid) {
			return ErrOwnership
		}
		colors[key] = 1
		height := 0
		for _, owner := range node.owners {
			if owner.Name == "" || owner.Kind == "" || owner.APIVersion == "" || !boundedIdentity(string(owner.UID)) {
				return ErrOwnership
			}
			// OwnerReferences do not carry a namespace. Namespaced children can
			// reference same-namespace or cluster owners, never another namespace.
			parent := installstate.Key{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: key.Namespace, Name: owner.Name}
			actual, exists := nodes[parent]
			if !exists {
				parent.Namespace = ""
				actual, exists = nodes[parent]
			}
			if !exists || actual.uid != owner.UID {
				return ErrOwnership
			}
			if err := walk(parent, depth+1); err != nil {
				return err
			}
			if parentHeight := heights[parent] + 1; parentHeight > height {
				height = parentHeight
			}
		}
		heights[key] = height
		colors[key] = 2
		return nil
	}
	for key := range roots {
		if err := walk(key, 0); err != nil {
			return err
		}
	}
	return nil
}

func validOwnerKey(key installstate.Key, namespace string) bool {
	gv, err := schema.ParseGroupVersion(key.APIVersion)
	return err == nil && gv.Version != "" && key.Kind != "" && len(key.Kind) <= 128 && !strings.ContainsAny(key.Kind, "/\r\n\x00") && key.Name != "" && len(key.Name) <= 253 && !strings.ContainsAny(key.Name, "/\r\n\x00") && (key.Namespace == namespace || key.Namespace == "")
}
