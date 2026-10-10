// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"errors"
	"strconv"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ownerReference(node OwnerNode) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: node.Key.APIVersion, Kind: node.Key.Kind, Name: node.Key.Name, UID: node.Metadata.UID}
}

func ownerNode(apiVersion, kind, name string, owner ...metav1.OwnerReference) OwnerNode {
	metadata := objectMeta(name)
	metadata.OwnerReferences = owner
	return OwnerNode{Key: installstate.Key{APIVersion: apiVersion, Kind: kind, Namespace: metadata.Namespace, Name: name}, Metadata: metadata}
}

func ownedRuntimeNode(t *testing.T, inventory []installstate.Resource, kind string) OwnerNode {
	t.Helper()
	for _, r := range inventory {
		if !r.Retained && r.Key.Kind == kind {
			return OwnerNode{Key: r.Key, Metadata: metav1.ObjectMeta{Name: r.Key.Name, Namespace: r.Key.Namespace, UID: r.UID, ResourceVersion: "1"}}
		}
	}
	t.Fatal("missing runtime fixture kind")
	return OwnerNode{}
}

func TestIndirectGarbageCollectionClosureRefusesRuntimeAncestors(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name  string
		chain func(*testing.T) []OwnerNode
	}{
		{"PVC Pod Deployment", func(t *testing.T) []OwnerNode {
			deployment := ownedRuntimeNode(t, inventory, "Deployment")
			pod := ownerNode("v1", "Pod", "foreign-pod", ownerReference(deployment))
			return []OwnerNode{pod, deployment}
		}},
		{"PVC ReplicaSet Deployment", func(t *testing.T) []OwnerNode {
			deployment := ownedRuntimeNode(t, inventory, "Deployment")
			rs := ownerNode("apps/v1", "ReplicaSet", "foreign-rs", ownerReference(deployment))
			return []OwnerNode{rs, deployment}
		}},
		{"PVC ConfigMap ServiceAccount", func(t *testing.T) []OwnerNode {
			sa := ownedRuntimeNode(t, inventory, "ServiceAccount")
			cm := ownerNode("v1", "ConfigMap", "foreign-cm", ownerReference(sa))
			return []OwnerNode{cm, sa}
		}},
		{"PVC Pod ReplicaSet Deployment", func(t *testing.T) []OwnerNode {
			deployment := ownedRuntimeNode(t, inventory, "Deployment")
			rs := ownerNode("apps/v1", "ReplicaSet", "foreign-rs", ownerReference(deployment))
			pod := ownerNode("v1", "Pod", "foreign-pod", ownerReference(rs))
			return []OwnerNode{pod, rs, deployment}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			chain := test.chain(t)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(chain[0])}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
			s.Owners = append(s.Owners, chain...)
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrRetention) {
				t.Fatalf("indirect GC hazard got %v", err)
			}
		})
	}
}

func TestOwnerClosureRejectsUnknownReplacedAliasedAndCyclicParents(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	parent := ownerNode("v1", "ConfigMap", "foreign-cm")
	for _, test := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"unresolved", func(s *Snapshot) {}},
		{"replaced uid", func(s *Snapshot) {
			replacement := parent
			replacement.Metadata.UID = "replacement"
			s.Owners = append(s.Owners, replacement)
		}},
		{"wrong kind", func(s *Snapshot) {
			replacement := parent
			replacement.Key.Kind = "Secret"
			s.Owners = append(s.Owners, replacement)
		}},
		{"wrong api version", func(s *Snapshot) {
			replacement := parent
			replacement.Key.APIVersion = "foreign.example/v1"
			s.Owners = append(s.Owners, replacement)
		}},
		{"foreign namespace", func(s *Snapshot) {
			replacement := parent
			replacement.Key.Namespace = "foreign"
			replacement.Metadata.Namespace = "foreign"
			s.Owners = append(s.Owners, replacement)
		}},
		{"self cycle", func(s *Snapshot) {
			cycle := parent
			cycle.Metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(cycle)}
			s.Owners = append(s.Owners, cycle)
		}},
		{"two node cycle", func(s *Snapshot) {
			a := parent
			b := ownerNode("v1", "ConfigMap", "other-cm", ownerReference(a))
			a.Metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(b)}
			s.Owners = append(s.Owners, a, b)
		}},
		{"conflicting observation", func(s *Snapshot) {
			replacement := parent
			replacement.Metadata.ResourceVersion = "2"
			s.Owners = append(s.Owners, parent, replacement)
		}},
		{"uid aliases two addresses", func(s *Snapshot) {
			replacement := parent
			replacement.Key.Name = "alias"
			replacement.Metadata.Name = "alias"
			s.Owners = append(s.Owners, parent, replacement)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(parent)}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrOwnership) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestResolvedRetainedDomainOwnerAndPinnedClusterAnchorAreSafe(t *testing.T) {
	plan, s, inventory := safetyFixture(t)
	var namespace OwnerNode
	for _, node := range s.Owners {
		if node.Key.Kind == "Namespace" {
			namespace = node
			break
		}
	}
	serverMeta := objectMeta("factory")
	serverMeta.OwnerReferences = []metav1.OwnerReference{ownerReference(namespace)}
	s.GameServers.Items = []arcade.GameServer{{ObjectMeta: serverMeta, Spec: arcade.GameServerSpec{DesiredState: arcade.DesiredStateStopped}, Status: arcade.GameServerStatus{ObservedGeneration: 1, Phase: arcade.PhaseStopped}}}
	backupMeta := objectMeta("nightly")
	backupMeta.OwnerReferences = []metav1.OwnerReference{{APIVersion: arcade.GroupVersion.String(), Kind: "GameServer", Name: serverMeta.Name, UID: serverMeta.UID}}
	s.Backups.Items = []arcade.GameBackup{{ObjectMeta: backupMeta, Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}}
	claimMeta := objectMeta("retained-world")
	claimMeta.OwnerReferences = []metav1.OwnerReference{{APIVersion: arcade.GroupVersion.String(), Kind: "GameBackup", Name: backupMeta.Name, UID: backupMeta.UID}}
	s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: claimMeta}}
	if err := Validate(plan, s, inventory); err != nil {
		t.Fatal(err)
	}
}

func TestResolvedOwnerlessExternalParentIsNotBlanketRejected(t *testing.T) {
	plan, s, inventory := safetyFixture(t)
	parent := ownerNode("v1", "ConfigMap", "external-owner")
	metadata := objectMeta("retained-world")
	metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(parent)}
	s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
	s.Owners = append(s.Owners, parent)
	if err := Validate(plan, s, inventory); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerClosureRequiresPinnedRetainedAnchorsAndBoundedEvidence(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name   string
		want   error
		mutate func(*Snapshot)
	}{
		{"missing namespace evidence", ErrOwnership, func(s *Snapshot) { s.Owners = s.Owners[1:] }},
		{"unreviewed cluster owner", ErrOwnership, func(s *Snapshot) {
			node := ownerNode("foreign.example/v1", "ClusterThing", "foreign-cluster")
			node.Key.Namespace = ""
			node.Metadata.Namespace = ""
			s.Owners = append(s.Owners, node)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(node)}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
		}},
		{"cluster kind disguised namespaced", ErrOwnership, func(s *Snapshot) {
			node := ownerNode("v1", "Namespace", "disguised")
			s.Owners = append(s.Owners, node)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(node)}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
		}},
		{"too many nodes", ErrInvalid, func(s *Snapshot) { s.Owners = make([]OwnerNode, MaxOwnerGraphNodes+1) }},
		{"too many references", ErrOwnership, func(s *Snapshot) {
			s.Secrets.Items[0].OwnerReferences = make([]metav1.OwnerReference, MaxOwnerReferences+1)
		}},
		{"deep unresolved closure", ErrOwnership, func(s *Snapshot) {
			first := ownerNode("v1", "ConfigMap", fmtName(0))
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(first)}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
			for i := 0; i <= MaxOwnerDepth; i++ {
				current := ownerNode("v1", "ConfigMap", fmtName(i))
				next := ownerNode("v1", "ConfigMap", fmtName(i+1))
				current.Metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(next)}
				s.Owners = append(s.Owners, current)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, test.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func fmtName(index int) string { return "deep-" + strconv.Itoa(index) }

func TestOwnerClosureDepthIncludesCachedSharedTail(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name  string
		nodes int
		want  error
	}{
		{"exact depth bound", MaxOwnerDepth, nil},
		{"fully resolved beyond depth bound", MaxOwnerDepth + 1, ErrOwnership},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			chain := make([]OwnerNode, test.nodes)
			for i := range chain {
				chain[i] = ownerNode("v1", "ConfigMap", fmtName(i))
			}
			for i := 0; i < len(chain)-1; i++ {
				chain[i].Metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(chain[i+1])}
			}
			s.Owners = append(s.Owners, chain...)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(chain[0])}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
			shortcut := objectMeta("short-root")
			shortcut.OwnerReferences = []metav1.OwnerReference{ownerReference(chain[len(chain)-8])}
			s.Secrets.Items = append(s.Secrets.Items, metav1.PartialObjectMetadata{ObjectMeta: shortcut})
			// The roots are deliberately a map. Every iteration must classify
			// identically whether the short root caches the tail first or not.
			for iteration := 0; iteration < 32; iteration++ {
				if err := Validate(plan, s, inventory); !errors.Is(err, test.want) {
					t.Fatalf("iteration %d got %v", iteration, err)
				}
			}
		})
	}
}

func TestOwnerClosureRefusesDeletingRetainedRootsAndResolvedParents(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"retained credential deleting", func(s *Snapshot) { now := metav1.Now(); s.Secrets.Items[0].DeletionTimestamp = &now }},
		{"external ConfigMap deleting", func(s *Snapshot) {
			node := ownerNode("v1", "ConfigMap", "external-cm")
			now := metav1.Now()
			node.Metadata.DeletionTimestamp = &now
			s.Owners = append(s.Owners, node)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(node)}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
		}},
		{"external Secret deleting", func(s *Snapshot) {
			node := ownerNode("v1", "Secret", "external-secret")
			now := metav1.Now()
			node.Metadata.DeletionTimestamp = &now
			s.Owners = append(s.Owners, node)
			metadata := objectMeta("retained-world")
			metadata.OwnerReferences = []metav1.OwnerReference{ownerReference(node)}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: metadata}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrRetention) {
				t.Fatalf("got %v", err)
			}
		})
	}
	// Different observed deletion state is contradictory evidence, even if a
	// broken adapter supplied the same UID/RV for both observations.
	s := cloneSnapshot(base)
	first := ownerNode("v1", "ConfigMap", "external-cm")
	second := first
	now := metav1.Now()
	second.Metadata.DeletionTimestamp = &now
	s.Owners = append(s.Owners, first, second)
	if err := Validate(plan, s, inventory); !errors.Is(err, ErrOwnership) {
		t.Fatalf("contradictory deletion evidence got %v", err)
	}
}
