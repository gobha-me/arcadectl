// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func safetyFixture(t *testing.T) (*installrender.Plan, *Snapshot, []installstate.Resource) {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	signature, err := installpackage.Sign(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(manifest, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, "isolated-install", installrender.Profile135)
	if err != nil {
		t.Fatal(err)
	}
	meta := metav1.ListMeta{ResourceVersion: "10"}
	s := &Snapshot{GameServers: &arcade.GameServerList{ListMeta: meta}, Backups: &arcade.GameBackupList{ListMeta: meta}, Restores: &arcade.GameRestoreList{ListMeta: meta}, Destroys: &arcade.GameDestroyList{ListMeta: meta}, Operations: &arcade.ArcadeOperationList{ListMeta: meta}, Jobs: &batchv1.JobList{ListMeta: meta}, Pods: &corev1.PodList{ListMeta: meta}, Leases: &coordinationv1.LeaseList{ListMeta: meta}, Claims: &corev1.PersistentVolumeClaimList{ListMeta: meta}, Secrets: &metav1.PartialObjectMetadataList{ListMeta: meta}, Policies: &admissionv1.ValidatingAdmissionPolicyList{ListMeta: meta}, Bindings: &admissionv1.ValidatingAdmissionPolicyBindingList{ListMeta: meta}}
	var inventory []installstate.Resource
	for i, r := range plan.Resources() {
		o := r.Object
		uid := types.UID(fmt.Sprintf("owned-%d", i))
		inventory = append(inventory, installstate.Resource{Key: installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}, UID: uid, TemplateSHA256: strings.Repeat("d", 64), Retained: r.Retained, Phase: r.Phase})
		// Retained anchors outside the twelve complete collections still need
		// actual metadata evidence, not just an inventory UID assertion.
		if r.Retained && o.GetKind() != "ValidatingAdmissionPolicy" && o.GetKind() != "ValidatingAdmissionPolicyBinding" {
			s.Owners = append(s.Owners, OwnerNode{Key: inventory[len(inventory)-1].Key, Metadata: metav1.ObjectMeta{Name: o.GetName(), Namespace: o.GetNamespace(), UID: uid, ResourceVersion: "1"}})
		}
		switch o.GetKind() {
		case "ValidatingAdmissionPolicy":
			var actual admissionv1.ValidatingAdmissionPolicy
			if runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &actual) != nil {
				t.Fatal("policy conversion failed")
			}
			actual.UID, actual.ResourceVersion, actual.Generation = uid, "1", 1
			actual.Status = admissionv1.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admissionv1.TypeChecking{}}
			s.Policies.Items = append(s.Policies.Items, actual)
		case "ValidatingAdmissionPolicyBinding":
			var actual admissionv1.ValidatingAdmissionPolicyBinding
			if runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &actual) != nil {
				t.Fatal("binding conversion failed")
			}
			actual.UID, actual.ResourceVersion = uid, "1"
			s.Bindings.Items = append(s.Bindings.Items, actual)
		}
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		metadata := objectMeta(name)
		s.Secrets.Items = append(s.Secrets.Items, metav1.PartialObjectMetadata{ObjectMeta: metadata})
		inventory = append(inventory, installstate.Resource{Key: installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: plan.Namespace(), Name: name}, UID: metadata.UID, Retained: true, Phase: installrender.API})
	}
	return plan, s, inventory
}

func objectMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: "isolated-install", UID: types.UID("uid-" + name), ResourceVersion: "1", Generation: 1}
}

func cloneSnapshot(s *Snapshot) *Snapshot {
	copy := &Snapshot{GameServers: s.GameServers.DeepCopy(), Backups: s.Backups.DeepCopy(), Restores: s.Restores.DeepCopy(), Destroys: s.Destroys.DeepCopy(), Operations: s.Operations.DeepCopy(), Jobs: s.Jobs.DeepCopy(), Pods: s.Pods.DeepCopy(), Leases: s.Leases.DeepCopy(), Claims: s.Claims.DeepCopy(), Secrets: s.Secrets.DeepCopy(), Policies: s.Policies.DeepCopy(), Bindings: s.Bindings.DeepCopy()}
	for _, node := range s.Owners {
		copy.Owners = append(copy.Owners, OwnerNode{Key: node.Key, Metadata: *node.Metadata.DeepCopy()})
	}
	return copy
}

func TestCompleteCurrentSnapshotAndNonmutation(t *testing.T) {
	plan, s, inventory := safetyFixture(t)
	s.GameServers.Items = []arcade.GameServer{{ObjectMeta: objectMeta("factory"), Spec: arcade.GameServerSpec{DesiredState: arcade.DesiredStateStopped}, Status: arcade.GameServerStatus{ObservedGeneration: 1, Phase: arcade.PhaseStopped}}}
	s.Backups.Items = []arcade.GameBackup{{ObjectMeta: objectMeta("nightly"), Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}}
	s.Backups.Items[0].Finalizers = []string{platformkube.BackupFinalizer}
	s.Restores.Items = []arcade.GameRestore{{ObjectMeta: objectMeta("restore"), Status: arcade.GameRestoreStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseFailed}}}}
	s.Restores.Items[0].Finalizers = []string{platformkube.RestoreFinalizer}
	s.Destroys.Items = []arcade.GameDestroy{{ObjectMeta: objectMeta("destroy"), Status: arcade.GameDestroyStatus{ObservedGeneration: 1, Phase: arcade.DestroyPhaseCancelled}}}
	s.Destroys.Items[0].Finalizers = []string{platformkube.DestroyFinalizer}
	s.Operations.Items = []arcade.ArcadeOperation{{ObjectMeta: objectMeta("receipt"), Status: arcade.ArcadeOperationStatus{ObservedGeneration: 1, Phase: arcade.OperationPhaseSucceeded}}}
	before := cloneSnapshot(s)
	beforeInventory := append([]installstate.Resource(nil), inventory...)
	if err := Validate(plan, s, inventory); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, s) || !reflect.DeepEqual(beforeInventory, inventory) {
		t.Fatal("pure validator mutated observations")
	}
}

func TestMissingPagedOrMalformedObservationFailsClosed(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"missing servers", func(s *Snapshot) { s.GameServers = nil }},
		{"missing secrets", func(s *Snapshot) { s.Secrets = nil }},
		{"missing policies", func(s *Snapshot) { s.Policies = nil }},
		{"unread jobs", func(s *Snapshot) { s.Jobs.ResourceVersion = "" }},
		{"more pods", func(s *Snapshot) { s.Pods.Continue = "next-page" }},
		{"remaining leases", func(s *Snapshot) { n := int64(1); s.Leases.RemainingItemCount = &n }},
		{"bounded claims", func(s *Snapshot) { s.Claims.Items = make([]corev1.PersistentVolumeClaim, MaxObjectsPerList+1) }},
		{"foreign pod", func(s *Snapshot) {
			m := objectMeta("foreign")
			m.Namespace = "other"
			s.Pods.Items = []corev1.Pod{{ObjectMeta: m}}
		}},
		{"missing uid", func(s *Snapshot) {
			m := objectMeta("unknown")
			m.UID = ""
			s.Pods.Items = []corev1.Pod{{ObjectMeta: m}}
		}},
		{"unbounded object rv", func(s *Snapshot) {
			m := objectMeta("unknown")
			m.ResourceVersion = strings.Repeat("x", 129)
			s.Pods.Items = []corev1.Pod{{ObjectMeta: m}}
		}},
		{"invalid object uid", func(s *Snapshot) {
			m := objectMeta("unknown")
			m.UID = "original\ncanary"
			s.Pods.Items = []corev1.Pod{{ObjectMeta: m}}
		}},
		{"duplicate pods", func(s *Snapshot) {
			o := corev1.Pod{ObjectMeta: objectMeta("duplicate")}
			s.Pods.Items = []corev1.Pod{o, o}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := Validate(nil, base, inventory); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil plan accepted")
	}
	if err := Validate(plan, nil, inventory); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil snapshot accepted")
	}
}

func TestUnsettledDomainAndReceiptFinalizersRefused(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"running intent", func(s *Snapshot) {
			s.GameServers.Items = []arcade.GameServer{{ObjectMeta: objectMeta("factory"), Spec: arcade.GameServerSpec{DesiredState: arcade.DesiredStateRunning}, Status: arcade.GameServerStatus{ObservedGeneration: 1, Phase: arcade.PhaseStopped}}}
		}},
		{"stale stopped", func(s *Snapshot) {
			s.GameServers.Items = []arcade.GameServer{{ObjectMeta: objectMeta("factory"), Spec: arcade.GameServerSpec{DesiredState: arcade.DesiredStateStopped}, Status: arcade.GameServerStatus{ObservedGeneration: 0, Phase: arcade.PhaseStopped}}}
		}},
		{"pending backup", func(s *Snapshot) {
			s.Backups.Items = []arcade.GameBackup{{ObjectMeta: objectMeta("backup"), Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhasePending}}}}
		}},
		{"stale restore", func(s *Snapshot) {
			s.Restores.Items = []arcade.GameRestore{{ObjectMeta: objectMeta("restore"), Status: arcade.GameRestoreStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 0, Phase: arcade.DataPhaseSucceeded}}}}
		}},
		{"deleting destroy", func(s *Snapshot) {
			m := objectMeta("destroy")
			now := metav1.Now()
			m.DeletionTimestamp = &now
			s.Destroys.Items = []arcade.GameDestroy{{ObjectMeta: m, Status: arcade.GameDestroyStatus{ObservedGeneration: 1, Phase: arcade.DestroyPhaseSucceeded}}}
		}},
		{"awaiting receipt", func(s *Snapshot) {
			s.Operations.Items = []arcade.ArcadeOperation{{ObjectMeta: objectMeta("receipt"), Status: arcade.ArcadeOperationStatus{ObservedGeneration: 1, Phase: arcade.OperationPhaseAwaitingConfirmation}}}
		}},
		{"foreign receipt finalizer", func(s *Snapshot) {
			m := objectMeta("receipt")
			m.Finalizers = []string{"foreign/hold"}
			s.Operations.Items = []arcade.ArcadeOperation{{ObjectMeta: m, Status: arcade.ArcadeOperationStatus{ObservedGeneration: 1, Phase: arcade.OperationPhaseSucceeded}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrDomain) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAnyNameWorkerAndFenceSignalsRefused(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"job name", func(s *Snapshot) { s.Jobs.Items = []batchv1.Job{{ObjectMeta: objectMeta("backup-old")}} }},
		{"job template sa", func(s *Snapshot) {
			s.Jobs.Items = []batchv1.Job{{ObjectMeta: objectMeta("renamed"), Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "restore-exact-authority"}}}}}
		}},
		{"job template label", func(s *Snapshot) {
			s.Jobs.Items = []batchv1.Job{{ObjectMeta: objectMeta("renamed"), Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{platformkube.LabelDestroyUID: "original"}}}}}}
		}},
		{"job owner", func(s *Snapshot) {
			m := objectMeta("renamed")
			m.OwnerReferences = []metav1.OwnerReference{{APIVersion: arcade.GroupVersion.String(), Kind: "GameBackup", UID: "old-backup"}}
			s.Jobs.Items = []batchv1.Job{{ObjectMeta: m}}
		}},
		{"pod sa", func(s *Snapshot) {
			s.Pods.Items = []corev1.Pod{{ObjectMeta: objectMeta("renamed"), Spec: corev1.PodSpec{ServiceAccountName: "destroy-exact-authority"}}}
		}},
		{"pod deprecated sa", func(s *Snapshot) {
			s.Pods.Items = []corev1.Pod{{ObjectMeta: objectMeta("renamed"), Spec: corev1.PodSpec{DeprecatedServiceAccount: "backup-exact-authority"}}}
		}},
		{"pod job owner", func(s *Snapshot) {
			m := objectMeta("renamed")
			m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "restore-original", UID: "old-job"}}
			s.Pods.Items = []corev1.Pod{{ObjectMeta: m}}
		}},
		{"pod data label", func(s *Snapshot) {
			m := objectMeta("renamed")
			m.Labels = map[string]string{platformkube.LabelDataOperation: "backup"}
			s.Pods.Items = []corev1.Pod{{ObjectMeta: m}}
		}},
		{"lease name", func(s *Snapshot) {
			s.Leases.Items = []coordinationv1.Lease{{ObjectMeta: objectMeta("data-operation-original")}}
		}},
		{"lease identity", func(s *Snapshot) {
			m := objectMeta("renamed")
			m.Labels = map[string]string{platformkube.LabelDataIdentity: "original-world"}
			s.Leases.Items = []coordinationv1.Lease{{ObjectMeta: m}}
		}},
		{"lease receipt uid", func(s *Snapshot) {
			m := objectMeta("renamed")
			m.Labels = map[string]string{"arcade.gobha.me/operation-uid": "original"}
			s.Leases.Items = []coordinationv1.Lease{{ObjectMeta: m}}
		}},
		{"lease holder", func(s *Snapshot) {
			o := arcade.GameBackup{ObjectMeta: objectMeta("backup"), Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}
			s.Backups.Items = []arcade.GameBackup{o}
			holder := string(o.UID)
			s.Leases.Items = []coordinationv1.Lease{{ObjectMeta: objectMeta("renamed"), Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, ErrWorker) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRetainedMountAndGarbageCollectionHazardsRefused(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	var removable types.UID
	for _, r := range inventory {
		if !r.Retained {
			removable = r.UID
			break
		}
	}
	volume := corev1.Volume{Name: "world", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "old-world"}}}
	for _, test := range []struct {
		name   string
		want   error
		mutate func(*Snapshot)
	}{
		{"retained pod mount", ErrRetention, func(s *Snapshot) {
			m := objectMeta("old-world")
			m.Labels = map[string]string{platformkube.LabelDataPolicy: "retain"}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: m}}
			s.Pods.Items = []corev1.Pod{{ObjectMeta: objectMeta("unlabelled"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{volume}}}}
		}},
		{"candidate history mount", ErrRetention, func(s *Snapshot) {
			s.Restores.Items = []arcade.GameRestore{{ObjectMeta: objectMeta("restore"), Status: arcade.GameRestoreStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseFailed}, CandidateData: []arcade.DataPathIdentity{{ClaimRef: arcade.ExactLocalReference{Name: "old-world", UID: "original-world"}}}}}}
			s.Pods.Items = []corev1.Pod{{ObjectMeta: objectMeta("unlabelled"), Spec: corev1.PodSpec{Volumes: []corev1.Volume{volume}}}}
		}},
		{"job retained mount", ErrWorker, func(s *Snapshot) {
			m := objectMeta("old-world")
			m.Labels = map[string]string{platformkube.LabelDataIdentity: "original"}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: m}}
			s.Jobs.Items = []batchv1.Job{{ObjectMeta: objectMeta("unlabelled"), Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Volumes: []corev1.Volume{volume}}}}}}
		}},
		{"foreign claim gc", ErrRetention, func(s *Snapshot) {
			m := objectMeta("foreign-world")
			m.OwnerReferences = []metav1.OwnerReference{{UID: removable}}
			s.Claims.Items = []corev1.PersistentVolumeClaim{{ObjectMeta: m}}
		}},
		{"credential gc", ErrRetention, func(s *Snapshot) { s.Secrets.Items[0].OwnerReferences = []metav1.OwnerReference{{UID: removable}} }},
		{"record gc", ErrRetention, func(s *Snapshot) {
			m := objectMeta("backup")
			m.OwnerReferences = []metav1.OwnerReference{{UID: removable}}
			s.Backups.Items = []arcade.GameBackup{{ObjectMeta: m, Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded}}}}
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

func TestExactAdmissionIdentitySpecificationsAndCurrentTypechecking(t *testing.T) {
	plan, base, inventory := safetyFixture(t)
	for _, test := range []struct {
		name   string
		want   error
		mutate func(*Snapshot)
	}{
		{"missing policy", ErrOwnership, func(s *Snapshot) { s.Policies.Items = s.Policies.Items[1:] }},
		{"replacement policy", ErrOwnership, func(s *Snapshot) { s.Policies.Items[0].UID = "replacement" }},
		{"stale checking", ErrAdmission, func(s *Snapshot) { s.Policies.Items[0].Status.ObservedGeneration = 0 }},
		{"missing checking", ErrAdmission, func(s *Snapshot) { s.Policies.Items[0].Status.TypeChecking = nil }},
		{"warning", ErrAdmission, func(s *Snapshot) {
			s.Policies.Items[0].Status.TypeChecking.ExpressionWarnings = []admissionv1.ExpressionWarning{{FieldRef: "spec", Warning: "bad"}}
		}},
		{"allow expression", ErrAdmission, func(s *Snapshot) { s.Policies.Items[0].Spec.Validations[0].Expression = "true" }},
		{"binding warns", ErrAdmission, func(s *Snapshot) {
			s.Bindings.Items[0].Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Warn}
		}},
		{"binding foreign namespace", ErrAdmission, func(s *Snapshot) {
			s.Bindings.Items[0].Spec.MatchResources.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] = "other"
		}},
		{"deleting binding", ErrAdmission, func(s *Snapshot) { now := metav1.Now(); s.Bindings.Items[0].DeletionTimestamp = &now }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := cloneSnapshot(base)
			test.mutate(s)
			if err := Validate(plan, s, inventory); !errors.Is(err, test.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
	bad := append([]installstate.Resource(nil), inventory...)
	bad[0].Retained = !bad[0].Retained
	if err := Validate(plan, base, bad); !errors.Is(err, ErrOwnership) {
		t.Fatal("inventory altered retention accepted")
	}
}
