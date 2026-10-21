// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"reflect"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

type coldFixture struct {
	plan      *installrender.Plan
	s         *Snapshot
	r         *RuntimeSnapshot
	inventory []installstate.Resource
	volumes   []*corev1.PersistentVolume
	games     *catalog.Catalog
}

func newColdFixture(t *testing.T, alternate bool) *coldFixture {
	t.Helper()
	f := &coldFixture{}
	f.plan, f.s, f.inventory = safetyFixture(t)
	f.games, _ = catalog.Builtins()
	definition, _ := f.games.Get("factorio")
	settings := `{"name":"test","maxPlayers":16,"visibility":"private"}`
	if alternate {
		definition = synthetic.Definition()
		// Two distinct adapter paths exercise complete selection coverage.
		definition.PersistentPaths = append(definition.PersistentPaths, definition.PersistentPaths[0])
		definition.PersistentPaths[1].Name, definition.PersistentPaths[1].MountPath = "extra", "/srv/extra"
		f.games, _ = catalog.New(definition)
		settings = `{"seed":"test"}`
	}
	server := arcade.GameServer{ObjectMeta: objectMeta("factory"), Spec: arcade.GameServerSpec{
		Game: definition.ID, ImageDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: arcade.DesiredStateStopped,
		Compute: arcade.ComputeSpec{CPURequest: resource.MustParse("500m"), CPULimit: resource.MustParse("2"), MemoryRequest: resource.MustParse("1Gi"), MemoryLimit: resource.MustParse("2Gi")},
		Storage: arcade.StorageSpec{Size: resource.MustParse("10Gi")}, Settings: runtime.RawExtension{Raw: []byte(settings)},
	}, Status: arcade.GameServerStatus{ObservedGeneration: 1, Phase: arcade.PhaseStopped}}
	p, err := platformkube.Build(&server, definition)
	if err != nil {
		t.Fatal(err)
	}
	server.Status.ObservedData = &arcade.RetainedDataReference{Identity: p.DataIdentity}
	for _, planned := range p.DataClaims {
		claim := planned.Desired.DeepCopy()
		claim.UID, claim.ResourceVersion = types.UID("uid-"+claim.Name), "1"
		claim.Spec.VolumeName = "pv-" + planned.Desired.Labels[platformkube.LabelDataPath]
		claim.Status.Phase, claim.Status.Capacity = corev1.ClaimBound, corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}
		f.s.Claims.Items = append(f.s.Claims.Items, *claim)
		server.Status.ObservedData.Claims = append(server.Status.ObservedData.Claims, arcade.RetainedDataClaimReference{Path: claim.Labels[platformkube.LabelDataPath], ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}})
		f.volumes = append(f.volumes, &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: claim.Spec.VolumeName, UID: types.UID("uid-" + claim.Spec.VolumeName), ResourceVersion: "1"}, Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "test.example", VolumeHandle: claim.Spec.VolumeName}},
			ClaimRef:               &corev1.ObjectReference{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}, AccessModes: claim.Spec.AccessModes, Capacity: claim.Status.Capacity.DeepCopy(),
		}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}})
	}
	f.s.GameServers.Items = []arcade.GameServer{server}
	meta := metav1.ListMeta{ResourceVersion: "10"}
	f.r = &RuntimeSnapshot{Deployments: &appsv1.DeploymentList{ListMeta: meta}, ReplicaSets: &appsv1.ReplicaSetList{ListMeta: meta}, StatefulSets: &appsv1.StatefulSetList{ListMeta: meta}, DaemonSets: &appsv1.DaemonSetList{ListMeta: meta}, ReplicationControllers: &corev1.ReplicationControllerList{ListMeta: meta}, CronJobs: &batchv1.CronJobList{ListMeta: meta}, Attachments: &storagev1.VolumeAttachmentList{ListMeta: meta}}
	return f
}

func (f *coldFixture) validate() error {
	return ValidateCold(f.plan, f.s, f.r, f.inventory, f.volumes, f.games)
}

func (f *coldFixture) attachment(name string, inline bool) {
	m := objectMeta("attachment")
	m.Namespace = ""
	a := storagev1.VolumeAttachment{ObjectMeta: m, Spec: storagev1.VolumeAttachmentSpec{Attacher: "test.example", NodeName: "node"}}
	if inline {
		a.Spec.Source.InlineVolumeSpec = &corev1.PersistentVolumeSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "test.example", VolumeHandle: name}}}
	} else {
		a.Spec.Source.PersistentVolumeName = ptr.To(name)
	}
	f.r.Attachments.Items = append(f.r.Attachments.Items, a)
}

func TestColdCurrentWorldAndPendingGeneratedDataNonmutation(t *testing.T) {
	for _, alternate := range []bool{false, true} {
		f := newColdFixture(t, alternate)
		before, runtimeBefore, pvBefore := cloneSnapshot(f.s), f.r.DeepCopy(), f.volumes[0].DeepCopy()
		if err := f.validate(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, f.s) || !reflect.DeepEqual(runtimeBefore, f.r) || !reflect.DeepEqual(pvBefore, f.volumes[0]) {
			t.Fatal("cold validator mutated evidence")
		}
		if alternate {
			a := f.s.GameServers.Items[0].Status.ObservedData.Claims
			a[0], a[1] = a[1], a[0]
			if err := f.validate(); err != nil {
				t.Fatal("path order became identity")
			}
		}
		f.s.GameServers.Items[0].Status.ObservedData = nil
		f.volumes = nil
		for i := range f.s.Claims.Items {
			f.s.Claims.Items[i].Status.Phase = corev1.ClaimPending
			f.s.Claims.Items[i].Spec.VolumeName = ""
			f.s.Claims.Items[i].Status.Capacity = nil
		}
		if err := f.validate(); err != nil {
			t.Fatal("new Pending generated data must remain retained", err)
		}
	}
}

func TestColdRefusesReplacedWorldBindingGCAndStatusOnlySwitch(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*coldFixture)
	}{
		{"missing-current-claim", func(f *coldFixture) { f.s.Claims.Items = nil }},
		{"replaced-current-uid", func(f *coldFixture) { f.s.Claims.Items[0].UID = "replacement" }},
		{"unknown-game", func(f *coldFixture) { f.s.GameServers.Items[0].Spec.Game = "uninstalled" }},
		{"invalid-intent", func(f *coldFixture) { f.s.GameServers.Items[0].Spec.ImageDigest = "latest" }},
		{"identity-label", func(f *coldFixture) { f.s.Claims.Items[0].Labels[platformkube.LabelDataIdentity] = "foreign" }},
		{"observed-identity", func(f *coldFixture) { f.s.GameServers.Items[0].Status.ObservedData.Identity = "foreign" }},
		{"observed-missing-path", func(f *coldFixture) { f.s.GameServers.Items[0].Status.ObservedData.Claims = nil }},
		{"observed-extra-path", func(f *coldFixture) {
			d := f.s.GameServers.Items[0].Status.ObservedData
			d.Claims = append(d.Claims, d.Claims[0])
		}},
		{"observed-foreign-path", func(f *coldFixture) { f.s.GameServers.Items[0].Status.ObservedData.Claims[0].Path = "foreign" }},
		{"observed-namespace", func(f *coldFixture) {
			f.s.GameServers.Items[0].Status.ObservedData.Claims[0].ClaimRef.Namespace = ptr.To("foreign")
		}},
		{"status-only-switch", func(f *coldFixture) {
			d := f.s.GameServers.Items[0].Status.ObservedData.DeepCopy()
			d.Identity = "restored"
			f.s.GameServers.Items[0].Status.ActiveData = d
		}},
		{"missing-bound-receipt", func(f *coldFixture) { f.s.GameServers.Items[0].Status.ObservedData = nil }},
		{"exact-pending-without-receipt", func(f *coldFixture) {
			server := &f.s.GameServers.Items[0]
			server.Spec.Storage.Reattach = server.Status.ObservedData.DeepCopy()
			server.Status.ObservedData = nil
			f.s.Claims.Items[0].Spec.VolumeName = ""
			f.s.Claims.Items[0].Status.Phase = corev1.ClaimPending
			f.volumes = nil
		}},
		{"deleting-claim", func(f *coldFixture) { now := metav1.Now(); f.s.Claims.Items[0].DeletionTimestamp = &now }},
		{"lost-claim", func(f *coldFixture) { f.s.Claims.Items[0].Status.Phase = corev1.ClaimLost }},
		{"pending-bound-name", func(f *coldFixture) { f.s.Claims.Items[0].Status.Phase = corev1.ClaimPending }},
		{"missing-pv", func(f *coldFixture) { f.volumes = nil }},
		{"pv-uid", func(f *coldFixture) { f.volumes[0].UID = "" }},
		{"pv-rv", func(f *coldFixture) { f.volumes[0].ResourceVersion = "" }},
		{"pv-bound-uid", func(f *coldFixture) { f.volumes[0].Spec.ClaimRef.UID = "replacement" }},
		{"pv-bound-namespace", func(f *coldFixture) { f.volumes[0].Spec.ClaimRef.Namespace = "foreign" }},
		{"pv-bound-name", func(f *coldFixture) { f.volumes[0].Spec.ClaimRef.Name = "foreign" }},
		{"pv-bound-kind", func(f *coldFixture) { f.volumes[0].Spec.ClaimRef.Kind = "Secret" }},
		{"pv-bound-api", func(f *coldFixture) { f.volumes[0].Spec.ClaimRef.APIVersion = "foreign/v1" }},
		{"pv-not-bound", func(f *coldFixture) { f.volumes[0].Status.Phase = corev1.VolumeReleased }},
		{"pv-deleting", func(f *coldFixture) { now := metav1.Now(); f.volumes[0].DeletionTimestamp = &now }},
		{"pv-gc-parent", func(f *coldFixture) {
			f.volumes[0].OwnerReferences = []metav1.OwnerReference{{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "arcadectl-controller", UID: "original-removable"}}
		}},
		{"pv-duplicate", func(f *coldFixture) { f.volumes = append(f.volumes, f.volumes[0].DeepCopy()) }},
		{"pv-unknown-source", func(f *coldFixture) {
			f.volumes[0].Spec.PersistentVolumeSource = corev1.PersistentVolumeSource{NFS: &corev1.NFSVolumeSource{Server: "server", Path: "/world"}}
		}},
		{"pv-ambiguous-source", func(f *coldFixture) {
			f.volumes[0].Spec.NFS = &corev1.NFSVolumeSource{Server: "server", Path: "/world"}
		}},
		{"pv-empty-driver", func(f *coldFixture) { f.volumes[0].Spec.CSI.Driver = "" }},
		{"pv-empty-handle", func(f *coldFixture) { f.volumes[0].Spec.CSI.VolumeHandle = "" }},
		{"pv-class", func(f *coldFixture) { f.volumes[0].Spec.StorageClassName = "foreign" }},
		{"pv-mode", func(f *coldFixture) { f.volumes[0].Spec.VolumeMode = ptr.To(corev1.PersistentVolumeBlock) }},
		{"current-path-block-mode", func(f *coldFixture) {
			f.s.Claims.Items[0].Spec.VolumeMode = ptr.To(corev1.PersistentVolumeBlock)
			f.volumes[0].Spec.VolumeMode = ptr.To(corev1.PersistentVolumeBlock)
		}},
		{"pv-capacity", func(f *coldFixture) { f.volumes[0].Spec.Capacity = nil }},
		{"bound-capacity", func(f *coldFixture) { f.s.Claims.Items[0].Status.Capacity = nil }},
		{"pv-access", func(f *coldFixture) {
			f.volumes[0].Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadOnlyMany}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newColdFixture(t, false)
			test.change(f)
			if err := f.validate(); err == nil {
				t.Fatal("accepted contradictory world/storage evidence")
			}
		})
	}
	f := newColdFixture(t, true)
	f.volumes[1].UID = f.volumes[0].UID
	if err := f.validate(); err == nil {
		t.Fatal("accepted duplicate PV identity across names")
	}
}

func TestColdAttachmentIntentAndPhysicalAliases(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*coldFixture)
		valid  bool
	}{
		{"matching-pending", func(f *coldFixture) { f.attachment(f.volumes[0].Name, false) }, false},
		{"matching-attached", func(f *coldFixture) {
			f.attachment(f.volumes[0].Name, false)
			f.r.Attachments.Items[0].Status.Attached = true
		}, false},
		{"matching-error", func(f *coldFixture) {
			f.attachment(f.volumes[0].Name, false)
			f.r.Attachments.Items[0].Status.AttachError = &storagev1.VolumeError{Message: "PRIVATE-CANARY"}
		}, false},
		{"matching-deleting", func(f *coldFixture) {
			f.attachment(f.volumes[0].Name, false)
			now := metav1.Now()
			f.r.Attachments.Items[0].DeletionTimestamp = &now
		}, false},
		{"inline-alias", func(f *coldFixture) { f.attachment(f.volumes[0].Spec.CSI.VolumeHandle, true) }, false},
		{"inline-distinct", func(f *coldFixture) { f.attachment("unrelated-handle", true) }, true},
		{"inline-attributes-not-identity", func(f *coldFixture) {
			f.attachment(f.volumes[0].Spec.CSI.VolumeHandle, true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.CSI.VolumeAttributes = map[string]string{"different": "value"}
		}, false},
		{"inline-driver-distinct", func(f *coldFixture) {
			f.attachment(f.volumes[0].Spec.CSI.VolumeHandle, true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.CSI.Driver = "other.example"
		}, true},
		{"inline-empty-driver", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.CSI.Driver = ""
		}, false},
		{"inline-empty-handle", func(f *coldFixture) { f.attachment("", true) }, false},
		{"inline-no-access", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.AccessModes = nil
		}, false},
		{"inline-foreign-access", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.AccessModes = []corev1.PersistentVolumeAccessMode{"unknown"}
		}, false},
		{"inline-mixed-once-pod", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod, corev1.ReadWriteMany}
		}, false},
		{"inline-bad-driver", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.CSI.Driver = "foreign/driver"
		}, false},
		{"no-attacher", func(f *coldFixture) { f.attachment("unrelated", true); f.r.Attachments.Items[0].Spec.Attacher = "" }, false},
		{"no-node", func(f *coldFixture) { f.attachment("unrelated", true); f.r.Attachments.Items[0].Spec.NodeName = "" }, false},
		{"inline-claimref", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.ClaimRef = &corev1.ObjectReference{Name: "foreign"}
		}, false},
		{"inline-ambiguous-source", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.NFS = &corev1.NFSVolumeSource{Server: "foreign", Path: "/world"}
		}, false},
		{"inline-block", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.VolumeMode = ptr.To(corev1.PersistentVolumeBlock)
		}, false},
		{"empty-source", func(f *coldFixture) {
			f.attachment("unrelated", false)
			f.r.Attachments.Items[0].Spec.Source.PersistentVolumeName = nil
		}, false},
		{"both-sources", func(f *coldFixture) {
			f.attachment("unrelated", true)
			f.r.Attachments.Items[0].Spec.Source.PersistentVolumeName = ptr.To("foreign")
		}, false},
		{"foreign-name-same-backing", func(f *coldFixture) {
			f.attachment("foreign", false)
			v := f.volumes[0].DeepCopy()
			v.Name, v.UID = "foreign", "foreign-uid"
			f.volumes = append(f.volumes, v)
		}, false},
		{"foreign-name-distinct-backing", func(f *coldFixture) {
			f.attachment("foreign", false)
			v := f.volumes[0].DeepCopy()
			v.Name, v.UID = "foreign", "foreign-uid"
			v.Spec.CSI.VolumeHandle = "unrelated"
			f.volumes = append(f.volumes, v)
		}, true},
		{"foreign-name-unread", func(f *coldFixture) { f.attachment("foreign", false) }, false},
		{"foreign-name-unsupported", func(f *coldFixture) {
			f.attachment("foreign", false)
			v := f.volumes[0].DeepCopy()
			v.Name, v.UID = "foreign", "foreign-uid"
			v.Spec.PersistentVolumeSource = corev1.PersistentVolumeSource{NFS: &corev1.NFSVolumeSource{Server: "foreign", Path: "/world"}}
			f.volumes = append(f.volumes, v)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newColdFixture(t, false)
			test.change(f)
			if err := f.validate(); (err == nil) != test.valid {
				t.Fatal("incorrect physical attachment classification", err)
			}
		})
	}
}

func TestColdEveryBuiltinTemplateRefusesFutureRemountEvenAtZero(t *testing.T) {
	for _, kind := range []string{"Pod", "Job", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "ReplicationController", "CronJob", "StatefulSetClaims", "Ephemeral"} {
		t.Run(kind, func(t *testing.T) {
			f := newColdFixture(t, false)
			// Even unlabeled claims outside platform histories are retained.
			claim := corev1.PersistentVolumeClaim{ObjectMeta: objectMeta("data-set-9"), Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
			f.s.Claims.Items = append(f.s.Claims.Items, claim)
			template := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name}}}}}}
			m := objectMeta("set")
			switch kind {
			case "Pod":
				f.s.Pods.Items = []corev1.Pod{{ObjectMeta: m, Spec: template.Spec, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}}
			case "Job":
				f.s.Jobs.Items = []batchv1.Job{{ObjectMeta: m, Spec: batchv1.JobSpec{Template: template, Suspend: ptr.To(true)}}}
			case "Deployment":
				f.r.Deployments.Items = []appsv1.Deployment{{ObjectMeta: m, Spec: appsv1.DeploymentSpec{Replicas: ptr.To(int32(0)), Template: template}}}
			case "ReplicaSet":
				f.r.ReplicaSets.Items = []appsv1.ReplicaSet{{ObjectMeta: m, Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To(int32(0)), Template: template}}}
			case "StatefulSet":
				f.r.StatefulSets.Items = []appsv1.StatefulSet{{ObjectMeta: m, Spec: appsv1.StatefulSetSpec{Replicas: ptr.To(int32(0)), Template: template}}}
			case "DaemonSet":
				f.r.DaemonSets.Items = []appsv1.DaemonSet{{ObjectMeta: m, Spec: appsv1.DaemonSetSpec{Template: template}}}
			case "ReplicationController":
				f.r.ReplicationControllers.Items = []corev1.ReplicationController{{ObjectMeta: m, Spec: corev1.ReplicationControllerSpec{Replicas: ptr.To(int32(0)), Template: &template}}}
			case "CronJob":
				f.r.CronJobs.Items = []batchv1.CronJob{{ObjectMeta: m, Spec: batchv1.CronJobSpec{Suspend: ptr.To(true), JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: template}}}}}
			case "StatefulSetClaims":
				f.r.StatefulSets.Items = []appsv1.StatefulSet{{ObjectMeta: m, Spec: appsv1.StatefulSetSpec{Replicas: ptr.To(int32(0)), VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}}}}}}
			case "Ephemeral":
				m.Name = "data-set"
				f.s.Claims.Items[len(f.s.Claims.Items)-1].Name = "data-set-9"
				f.s.Pods.Items = []corev1.Pod{{ObjectMeta: m, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "9", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}}}}}
			}
			if err := f.validate(); err == nil {
				t.Fatal("template can remount retained data")
			}
		})
	}
}

func TestColdCompleteRuntimeAndHistoricalReferences(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*coldFixture)
	}{
		{"missing-list", func(f *coldFixture) { f.r.CronJobs = nil }},
		{"paged-list", func(f *coldFixture) { f.r.StatefulSets.Continue = "next" }},
		{"unread-list", func(f *coldFixture) { f.r.Attachments.ResourceVersion = "" }},
		{"remaining-list", func(f *coldFixture) { f.r.Deployments.RemainingItemCount = ptr.To(int64(1)) }},
		{"duplicate-uid", func(f *coldFixture) {
			a := appsv1.Deployment{ObjectMeta: objectMeta("a")}
			b := a
			b.Name = "b"
			f.r.Deployments.Items = []appsv1.Deployment{a, b}
		}},
		{"foreign-scope", func(f *coldFixture) {
			f.attachment("foreign", true)
			f.r.Attachments.Items[0].Namespace = f.plan.Namespace()
		}},
		{"worker-template", func(f *coldFixture) {
			f.r.Deployments.Items = []appsv1.Deployment{{ObjectMeta: objectMeta("renamed"), Spec: appsv1.DeploymentSpec{Replicas: ptr.To(int32(0)), Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "restore-exact-authority"}}}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newColdFixture(t, false)
			test.change(f)
			if f.validate() == nil {
				t.Fatal("accepted incomplete/worker runtime")
			}
		})
	}
	f := newColdFixture(t, false)
	// Settled historical references may outlive their exact source claims.
	f.s.Backups.Items = []arcade.GameBackup{{ObjectMeta: objectMeta("nightly"), Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{ObservedGeneration: 1, Phase: arcade.DataPhaseSucceeded, Source: &arcade.DataSourceSnapshot{Paths: []arcade.DataPathIdentity{{Name: "world", ClaimRef: arcade.ExactLocalReference{Name: "deleted-history", UID: "old-uid"}}}}}}}}
	if err := f.validate(); err != nil {
		t.Fatal("historical source became mandatory-live", err)
	}
	f.r.Deployments.Items = []appsv1.Deployment{{ObjectMeta: objectMeta("remount"), Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "deleted-history"}}}}}}}}}
	if f.validate() == nil {
		t.Fatal("historical claim name lost conservative mount evidence")
	}
}
